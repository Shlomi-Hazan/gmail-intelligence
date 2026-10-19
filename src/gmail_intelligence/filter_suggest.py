"""Gmail filter SUGGESTIONS (M5E). LOCAL ONLY: this module never creates a filter, never calls Gmail and needs no Gmail settings (filter-management) scope. A suggestion is text the owner
could recreate by hand in Gmail; it is distinct from an M3 classification rule (which only labels messages in the LOCAL index).

Safe vocabulary: a criterion is an exact sender address or exact sender domain (the same exact-match vocabulary as classification rules, no wildcards); the only action ever
suggested is APPLY_LABEL with a user label. `validate_filter` is the explicit gate: forwarding, Trash, delete, skip-Inbox (archive), send, mark-as-spam, never-spam, star, mark read
and every unknown action are rejected, so even a future suggestion source cannot emit one. Estimated effect counts messages already in the local index only; what a filter does to
FUTURE mail cannot be measured here and is stated as unknown.
"""
from dataclasses import dataclass

from gmail_intelligence import classify, label_model as lm, label_suggest as ls

NOTHING_APPLIED = "Nothing was applied: no Gmail filter was created, changed or requested, and this tool has no permission to do so."
SAFE_ACTIONS = ("APPLY_LABEL",)
FORBIDDEN_ACTIONS = frozenset({"FORWARD", "FORWARD_TO", "TRASH", "DELETE", "DELETE_IT", "SKIP_INBOX", "ARCHIVE", "REMOVE_LABEL_INBOX", "SEND", "SEND_CANNED_RESPONSE", "REPLY",
                               "MARK_SPAM", "NEVER_SPAM", "MARK_AS_READ", "MARK_READ", "STAR", "MARK_IMPORTANT", "NEVER_IMPORTANT", "CATEGORIZE"})
FORBIDDEN_LABELS = frozenset({"INBOX", "TRASH", "SPAM", "UNREAD", "SENT", "DRAFT", "STARRED", "IMPORTANT"})


class FilterError(ValueError):
    """A filter suggestion that the safe vocabulary does not allow. `code` is a fixed identifier."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def validate_filter(criteria, actions):
    """Validated (criteria, actions) as sorted tuples, or FilterError. `criteria`: {'sender'|'domain': exact value}; `actions`: [(name, value)]."""
    if not isinstance(criteria, dict) or set(criteria) - {"sender", "domain"} or not criteria:
        raise FilterError("BAD_CRITERIA", "a filter needs exactly sender and/or domain criteria (exact match only)")
    try:
        cond = classify.validate_conditions(sender=criteria.get("sender"), domain=criteria.get("domain"))
    except classify.RuleError as exc:
        raise FilterError("BAD_CRITERIA", str(exc)) from None
    if not actions:
        raise FilterError("NO_ACTION", "a filter needs at least one action")
    out = []
    for item in actions:
        try:
            name, value = item
        except (TypeError, ValueError):
            raise FilterError("UNSUPPORTED_ACTION", "an action must be a (name, value) pair") from None
        name = str(name).strip().upper()
        if name in FORBIDDEN_ACTIONS:
            raise FilterError("FORBIDDEN_ACTION", f"the action {name} is never suggested (forwarding, Trash, delete, skip Inbox, send and similar are excluded)")
        if name not in SAFE_ACTIONS:
            raise FilterError("UNSUPPORTED_ACTION", f"the action {name[:30]} is not supported")
        value = str(value or "")
        if value.upper() in FORBIDDEN_LABELS or lm.reserved(value) or value in lm.SYSTEM_IDS or value.startswith("CATEGORY_"):
            raise FilterError("SYSTEM_LABEL", "a filter may only apply a user label, never a system label")
        if not (value.startswith("Label_") or lm.name_problem(value) is None):
            raise FilterError("BAD_LABEL", "the label must be a user label id or a valid label name")
        out.append((name, value))
    return tuple(sorted(cond.items())), tuple(sorted(set(out)))


@dataclass(frozen=True)
class FilterSuggestion:
    criteria: tuple
    actions: tuple
    confidence: str
    basis: str
    reason: str
    evidence: tuple
    effect: tuple  # ((name, n), ...): indexed messages that match / already carry the label / would gain it
    warnings: tuple


@dataclass(frozen=True)
class FilterSuggestions:
    items: tuple
    suppressed: tuple
    messages_indexed: int
    index_state: str
    index_why: str


def suggest(index, account):
    rec = ls.recommend(index, account)
    out = []
    for r in rec.items:
        if r.kind != "APPLY_LABEL" or r.group[0] not in ("sender", "domain"):
            continue
        try:
            criteria, actions = validate_filter({r.group[0]: r.group[1]}, [("APPLY_LABEL", r.target)])
        except FilterError:
            continue
        ev = dict(r.evidence)
        warnings = ["filters act on FUTURE mail too; this tool cannot measure that, only the messages already indexed",
                    "Gmail's own filter behaviour is not verified by this tool"]
        if rec.index_state != "complete":
            warnings.insert(0, "the index is partial: the real effect may be larger than the indexed counts")
        out.append(FilterSuggestion(criteria, actions, r.confidence, r.basis, r.reason, r.evidence,
                                    (("matching_indexed", ev["messages"]), ("already_labeled", ev["with_label"]), ("would_gain_label", ev["missing"])), tuple(warnings)))
    return FilterSuggestions(tuple(out), rec.suppressed, rec.messages_indexed, rec.index_state, rec.index_why)
