"""Label recommendations (M5B) and proposed classification rules (M5C). LOCAL ONLY, read-only: nothing here is applied, saved or sent anywhere.

Inputs are exactly what the local index stores: sender address/domain, label ids, unread flag and the M3 classifications. Subjects, bodies and snippets do not exist
locally and are never used. A "tag" in M5 is the local classification TYPE (NEWSLETTER, ...); a "label" is an existing Gmail user label. A recommendation never edits Gmail.

Confidence is EVIDENCE STRENGTH, not a probability. Tiers (conservative, documented in docs/LABELS.md):
  LOW     : at least MIN_GROUP messages in the group and a dominant pattern covering at least 60% of them.
  MEDIUM  : at least 5 messages and at least 80% agreement.
  HIGH    : at least 20 messages and at least 95% agreement.
Caps: a partial index, an INFERRED basis (classification instead of observed label usage), stale classifications or any AI-sourced classification limit a suggestion to MEDIUM,
so such evidence can never yield HIGH on its own. Groups containing protected or potentially important mail are suppressed (and counted), never suggested.

Rule proposals reuse the M3 rule model (`classify.validate_new_rule`) and the single M3 preview (`classifier.preview_rule`); there is no second preview implementation, and a
proposal is never persisted (`classify rules add` is the only way a rule is stored, run by the owner).
"""
from collections import Counter, defaultdict
from dataclasses import dataclass

from gmail_intelligence import classifier, classify, cleanup_protect, label_model as lm, report

MIN_GROUP = 3
CREATE_MIN_MESSAGES = 10
LABEL_USAGE_RATIO = 0.6
_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_NAMES = ("LOW", "MEDIUM", "HIGH")
IGNORED_LABELS = frozenset({"TRASH", "SPAM"})
PROTECTED_LABELS = frozenset({"STARRED", "IMPORTANT", "SENT", "DRAFT"})
TYPE_LABEL_NAMES = {"NEWSLETTER": "Newsletters", "PROMOTIONAL": "Promotions", "SOCIAL": "Social updates", "AUTOMATED_NOTIFICATION": "Notifications",
                    "TRANSACTIONAL": "Receipts and orders", "FINANCIAL": "Finance", "EDUCATIONAL": "Learning"}


@dataclass(frozen=True)
class Recommendation:
    kind: str  # APPLY_LABEL | CREATE_LABEL
    group: tuple  # ("domain"|"sender", key) or ("type", TYPE) for CREATE_LABEL; private, hidden by default
    target: str  # existing label id (APPLY_LABEL) or the proposed generic label name (CREATE_LABEL)
    confidence: str
    basis: str  # OBSERVED (existing label usage) | INFERRED (classification / sender pattern)
    source: str  # label-usage | classification-rules | classification-ai
    reason: str
    evidence: tuple  # ((name, value), ...)
    caveats: tuple = ()


@dataclass(frozen=True)
class RuleProposal:
    group: tuple
    kind: str
    value: str
    confidence: str
    basis: str
    reason: str
    supporting: tuple
    false_positives: tuple
    preview: tuple  # ((name, n), ...) from classifier.preview_rule
    existing: str
    fields: tuple  # the exact `classify.validate_new_rule` fields, ((name, value), ...)


@dataclass(frozen=True)
class Suggestions:
    items: tuple
    suppressed: tuple  # ((reason, groups), ...)
    messages_indexed: int
    groups_considered: int
    index_state: str
    index_why: str


def _cap(conf, ceiling):
    return _NAMES[min(_RANK[conf], _RANK[ceiling])]


def tier(n, ratio, *, complete=True, inferred=False, weak=False):
    """Evidence tier for `n` messages agreeing at `ratio`, or None when the evidence is too small to suggest anything."""
    if n < MIN_GROUP or ratio < 0.6:
        return None
    conf = "HIGH" if n >= 20 and ratio >= 0.95 else "MEDIUM" if n >= 5 and ratio >= 0.8 else "LOW"
    return _cap(conf, "MEDIUM") if (not complete or inferred or weak) else conf


def _domain(sender):
    return sender.rpartition("@")[2] if "@" in sender else ""


class _Group:
    __slots__ = ("n", "user_labels", "types", "unread", "protected", "stale", "ai", "classified")

    def __init__(self):
        self.n = self.unread = self.protected = self.stale = self.ai = self.classified = 0
        self.user_labels, self.types = Counter(), Counter()


def _gather(index, account):
    """{('domain'|'sender', key): _Group} over non-trash/spam messages, plus the protected-signal tallies. Pure reads."""
    rhash = classifier.current_hash(index, account)
    rows = index._q("SELECT id, sender, unread, scan_id FROM messages WHERE account=? ORDER BY id", account)
    labels = defaultdict(set)
    for r in index._q("SELECT message_id, label_id FROM message_labels WHERE account=?", account):
        labels[r["message_id"]].add(r["label_id"])
    names = {l.id: l.name.lower() for l in lm.load_labels(index, account)}
    user_ids = {l.id for l in lm.load_labels(index, account) if l.user}
    cls = defaultdict(list)
    for r in index._q("SELECT message_id, kind, value, source, ruleset_hash, msg_scan_id FROM message_class WHERE account=?", account):
        cls[r["message_id"]].append(r)
    scan = {r["id"]: r["scan_id"] for r in rows}
    protect = cleanup_protect.active(index, account)
    groups = defaultdict(_Group)
    for r in rows:
        ids = labels[r["id"]]
        sender = (r["sender"] or "").strip().lower()
        if not sender or "@" not in sender or ids & IGNORED_LABELS:
            continue
        feats = classify.Features(sender, bool(r["unread"]), frozenset(ids), frozenset(names[i] for i in ids if i in names))
        rows_c = cls.get(r["id"], [])
        current = [c for c in rows_c if c["ruleset_hash"] == rhash and c["msg_scan_id"] == scan[r["id"]]]
        types = {c["value"] for c in current if c["kind"] == "type"}
        attention = any(c["kind"] == "attention" for c in current)
        protected = bool(ids & PROTECTED_LABELS) or attention or "PERSONAL" in types or any(p.matches(feats) for p in protect)
        for key in (("domain", _domain(sender)), ("sender", sender)):
            g = groups[key]
            g.n += 1
            g.unread += bool(r["unread"])
            g.protected += protected
            g.user_labels.update(i for i in ids if i in user_ids)
            if current:
                g.classified += 1
                for c in current:
                    g.ai += c["source"] == "ai"
                for t in types - {"UNKNOWN"}:
                    g.types[t] += 1
            elif rows_c:
                g.stale += 1
    return groups


def _sorted(items):
    def key(i):
        return (-_RANK[i.confidence], -dict(getattr(i, "evidence", None) or i.supporting).get("messages", 0), i.kind, str(i.group), str(getattr(i, "target", "")))
    return tuple(sorted(items, key=key))


def gather(index, account):
    """The per-group facts both `recommend` and `suggest_rules` read. Read-only; compute it once per request and pass it to both (it is never cached between requests)."""
    return _gather(index, account)


def recommend(index, account, groups=None):
    """Label recommendations. See the module docstring. Deterministic. `groups` may be the result of `gather`, to avoid reading the index again."""
    state, why = report.completeness(index, account)
    complete = state == "complete"
    total = index._q("SELECT COUNT(*) FROM messages WHERE account=?", account)[0][0]
    labels = {l.id: l for l in lm.load_labels(index, account) if l.user}
    groups = _gather(index, account) if groups is None else groups
    out, suppressed, considered = [], Counter(), 0
    seen = set()
    for key, g in sorted(groups.items()):
        if g.n < MIN_GROUP:
            continue
        considered += 1
        if g.protected:
            suppressed["protected or potentially important mail in the group"] += 1
            continue
        if not g.user_labels:
            continue
        lid, used = sorted(g.user_labels.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        missing = g.n - used
        conf = tier(g.n, used / g.n, complete=complete)
        if conf is None or missing < 1 or lid not in labels:
            continue
        # the sender-level suggestion is redundant when its domain already yields the same label
        if key[0] == "sender" and ("domain", _domain(key[1])) in seen and (("domain", _domain(key[1])), lid) in seen:
            continue
        seen.add(key)
        seen.add((key, lid))
        out.append(Recommendation("APPLY_LABEL", key, lid, conf, "OBSERVED", "label-usage",
                                  f"{used} of {g.n} indexed messages from this {key[0]} already carry this label; {missing} do not",
                                  (("messages", g.n), ("with_label", used), ("missing", missing), ("agreement_pct", round(100 * used / g.n))),
                                  () if complete else ("the index is partial: other messages from this sender may exist in Gmail",)))
    by_type = defaultdict(lambda: {"groups": 0, "messages": 0, "ai": 0, "stale": 0})
    for key, g in sorted(groups.items()):
        if key[0] != "domain" or g.n < MIN_GROUP or g.protected or g.user_labels or not g.types:
            continue
        t, n = g.types.most_common(1)[0]
        if t not in TYPE_LABEL_NAMES or n / g.n < 0.8 or g.stale:
            continue
        agg = by_type[t]
        agg["groups"] += 1
        agg["messages"] += g.n
        agg["ai"] += g.ai
    taken = {lm.normalize(l.name): l.id for l in labels.values()}
    for t, agg in sorted(by_type.items()):
        if agg["messages"] < CREATE_MIN_MESSAGES:
            continue
        name = TYPE_LABEL_NAMES[t]
        conf = tier(agg["messages"], 1.0, complete=complete, inferred=True, weak=bool(agg["ai"]))
        if conf is None:
            continue
        src = "classification-ai" if agg["ai"] else "classification-rules"
        ev = (("messages", agg["messages"]), ("domains", agg["groups"]), ("type", t))
        if lm.normalize(name) in taken:
            out.append(Recommendation("APPLY_LABEL", ("type", t), taken[lm.normalize(name)], conf, "INFERRED", src,
                                      f"{agg['messages']} messages from {agg['groups']} domains are classified {t} and carry no label; an existing label has a matching name", ev))
        else:
            out.append(Recommendation("CREATE_LABEL", ("type", t), name, conf, "INFERRED", src,
                                      f"{agg['messages']} messages from {agg['groups']} domains are classified {t} and carry no label of yours", ev,
                                      ("the name is a generic suggestion; creating a label is a separate, approved step (labels plan create)",)))
    return Suggestions(_sorted(out), tuple(sorted(suppressed.items())), total, considered, state, why)


def suggest_rules(index, account, groups=None, context=None):
    """Proposed M3 classification rules. Each reuses `classify.validate_new_rule` and the M3 preview (`classifier.PreviewContext.preview`, the single implementation behind
    `classifier.preview_rule`); nothing is saved. `groups` (from `gather`) and `context` (a `classifier.PreviewContext`) may be passed in to avoid recomputing them."""
    state, why = report.completeness(index, account)
    complete = state == "complete"
    total = index._q("SELECT COUNT(*) FROM messages WHERE account=?", account)[0][0]
    groups = _gather(index, account) if groups is None else groups
    existing = classifier.active_rules(index, account)
    out, suppressed, considered = [], Counter(), 0
    for key, g in sorted(groups.items()):
        if g.n < MIN_GROUP:
            continue
        considered += 1
        same = [r for r in existing if r.kind == "type" and (r.sender, r.domain) == ((key[1], None) if key[0] == "sender" else (None, key[1])) and r.label is None]
        if same:  # an enabled rule on the same condition exists (agreeing or not): never duplicate or contradict it
            suppressed["an enabled rule already exists for this group (never duplicated or contradicted)"] += 1
            continue
        if not g.types:
            continue
        t, n = g.types.most_common(1)[0]
        ratio = n / g.n
        if g.protected:
            suppressed["protected or potentially important mail in the group"] += 1
            continue
        conf = tier(g.n, ratio, complete=complete, inferred=True, weak=bool(g.ai or g.stale))
        if conf is None or t == "UNKNOWN":
            continue
        fields = {"kind": "type", "value": t, "confidence": conf, "priority": 0, key[0]: key[1], "note": "proposed by labels suggest-rules"}
        try:
            classify.validate_new_rule(**fields)
        except classify.RuleError:
            suppressed["not a valid rule"] += 1
            continue
        if context is None:  # built on first use, so an index with nothing to preview pays nothing
            context = classifier.PreviewContext(index, account)
        prev = context.preview(**fields)
        if prev["type_changes"] == 0 and prev["now_unknown"] == 0:
            suppressed["no effect: current classification already agrees"] += 1
            continue
        other = g.n - n
        if key[0] == "sender" and ("domain", _domain(key[1])) in {p.group for p in out if p.value == t}:
            suppressed["the domain-level proposal already covers this sender"] += 1
            continue
        out.append(RuleProposal(key, "type", t, conf, "INFERRED", f"{n} of {g.n} classified messages from this {key[0]} are {t}; a rule would classify the rest the same way",
                                (("messages", g.n), ("agree", n), ("agreement_pct", round(100 * ratio))),
                                (("classified_differently_or_unknown", other), ("unread", g.unread), ("ai_sourced", g.ai), ("stale", g.stale)),
                                tuple(sorted(prev.items())), "no enabled rule for this " + key[0], tuple(sorted(fields.items()))))
    return Suggestions(_sorted(out), tuple(sorted(suppressed.items())), total, considered, state, why)
