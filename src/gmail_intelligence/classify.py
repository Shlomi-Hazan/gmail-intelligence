"""Deterministic, offline classification of locally indexed message metadata (M3). Stdlib only.

Pure logic: no database, no network, no Gmail. A message is described by `Features` (sender, domain, label ids/names,
unread flag). Rules are plain data (explicit match fields, no regex, no code execution). The same input and the same
ruleset always give the same result. Precedence, conflicts and confidence semantics are documented in
docs/CLASSIFICATION.md.
"""
import hashlib
import json
from dataclasses import dataclass, field

TAXONOMY_VERSION = 1
BUILTIN_VERSION = 1

# What the message IS (several may apply) vs. whether it deserves a look (attention) vs. how sure we are (confidence).
TYPES = ("PERSONAL", "PROMOTIONAL", "NEWSLETTER", "SOCIAL", "AUTOMATED_NOTIFICATION", "TRANSACTIONAL", "FINANCIAL",
         "EDUCATIONAL", "UNKNOWN")
ATTENTION = ("POTENTIALLY_IMPORTANT", "REVIEW_NEEDED")
KINDS = ("type", "attention")
CONFIDENCE = ("LOW", "MEDIUM", "HIGH")  # evidence strength of the rule; NOT a calibrated probability
_RANK = {c: i for i, c in enumerate(CONFIDENCE)}
SOURCES = ("rules", "ai")
TIER_BUILTIN, TIER_USER = 1, 2

# Type pairs that can legitimately be true together; any other combination at the same precedence is a conflict.
_COMPATIBLE = {frozenset(p) for p in (("TRANSACTIONAL", "FINANCIAL"), ("NEWSLETTER", "EDUCATIONAL"),
                                      ("NEWSLETTER", "PROMOTIONAL"), ("FINANCIAL", "PROMOTIONAL"))}
NO_MATCH_RULE, CONFLICT_RULE = "engine.no-match", "engine.conflict"
AUTOMATED_LOCALPARTS = frozenset({"noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "do_not_reply",
                                  "notification", "notifications", "notify", "mailer-daemon", "postmaster", "alerts"})


@dataclass(frozen=True)
class Features:
    """Metadata the M2 index actually stores. No subject, body, snippet, recipients or attachments."""
    sender: str  # lower-cased address, or ""
    unread: bool
    label_ids: frozenset
    label_names: frozenset = frozenset()  # lower-cased display names of those labels, when known

    @property
    def domain(self):
        return self.sender.rpartition("@")[2] if "@" in self.sender else ""

    @property
    def localpart(self):
        return self.sender.partition("@")[0] if "@" in self.sender else ""


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str  # "type" | "attention"
    value: str
    confidence: str
    note: str
    tier: int = TIER_USER
    priority: int = 0  # higher wins among user rules
    sender: str = None  # exact lower-cased address
    domain: str = None  # exact lower-cased domain (subdomains are NOT matched)
    label: str = None  # Gmail label id (e.g. CATEGORY_PROMOTIONS) or label name, case-insensitive
    unread: bool = None  # None = any
    localparts: frozenset = None  # built-in only: exact local parts such as "noreply"

    def matches(self, f):
        if self.sender is not None and f.sender != self.sender:
            return False
        if self.domain is not None and f.domain != self.domain:
            return False
        if self.localparts is not None and f.localpart not in self.localparts:
            return False
        if self.label is not None and not (self.label in f.label_ids or self.label.upper() in f.label_ids
                                           or self.label.lower() in f.label_names):
            return False
        return self.unread is None or f.unread == self.unread


def _b(rid, kind, value, conf, note, **cond):
    return Rule(rid, kind, value, conf, note, tier=TIER_BUILTIN, **cond)


# Conservative defaults. Gmail's own tabs are Gmail's judgment, so they are at most MEDIUM evidence. Nothing below is
# derived from a message's subject or body because the index does not store them.
BUILTIN_RULES = (
    _b("builtin.sender-automated", "type", "AUTOMATED_NOTIFICATION", "MEDIUM",
       "sender address looks automated (noreply/notifications style); says nothing about importance",
       localparts=AUTOMATED_LOCALPARTS),
    _b("builtin.label-promotions", "type", "PROMOTIONAL", "MEDIUM", "Gmail placed it in its Promotions tab",
       label="CATEGORY_PROMOTIONS"),
    _b("builtin.label-social", "type", "SOCIAL", "MEDIUM", "Gmail placed it in its Social tab", label="CATEGORY_SOCIAL"),
    _b("builtin.label-forums", "type", "SOCIAL", "LOW", "Gmail placed it in its Forums tab (group discussions)",
       label="CATEGORY_FORUMS"),
    _b("builtin.label-updates", "type", "AUTOMATED_NOTIFICATION", "LOW",
       "Gmail placed it in its Updates tab (mixed: receipts, alerts, bills)", label="CATEGORY_UPDATES"),
    _b("builtin.label-primary", "type", "PERSONAL", "LOW",
       "Gmail Primary tab only means 'not sorted into another tab'; weak evidence", label="CATEGORY_PERSONAL"),
    _b("builtin.label-important", "attention", "POTENTIALLY_IMPORTANT", "LOW",
       "Gmail's own IMPORTANT marker (an automatic guess, not proof)", label="IMPORTANT"),
    _b("builtin.label-starred", "attention", "POTENTIALLY_IMPORTANT", "MEDIUM", "starred by the mailbox owner",
       label="STARRED"),
)


@dataclass(frozen=True)
class Result:
    """One classification row: what, how sure, why, and which rule/source produced it."""
    kind: str
    value: str
    confidence: str
    rule_id: str
    explanation: str
    source: str = "rules"


@dataclass
class Outcome:
    results: list = field(default_factory=list)

    def values(self, kind="type"):
        return [r.value for r in self.results if r.kind == kind]

    def best_confidence(self):
        ranks = [_RANK[r.confidence] for r in self.results if r.kind == "type" and r.value != "UNKNOWN"]
        return CONFIDENCE[max(ranks)] if ranks else None


def _best(matches):
    """Matches of the strongest precedence group: (tier, priority, confidence) - user over built-in, then priority."""
    def key(r):
        return (r.tier, r.priority, _RANK[r.confidence])
    top = max(key(r) for r in matches)
    return [r for r in matches if key(r) == top], len(matches)


def _conflicting(values):
    vs = sorted(set(values))
    return any(frozenset((a, b)) not in _COMPATIBLE
               and not ("AUTOMATED_NOTIFICATION" in (a, b) and "PERSONAL" not in (a, b))
               for i, a in enumerate(vs) for b in vs[i + 1:])


def evaluate(features, user_rules=(), builtin=BUILTIN_RULES):
    """Classify one message with the built-in rules plus the active (enabled) user rules."""
    matched = [r for r in (*builtin, *user_rules) if r.matches(features)]
    results = []
    types = [r for r in matched if r.kind == "type"]
    if not types:
        results.append(Result("type", "UNKNOWN", "LOW", NO_MATCH_RULE,
                              "no rule matched the available metadata (sender, labels, unread state)"))
    else:
        winners, total = _best(types)
        merged = {}
        for r in sorted(winners, key=lambda r: r.id):
            merged.setdefault(r.value, r)
        overridden = total - len(winners)
        for value, r in sorted(merged.items()):
            extra = f" (overrode {overridden} lower-precedence match(es))" if overridden else ""
            results.append(Result("type", value, r.confidence, r.id, r.note + extra))
        if _conflicting(merged):
            results.append(Result("attention", "REVIEW_NEEDED", "LOW", CONFLICT_RULE,
                                  "equal-precedence rules disagree on the type: " + ", ".join(sorted(merged))))
    seen = {}
    for r in sorted((r for r in matched if r.kind == "attention"),
                    key=lambda r: (-r.tier, -r.priority, -_RANK[r.confidence], r.id)):
        seen.setdefault(r.value, r)
    for value, r in sorted(seen.items()):
        if not any(x.kind == "attention" and x.value == value for x in results):
            results.append(Result("attention", value, r.confidence, r.id, r.note))
    return Outcome(results)


def ruleset_hash(account, user_rules):
    """Fingerprint of everything that can change a result; stored with each result to detect stale ones."""
    payload = [TAXONOMY_VERSION, BUILTIN_VERSION, account.lower(),
               sorted((r.id, r.kind, r.value, r.confidence, r.priority, r.sender, r.domain, r.label, r.unread)
                      for r in user_rules)]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


class RuleError(ValueError):
    """Invalid user rule input, with a user-facing message."""


def validate_new_rule(kind, value, confidence, priority, sender=None, domain=None, label=None, unread=None, note=None):
    """Normalize and validate user input; returns a dict of column values. Never executes or compiles input."""
    if kind not in KINDS:
        raise RuleError("kind must be 'type' or 'attention'")
    allowed = [t for t in TYPES if t != "UNKNOWN"] if kind == "type" else list(ATTENTION)
    value = (value or "").strip().upper()
    if value not in allowed:
        raise RuleError(f"{kind} must be one of: {', '.join(allowed)}")
    confidence = (confidence or "HIGH").strip().upper()
    if confidence not in CONFIDENCE:
        raise RuleError(f"confidence must be one of: {', '.join(CONFIDENCE)}")
    if isinstance(priority, bool) or not isinstance(priority, int) or not -1000 <= priority <= 1000:
        raise RuleError("priority must be an integer between -1000 and 1000")
    cond = validate_conditions(sender, domain, label)
    if unread is not None:
        cond["unread"] = bool(unread)
    if not [k for k in cond if k != "unread"]:
        raise RuleError("a rule needs at least one of sender, domain or label (unread alone is not evidence)")
    note = (note or "").strip()[:200]
    if any(ord(c) < 32 for c in note):
        raise RuleError("note must not contain control characters")
    return dict(kind=kind, value=value, confidence=confidence, priority=priority, note=note, **cond)


def validate_conditions(sender=None, domain=None, label=None):
    """Normalize exact sender/domain/label match conditions (shared with M4A protection rules). No wildcards or regex."""
    cond = {}
    if sender is not None:
        s = sender.strip().lower()
        local, at, dom = s.rpartition("@")
        if not at or not local or not _valid_domain(dom) or any(c.isspace() or c in "<>,;\"'*?" for c in s):
            raise RuleError("sender must be one exact address like name@example.test (no wildcards)")
        cond["sender"] = s
    if domain is not None:
        d = domain.strip().lower()
        if not _valid_domain(d):
            raise RuleError("domain must be an exact domain like example.test (no wildcards, no '@')")
        cond["domain"] = d
    if label is not None:
        lab = label.strip()
        if not lab or len(lab) > 100 or any(ord(c) < 32 for c in lab):
            raise RuleError("label must be a Gmail label id or name (1-100 printable characters)")
        cond["label"] = lab
    return cond


def _valid_domain(d):
    parts = d.split(".")
    return (3 <= len(d) <= 253 and len(parts) >= 2 and all(
        p and len(p) <= 63 and all(c.isalnum() or c == "-" for c in p) and not p.startswith("-") and not p.endswith("-")
        for p in parts))
