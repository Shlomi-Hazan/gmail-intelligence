"""Candidate engine for safe cleanup (M4A): pure, deterministic, local. NEVER contacts Gmail and NEVER executes anything.

For each indexed message it decides one of three outcomes:
  EXCLUDED         hard protections, unsafe/stale data, or simply nothing to archive (not in INBOX, too recent).
  REVIEW_REQUIRED  not a recommendation; informational only (important, personal/financial/..., weak evidence, unread, ...).
  ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION  conservative defaults met. A recommendation, never an authorization.
The outcome is computed on demand from the M2 index, the current M3 classifications and the user's protection rules;
nothing is persisted, so any change to those inputs changes the next output. Trash is never recommended in M4A.
See docs/CLEANUP.md and decisions D27-D35.
"""
import time
from dataclasses import dataclass, field

from gmail_intelligence import classifier, classify, cleanup_protect, report

POLICY_VERSION = 1
MIN_AGE_DAYS = 90  # default AND lower bound (the user may only be stricter)
DAY_MS = 86_400_000
# The ONLY reasons a canary exception may waive, and only for the ONE message of a canary plan (never for ordinary cleanup): the age rule and the classification-type rules.
# Hard protections (including SENT), unsafe data, missing or stale classification, not-in-inbox, important/unread/user-label/attention/AI signals, protection rules and
# mixed threads are never waived.
CANARY_WAIVED = frozenset({"TOO_RECENT", "UNKNOWN_TYPE", "RISKY_TYPE", "TYPE_NOT_APPROVED", "WEAK_EVIDENCE", "AMBIGUOUS_TYPES"})
APPROVED_TYPES = frozenset({"PROMOTIONAL", "SOCIAL", "NEWSLETTER"})
COMPANION_TYPES = frozenset({"AUTOMATED_NOTIFICATION"})  # may accompany an approved type, never suffices alone
RISKY_TYPES = frozenset({"PERSONAL", "FINANCIAL", "TRANSACTIONAL", "EDUCATIONAL"})
HARD_LABELS = ("STARRED", "SENT", "DRAFT", "TRASH", "SPAM")

EXCLUDED, REVIEW, ELIGIBLE = "EXCLUDED", "REVIEW_REQUIRED", "ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION"
HARD, DATA, NA, RISK = "hard-protection", "unsafe-data", "not-applicable", "review"


@dataclass(frozen=True)
class Reason:
    code: str
    category: str
    detail: str = ""


@dataclass(frozen=True)
class Decision:
    message_id: str
    thread_id: str
    outcome: str
    reasons: tuple
    evidence: tuple = ()  # (type, confidence, rule_id) of the approving rules, ELIGIBLE only
    age_days: int = None
    sender: str = ""

    @property
    def codes(self):
        return tuple(sorted({r.code for r in self.reasons}))


@dataclass
class Result:
    decisions: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


def _self_reasons(m, rows, current, protect_rules, now_ms, min_age_days, canary=False):
    """Reasons for one message in isolation (thread context is applied afterwards). Returns (reasons, evidence)."""
    out = []
    add = lambda code, cat, detail="": out.append(Reason(code, cat, detail))  # noqa: E731
    for lab in HARD_LABELS:
        if lab in m["labels"]:
            add(lab, HARD)
    feats = classify.Features(m["sender"], m["unread"], m["labels"], m["names"])
    for r in protect_rules:
        if r.matches(feats):
            add("USER_PROTECTED", HARD, r.id)
    if not m["thread_id"]:
        add("MISSING_THREAD_ID", DATA)
    if m["internal_ms"] is None:
        add("MISSING_DATE", DATA)
    if not m["sender"] or "@" not in m["sender"]:
        add("MISSING_SENDER", DATA)
    if m["unread"] != ("UNREAD" in m["labels"]):
        add("UNREAD_FLAG_MISMATCH", DATA)
    if current is None:
        add("CLASSIFICATION_MISSING", DATA)
    elif current is False:
        add("CLASSIFICATION_STALE", DATA)
    if "INBOX" not in m["labels"]:
        add("NOT_IN_INBOX", NA)
    if m["internal_ms"] is not None and now_ms - m["internal_ms"] < min_age_days * DAY_MS:
        add("TOO_RECENT", NA)
    # ---- review-required conditions ----
    if "IMPORTANT" in m["labels"]:
        add("IMPORTANT_LABEL", RISK)
    if m["unread"]:
        add("UNREAD", RISK)
    if m["user_label"]:
        add("USER_LABEL", RISK)
    evidence = []
    if rows:
        types = {r["value"]: r for r in rows if r["kind"] == "type"}
        if any(r["source"] != "rules" for r in rows):
            add("AI_EVIDENCE", RISK)
        if any(r["kind"] == "attention" for r in rows):
            add("ATTENTION_SIGNAL", RISK, ",".join(sorted({r["value"] for r in rows if r["kind"] == "attention"})))
        if "UNKNOWN" in types:
            add("UNKNOWN_TYPE", RISK)
        for t in sorted(RISKY_TYPES & set(types)):
            add("RISKY_TYPE", RISK, t)
        known = {t for t in types if t != "UNKNOWN"}
        if known - APPROVED_TYPES - COMPANION_TYPES - RISKY_TYPES:
            add("TYPE_NOT_APPROVED", RISK)
        approving = known & APPROVED_TYPES
        if not approving:
            add("TYPE_NOT_APPROVED", RISK)
        else:
            strong = [types[t] for t in sorted(approving)
                      if types[t]["source"] == "rules" and types[t]["confidence"] in ("MEDIUM", "HIGH")]
            if not strong:
                add("WEAK_EVIDENCE", RISK)
            evidence = [(r["value"], r["confidence"], r["rule_id"]) for r in strong]
        if classify._conflicting(known):
            add("AMBIGUOUS_TYPES", RISK)
    if canary:  # the explicit, narrow canary exception: waive ONLY the listed age/classification reasons of this one message; evidence never counts
        out = [r for r in out if r.code not in CANARY_WAIVED]
        evidence = []
    return out, tuple(evidence)


def evaluate_all(index, account, now_ms=None, min_age_days=MIN_AGE_DAYS, canary_ids=frozenset()):
    """Evaluate every indexed message of `account`. Read-only. Raises ValueError for a weaker-than-default age.

    `canary_ids` is empty for all ordinary cleanup. A canary plan passes its single message id: for that message only, the reasons in CANARY_WAIVED are waived."""
    if min_age_days < MIN_AGE_DAYS:
        raise ValueError(f"--min-age-days must be at least {MIN_AGE_DAYS} (you may only be stricter)")
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    names = {r["id"]: ((r["name"] or "").lower(), r["type"]) for r in index._q(
        "SELECT id, name, type FROM labels WHERE account=?", account)}
    labels = {}
    for r in index._q("SELECT message_id, label_id FROM message_labels WHERE account=?", account):
        labels.setdefault(r["message_id"], set()).add(r["label_id"])
    protect = cleanup_protect.active(index, account)
    cur_hash = classifier.current_hash(index, account)
    cls = {}
    for r in index._q("SELECT message_id, kind, value, confidence, source, rule_id, ruleset_hash, msg_scan_id "
                      "FROM message_class WHERE account=?", account):
        cls.setdefault(r["message_id"], []).append(dict(r))
    state, why = report.completeness(index, account)

    msgs = index._q("SELECT id, thread_id, internal_ms, sender, unread, scan_id FROM messages WHERE account=? "
                    "ORDER BY internal_ms, id", account)
    own, evid, info = {}, {}, {}
    threads = {}
    for r in msgs:
        labs = frozenset(labels.get(r["id"], ()))
        m = {"id": r["id"], "thread_id": r["thread_id"] or "", "internal_ms": r["internal_ms"],
             "sender": (r["sender"] or "").lower(), "unread": bool(r["unread"]), "labels": labs,
             "names": frozenset(n for l in labs for n in [names.get(l, ("", ""))[0]] if n),
             "user_label": any(l.startswith("Label_") or names.get(l, ("", ""))[1] == "user" for l in labs)}
        rows = cls.get(r["id"], [])
        current = None if not rows else all(x["ruleset_hash"] == cur_hash and x["msg_scan_id"] == r["scan_id"] for x in rows)
        own[r["id"]], evid[r["id"]] = _self_reasons(m, rows, current, protect, now_ms, min_age_days, r["id"] in canary_ids)
        info[r["id"]] = m
        if m["thread_id"]:
            threads.setdefault(m["thread_id"], []).append(r["id"])

    risky_cats = {HARD, DATA, RISK}
    mixed_threads = set()
    final = {}
    for mid, reasons in own.items():
        reasons = list(reasons)
        t = info[mid]["thread_id"]
        if not reasons and t:
            if any(own[s] and any(x.category in risky_cats for x in own[s]) for s in threads[t] if s != mid):
                reasons.append(Reason("MIXED_THREAD", RISK, "another message in the thread is protected, unsafe or needs review"))
                mixed_threads.add(t)
        if not reasons and state != "complete":
            reasons.append(Reason("INDEX_PARTIAL", RISK, "thread completeness cannot be established: " + why))
        final[mid] = reasons

    decisions = []
    for r in msgs:
        mid, reasons, m = r["id"], final[r["id"]], info[r["id"]]
        cats = {x.category for x in reasons}
        outcome = EXCLUDED if cats & {HARD, DATA, NA} else REVIEW if reasons else ELIGIBLE
        age = None if m["internal_ms"] is None else (now_ms - m["internal_ms"]) // DAY_MS
        decisions.append(Decision(mid, m["thread_id"], outcome, tuple(reasons), evid[mid] if outcome == ELIGIBLE else (),
                                  age, m["sender"]))
    return Result(decisions, _summary(decisions, account, protect, state, why, min_age_days, len(threads), len(mixed_threads)))


def _summary(decisions, account, protect, state, why, min_age_days, n_threads, n_mixed):
    outcomes = {EXCLUDED: 0, REVIEW: 0, ELIGIBLE: 0}
    reasons, decisive, accompanying, ev = {}, {}, {}, {}
    for d in decisions:
        outcomes[d.outcome] += 1
        for code in d.codes:
            reasons.setdefault(d.outcome, {})
            reasons[d.outcome][code] = reasons[d.outcome].get(code, 0) + 1
        # An EXCLUDED message is excluded by hard-protection / unsafe-data / not-applicable reasons only; any review-type
        # signals it also carries are accompanying information, not why it was excluded.
        for code in {x.code for x in d.reasons if x.category != RISK or d.outcome == REVIEW}:
            decisive.setdefault(d.outcome, {})
            decisive[d.outcome][code] = decisive[d.outcome].get(code, 0) + 1
        if d.outcome == EXCLUDED:
            for code in {x.code for x in d.reasons if x.category == RISK}:
                accompanying[code] = accompanying.get(code, 0) + 1
        for t, c, rid in d.evidence:
            key = (t, c, rid)
            ev[key] = ev.get(key, 0) + 1
    return {"total": len(decisions), "outcomes": outcomes, "reasons": reasons, "decisive": decisive,
            "accompanying": accompanying, "evidence": ev,
            "policy": f"v{POLICY_VERSION}/archive>={min_age_days}d", "min_age_days": min_age_days,
            "protection_fingerprint": cleanup_protect.fingerprint(account, protect),
            "protection_rules_active": len(protect), "index_state": state, "index_why": why,
            "threads": n_threads, "mixed_threads": n_mixed, "trash_recommendations": 0}
