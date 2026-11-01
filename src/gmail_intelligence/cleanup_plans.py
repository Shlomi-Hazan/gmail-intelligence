"""Immutable cleanup plans, one-time local approvals and freshness checks (M4B). Local SQLite only; NEVER contacts Gmail.

A plan is a finite, explicit set of message ids for ONE action (ARCHIVE) on ONE account, frozen as canonical JSON and bound by
its full SHA-256. An approval is only a LOCAL LEDGER RECORD of a typed confirmation; it grants no OAuth permission and cannot
execute anything. Execution does not exist in M4B. Freshness is judged against the LOCAL index only; it cannot see mailbox
changes made after the last Gmail scan, so a future executor (M4C) must re-validate live state itself.

Requirements a future executor must meet (documented here, deliberately not implemented):
  * call `verify_approved` (exact stored hash, targets, account, policy, expiry) and refuse on any problem;
  * consume the approval atomically in the same transaction that starts execution (VALID -> CONSUMED, one time only);
  * re-validate each message against live Gmail state immediately before acting and skip drifted messages;
  * never retry or continue automatically after an ambiguous outcome; never widen the target set.
"""
import contextlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from gmail_intelligence import classifier, cleanup_audit as audit, cleanup_candidates as cc, cleanup_protect, report, sync_health
from gmail_intelligence.cleanup_audit import canonical, sha256

FORMAT_VERSION = 1
SYNC_GUARD_CONTRACT = 1  # D145: sync_lease refuses to start any run unless this exact contract version is declared (E1-E5 present)
SYNC_CODES = frozenset(sync_health.CODES)
ACTION = "ARCHIVE"
MAX_PLAN_ITEMS = 500
PLAN_TTL = timedelta(hours=48)
APPROVAL_TTL = timedelta(hours=24)
PAGE_SIZE = 25
CLOCK_TOLERANCE = timedelta(minutes=5)  # how far "now" may lag the last recorded event / an approval's creation time
MAX_FAILED_ATTEMPTS = 10  # failed review/approval confirmations per plan within LOCKOUT_WINDOW before further attempts are refused
LOCKOUT_WINDOW = timedelta(minutes=15)
ITEM_KEYS = frozenset({"id", "thread_id", "internal_ms", "scan_id", "unread", "sender_sha256", "labels_sha256", "class_sha256"})
SNAPSHOT_KEYS = ("format", "plan_id", "version", "parent", "account", "action", "created_at", "expires_at", "policy",
                 "classification_ruleset", "protection_digest", "index", "items")
TERMINAL = ("CANCELLED", "EXPIRED", "SUPERSEDED")
LIVE_STATES = ("DRAFT", "REVIEWED", "APPROVED")
_CHUNK = 400


class PlanError(Exception):
    """Refusal with a stable `code` and a privacy-safe message (counts and codes only; never ids)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _utc(now):
    return now if now is not None else datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ms(dt):
    return int(dt.timestamp() * 1000)


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _check_clock(index, account, now):
    """Refuse to record anything if the clock is earlier than the last recorded cleanup event (rollback or wrong clock).

    A local wall clock can never prove real elapsed time against someone who controls it; this only catches accidents and
    naive rollbacks.
    """
    last = audit.last_time(index, account)
    if last and now < _parse(last) - CLOCK_TOLERANCE:
        raise PlanError("CLOCK_ROLLBACK", "the system clock is earlier than the last recorded cleanup event; fix the clock "
                        "before continuing (nothing was changed)")


@contextlib.contextmanager
def _txn(index):
    """One IMMEDIATE (write-locking) transaction: concurrent writers cannot interleave; everything commits or nothing does."""
    if index.conn.in_transaction:
        raise RuntimeError("nested cleanup transaction")
    index.conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        index.conn.commit()
    except BaseException:
        index.conn.rollback()
        raise


def valid_id(s):
    return isinstance(s, str) and 1 <= len(s) <= 64 and s.isascii() and all(c.isalnum() or c in "-_" for c in s)


def short(h):
    return h[:8]


def approval_phrase(plan):
    return f"{plan['action']} {plan['item_count']} {short(plan['plan_hash'])}"


def review_phrase(plan):
    return f"REVIEWED {plan['item_count']} {short(plan['plan_hash'])}"


# ---------------------------------------------------------------- facts and snapshots
def _facts(index, account, ids):
    """Security-relevant local facts per message, reduced to digests so snapshots hold no sender/label text."""
    out = {}
    ids = list(ids)
    for k in range(0, len(ids), _CHUNK):
        chunk = ids[k:k + _CHUNK]
        marks = ",".join("?" * len(chunk))
        labels, cls = {}, {}
        for r in index._q(f"SELECT message_id, label_id FROM message_labels WHERE account=? AND message_id IN ({marks})",
                          account, *chunk):
            labels.setdefault(r["message_id"], []).append(r["label_id"])
        for r in index._q(f"SELECT message_id, kind, value, confidence, source, rule_id, ruleset_hash, msg_scan_id "
                          f"FROM message_class WHERE account=? AND message_id IN ({marks})", account, *chunk):
            cls.setdefault(r["message_id"], []).append([r["kind"], r["value"], r["confidence"], r["source"], r["rule_id"],
                                                         r["ruleset_hash"], r["msg_scan_id"]])
        for r in index._q(f"SELECT id, thread_id, internal_ms, sender, unread, scan_id FROM messages "
                          f"WHERE account=? AND id IN ({marks})", account, *chunk):
            out[r["id"]] = {"id": r["id"], "thread_id": r["thread_id"] or "", "internal_ms": r["internal_ms"],
                            "scan_id": r["scan_id"], "unread": int(bool(r["unread"])),
                            "sender_sha256": sha256((r["sender"] or "").lower()),
                            "labels_sha256": sha256(canonical(sorted(labels.get(r["id"], [])))),
                            "class_sha256": sha256(canonical(sorted(cls.get(r["id"], []))))}
    return out


def _policy(min_age_days, canary=False):
    policy = {"cleanup_policy": cc.POLICY_VERSION, "min_age_days": min_age_days, "approved_types": sorted(cc.APPROVED_TYPES), "plan_format": FORMAT_VERSION}
    if canary:  # a canary plan only: its single message is exempt from the age and classification-type rules (see cleanup_candidates.CANARY_WAIVED). Ordinary plans are byte-for-byte unchanged.
        policy["canary_exception"] = True
    return policy


def _anchor(index, account):
    state, _ = report.completeness(index, account)
    scans = [s for s in index.recent_scans(account, 50) if s["mode"] == "full" and s["status"] == "completed"]
    return {"completeness": state, "last_full_scan": scans[0]["finished_at"] if scans else None}


def _snapshot(plan_id, version, parent, account, created, expires, min_age_days, ruleset, protection, anchor, items, canary=False):
    return {"format": FORMAT_VERSION, "plan_id": plan_id, "version": version,
            "parent": parent, "account": account, "action": ACTION, "created_at": created, "expires_at": expires,
            "policy": _policy(min_age_days, canary), "classification_ruleset": ruleset, "protection_digest": protection,
            "index": anchor, "items": sorted(items, key=lambda i: i["id"])}


# ---------------------------------------------------------------- loading and integrity
def _row(index, account, plan_id):
    rows = index._q("SELECT * FROM cleanup_plan WHERE account=? AND plan_id=?", account, plan_id)
    if not rows:
        raise PlanError("NO_SUCH_PLAN", "no such plan for this account")
    return dict(rows[0])


def get_plan(index, account, plan_id):
    p = _row(index, account, plan_id)
    p["items"] = [dict(r) for r in index._q(
        "SELECT message_id, thread_id, item_digest FROM cleanup_item WHERE account=? AND plan_id=? ORDER BY message_id",
        account, plan_id)]
    return p


def integrity_problems(plan):
    """Re-derive everything from the stored canonical snapshot: hash, bound columns, and the redundant item rows."""
    problems = []
    if sha256(plan["snapshot"]) != plan["plan_hash"]:
        return ["HASH_MISMATCH"]
    try:
        snap = json.loads(plan["snapshot"])
    except (ValueError, TypeError):
        return ["SNAPSHOT_UNREADABLE"]
    if not _shape_ok(snap):
        return ["SNAPSHOT_MALFORMED"]
    if canonical(snap) != plan["snapshot"]:
        problems.append("SNAPSHOT_NOT_CANONICAL")
    for key in ("account", "plan_id", "version", "action", "created_at", "expires_at"):
        if snap.get(key) != plan[key]:
            problems.append("COLUMN_MISMATCH")
    if (snap.get("parent") or {}).get("plan_id") != plan["parent_id"]:
        problems.append("COLUMN_MISMATCH")
    if len(snap.get("items", [])) != plan["item_count"]:
        problems.append("COLUMN_MISMATCH")
    if "canary_exception" in snap["policy"] and (snap["policy"]["canary_exception"] is not True or len(snap["items"]) != 1 or snap["version"] != 1):
        problems.append("CANARY_SHAPE")  # the exception exists only on a first-version plan of exactly ONE message
    table = {i["message_id"]: (i["thread_id"], i["item_digest"]) for i in plan["items"]}
    want = {i["id"]: (i["thread_id"], sha256(canonical(i))) for i in snap.get("items", [])}
    if table != want:
        problems.append("ITEM_TABLE_MISMATCH")
    return sorted(set(problems))


def _shape_ok(snap):
    try:
        return (isinstance(snap, dict) and all(k in snap for k in SNAPSHOT_KEYS) and snap["format"] == FORMAT_VERSION
                and isinstance(snap["items"], list) and all(isinstance(i, dict) and set(i) == ITEM_KEYS for i in snap["items"])
                and isinstance(snap["policy"], dict) and isinstance(snap["policy"].get("min_age_days"), int)
                and isinstance(snap["index"], dict) and isinstance(snap["account"], str))
    except (KeyError, TypeError):
        return False


def snapshot_of(plan):
    """Parsed snapshot, or a clean PlanError (never a raw JSON error, traceback or snapshot text)."""
    try:
        snap = json.loads(plan["snapshot"])
    except (ValueError, TypeError):
        snap = None
    if not _shape_ok(snap):
        raise PlanError("SNAPSHOT_UNREADABLE", "the stored plan snapshot is unreadable or malformed; nothing was changed. "
                        "Cancel this plan and create a new one.")
    return snap


# ---------------------------------------------------------------- freshness
def revalidate(index, account, plan, now=None, _out=None, only_ids=None, _cache=None):
    """Fail-closed freshness check against the LOCAL index. Returns {problem_code: count}; empty means fresh.

    Never trims the target set: any single stale or ineligible target makes the whole plan stale.
    """
    now = _utc(now)
    problems = {}

    def bad(code, n=1):
        problems[code] = problems.get(code, 0) + n
    if plan["account"] != account:
        bad("ACCOUNT_MISMATCH")
    for code in integrity_problems(plan):
        bad(code)
    if problems:
        return problems
    snap = snapshot_of(plan)
    if _iso(now) >= plan["expires_at"]:
        bad("PLAN_EXPIRED")
    if now < _parse(plan["created_at"]) - CLOCK_TOLERANCE:
        bad("PLAN_FROM_THE_FUTURE")
    min_age = snap["policy"]["min_age_days"]
    canary = snap["policy"].get("canary_exception") is True
    if snap["policy"] != _policy(min_age, canary):
        bad("POLICY_CHANGED")
    if snap["classification_ruleset"] != classifier.current_hash(index, account):
        bad("CLASSIFICATION_RULES_CHANGED")
    if snap["protection_digest"] != cleanup_protect.digest(account, cleanup_protect.active(index, account)):
        bad("PROTECTION_RULES_CHANGED")
    anchor = _anchor(index, account)
    if anchor["completeness"] != "complete":
        bad("INDEX_NOT_COMPLETE")
    elif anchor != snap["index"]:
        bad("INDEX_RESCANNED")
    for code in sync_codes(index, account, now):  # E1: index freshness uncertain -> prohibited (no writes; see sync_guard_error)
        bad(code)
    wanted = None if only_ids is None else set(only_ids)  # continuation checks only the not-yet-executed targets
    ids = [i["id"] for i in snap["items"] if wanted is None or i["id"] in wanted]
    facts = _facts(index, account, ids)
    canary_ids = frozenset(i["id"] for i in snap["items"]) if canary and len(snap["items"]) == 1 else frozenset()
    # M12D: a batch revalidates every item of a slice. The eligibility decisions depend only on tables this connection never writes while executing (messages, labels, classes,
    # protection rules), so they are reused across the slice for as long as SQLite's data_version (which changes when ANOTHER connection commits) and the inputs stay the same;
    # any concurrent change recomputes them (fail closed, never a stale reuse). Without a cache nothing changes: one full evaluation per call.
    stamp = (index.conn.execute("PRAGMA data_version").fetchone()[0], min_age, canary_ids, plan["plan_id"]) if _cache is not None else None
    if _cache is not None and _cache.get("stamp") == stamp:
        decisions = _cache["decisions"]
    else:
        res = cc.evaluate_all(index, account, now_ms=_ms(now), min_age_days=min_age, canary_ids=canary_ids)
        decisions = {d.message_id: d for d in res.decisions}
        if _cache is not None:
            _cache["stamp"], _cache["decisions"] = stamp, decisions
    if _out is not None:
        _out["decisions"] = decisions
    for item in snap["items"]:
        if wanted is not None and item["id"] not in wanted:
            continue
        cur = facts.get(item["id"])
        if cur is None:
            bad("ITEM_MISSING")
            continue
        if cur != item:
            bad("ITEM_CHANGED")
        d = decisions.get(item["id"])
        if d is None or d.outcome != cc.ELIGIBLE:
            bad("ITEM_NOT_ELIGIBLE")
            for code in (d.codes if d else ()):
                bad("REASON_" + code)
    return problems


PARTIAL_INDEX_CODES = frozenset({"INDEX_NOT_COMPLETE", "REASON_INDEX_PARTIAL", "ITEM_NOT_ELIGIBLE"})  # what the pre-M7 completeness check reports during a full scan


def sync_codes(index, account, now):
    """E1: the sync-health codes that currently apply (empty = healthy). Read-only."""
    return sync_health.problems(index, account, now)


def require_sync_health(index, account, now):
    """E2/E3/E5: the first thing every guarded operation does INSIDE its write transaction, before any plan, approval, lockout or rejection logic.

    An unhealthy index is a prohibition, not a plan problem: it raises SYNC_NOT_HEALTHY (never audited, never counted towards a lockout) whatever the
    plan's own state is, so even a request about an expired or unknown plan cannot cause a rejection record while health is the real obstacle.
    """
    codes = sync_codes(index, account, now)
    if codes:
        raise sync_guard_error({c: 1 for c in codes})


def sync_only(problems):
    """True when the refusal is about index freshness, not about the plan: at least one sync-health code and nothing else except the pre-M7 partial-index
    codes that an active or unfinished full scan produces by itself (ITEM_NOT_ELIGIBLE only counts when its sole reason is the partial index)."""
    codes = set(problems)
    return bool(codes & SYNC_CODES) and codes <= (SYNC_CODES | PARTIAL_INDEX_CODES)


def sync_guard_error(problems):
    """E3/E5: the distinct refusal for 'prohibited until sync health is restored'. It is not a stale plan and changes nothing."""
    return PlanError("SYNC_NOT_HEALTHY", "this operation is prohibited until the local index is fresh again (" + _describe(problems)
                     + "); the plan and its approval are unchanged. Run `mailbox sync` (or `mailbox scan --all`) and try again")


def _has_execution(index, account, plan_id):
    return bool(index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND plan_id=? LIMIT 1", account, plan_id))


def _describe(problems):
    return ", ".join(f"{k}={v}" for k, v in sorted(problems.items()))


# ---------------------------------------------------------------- lifecycle
def _set_state(index, account, plan_id, state, at, reviewed=False):
    if reviewed:
        index.conn.execute("UPDATE cleanup_plan SET state=?, reviewed_at=?, state_changed_at=? WHERE account=? AND plan_id=?",
                           (state, at, at, account, plan_id))
    else:
        index.conn.execute("UPDATE cleanup_plan SET state=?, state_changed_at=? WHERE account=? AND plan_id=?",
                           (state, at, account, plan_id))


def _close_approvals(index, account, plan_id, status, at):
    n = index.conn.execute("UPDATE cleanup_approval SET status=?, status_changed_at=? WHERE account=? AND plan_id=? "
                           "AND status='VALID'", (status, at, account, plan_id)).rowcount
    return n


def expire_due(index, account, now=None):
    """Move plans/approvals past their expiry to EXPIRED. Maintenance write; returns the number of plans expired."""
    now = _utc(now)
    at = _iso(now)
    due = [r["plan_id"] for r in index._q(
        "SELECT p.plan_id FROM cleanup_plan p WHERE p.account=? AND p.state IN ('DRAFT','REVIEWED','APPROVED') AND "
        "(p.expires_at <= ? OR EXISTS (SELECT 1 FROM cleanup_approval a WHERE a.account=p.account AND a.plan_id=p.plan_id "
        "AND a.status='VALID' AND a.expires_at <= ?)) AND NOT EXISTS (SELECT 1 FROM cleanup_execution e "
        "WHERE e.account=p.account AND e.plan_id=p.plan_id)", account, at, at)]
    if not due:
        return 0
    with _txn(index):
        for pid in due:
            if _close_approvals(index, account, pid, "EXPIRED", at):
                audit.append(index, account, pid, "APPROVAL_EXPIRED", at, {})
            _set_state(index, account, pid, "EXPIRED", at)
            audit.append(index, account, pid, "PLAN_EXPIRED", at, {})
    return len(due)


def _insert_plan(index, account, ids, min_age_days, now, parent=None, canary=False):
    """Validate and insert a new DRAFT plan inside the caller's transaction. Returns the plan id."""
    at = _iso(now)
    ids = sorted(set(ids))
    require_sync_health(index, account, now)  # E2: no plan is created while index freshness is uncertain
    if canary and (len(ids) != 1 or parent is not None):
        raise PlanError("BAD_INPUT", "a canary exception covers exactly one message and is never revised")
    res = cc.evaluate_all(index, account, now_ms=_ms(now), min_age_days=min_age_days, canary_ids=frozenset(ids) if canary else frozenset())
    decisions = {d.message_id: d for d in res.decisions}
    unknown = [i for i in ids if i not in decisions]
    if unknown:
        raise PlanError("UNKNOWN_IDS", f"{len(unknown)} selected id(s) are not in this account's local index; nothing was created")
    bad = [decisions[i] for i in ids if decisions[i].outcome != cc.ELIGIBLE]
    if bad:
        counts, codes = {}, {}
        for d in bad:
            counts[d.outcome] = counts.get(d.outcome, 0) + 1
            for c in d.codes:
                codes[c] = codes.get(c, 0) + 1
        raise PlanError("NOT_ELIGIBLE", f"{len(bad)} of {len(ids)} selected message(s) are not eligible archive candidates "
                        f"({_describe(counts)}; reasons: {_describe(codes)}); nothing was created. "
                        "Plans never include excluded or review-required messages and are never trimmed silently.")
    facts = _facts(index, account, ids)
    items = [facts[i] for i in ids]
    for _ in range(5):
        plan_id = "plan-" + secrets.token_hex(4)
        if not index._q("SELECT 1 FROM cleanup_plan WHERE account=? AND plan_id=?", account, plan_id):
            break
    version = 1 if parent is None else parent["version"] + 1
    snap = _snapshot(plan_id, version, None if parent is None else {"plan_id": parent["plan_id"], "hash": parent["plan_hash"]},
                     account, at, _iso(now + PLAN_TTL), min_age_days, classifier.current_hash(index, account),
                     cleanup_protect.digest(account, cleanup_protect.active(index, account)), _anchor(index, account), items, canary)
    if snap["index"]["completeness"] != "complete":
        raise PlanError("INDEX_NOT_COMPLETE", "the local index is not complete (no finished full scan); nothing was created")
    text = canonical(snap)
    plan_hash = sha256(text)
    index.conn.execute("INSERT INTO cleanup_plan (account, plan_id, version, parent_id, action, state, plan_hash, snapshot, "
                       "item_count, created_at, expires_at, state_changed_at) VALUES (?,?,?,?,?,'DRAFT',?,?,?,?,?,?)",
                       (account, plan_id, version, None if parent is None else parent["plan_id"], ACTION, plan_hash, text,
                        len(items), at, snap["expires_at"], at))
    index.conn.executemany("INSERT INTO cleanup_item (account, plan_id, message_id, thread_id, item_digest) VALUES (?,?,?,?,?)",
                           [(account, plan_id, i["id"], i["thread_id"], sha256(canonical(i))) for i in items])
    audit.append(index, account, plan_id, "PLAN_CREATED", at,
                 {"action": ACTION, "items": len(items), "plan_hash": plan_hash, "version": version,
                  "parent": None if parent is None else parent["plan_id"], **({"canary_exception": 1} if canary else {})})
    return plan_id


def create_plan(index, account, message_ids, min_age_days=cc.MIN_AGE_DAYS, now=None):
    """Create a DRAFT plan from an explicit id list. Fails closed (nothing created) on any ineligible or unknown id."""
    if min_age_days < cc.MIN_AGE_DAYS:
        raise PlanError("BAD_INPUT", f"min age must be at least {cc.MIN_AGE_DAYS} days")
    ids = list(message_ids)
    if not ids:
        raise PlanError("NO_TARGETS", "no targets selected; select messages explicitly (nothing is selected by default)")
    if any(not valid_id(i) for i in ids):
        raise PlanError("BAD_INPUT", "message ids may only contain letters, digits, '-' and '_' (max 64 characters)")
    if len(set(ids)) > MAX_PLAN_ITEMS:
        raise PlanError("TOO_MANY", f"a plan may contain at most {MAX_PLAN_ITEMS} messages")
    now = _utc(now)
    expire_due(index, account, now)
    with _txn(index):
        _check_clock(index, account, now)
        pid = _insert_plan(index, account, ids, min_age_days, now)
    return get_plan(index, account, pid)


def revise_exclude(index, account, plan_id, exclude_ids, now=None):
    """Exclude messages: creates a NEW DRAFT version (new hash); the old plan and its approval become SUPERSEDED/REVOKED."""
    now = _utc(now)
    expire_due(index, account, now)
    exclude = set(exclude_ids)
    if not exclude or any(not valid_id(i) for i in exclude):
        raise PlanError("BAD_INPUT", "give at least one valid --message-id to exclude")
    with _txn(index):
        _check_clock(index, account, now)
        parent = get_plan(index, account, plan_id)
        if parent["state"] not in LIVE_STATES:
            raise PlanError("NOT_ACTIVE", f"plan is {parent['state']}; only an active plan can be revised")
        if _has_execution(index, account, plan_id):
            raise PlanError("HAS_EXECUTION", "this plan already has an execution record and can no longer be revised")
        if integrity_problems(parent):
            raise PlanError("INTEGRITY", "stored plan failed its integrity check; refusing to revise it")
        current = {i["message_id"] for i in parent["items"]}
        if exclude - current:
            raise PlanError("NOT_IN_PLAN", f"{len(exclude - current)} id(s) to exclude are not in this plan; nothing changed")
        remaining = sorted(current - exclude)
        if not remaining:
            raise PlanError("NO_TARGETS", "excluding everything leaves no targets; cancel the plan instead")
        min_age = snapshot_of(parent)["policy"]["min_age_days"]
        at = _iso(now)
        new_id = _insert_plan(index, account, remaining, min_age, now, parent=parent)
        if _close_approvals(index, account, plan_id, "REVOKED", at):
            audit.append(index, account, plan_id, "APPROVAL_REVOKED", at, {"reason": "superseded"})
        _set_state(index, account, plan_id, "SUPERSEDED", at)
        audit.append(index, account, plan_id, "PLAN_SUPERSEDED", at, {"by": new_id, "excluded": len(exclude)})
    return get_plan(index, account, new_id)


def _reject(index, account, plan_id, event, at, code, detail=None):
    """Record a failed validation in its own transaction (the failed operation was rolled back). Returns False on failure."""
    try:
        with _txn(index):
            audit.append(index, account, plan_id, event, at, {"code": code, "detail": (detail or "")[:190]})
        return True
    except sqlite3.Error:
        return False


def _lockout(index, account, plan_id, now):
    """Inside the caller's transaction: refuse when too many confirmations failed recently (bounds log growth and guessing)."""
    since = _iso(now - LOCKOUT_WINDOW)
    if audit.recent(index, account, plan_id, ("APPROVAL_REJECTED", "REVIEW_REJECTED"), since) >= MAX_FAILED_ATTEMPTS:
        raise PlanError("LOCKED_OUT", f"{MAX_FAILED_ATTEMPTS} failed confirmations for this plan in the last "
                        f"{int(LOCKOUT_WINDOW.total_seconds() // 60)} minutes; further attempts are refused until the window passes")


def _note_lockout(index, account, plan_id, now):
    """Record ONE lockout event per window (refused attempts after that write nothing, so the log cannot be flooded)."""
    since = _iso(now - LOCKOUT_WINDOW)
    try:
        with _txn(index):
            if not audit.recent(index, account, plan_id, ("ATTEMPTS_LOCKED_OUT",), since):
                audit.append(index, account, plan_id, "ATTEMPTS_LOCKED_OUT", _iso(now), {"window_minutes": int(LOCKOUT_WINDOW.total_seconds() // 60)})
    except sqlite3.Error:
        pass


def _guard(index, account, plan_id, event, now, body, duplicate_check=False):
    """Run `body(plan)` in one IMMEDIATE transaction with clock, lockout and error handling shared by review and approval."""
    at = _iso(now)
    err = None
    try:
        with _txn(index):
            _check_clock(index, account, now)
            plan = get_plan(index, account, plan_id)
            require_sync_health(index, account, now)  # E3/E4: before the lockout and before any plan-state judgement
            _lockout(index, account, plan_id, now)
            return body(plan)
    except sqlite3.IntegrityError:
        dup = duplicate_check and bool(index._q("SELECT 1 FROM cleanup_approval WHERE account=? AND plan_id=? AND status='VALID'",
                                                account, plan_id))
        err = PlanError("ALREADY_APPROVED", "a valid approval already exists for this plan") if dup else PlanError(
            "DB_CONSTRAINT", "an unexpected database constraint stopped this step; nothing was changed")
    except PlanError as exc:
        err = exc
    if err.code == "LOCKED_OUT":
        _note_lockout(index, account, plan_id, now)
    elif err.code not in ("NO_SUCH_PLAN", "CLOCK_ROLLBACK", "SYNC_NOT_HEALTHY") and not _reject(index, account, plan_id, event, at, err.code):
        err = PlanError(err.code, str(err) + " [warning: the audit entry for this failure could not be written]")
    raise err


def mark_reviewed(index, account, plan_id, phrase, now=None):
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)

    def body(plan):
        if plan["state"] != "DRAFT":
            raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a DRAFT plan can be reviewed")
        problems = revalidate(index, account, plan, now)
        if sync_only(problems):
            raise sync_guard_error(problems)  # E3
        if problems:
            raise PlanError("STALE", "plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
        if (phrase or "").strip() != review_phrase(plan):
            raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; plan stays DRAFT")
        _set_state(index, account, plan_id, "REVIEWED", at, reviewed=True)
        audit.append(index, account, plan_id, "PLAN_REVIEWED", at, {"items": plan["item_count"], "plan_hash": plan["plan_hash"]})
    _guard(index, account, plan_id, "REVIEW_REJECTED", now, body)
    return get_plan(index, account, plan_id)


def approve(index, account, plan_id, phrase, now=None):
    """Record a LOCAL one-time approval for a REVIEWED, fresh plan. Grants no Gmail permission; executes nothing."""
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)

    def body(plan):
        if plan["state"] == "APPROVED":
            raise PlanError("ALREADY_APPROVED", "this plan already has an approval; approvals are one-time and cannot be repeated")
        if plan["state"] != "REVIEWED":
            raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a REVIEWED plan can be approved")
        problems = revalidate(index, account, plan, now)
        if sync_only(problems):
            raise sync_guard_error(problems)  # E3
        if problems:
            raise PlanError("STALE", "plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
        if (phrase or "").strip() != approval_phrase(plan):
            raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; nothing was approved")
        nonce = secrets.token_hex(16)
        expires = min(now + APPROVAL_TTL, _parse(plan["expires_at"]))
        index.conn.execute("INSERT INTO cleanup_approval (account, plan_id, nonce, plan_hash, action, item_count, created_at, "
                           "expires_at, status, status_changed_at) VALUES (?,?,?,?,?,?,?,?,'VALID',?)",
                           (account, plan_id, nonce, plan["plan_hash"], plan["action"], plan["item_count"], at, _iso(expires), at))
        _set_state(index, account, plan_id, "APPROVED", at)
        audit.append(index, account, plan_id, "PLAN_APPROVED", at,
                     {"items": plan["item_count"], "plan_hash": plan["plan_hash"], "nonce_sha256": sha256(nonce),
                      "expires_at": _iso(expires)})
    _guard(index, account, plan_id, "APPROVAL_REJECTED", now, body, duplicate_check=True)
    return approval_status(index, account, plan_id, now)


def cancel(index, account, plan_id, now=None):
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        plan = _row(index, account, plan_id)
        if plan["state"] not in LIVE_STATES:
            raise PlanError("NOT_ACTIVE", f"plan is already {plan['state']}")
        if _has_execution(index, account, plan_id):
            raise PlanError("HAS_EXECUTION", "this plan already has an execution record and can no longer be cancelled")
        if _close_approvals(index, account, plan_id, "REVOKED", at):
            audit.append(index, account, plan_id, "APPROVAL_REVOKED", at, {"reason": "cancelled"})
        _set_state(index, account, plan_id, "CANCELLED", at)
        audit.append(index, account, plan_id, "PLAN_CANCELLED", at, {"from_state": plan["state"]})
    return _row(index, account, plan_id)


def list_plans(index, account):
    return [dict(r) for r in index._q(
        "SELECT plan_id, version, parent_id, state, item_count, plan_hash, created_at, expires_at FROM cleanup_plan "
        "WHERE account=? ORDER BY created_at, plan_id", account)]


def approval_status(index, account, plan_id, now=None):
    plan = _row(index, account, plan_id)
    rows = [dict(r) for r in index._q("SELECT nonce, status, created_at, expires_at, plan_hash, item_count FROM cleanup_approval "
                                      "WHERE account=? AND plan_id=? ORDER BY created_at", account, plan_id)]
    for r in rows:
        r["nonce"] = r["nonce"][:6] + "..."  # never print the full nonce
    return {"plan_id": plan_id, "plan_state": plan["state"], "approvals": rows}


def verify_approved(index, account, plan_id, now=None):
    """Read-only check an executor must pass FIRST: returns {problem: count}; empty means locally approved and fresh.

    It consumes nothing and is NOT an authorization to touch Gmail. It cross-checks the approval row against the plan, the clock
    and the audit chain, which catches accidental inconsistencies and naive forgeries; it cannot authenticate a database that
    someone with write access has consistently rewritten (the executor must also re-validate live Gmail state and ask the owner
    again at execution time).
    """
    now = _utc(now)
    plan = get_plan(index, account, plan_id)
    problems = revalidate(index, account, plan, now)

    def bad(code):
        problems[code] = problems.get(code, 0) + 1
    if plan["state"] != "APPROVED":
        bad("NOT_APPROVED")
    valid = [r for r in index._q("SELECT * FROM cleanup_approval WHERE account=? AND plan_id=? AND status='VALID'", account, plan_id)]
    if len(valid) != 1:
        bad("NO_SINGLE_VALID_APPROVAL")
        return problems
    a = valid[0]
    if a["plan_hash"] != plan["plan_hash"] or a["action"] != plan["action"] or a["item_count"] != plan["item_count"]:
        bad("APPROVAL_MISMATCH")
    if _iso(now) >= a["expires_at"]:
        bad("APPROVAL_EXPIRED")
    try:
        created, expires, plan_created, plan_expires = (_parse(a["created_at"]), _parse(a["expires_at"]),
                                                        _parse(plan["created_at"]), _parse(plan["expires_at"]))
    except ValueError:
        bad("APPROVAL_TIMESTAMP_INVALID")
        return problems
    if now < created - CLOCK_TOLERANCE:
        bad("CLOCK_BEFORE_APPROVAL")
    if created < plan_created or expires - created > APPROVAL_TTL or expires > plan_expires:
        bad("APPROVAL_TIMES_INCONSISTENT")
    if not audit.verify_chain(index, account)[0]:
        bad("AUDIT_CHAIN_BROKEN")
    logged = False
    for e in audit.events(index, account, plan_id, 1000):
        if e["event_type"] == "PLAN_APPROVED":
            meta = json.loads(e["meta"])
            logged = logged or (meta.get("plan_hash") == plan["plan_hash"] and meta.get("nonce_sha256") == sha256(a["nonce"]))
    if not logged:
        bad("APPROVAL_NOT_IN_AUDIT")
    return problems
