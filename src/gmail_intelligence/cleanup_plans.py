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

from gmail_intelligence import classifier, cleanup_audit as audit, cleanup_candidates as cc, cleanup_protect, report
from gmail_intelligence.cleanup_audit import canonical, sha256

FORMAT_VERSION = 1
ACTION = "ARCHIVE"
MAX_PLAN_ITEMS = 500
PLAN_TTL = timedelta(hours=48)
APPROVAL_TTL = timedelta(hours=24)
PAGE_SIZE = 25
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


def _policy(min_age_days):
    return {"cleanup_policy": cc.POLICY_VERSION, "min_age_days": min_age_days, "approved_types": sorted(cc.APPROVED_TYPES),
            "plan_format": FORMAT_VERSION}


def _anchor(index, account):
    state, _ = report.completeness(index, account)
    scans = [s for s in index.recent_scans(account, 50) if s["mode"] == "full" and s["status"] == "completed"]
    return {"completeness": state, "last_full_scan": scans[0]["finished_at"] if scans else None}


def _snapshot(plan_id, version, parent, account, created, expires, min_age_days, ruleset, protection, anchor, items):
    return {"format": FORMAT_VERSION, "plan_id": plan_id, "version": version,
            "parent": parent, "account": account, "action": ACTION, "created_at": created, "expires_at": expires,
            "policy": _policy(min_age_days), "classification_ruleset": ruleset, "protection_digest": protection,
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
    except ValueError:
        return ["SNAPSHOT_UNREADABLE"]
    if canonical(snap) != plan["snapshot"]:
        problems.append("SNAPSHOT_NOT_CANONICAL")
    for key in ("account", "plan_id", "version", "action", "created_at", "expires_at"):
        if snap.get(key) != plan[key]:
            problems.append("COLUMN_MISMATCH")
    if (snap.get("parent") or {}).get("plan_id") != plan["parent_id"]:
        problems.append("COLUMN_MISMATCH")
    if len(snap.get("items", [])) != plan["item_count"]:
        problems.append("COLUMN_MISMATCH")
    table = {i["message_id"]: (i["thread_id"], i["item_digest"]) for i in plan["items"]}
    want = {i["id"]: (i["thread_id"], sha256(canonical(i))) for i in snap.get("items", [])}
    if table != want:
        problems.append("ITEM_TABLE_MISMATCH")
    return sorted(set(problems))


def snapshot_of(plan):
    return json.loads(plan["snapshot"])


# ---------------------------------------------------------------- freshness
def revalidate(index, account, plan, now=None, _out=None):
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
    min_age = snap["policy"]["min_age_days"]
    if snap["policy"] != _policy(min_age):
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
    ids = [i["id"] for i in snap["items"]]
    facts = _facts(index, account, ids)
    res = cc.evaluate_all(index, account, now_ms=_ms(now), min_age_days=min_age)
    decisions = {d.message_id: d for d in res.decisions}
    if _out is not None:
        _out["decisions"] = decisions
    for item in snap["items"]:
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
        "AND a.status='VALID' AND a.expires_at <= ?))", account, at, at)]
    if not due:
        return 0
    with _txn(index):
        for pid in due:
            if _close_approvals(index, account, pid, "EXPIRED", at):
                audit.append(index, account, pid, "APPROVAL_EXPIRED", at, {})
            _set_state(index, account, pid, "EXPIRED", at)
            audit.append(index, account, pid, "PLAN_EXPIRED", at, {})
    return len(due)


def _insert_plan(index, account, ids, min_age_days, now, parent=None):
    """Validate and insert a new DRAFT plan inside the caller's transaction. Returns the plan id."""
    at = _iso(now)
    ids = sorted(set(ids))
    res = cc.evaluate_all(index, account, now_ms=_ms(now), min_age_days=min_age_days)
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
                     cleanup_protect.digest(account, cleanup_protect.active(index, account)), _anchor(index, account), items)
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
                  "parent": None if parent is None else parent["plan_id"]})
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
        parent = get_plan(index, account, plan_id)
        if parent["state"] not in LIVE_STATES:
            raise PlanError("NOT_ACTIVE", f"plan is {parent['state']}; only an active plan can be revised")
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
    """Record a failed validation in its own transaction (the failed operation was rolled back)."""
    try:
        with _txn(index):
            audit.append(index, account, plan_id, event, at, {"code": code, "detail": (detail or "")[:190]})
    except sqlite3.Error:
        pass


def mark_reviewed(index, account, plan_id, phrase, now=None):
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)
    try:
        with _txn(index):
            plan = get_plan(index, account, plan_id)
            if plan["state"] != "DRAFT":
                raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a DRAFT plan can be reviewed")
            problems = revalidate(index, account, plan, now)
            if problems:
                raise PlanError("STALE", "plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
            if (phrase or "").strip() != review_phrase(plan):
                raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; plan stays DRAFT")
            _set_state(index, account, plan_id, "REVIEWED", at, reviewed=True)
            audit.append(index, account, plan_id, "PLAN_REVIEWED", at, {"items": plan["item_count"], "plan_hash": plan["plan_hash"]})
    except PlanError as exc:
        if exc.code != "NO_SUCH_PLAN":
            _reject(index, account, plan_id, "REVIEW_REJECTED", at, exc.code)
        raise
    return get_plan(index, account, plan_id)


def approve(index, account, plan_id, phrase, now=None):
    """Record a LOCAL one-time approval for a REVIEWED, fresh plan. Grants no Gmail permission; executes nothing."""
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)
    try:
        with _txn(index):
            plan = get_plan(index, account, plan_id)
            if plan["state"] == "APPROVED":
                raise PlanError("ALREADY_APPROVED", "this plan already has an approval; approvals are one-time and cannot be repeated")
            if plan["state"] != "REVIEWED":
                raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a REVIEWED plan can be approved")
            problems = revalidate(index, account, plan, now)
            if problems:
                raise PlanError("STALE", "plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
            if (phrase or "").strip() != approval_phrase(plan):
                raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; nothing was approved")
            nonce = secrets.token_hex(16)
            expires = min(now + APPROVAL_TTL, datetime.strptime(plan["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc))
            index.conn.execute("INSERT INTO cleanup_approval (account, plan_id, nonce, plan_hash, action, item_count, created_at, "
                               "expires_at, status, status_changed_at) VALUES (?,?,?,?,?,?,?,?,'VALID',?)",
                               (account, plan_id, nonce, plan["plan_hash"], plan["action"], plan["item_count"], at, _iso(expires), at))
            _set_state(index, account, plan_id, "APPROVED", at)
            audit.append(index, account, plan_id, "PLAN_APPROVED", at,
                         {"items": plan["item_count"], "plan_hash": plan["plan_hash"], "nonce_sha256": sha256(nonce),
                          "expires_at": _iso(expires)})
    except sqlite3.IntegrityError:
        _reject(index, account, plan_id, "APPROVAL_REJECTED", at, "CONFLICT")
        raise PlanError("ALREADY_APPROVED", "a valid approval already exists for this plan")
    except PlanError as exc:
        if exc.code != "NO_SUCH_PLAN":
            _reject(index, account, plan_id, "APPROVAL_REJECTED", at, exc.code)
        raise
    return approval_status(index, account, plan_id, now)


def cancel(index, account, plan_id, now=None):
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        plan = _row(index, account, plan_id)
        if plan["state"] not in LIVE_STATES:
            raise PlanError("NOT_ACTIVE", f"plan is already {plan['state']}")
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

    It consumes nothing and is not an authorization to touch Gmail.
    """
    now = _utc(now)
    plan = get_plan(index, account, plan_id)
    problems = revalidate(index, account, plan, now)
    if plan["state"] != "APPROVED":
        problems["NOT_APPROVED"] = 1
    valid = [r for r in index._q("SELECT * FROM cleanup_approval WHERE account=? AND plan_id=? AND status='VALID'", account, plan_id)]
    if len(valid) != 1:
        problems["NO_SINGLE_VALID_APPROVAL"] = 1
    else:
        a = valid[0]
        if a["plan_hash"] != plan["plan_hash"] or a["action"] != plan["action"] or a["item_count"] != plan["item_count"]:
            problems["APPROVAL_MISMATCH"] = 1
        if _iso(now) >= a["expires_at"]:
            problems["APPROVAL_EXPIRED"] = 1
    return problems
