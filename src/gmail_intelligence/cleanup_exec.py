"""Local execution state for approved cleanup plans (M4C-A). Local SQLite only: NO Gmail client, NO OAuth, NO network.

This module is the bookkeeping that a future executor (M4C-C) will drive. In M4C-A nothing here can change a mailbox, and no
production command reserves or runs an execution; the functions are exercised by tests with synthetic data.

Invariants (also enforced by schema triggers where practical):
  * An execution is created only together with the atomic, one-time consumption of the plan's VALID approval, and only after a
    SEPARATE typed execution confirmation. Dry-runs, listings and status never consume anything.
  * The target set is frozen at reservation: exact items of the immutable plan, never more.
  * One non-final execution per account (PREPARED / EXECUTING / RECONCILIATION_REQUIRED); overlapping plans never cause an
    automatic duplicate operation (unresolved overlap refuses; already-applied overlap is pre-skipped).
  * Item and execution states only move forward. A crash or lost lease NEVER resumes automatically: interrupted work becomes
    UNKNOWN and the execution RECONCILIATION_REQUIRED.
  * Each step is a short SQLite transaction. SQLite and Gmail cannot commit atomically, so the intent is committed BEFORE any
    future Gmail call and the outcome AFTER it; the gap is exactly what reconciliation covers.
  * Rows hold ids, states, timestamps, error codes and previous label ids (for a future undo) - never message content or credentials.
"""
import json
import secrets
import sqlite3
from datetime import timedelta

from gmail_intelligence import cleanup_audit as audit, cleanup_plans as cp
from gmail_intelligence.cleanup_audit import sha256
from gmail_intelligence.cleanup_plans import PlanError, _iso, _parse, _txn, _utc, short

CANARY_SIZE = 25
MAX_SLICE = 100
LEASE_TTL = timedelta(minutes=5)
ACTIVE_STATES = ("PREPARED", "EXECUTING", "RECONCILIATION_REQUIRED")
FINAL_ITEM_STATES = ("APPLIED", "SKIPPED_DRIFT", "SKIPPED_GONE", "NOT_APPLIED", "CONFLICT")
OPEN_ITEM_STATES = ("PENDING", "INTENT", "UNKNOWN")
SKIP_CODES = {"SKIPPED_DRIFT", "SKIPPED_GONE"}


class ExecError(PlanError):
    """Refusal with a stable `code` and a privacy-safe message (counts and codes only; never ids)."""


# ---------------------------------------------------------------- confirmations (separate from the M4B approval phrase)
def plan_slices(n):
    """Slice sizes: up to 100 targets run as one slice; larger plans start with a canary of 25, then slices of at most 100."""
    if n <= MAX_SLICE:
        return [n]
    sizes, left = [CANARY_SIZE], n - CANARY_SIZE
    while left > 0:
        sizes.append(min(MAX_SLICE, left))
        left -= sizes[-1]
    return sizes


def execution_phrase(plan, first_slice_size):
    """What the owner must type to reserve an execution (different from the approval phrase)."""
    return f"EXECUTE {plan['action']} {first_slice_size} {short(plan['plan_hash'])}"


def continuation_phrase(plan, slice_no, size):
    return f"CONTINUE {plan['action']} {size} {short(plan['plan_hash'])} slice {slice_no}"


# ---------------------------------------------------------------- reading
def get_execution(index, account, exec_id):
    rows = index._q("SELECT * FROM cleanup_execution WHERE account=? AND exec_id=?", account, exec_id)
    if not rows:
        raise ExecError("NO_SUCH_EXECUTION", "no such execution for this account")
    return dict(rows[0])


def list_executions(index, account):
    return [dict(r) for r in index._q(
        "SELECT exec_id, plan_id, state, item_count, slice_count, created_at, state_changed_at FROM cleanup_execution "
        "WHERE account=? ORDER BY created_at, exec_id", account)]


def item_counts(index, account, exec_id):
    return {r["state"]: r["n"] for r in index._q(
        "SELECT state, COUNT(*) n FROM cleanup_exec_item WHERE account=? AND exec_id=? GROUP BY state", account, exec_id)}


def slices(index, account, exec_id):
    return [dict(r) for r in index._q("SELECT * FROM cleanup_exec_slice WHERE account=? AND exec_id=? ORDER BY slice_no", account, exec_id)]


def _slice(index, account, exec_id, slice_no):
    rows = index._q("SELECT * FROM cleanup_exec_slice WHERE account=? AND exec_id=? AND slice_no=?", account, exec_id, slice_no)
    if not rows:
        raise ExecError("NO_SUCH_SLICE", "no such slice")
    return dict(rows[0])


# ---------------------------------------------------------------- dry run (zero writes)
def overlap(index, account, plan_id, exclude_exec=None):
    """Targets of `plan_id` that other executions touch: {'unresolved': n, 'applied': n}. Read-only."""
    ids = [r["message_id"] for r in index._q("SELECT message_id FROM cleanup_item WHERE account=? AND plan_id=?", account, plan_id)]
    res = {"unresolved": 0, "applied": 0}
    for k in range(0, len(ids), 400):
        chunk = ids[k:k + 400]
        marks = ",".join("?" * len(chunk))
        for r in index._q(
                f"SELECT i.state, e.state es FROM cleanup_exec_item i JOIN cleanup_execution e ON e.account=i.account AND e.exec_id=i.exec_id "
                f"WHERE i.account=? AND i.message_id IN ({marks}) AND e.plan_id<>?", account, *chunk, plan_id):
            if r["state"] == "APPLIED":
                res["applied"] += 1
            elif r["state"] in OPEN_ITEM_STATES and r["es"] not in ("ABORTED", "EXECUTED", "FAILED"):
                res["unresolved"] += 1
    return res


def dry_run(index, account, plan_id, now=None):
    """Everything a reservation would check, WITHOUT writing anything (no expiry sweep, no audit event, no consumption)."""
    now = _utc(now)
    plan = cp.get_plan(index, account, plan_id)
    existing = index._q("SELECT exec_id, state FROM cleanup_execution WHERE account=? AND plan_id=?", account, plan_id)
    problems = cp.verify_approved(index, account, plan_id, now) if plan["state"] == "APPROVED" else {"NOT_APPROVED": 1}
    if existing:
        problems["PLAN_ALREADY_HAS_EXECUTION"] = 1
    active = index._q("SELECT COUNT(*) FROM cleanup_execution WHERE account=? AND state IN ('PREPARED','EXECUTING','RECONCILIATION_REQUIRED')", account)[0][0]
    if active:
        problems["ACTIVE_EXECUTION_EXISTS"] = 1
    ov = overlap(index, account, plan_id)
    if ov["unresolved"]:
        problems["OVERLAP_UNRESOLVED"] = ov["unresolved"]
    sizes = plan_slices(plan["item_count"])
    return {"plan_id": plan_id, "plan_state": plan["state"], "action": plan["action"], "targets": plan["item_count"],
            "hash8": short(plan["plan_hash"]), "slices": sizes, "problems": problems, "overlap_applied": ov["applied"],
            "executable_now": not problems and ov["applied"] < plan["item_count"],
            "confirmation_phrase": execution_phrase(plan, sizes[0]),
            "note": "dry run: nothing was reserved, consumed or written; execution does not exist in this version"}


# ---------------------------------------------------------------- audit helpers (inside the caller's transaction)
def _tr(index, account, plan_id, event, at, **meta):
    audit.append(index, account, plan_id, event, at, meta)


def _set_exec(index, account, exec_id, plan_id, new, old, at, **extra):
    n = index.conn.execute("UPDATE cleanup_execution SET state=?, state_changed_at=?, lease_token=NULL, lease_expires_at=NULL "
                           "WHERE account=? AND exec_id=? AND state=?", (new, at, account, exec_id, old)).rowcount
    if n != 1:
        raise ExecError("BAD_STATE", f"execution is not {old}")
    _tr(index, account, plan_id, "EXECUTION_TRANSITION", at, exec=exec_id, **{"from": old, "to": new}, **extra)


def _set_slice(index, account, exec_id, plan_id, slice_no, new, old, at, **cols):
    sets = ", ".join(f"{k}=?" for k in cols)
    n = index.conn.execute(f"UPDATE cleanup_exec_slice SET state=?{', ' + sets if sets else ''} WHERE account=? AND exec_id=? "
                           "AND slice_no=? AND state=?", (new, *cols.values(), account, exec_id, slice_no, old)).rowcount
    if n != 1:
        raise ExecError("BAD_SLICE_STATE", f"slice {slice_no} is not {old}")
    _tr(index, account, plan_id, "SLICE_TRANSITION", at, exec=exec_id, slice=slice_no, **{"from": old, "to": new})


def _set_item(index, account, exec_id, plan_id, message_id, new, old, at, code=None, **cols):
    sets = "".join(f", {k}=?" for k in cols)
    n = index.conn.execute(f"UPDATE cleanup_exec_item SET state=?, error_code=COALESCE(?, error_code){sets} WHERE account=? AND "
                           "exec_id=? AND message_id=? AND state=?", (new, code, *cols.values(), account, exec_id, message_id, old)).rowcount
    if n != 1:
        raise ExecError("BAD_ITEM_STATE", f"item is not {old}")
    row = index._q("SELECT seq, slice_no FROM cleanup_exec_item WHERE account=? AND exec_id=? AND message_id=?", account, exec_id, message_id)[0]
    _tr(index, account, plan_id, "ITEM_TRANSITION", at, exec=exec_id, seq=row["seq"], slice=row["slice_no"], code=code or "",
        **{"from": old, "to": new})  # a sequence number identifies the item; message ids never enter the audit log


# ---------------------------------------------------------------- reservation (consumes the approval)
def reserve_execution(index, account, plan_id, confirmation, now=None):
    """Consume the plan's one-time approval and reserve an execution in ONE transaction.

    Requires the separate typed execution confirmation. Starts nothing: the execution is PREPARED and slice 1 CONFIRMED.
    """
    now = _utc(now)
    at = _iso(now)
    err = None
    try:
        with _txn(index):
            cp._check_clock(index, account, now)
            plan = cp.get_plan(index, account, plan_id)
            since = _iso(now - cp.LOCKOUT_WINDOW)
            if audit.recent(index, account, plan_id, ("RESERVATION_REJECTED",), since) >= cp.MAX_FAILED_ATTEMPTS:
                raise ExecError("LOCKED_OUT", "too many failed execution confirmations for this plan; try again later")
            if plan["state"] != "APPROVED":
                raise ExecError("NOT_APPROVED", f"plan is {plan['state']}; only an APPROVED plan can be reserved for execution")
            if index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND plan_id=?", account, plan_id):
                raise ExecError("PLAN_ALREADY_HAS_EXECUTION", "this plan's approval was already consumed by an execution")
            problems = cp.verify_approved(index, account, plan_id, now)
            if problems:
                raise ExecError("NOT_EXECUTABLE", "plan is not executable: " + cp._describe(problems))
            sizes = plan_slices(plan["item_count"])
            if (confirmation or "").strip() != execution_phrase(plan, sizes[0]):
                raise ExecError("BAD_CONFIRMATION", "execution confirmation did not match; nothing was reserved or consumed")
            if index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND state IN ('PREPARED','EXECUTING','RECONCILIATION_REQUIRED')", account):
                raise ExecError("ACTIVE_EXECUTION_EXISTS", "another execution for this account is not finished; reconcile or abort it first")
            ids = sorted(i["message_id"] for i in plan["items"])
            applied, unresolved = _overlap_sets(index, account, plan_id, ids)
            if unresolved:
                raise ExecError("OVERLAP_UNRESOLVED", f"{len(unresolved)} target(s) belong to another execution with unresolved work; "
                                "reconcile it first (nothing was consumed)")
            if len(applied) >= len(ids):
                raise ExecError("NOTHING_TO_DO", "every target was already archived by another execution; nothing was consumed")
            (appr,) = index._q("SELECT nonce FROM cleanup_approval WHERE account=? AND plan_id=? AND status='VALID'", account, plan_id)
            n = index.conn.execute("UPDATE cleanup_approval SET status='CONSUMED', status_changed_at=? WHERE account=? AND plan_id=? "
                                   "AND nonce=? AND status='VALID'", (at, account, plan_id, appr["nonce"])).rowcount
            if n != 1:
                raise ExecError("APPROVAL_NOT_VALID", "the approval could not be consumed")
            exec_id = "exec-" + secrets.token_hex(4)
            index.conn.execute(
                "INSERT INTO cleanup_execution (account, exec_id, plan_id, plan_hash, approval_nonce, action, state, item_count, slice_count, "
                "confirmation_sha256, created_at, state_changed_at) VALUES (?,?,?,?,?,?,'PREPARED',?,?,?,?,?)",
                (account, exec_id, plan_id, plan["plan_hash"], appr["nonce"], plan["action"], plan["item_count"], len(sizes),
                 sha256(execution_phrase(plan, sizes[0]) + exec_id), at, at))
            for no, size in enumerate(sizes, 1):
                index.conn.execute("INSERT INTO cleanup_exec_slice (account, exec_id, slice_no, size, state, confirmation_sha256, confirmed_at) "
                                   "VALUES (?,?,?,?,?,?,?)", (account, exec_id, no, size, "CONFIRMED" if no == 1 else "PENDING",
                                                              sha256(execution_phrase(plan, sizes[0]) + exec_id) if no == 1 else None,
                                                              at if no == 1 else None))
            seq = 0
            for no, size in enumerate(sizes, 1):
                for mid in ids[seq:seq + size]:
                    skip = mid in applied
                    index.conn.execute("INSERT INTO cleanup_exec_item (account, exec_id, message_id, seq, slice_no, state, error_code) "
                                       "VALUES (?,?,?,?,?,?,?)", (account, exec_id, mid, ids.index(mid) + 1, no,
                                                                 "SKIPPED_DRIFT" if skip else "PENDING", "OVERLAP_ALREADY_APPLIED" if skip else None))
                seq += size
            _tr(index, account, plan_id, "EXECUTION_RESERVED", at, exec=exec_id, items=len(ids), slices=len(sizes),
                pre_skipped=len(applied), plan_hash=plan["plan_hash"], approval_consumed=1)
            _tr(index, account, plan_id, "SLICE_CONFIRMED", at, exec=exec_id, slice=1, size=sizes[0])
    except PlanError as exc:
        err = exc
    except sqlite3.IntegrityError:  # database-level refusal (trigger / constraint): fail closed with a generic code
        err = ExecError("DB_CONSTRAINT", "an unexpected database constraint stopped the reservation; nothing was consumed")
    if err is not None:
        if err.code not in ("NO_SUCH_PLAN", "CLOCK_ROLLBACK", "LOCKED_OUT"):
            cp._reject(index, account, plan_id, "RESERVATION_REJECTED", at, err.code)
        raise err
    return get_execution(index, account, exec_id)


def _overlap_sets(index, account, plan_id, ids):
    applied, unresolved = set(), set()
    for k in range(0, len(ids), 400):
        chunk = ids[k:k + 400]
        marks = ",".join("?" * len(chunk))
        for r in index._q(
                f"SELECT i.message_id, i.state, e.state es FROM cleanup_exec_item i JOIN cleanup_execution e "
                f"ON e.account=i.account AND e.exec_id=i.exec_id WHERE i.account=? AND i.message_id IN ({marks}) AND e.plan_id<>?",
                account, *chunk, plan_id):
            if r["state"] == "APPLIED":
                applied.add(r["message_id"])
            elif r["state"] in OPEN_ITEM_STATES and r["es"] not in ("ABORTED", "EXECUTED", "FAILED"):
                unresolved.add(r["message_id"])
    return applied, unresolved


# ---------------------------------------------------------------- slices and leases
def _lease_ok(ex, token, now):
    return (ex["state"] == "EXECUTING" and token and ex["lease_token"] == token and ex["lease_expires_at"]
            and _iso(now) < ex["lease_expires_at"])


def start_slice(index, account, exec_id, slice_no, lease_token, now=None):
    """CONFIRMED slice -> ACTIVE and execution -> EXECUTING, taking a lease. Never resumes an interrupted execution."""
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        cp._check_clock(index, account, now)
        ex = get_execution(index, account, exec_id)
        if ex["state"] not in ("PREPARED", "PARTIAL"):
            raise ExecError("BAD_STATE", f"execution is {ex['state']}; it cannot start a slice")
        sl = _slice(index, account, exec_id, slice_no)
        if sl["state"] != "CONFIRMED":
            raise ExecError("SLICE_NOT_CONFIRMED", "this slice has no fresh execution confirmation")
        if any(s["state"] != "COMPLETED" for s in slices(index, account, exec_id) if s["slice_no"] < slice_no):
            raise ExecError("PREVIOUS_SLICE_INCOMPLETE", "earlier slices must be COMPLETED first")
        try:
            index.conn.execute("UPDATE cleanup_execution SET state='EXECUTING', state_changed_at=?, lease_token=?, lease_expires_at=? "
                               "WHERE account=? AND exec_id=? AND state=?", (at, lease_token, _iso(now + LEASE_TTL), account, exec_id, ex["state"]))
        except sqlite3.IntegrityError:
            raise ExecError("ACTIVE_EXECUTION_EXISTS", "another execution of this account is not finished (or the targets are not frozen)") from None
        _tr(index, account, ex["plan_id"], "EXECUTION_TRANSITION", at, exec=exec_id, **{"from": ex["state"], "to": "EXECUTING"})
        _set_slice(index, account, exec_id, ex["plan_id"], slice_no, "ACTIVE", "CONFIRMED", at, started_at=at)


def renew_lease(index, account, exec_id, lease_token, now=None):
    now = _utc(now)
    with _txn(index):
        ex = get_execution(index, account, exec_id)
        if not _lease_ok(ex, lease_token, now):
            raise ExecError("LEASE_LOST", "this process no longer holds the execution lease; stop")
        index.conn.execute("UPDATE cleanup_execution SET lease_expires_at=? WHERE account=? AND exec_id=?",
                           (_iso(now + LEASE_TTL), account, exec_id))


def _active(index, account, exec_id, token, now):
    ex = get_execution(index, account, exec_id)
    if not _lease_ok(ex, token, now):
        raise ExecError("LEASE_LOST", "this process does not hold a live execution lease; stop")
    return ex


def _item(index, account, exec_id, message_id):
    rows = index._q("SELECT * FROM cleanup_exec_item WHERE account=? AND exec_id=? AND message_id=?", account, exec_id, message_id)
    if not rows:
        raise ExecError("NO_SUCH_ITEM", "that message is not a target of this execution")
    return dict(rows[0])


def _in_active_slice(index, account, exec_id, item):
    sl = _slice(index, account, exec_id, item["slice_no"])
    if sl["state"] != "ACTIVE":
        raise ExecError("SLICE_NOT_ACTIVE", "the item's slice is not active")


# ---------------------------------------------------------------- per-item intent / outcome
def record_skip(index, account, exec_id, token, message_id, kind, code, now=None):
    """PENDING -> SKIPPED_DRIFT | SKIPPED_GONE (a pre-write live check failed). Nothing was attempted."""
    if kind not in SKIP_CODES:
        raise ExecError("BAD_INPUT", "kind must be SKIPPED_DRIFT or SKIPPED_GONE")
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        it = _item(index, account, exec_id, message_id)
        _in_active_slice(index, account, exec_id, it)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, kind, "PENDING", _iso(now), code=code, result_at=_iso(now))


def record_intent(index, account, exec_id, token, message_id, prev_label_ids, now=None):
    """Commit the INTENT (and the label ids before the change, for a future undo) BEFORE any Gmail write."""
    now = _utc(now)
    labels = list(prev_label_ids or [])
    if not labels or any(not isinstance(x, str) or not x or len(x) > 64 for x in labels) or len(labels) > 100:
        raise ExecError("BAD_INPUT", "previous label ids are required (strings, at most 100) to allow a later undo")
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        it = _item(index, account, exec_id, message_id)
        _in_active_slice(index, account, exec_id, it)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, "INTENT", "PENDING", _iso(now),
                  prev_label_ids=json.dumps(sorted(labels)), intent_at=_iso(now))


def record_outcome(index, account, exec_id, token, message_id, outcome, code="", verified=False, now=None):
    """INTENT -> APPLIED | NOT_APPLIED (known result) | UNKNOWN (ambiguous: needs reconciliation, never retried automatically)."""
    if outcome not in ("APPLIED", "NOT_APPLIED", "UNKNOWN"):
        raise ExecError("BAD_INPUT", "outcome must be APPLIED, NOT_APPLIED or UNKNOWN")
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        _item(index, account, exec_id, message_id)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, outcome, "INTENT", _iso(now), code=code or outcome,
                  result_at=_iso(now), verified=1 if verified and outcome == "APPLIED" else 0)


# ---------------------------------------------------------------- finishing, stopping, interruption
def _settle(index, account, ex, at):
    """Pick the final state of an execution with no open items left. Caller is inside a transaction."""
    c = item_counts(index, account, ex["exec_id"])
    applied, bad = c.get("APPLIED", 0), c.get("NOT_APPLIED", 0) + c.get("CONFLICT", 0)
    if applied and not bad:
        return "EXECUTED"
    return "PARTIAL" if applied else "FAILED"


def end_slice(index, account, exec_id, slice_no, token, now=None):
    """ACTIVE -> COMPLETED when every item of the slice is final. Leaves PARTIAL (awaiting a fresh confirmation) or settles."""
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        open_n = index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE account=? AND exec_id=? AND slice_no=? AND state IN ('PENDING','INTENT','UNKNOWN')",
                          account, exec_id, slice_no)[0][0]
        if open_n:
            raise ExecError("SLICE_INCOMPLETE", f"{open_n} item(s) of this slice are not final; stop the execution instead")
        _set_slice(index, account, exec_id, ex["plan_id"], slice_no, "COMPLETED", "ACTIVE", at, finished_at=at)
        more = index._q("SELECT COUNT(*) FROM cleanup_exec_slice WHERE account=? AND exec_id=? AND state='PENDING'", account, exec_id)[0][0]
        _set_exec(index, account, exec_id, ex["plan_id"], "PARTIAL" if more else _settle(index, account, ex, at), "EXECUTING", at,
                  awaiting_continuation=1 if more else 0)


def _stop(index, account, ex, reason, at, from_state):
    """INTENT->UNKNOWN, unattempted PENDING->NOT_APPLIED, open slices STOPPED, then the right execution state."""
    plan_id, exec_id = ex["plan_id"], ex["exec_id"]
    for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='INTENT' ORDER BY seq", account, exec_id):
        _set_item(index, account, exec_id, plan_id, r["message_id"], "UNKNOWN", "INTENT", at, code=reason, result_at=at)
    for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='PENDING' ORDER BY seq", account, exec_id):
        _set_item(index, account, exec_id, plan_id, r["message_id"], "NOT_APPLIED", "PENDING", at, code=reason, result_at=at)
    for s in slices(index, account, exec_id):
        if s["state"] in ("PENDING", "CONFIRMED", "ACTIVE"):
            _set_slice(index, account, exec_id, plan_id, s["slice_no"], "STOPPED", s["state"], at, finished_at=at)
    unknown = item_counts(index, account, exec_id).get("UNKNOWN", 0)
    _set_exec(index, account, exec_id, plan_id, "RECONCILIATION_REQUIRED" if unknown else _settle(index, account, ex, at), from_state, at,
              reason=reason, unknown=unknown)


def stop_execution(index, account, exec_id, token, reason, now=None):
    """Executor-initiated halt (circuit breaker, ambiguous result, auth/account problem). Never continues automatically."""
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        _stop(index, account, ex, (reason or "STOPPED")[:60], _iso(now), "EXECUTING")
    return get_execution(index, account, exec_id)


def recover_interrupted(index, account, now=None):
    """Executions whose lease expired (crash, kill, lost process) become UNKNOWN work needing reconciliation. NEVER resumed."""
    now = _utc(now)
    at = _iso(now)
    stale = [r["exec_id"] for r in index._q("SELECT exec_id FROM cleanup_execution WHERE account=? AND state='EXECUTING' AND "
                                            "(lease_expires_at IS NULL OR lease_expires_at <= ?)", account, at)]
    if not stale:
        return []
    with _txn(index):
        for exec_id in stale:
            ex = get_execution(index, account, exec_id)
            _tr(index, account, ex["plan_id"], "EXECUTION_INTERRUPTED", at, exec=exec_id)
            _stop(index, account, ex, "INTERRUPTED", at, "EXECUTING")
    return stale


def abort_execution(index, account, exec_id, now=None):
    """Owner abandons an execution that is PREPARED or waiting for a continuation. The approval stays CONSUMED forever."""
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        ex = get_execution(index, account, exec_id)
        if ex["state"] not in ("PREPARED", "PARTIAL"):
            raise ExecError("BAD_STATE", f"execution is {ex['state']}; only PREPARED or PARTIAL executions can be aborted")
        for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='PENDING' ORDER BY seq", account, exec_id):
            _set_item(index, account, exec_id, ex["plan_id"], r["message_id"], "NOT_APPLIED", "PENDING", at, code="OWNER_ABORT", result_at=at)
        for s in slices(index, account, exec_id):
            if s["state"] in ("PENDING", "CONFIRMED"):
                _set_slice(index, account, exec_id, ex["plan_id"], s["slice_no"], "STOPPED", s["state"], at, finished_at=at)
        _set_exec(index, account, exec_id, ex["plan_id"], "ABORTED", ex["state"], at, reason="OWNER_ABORT")
    return get_execution(index, account, exec_id)


def confirm_slice(index, account, exec_id, slice_no, confirmation, now=None):
    """Fresh typed confirmation for the next slice of a PARTIAL execution. Re-checks the remaining targets against the local index."""
    now = _utc(now)
    at = _iso(now)
    err = None
    try:
        with _txn(index):
            cp._check_clock(index, account, now)
            ex = get_execution(index, account, exec_id)
            plan = cp.get_plan(index, account, ex["plan_id"])
            if ex["state"] != "PARTIAL":
                raise ExecError("BAD_STATE", f"execution is {ex['state']}; only a PARTIAL execution can continue")
            sl = _slice(index, account, exec_id, slice_no)
            prev = [s for s in slices(index, account, exec_id) if s["slice_no"] < slice_no]
            if sl["state"] != "PENDING" or any(s["state"] != "COMPLETED" for s in prev):
                raise ExecError("SLICE_NOT_NEXT", "this slice cannot be confirmed now (earlier slices must be COMPLETED)")
            if (confirmation or "").strip() != continuation_phrase(plan, slice_no, sl["size"]):
                raise ExecError("BAD_CONFIRMATION", "continuation confirmation did not match; nothing was confirmed")
            remaining = [r["message_id"] for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='PENDING'", account, exec_id)]
            problems = cp.revalidate(index, account, plan, now, only_ids=remaining)
            if problems:
                raise ExecError("STALE", "the remaining targets are stale or inconsistent: " + cp._describe(problems))
            _set_slice(index, account, exec_id, ex["plan_id"], slice_no, "CONFIRMED", "PENDING", at, confirmed_at=at,
                       confirmation_sha256=sha256(continuation_phrase(plan, slice_no, sl["size"]) + exec_id))
            _tr(index, account, ex["plan_id"], "SLICE_CONFIRMED", at, exec=exec_id, slice=slice_no, size=sl["size"])
    except PlanError as exc:
        err = exc
    if err is not None:
        if err.code not in ("NO_SUCH_EXECUTION", "CLOCK_ROLLBACK"):
            ex = index._q("SELECT plan_id FROM cleanup_execution WHERE account=? AND exec_id=?", account, exec_id)
            if ex:
                cp._reject(index, account, ex[0]["plan_id"], "RESERVATION_REJECTED", at, err.code)
        raise err


# ---------------------------------------------------------------- reconciliation of UNKNOWN items (decided from observed state)
def reconcile_item(index, account, exec_id, message_id, outcome, now=None):
    """UNKNOWN -> APPLIED | NOT_APPLIED | CONFLICT, based on a READ of the current state made by the caller. Never retries a write."""
    if outcome not in ("APPLIED", "NOT_APPLIED", "CONFLICT"):
        raise ExecError("BAD_INPUT", "outcome must be APPLIED, NOT_APPLIED or CONFLICT")
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        ex = get_execution(index, account, exec_id)
        if ex["state"] != "RECONCILIATION_REQUIRED":
            raise ExecError("BAD_STATE", "only an execution that requires reconciliation can be reconciled")
        _item(index, account, exec_id, message_id)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, outcome, "UNKNOWN", at, code="RECONCILED_" + outcome,
                  result_at=at, verified=1 if outcome == "APPLIED" else 0)
        _tr(index, account, ex["plan_id"], "EXECUTION_TRANSITION", at, exec=exec_id, reconciled_item=1)
        if not item_counts(index, account, exec_id).get("UNKNOWN", 0):
            _set_exec(index, account, exec_id, ex["plan_id"], _settle(index, account, ex, at), "RECONCILIATION_REQUIRED", at, reason="RECONCILED")
    return get_execution(index, account, exec_id)
