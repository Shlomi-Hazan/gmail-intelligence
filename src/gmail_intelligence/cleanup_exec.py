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
  * Leases are random tokens generated here (never chosen by callers); only their SHA-256 is stored.
  * Every mutation applies one clock policy (`_check_clock`): it is refused if the local clock is earlier than the last recorded event.
  * Reason codes come from a closed vocabulary and are validated BEFORE any state changes; free text is never stored.
  * APPLIED requires structured evidence of a live read (see `Evidence`). Local metadata alone cannot prove that Gmail changed.
  * Each step is a short SQLite transaction. SQLite and Gmail cannot commit atomically, so the intent is committed BEFORE any
    future Gmail call and the outcome AFTER it; the gap is exactly what reconciliation covers.
  * Related rows are written in a fixed order: items, then slices, then the execution (triggers refuse the reverse).
  * Rows hold ids, states, timestamps, vocabulary codes and previous label ids (for a future undo) - never message content or credentials.
"""
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import timedelta

from gmail_intelligence import cleanup_audit as audit, cleanup_plans as cp
from gmail_intelligence.cleanup_audit import sha256
from gmail_intelligence.cleanup_plans import PlanError, _iso, _parse, _txn, _utc, short
from gmail_intelligence.index import EXEC_ITEM_CODES

CANARY_SIZE = 25
MAX_SLICE = 100
LEASE_TTL = timedelta(minutes=5)
ACTIVE_STATES = ("PREPARED", "EXECUTING", "RECONCILIATION_REQUIRED")
TERMINAL_STATES = ("EXECUTED", "PARTIAL", "FAILED", "ABORTED")
OPEN_ITEM_STATES = ("PENDING", "INTENT", "UNKNOWN")
SKIP_KINDS = ("SKIPPED_DRIFT", "SKIPPED_GONE")

# ---- closed vocabularies (also enforced by a CHECK constraint on cleanup_exec_item.error_code) ----
SKIP_REASONS = ("LABELS_CHANGED", "STATE_CHANGED", "THREAD_CHANGED", "NOT_IN_INBOX", "NOT_FOUND")
OUTCOME_CODES = {"APPLIED": ("APPLIED",), "NOT_APPLIED": ("REJECTED",),
                 "UNKNOWN": ("TIMEOUT", "SERVER_ERROR", "NETWORK_ERROR", "AMBIGUOUS_RESULT")}
STOP_REASONS = ("CIRCUIT_BREAKER", "AMBIGUOUS_RESULT", "AUTH_PROBLEM", "ACCOUNT_MISMATCH", "RATE_LIMITED", "OWNER_REQUEST",
                "OWNER_ABORT", "INTERRUPTED")
assert set(SKIP_REASONS) | {c for v in OUTCOME_CODES.values() for c in v} <= set(EXEC_ITEM_CODES)
CODE_MEANING = {
    "NEVER_ATTEMPTED": "never attempted: execution stopped or was aborted before this message was touched",
    "REJECTED": "attempt rejected by Gmail (known, unmodified)",
    "RECONCILED_UNMODIFIED": "observed equal to its state before the attempt (does not prove no write occurred)",
    "RECONCILED_APPLIED": "observed in the expected archived state",
    "RECONCILED_CONFLICT": "observed in a state that is neither before nor after",
    "INTERRUPTED": "process or lease lost while the outcome was open (uncertain write)",
    "AMBIGUOUS_RESULT": "result of the attempt is uncertain",
    "TIMEOUT": "no answer (uncertain write)", "SERVER_ERROR": "server error (uncertain write)", "NETWORK_ERROR": "network error (uncertain write)",
    "OVERLAP_ALREADY_APPLIED": "already archived by another execution",
}


class ExecError(PlanError):
    """Refusal with a stable `code` and a privacy-safe message (counts and codes only; never ids)."""


def _code(value, allowed):
    """Normalize and validate a vocabulary code. The offending value is never echoed or stored."""
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise ExecError("BAD_CODE", "reason code is not in the allowed vocabulary")
    v = value.strip().upper()
    if len(v) > 40 or v not in allowed or any(not (c.isalnum() or c == "_") for c in v):
        raise ExecError("BAD_CODE", "reason code is not in the allowed vocabulary")
    return v


# ---------------------------------------------------------------- evidence contract (what the future live adapter must supply)
@dataclass(frozen=True)
class Evidence:
    """A structured observation of a message's label ids made by a LIVE READ of Gmail.

    This is the contract the future M4C-C adapter must satisfy. The library checks it against the recorded intent but CANNOT
    authenticate it: local metadata alone can never prove that a Gmail mutation occurred. In M4C-A no code produces real evidence;
    tests construct it explicitly.
    """
    kind: str
    message_id: str
    labels: tuple
    observed_at: str
    source: str = "gmail-live-read"


def _check_evidence(ev, item, now):
    ok = (isinstance(ev, Evidence) and ev.kind == "LIVE_READ" and ev.source == "gmail-live-read" and ev.message_id == item["message_id"]
          and isinstance(ev.labels, (tuple, list)) and 0 < len(ev.labels) <= 100 and all(isinstance(x, str) and 0 < len(x) <= 64 for x in ev.labels)
          and isinstance(ev.observed_at, str))
    if ok:
        try:
            seen = _parse(ev.observed_at)
        except ValueError:
            ok = False
        else:
            ok = (item["intent_at"] is not None and seen >= _parse(item["intent_at"]) - cp.CLOCK_TOLERANCE
                  and seen <= now + cp.CLOCK_TOLERANCE)
    if not ok:
        raise ExecError("BAD_EVIDENCE", "the evidence is missing, malformed or inconsistent with the recorded intent")
    return sorted(set(ev.labels))


def _expected_after(item):
    prev = set(json.loads(item["prev_label_ids"]))
    return sorted(prev - {"INBOX"}), sorted(prev)


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


# ---------------------------------------------------------------- leases (random, library-generated, stored hashed)
def _token_ok(token):
    return (isinstance(token, str) and 32 <= len(token) <= 64 and token.isascii()
            and all(c.isalnum() or c in "-_" for c in token))


def _lease_ok(ex, token, now):
    return bool(ex["state"] == "EXECUTING" and _token_ok(token) and ex["lease_token"]
                and hmac.compare_digest(ex["lease_token"], sha256(token)) and ex["lease_expires_at"] and _iso(now) < ex["lease_expires_at"])


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


def code_counts(index, account, exec_id):
    """{(state, code): n} for non-success items, so reasons and uncertainty are visible without any message id."""
    return {(r["state"], r["code"]): r["n"] for r in index._q(
        "SELECT state, COALESCE(error_code,'-') code, COUNT(*) n FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state<>'PENDING' "
        "AND state<>'APPLIED' GROUP BY state, code", account, exec_id)}


def slices(index, account, exec_id):
    return [dict(r) for r in index._q("SELECT * FROM cleanup_exec_slice WHERE account=? AND exec_id=? ORDER BY slice_no", account, exec_id)]


def _slice(index, account, exec_id, slice_no):
    rows = index._q("SELECT * FROM cleanup_exec_slice WHERE account=? AND exec_id=? AND slice_no=?", account, exec_id, slice_no)
    if not rows:
        raise ExecError("NO_SUCH_SLICE", "no such slice")
    return dict(rows[0])


def _item(index, account, exec_id, message_id):
    rows = index._q("SELECT * FROM cleanup_exec_item WHERE account=? AND exec_id=? AND message_id=?", account, exec_id, message_id)
    if not rows:
        raise ExecError("NO_SUCH_ITEM", "that message is not a target of this execution")
    return dict(rows[0])


# ---------------------------------------------------------------- dry run (zero writes)
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
            elif r["state"] in OPEN_ITEM_STATES and r["es"] not in TERMINAL_STATES:
                unresolved.add(r["message_id"])
    return applied, unresolved


def overlap(index, account, plan_id):
    ids = [r["message_id"] for r in index._q("SELECT message_id FROM cleanup_item WHERE account=? AND plan_id=?", account, plan_id)]
    applied, unresolved = _overlap_sets(index, account, plan_id, ids)
    return {"applied": len(applied), "unresolved": len(unresolved)}


def dry_run(index, account, plan_id, now=None):
    """Everything a reservation would check, WITHOUT writing anything (no expiry sweep, no audit event, no consumption)."""
    now = _utc(now)
    plan = cp.get_plan(index, account, plan_id)
    problems = cp.verify_approved(index, account, plan_id, now) if plan["state"] == "APPROVED" else {"NOT_APPROVED": 1}
    if index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND plan_id=?", account, plan_id):
        problems["PLAN_ALREADY_HAS_EXECUTION"] = 1
    if index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND state IN ('PREPARED','EXECUTING','RECONCILIATION_REQUIRED')", account):
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
            confirm_hash = sha256(execution_phrase(plan, sizes[0]) + exec_id)
            index.conn.execute(
                "INSERT INTO cleanup_execution (account, exec_id, plan_id, plan_hash, approval_nonce, action, state, item_count, slice_count, "
                "confirmation_sha256, created_at, state_changed_at) VALUES (?,?,?,?,?,?,'PREPARED',?,?,?,?,?)",
                (account, exec_id, plan_id, plan["plan_hash"], appr["nonce"], plan["action"], plan["item_count"], len(sizes),
                 confirm_hash, at, at))
            for no, size in enumerate(sizes, 1):
                index.conn.execute("INSERT INTO cleanup_exec_slice (account, exec_id, slice_no, size, state, confirmation_sha256, confirmed_at) "
                                   "VALUES (?,?,?,?,?,?,?)", (account, exec_id, no, size, "CONFIRMED" if no == 1 else "PENDING",
                                                              confirm_hash if no == 1 else None, at if no == 1 else None))
            offset = 0
            for no, size in enumerate(sizes, 1):
                for pos, mid in enumerate(ids[offset:offset + size], offset + 1):
                    skip = mid in applied
                    index.conn.execute("INSERT INTO cleanup_exec_item (account, exec_id, message_id, seq, slice_no, state, error_code) "
                                       "VALUES (?,?,?,?,?,?,?)", (account, exec_id, mid, pos, no, "SKIPPED_DRIFT" if skip else "PENDING",
                                                                 "OVERLAP_ALREADY_APPLIED" if skip else None))
                offset += size
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


# ---------------------------------------------------------------- slices and leases
def start_slice(index, account, exec_id, slice_no, now=None):
    """CONFIRMED slice -> ACTIVE and execution -> EXECUTING. Returns the NEW lease token (random, shown only to the caller).

    Never resumes an interrupted execution. The token is generated here and only its hash is stored.
    """
    now = _utc(now)
    at = _iso(now)
    token = secrets.token_urlsafe(24)  # 192 bits
    with _txn(index):
        cp._check_clock(index, account, now)
        ex = get_execution(index, account, exec_id)
        if ex["state"] not in ("PREPARED", "AWAITING_CONTINUATION"):
            raise ExecError("BAD_STATE", f"execution is {ex['state']}; it cannot start a slice")
        sl = _slice(index, account, exec_id, slice_no)
        if sl["state"] != "CONFIRMED":
            raise ExecError("SLICE_NOT_CONFIRMED", "this slice has no fresh execution confirmation")
        if any(s["state"] != "COMPLETED" for s in slices(index, account, exec_id) if s["slice_no"] < slice_no):
            raise ExecError("PREVIOUS_SLICE_INCOMPLETE", "earlier slices must be COMPLETED first")
        try:
            index.conn.execute("UPDATE cleanup_execution SET state='EXECUTING', state_changed_at=?, lease_token=?, lease_expires_at=? "
                               "WHERE account=? AND exec_id=? AND state=?", (at, sha256(token), _iso(now + LEASE_TTL), account, exec_id, ex["state"]))
        except sqlite3.IntegrityError:
            raise ExecError("ACTIVE_EXECUTION_EXISTS", "another execution of this account is not finished (or the targets are not frozen)") from None
        _tr(index, account, ex["plan_id"], "EXECUTION_TRANSITION", at, exec=exec_id, **{"from": ex["state"], "to": "EXECUTING"})
        _set_slice(index, account, exec_id, ex["plan_id"], slice_no, "ACTIVE", "CONFIRMED", at, started_at=at)
    return token


def _active(index, account, exec_id, token, now):
    """Inside a transaction: clock policy, then ownership of a live lease. The token must be library-shaped and match the stored hash."""
    cp._check_clock(index, account, now)
    ex = get_execution(index, account, exec_id)
    if not _token_ok(token):
        raise ExecError("BAD_LEASE", "the lease token is malformed")
    if not _lease_ok(ex, token, now):
        raise ExecError("LEASE_LOST", "this process does not hold a live execution lease; stop")
    return ex


def renew_lease(index, account, exec_id, token, now=None):
    now = _utc(now)
    with _txn(index):
        _active(index, account, exec_id, token, now)
        index.conn.execute("UPDATE cleanup_execution SET lease_expires_at=? WHERE account=? AND exec_id=?",
                           (_iso(now + LEASE_TTL), account, exec_id))


def _in_active_slice(index, account, exec_id, item):
    if _slice(index, account, exec_id, item["slice_no"])["state"] != "ACTIVE":
        raise ExecError("SLICE_NOT_ACTIVE", "the item's slice is not active")


# ---------------------------------------------------------------- per-item intent / outcome
def record_skip(index, account, exec_id, token, message_id, kind, reason, now=None):
    """PENDING -> SKIPPED_DRIFT | SKIPPED_GONE (a pre-write live check failed). Nothing was attempted."""
    if kind not in SKIP_KINDS:
        raise ExecError("BAD_INPUT", "kind must be SKIPPED_DRIFT or SKIPPED_GONE")
    code = _code(reason, SKIP_REASONS)
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        it = _item(index, account, exec_id, message_id)
        _in_active_slice(index, account, exec_id, it)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, kind, "PENDING", _iso(now), code=code, result_at=_iso(now))


def record_intent(index, account, exec_id, token, message_id, prev_label_ids, now=None):
    """Commit the INTENT (and the label ids before the change, for a future undo) BEFORE any Gmail write.

    The previous labels must include INBOX (ARCHIVE removes only INBOX) and become immutable once recorded.
    """
    now = _utc(now)
    labels = list(prev_label_ids) if isinstance(prev_label_ids, (list, tuple, set, frozenset)) else None
    if (not labels or len(labels) > 100 or any(not isinstance(x, str) or not x or len(x) > 64 or not x.isascii() for x in labels)
            or "INBOX" not in labels):
        raise ExecError("BAD_INPUT", "previous label ids are required (ASCII strings, at most 100, including INBOX) to allow a later undo")
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        it = _item(index, account, exec_id, message_id)
        _in_active_slice(index, account, exec_id, it)
        _set_item(index, account, exec_id, ex["plan_id"], message_id, "INTENT", "PENDING", _iso(now),
                  prev_label_ids=json.dumps(sorted(set(labels))), intent_at=_iso(now))


def record_outcome(index, account, exec_id, token, message_id, outcome, code=None, evidence=None, now=None):
    """INTENT -> APPLIED | NOT_APPLIED (known rejection) | UNKNOWN (ambiguous: needs reconciliation, never retried automatically).

    APPLIED requires `Evidence` of a live read showing exactly the previous labels minus INBOX; anything else is not APPLIED.
    """
    if outcome not in OUTCOME_CODES:
        raise ExecError("BAD_INPUT", "outcome must be APPLIED, NOT_APPLIED or UNKNOWN")
    code = _code(code if code is not None else OUTCOME_CODES[outcome][0], OUTCOME_CODES[outcome])
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        it = _item(index, account, exec_id, message_id)
        extra = {}
        if outcome == "APPLIED":
            observed = _check_evidence(evidence, it, now)
            if it["prev_label_ids"] is None or observed != _expected_after(it)[0]:
                raise ExecError("EVIDENCE_MISMATCH", "the observed labels are not the expected archived state; record UNKNOWN instead")
            extra["verified"] = 1
        _set_item(index, account, exec_id, ex["plan_id"], message_id, outcome, "INTENT", _iso(now), code=code, result_at=_iso(now), **extra)


# ---------------------------------------------------------------- finishing, stopping, interruption
def _settle(index, account, exec_id):
    """Final state of an execution that has no open items. Caller is inside a transaction."""
    c = item_counts(index, account, exec_id)
    applied, bad = c.get("APPLIED", 0), c.get("NOT_APPLIED", 0) + c.get("CONFLICT", 0)
    if not applied:
        return "FAILED"
    return "PARTIAL" if bad else "EXECUTED"


def end_slice(index, account, exec_id, slice_no, token, now=None):
    """ACTIVE -> COMPLETED when every item of the slice is final. Then AWAITING_CONTINUATION (a later slice exists) or a final state."""
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
        _set_exec(index, account, exec_id, ex["plan_id"], "AWAITING_CONTINUATION" if more else _settle(index, account, exec_id), "EXECUTING", at,
                  awaiting_continuation=1 if more else 0)


def _stop(index, account, ex, reason, at):
    """INTENT->UNKNOWN, unattempted PENDING->NEVER_ATTEMPTED, open slices STOPPED, then the right execution state (items, slices, execution)."""
    plan_id, exec_id = ex["plan_id"], ex["exec_id"]
    unknown_code = "INTERRUPTED" if reason == "INTERRUPTED" else "AMBIGUOUS_RESULT"
    for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='INTENT' ORDER BY seq", account, exec_id):
        _set_item(index, account, exec_id, plan_id, r["message_id"], "UNKNOWN", "INTENT", at, code=unknown_code, result_at=at)
    for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='PENDING' ORDER BY seq", account, exec_id):
        _set_item(index, account, exec_id, plan_id, r["message_id"], "NOT_APPLIED", "PENDING", at, code="NEVER_ATTEMPTED", result_at=at)
    for s in slices(index, account, exec_id):
        if s["state"] in ("PENDING", "CONFIRMED", "ACTIVE"):
            _set_slice(index, account, exec_id, plan_id, s["slice_no"], "STOPPED", s["state"], at, finished_at=at)
    unknown = item_counts(index, account, exec_id).get("UNKNOWN", 0)
    _set_exec(index, account, exec_id, plan_id, "RECONCILIATION_REQUIRED" if unknown else _settle(index, account, exec_id), "EXECUTING", at,
              reason=reason, unknown=unknown)


def stop_execution(index, account, exec_id, token, reason, now=None):
    """Executor-initiated halt (circuit breaker, ambiguous result, auth/account problem). Never continues automatically."""
    reason = _code(reason, STOP_REASONS)
    now = _utc(now)
    with _txn(index):
        ex = _active(index, account, exec_id, token, now)
        _stop(index, account, ex, reason, _iso(now))
    return get_execution(index, account, exec_id)


def recover_interrupted(index, account, now=None):
    """Executions whose lease expired (crash, kill, lost process) become UNKNOWN work needing reconciliation. NEVER resumed."""
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        cp._check_clock(index, account, now)
        stale = [r["exec_id"] for r in index._q("SELECT exec_id FROM cleanup_execution WHERE account=? AND state='EXECUTING' AND "
                                                "(lease_expires_at IS NULL OR lease_expires_at <= ?)", account, at)]
        for exec_id in stale:
            ex = get_execution(index, account, exec_id)
            _tr(index, account, ex["plan_id"], "EXECUTION_INTERRUPTED", at, exec=exec_id)
            _stop(index, account, ex, "INTERRUPTED", at)
    return stale


def abort_execution(index, account, exec_id, now=None):
    """Owner abandons an execution that is PREPARED or AWAITING_CONTINUATION. A finished execution (even PARTIAL) can never be aborted.

    The approval stays CONSUMED forever.
    """
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        cp._check_clock(index, account, now)
        ex = get_execution(index, account, exec_id)
        if ex["state"] not in ("PREPARED", "AWAITING_CONTINUATION"):
            raise ExecError("BAD_STATE", f"execution is {ex['state']}; only a PREPARED or AWAITING_CONTINUATION execution can be aborted")
        for r in index._q("SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='PENDING' ORDER BY seq", account, exec_id):
            _set_item(index, account, exec_id, ex["plan_id"], r["message_id"], "NOT_APPLIED", "PENDING", at, code="NEVER_ATTEMPTED", result_at=at)
        for s in slices(index, account, exec_id):
            if s["state"] in ("PENDING", "CONFIRMED"):
                _set_slice(index, account, exec_id, ex["plan_id"], s["slice_no"], "STOPPED", s["state"], at, finished_at=at)
        _set_exec(index, account, exec_id, ex["plan_id"], "ABORTED", ex["state"], at, reason="OWNER_ABORT")
    return get_execution(index, account, exec_id)


def confirm_slice(index, account, exec_id, slice_no, confirmation, now=None):
    """Fresh typed confirmation for the next slice of an AWAITING_CONTINUATION execution. Re-checks the remaining targets locally."""
    now = _utc(now)
    at = _iso(now)
    err = None
    try:
        with _txn(index):
            cp._check_clock(index, account, now)
            ex = get_execution(index, account, exec_id)
            plan = cp.get_plan(index, account, ex["plan_id"])
            if ex["state"] != "AWAITING_CONTINUATION":
                raise ExecError("BAD_STATE", f"execution is {ex['state']}; only an AWAITING_CONTINUATION execution can continue")
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


# ---------------------------------------------------------------- reconciliation of UNKNOWN items (from OBSERVED state only)
def reconcile_item(index, account, exec_id, message_id, evidence, now=None):
    """Resolve an UNKNOWN item from structured evidence of a LIVE READ. The caller cannot assert an outcome; the library derives it.

    Observed == expected archived state -> APPLIED (verified); observed == the state before the attempt -> NOT_APPLIED
    (RECONCILED_UNMODIFIED, which does not prove that no write occurred); anything else -> CONFLICT. No write is ever retried here.
    Not reachable from the CLI: M4C-A has no Gmail client to produce real evidence.
    """
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        cp._check_clock(index, account, now)
        ex = get_execution(index, account, exec_id)
        if ex["state"] != "RECONCILIATION_REQUIRED":
            raise ExecError("BAD_STATE", "only an execution that requires reconciliation can be reconciled")
        it = _item(index, account, exec_id, message_id)
        if it["state"] != "UNKNOWN":
            raise ExecError("BAD_ITEM_STATE", "only an UNKNOWN item can be reconciled")
        observed = _check_evidence(evidence, it, now)
        after, before = _expected_after(it)
        if observed == after:
            new, code, extra = "APPLIED", "RECONCILED_APPLIED", {"verified": 1}
        elif observed == before:
            new, code, extra = "NOT_APPLIED", "RECONCILED_UNMODIFIED", {}
        else:
            new, code, extra = "CONFLICT", "RECONCILED_CONFLICT", {}
        _set_item(index, account, exec_id, ex["plan_id"], message_id, new, "UNKNOWN", at, code=code, result_at=at, **extra)
        if not item_counts(index, account, exec_id).get("UNKNOWN", 0):
            _set_exec(index, account, exec_id, ex["plan_id"], _settle(index, account, exec_id), "RECONCILIATION_REQUIRED", at, reason="RECONCILED")
    return get_execution(index, account, exec_id)
