"""The single-message live canary entry point (M4): DISABLED, not reachable from the CLI, never exercised against Gmail.

`run_canary` is the one explicitly gated way to archive ONE approved message through the existing live boundary. It adds a gate and an owner confirmation, nothing else: the
archive itself is `cleanup_live.execute_live_batch`, i.e. the same per-item executor flow, the same genuine archive-only adapter and the same recovery as everything else (no
second archive path). In order:

  1. `exec_live_mailbox.LIVE_EXECUTION_ENABLED` must be True. It is False in this build and nothing changes it, so the very first statement refuses, BEFORE the index, the
     credential store, the client file or the network are touched. No environment variable, configuration value or command line option enables it.
  2. Local checks only (the index, no credentials; repeated INSIDE the transaction that records the confirmation, after the credentials were opened): the execution is EXECUTING with a live lease for this account, ARCHIVE, exactly ONE target in ONE slice (reserved from an
     approved plan of one message), and the owner typed the separate canary confirmation `canary_phrase` (not any archive, execution or undo phrase; wrong phrases are
     recorded and locked out).
  3. Credentials are opened (local checks only, no network) and the confirmation is recorded durably once per execution (`CANARY_CONFIRMED`; a second confirmation is refused).
  4. The shared executor then performs: approval and plan integrity, lease, live account verification, protection and drift checks, the live message and thread preflight,
     durable intent, at most ONE archive request, an independent execution-bound trusted post-read, UNKNOWN on any ambiguity (never retried) and recovery by fresh observation only.
Undo is not part of the canary (deferred). Like every in-process guard this stops mistakes and ordinary callers, not deliberate monkey-patching in the same process.
"""
import json
from dataclasses import dataclass

from gmail_intelligence import cleanup_audit as audit, cleanup_candidates as cc, cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, exec_live_mailbox as live
from gmail_intelligence.cleanup_audit import sha256


@dataclass(frozen=True)
class CanaryResult:
    item_state: str  # APPLIED | UNKNOWN | NOT_APPLIED | SKIPPED_DRIFT | SKIPPED_GONE (the one item)
    code: str
    execution_state: str
    posts: int  # archive requests made: 0 or 1


def canary_phrase(plan, exec_id):
    """What the owner must type to confirm the live canary of ONE message. A different prefix and shape from the approval, execution and undo phrases."""
    return f"CANARY ARCHIVE 1 {exec_id} {cp.short(plan['plan_hash'])}"


def _require_enabled():
    if live.LIVE_EXECUTION_ENABLED is not True:  # nothing below is reachable while the switch is off
        raise ce.ExecError("LIVE_DISABLED", "live Gmail execution is disabled in this build; nothing was read or changed")


def canary_plan_phrase(account, message_id):
    """What the owner must type to request the canary EXCEPTION for ONE message. It is derived from the account and the message id, so it only has meaning for that
    message, and it differs from every other phrase. (A deliberate confirmation, not a secret.)"""
    return "CANARY PLAN " + sha256(account.strip().lower() + "|" + message_id)[:12]


def describe_candidate(index, account, message_id):
    """Read-only: how the ordinary rules and the canary exception judge ONE message, as reason codes only (never ids, senders or labels). Local preparation only: it
    touches the index and nothing else, so it does not need the live switch."""
    if not cp.valid_id(message_id):
        raise cp.PlanError("BAD_INPUT", "a message id may only contain letters, digits, '-' and '_' (max 64 characters)")
    now_ms = cp._ms(live._utcnow())
    out = {}
    for name, ids in (("ordinary", frozenset()), ("canary", frozenset({message_id}))):
        decisions = {d.message_id: d for d in cc.evaluate_all(index, account, now_ms=now_ms, canary_ids=ids).decisions}
        if message_id not in decisions:
            raise cp.PlanError("UNKNOWN_IDS", "that message id is not in this account's local index")
        d = decisions[message_id]
        out[name] = {"outcome": d.outcome, "reasons": d.codes}
    out["self_sent"] = "SENT" in out["canary"]["reasons"]
    out["phrase"] = canary_plan_phrase(account, message_id)
    return out


def create_canary_plan(index, account, message_id, confirmation):
    """Create a DRAFT plan for exactly ONE explicitly named message under the canary exception, after the owner's separate typed confirmation.

    The exception waives only the age rule and the classification-type rules (`cleanup_candidates.CANARY_WAIVED`) for that one message. Everything else still applies and
    the message must come out ELIGIBLE under it: in particular SENT (a message sent from this very account), protected labels, user protection rules, unread, important,
    not-in-inbox, mixed threads and missing or stale classification still refuse it, and nothing is trimmed or widened. The plan then goes through the ordinary review,
    approval, reservation and execution safeguards. Local preparation only (the index, no Gmail, no credentials, no mutation of any mailbox): creating the plan does not need
    the live switch, because nothing can be executed live without it; it needs the owner's typed phrase."""
    if not isinstance(message_id, str) or not cp.valid_id(message_id):
        raise cp.PlanError("BAD_INPUT", "give exactly one valid message id (letters, digits, '-' and '_', max 64 characters)")
    if (confirmation or "").strip() != canary_plan_phrase(account, message_id):
        raise cp.PlanError("BAD_CONFIRMATION", "canary plan confirmation did not match; nothing was created")
    now = live._utcnow()
    cp.expire_due(index, account, now)
    with cp._txn(index):
        cp._check_clock(index, account, now)
        verdict = describe_candidate(index, account, message_id)
        if verdict["self_sent"]:
            raise cp.PlanError("CANARY_SELF_SENT", "this message carries the SENT label (it was sent from this account); the SENT protection is never bypassed. "
                               "Send the test message from a DIFFERENT account")
        plan_id = cp._insert_plan(index, account, [message_id], cc.MIN_AGE_DAYS, now, canary=True)
    return cp.get_plan(index, account, plan_id)


def _confirmations(index, account, exec_id):
    out = []
    for r in index._q("SELECT meta FROM cleanup_audit WHERE account=? AND event_type='CANARY_CONFIRMED' ORDER BY seq", account):
        if json.loads(r["meta"]).get("exec") == exec_id:
            out.append(r)
    return out


def _local_checks(index, account, exec_id, token, confirmation, now):
    """Everything that must hold for the canary, from the index alone (no credentials). Run inside a write transaction: once before the credentials are opened and AGAIN
    inside the transaction that records the confirmation, so a change in between (a lost lease, a stopped execution, an altered plan or approval) can neither be
    recorded as an authorization nor consume the confirmation. Returns (execution, plan)."""
    cp._check_clock(index, account, now)
    ex = ce.get_execution(index, account, exec_id)
    if ex["state"] != "EXECUTING" or not ce._lease_ok(ex, token, now):
        raise ce.ExecError("LEASE_LOST", "the execution is not running under this lease; nothing was changed")
    if ex["action"] != "ARCHIVE" or ex["item_count"] != 1 or ex["slice_count"] != 1:
        raise ce.ExecError("NOT_A_CANARY", "a canary needs an execution of exactly one ARCHIVE target in one slice; nothing was changed")
    if ce.invariant_problems(index, account, exec_id):
        raise ce.ExecError("INVARIANT_BROKEN", "the execution's slice/lease state is inconsistent; refusing to continue (nothing was changed)")
    plan = cp.get_plan(index, account, ex["plan_id"])
    if cp.integrity_problems(plan) or plan["plan_hash"] != ex["plan_hash"]:
        raise ce.ExecError("PLAN_CHANGED", "the plan no longer matches the execution; nothing was changed")
    approvals = index._q("SELECT status, nonce FROM cleanup_approval WHERE account=? AND plan_id=?", account, ex["plan_id"])
    if len(approvals) != 1 or approvals[0]["status"] != "CONSUMED" or approvals[0]["nonce"] != ex["approval_nonce"]:
        raise ce.ExecError("APPROVAL_NOT_CONSUMED", "the execution's approval is missing or not the one consumed at reservation; nothing was changed")
    if audit.recent(index, account, ex["plan_id"], ("CANARY_REJECTED",), cp._iso(now - cp.LOCKOUT_WINDOW)) >= cp.MAX_FAILED_ATTEMPTS:
        raise ce.ExecError("LOCKED_OUT", "too many failed canary confirmations for this plan; try again later")
    if _confirmations(index, account, exec_id):
        raise ce.ExecError("CANARY_ALREADY_CONFIRMED", "this execution's canary was already confirmed once; it is never repeated")
    if (confirmation or "").strip() != canary_phrase(plan, exec_id):
        raise ce.ExecError("BAD_CONFIRMATION", "canary confirmation did not match; nothing was confirmed")
    return ex, plan


def run_canary(index, account, exec_id, token, confirmation, store, client_path):
    """Archive the ONE approved message of a started single-target execution through the live boundary. See the module docstring. Disabled in this build."""
    _require_enabled()  # the very first statement: nothing below is reachable while the switch is off
    now = live._utcnow()
    err, plan_id = None, None
    try:
        with cp._txn(index):  # local checks and the owner's confirmation: the index only, no credentials
            plan_id = ce.get_execution(index, account, exec_id)["plan_id"]
            _local_checks(index, account, exec_id, token, confirmation, now)
    except cp.PlanError as exc:
        err = exc
    if err is not None:
        if err.code == "BAD_CONFIRMATION" and plan_id:
            cp._reject(index, account, plan_id, "CANARY_REJECTED", cp._iso(now), err.code)
        raise err
    mailbox = live.open_live_mailbox(account, store, client_path)  # credentials: local checks only; a problem here has not consumed the confirmation
    now = live._utcnow()
    with cp._txn(index):  # the confirmation is recorded durably, once, before anything is requested, after re-validating EVERYTHING in the same transaction
        _local_checks(index, account, exec_id, token, confirmation, now)
        audit.append(index, account, plan_id, "CANARY_CONFIRMED", cp._iso(now), {"exec": exec_id, "phrase_sha256": sha256(confirmation.strip() + exec_id)})
    res = cl.execute_live_batch(index, account, exec_id, token, mailbox, _permit=live._CANARY_PERMIT)
    (_, item), = res.items
    return CanaryResult(item.item_state, item.code, res.execution_state, res.posts)
