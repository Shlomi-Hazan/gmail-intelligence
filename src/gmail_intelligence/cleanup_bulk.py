"""M12D: the owner-operated BULK archive entry point (library): DISABLED, never exercised against Gmail. It adds a gate, local checks and the owner's per-slice run confirmation to the
EXISTING M4 execution engine; the archive itself is `cleanup_live.execute_live_slice` -> `cleanup_executor._execute_batch`, i.e. the same per-item flow (approval and plan integrity,
lease, account verification, local revalidation of EACH item, live message and whole-thread checks, durable intent before the one archive request, independent execution-bound trusted
post-read, UNKNOWN and stop on any ambiguity, no retry), the same bounded slices and the same recovery as everything else. There is no second executor.

Owner workflow (each step is a separate typed confirmation; nothing continues automatically):
  1. an APPROVED immutable plan (M12B review -> `cleanup plan review` -> `cleanup approve`);
  2. `reserve_execution` (the typed execution phrase consumes the one-time approval and freezes the targets; slice 1 is CONFIRMED by that same phrase);
  3. `run_bulk_slice` for the CONFIRMED slice: a separate typed run phrase, then ONE bounded slice runs;
  4. while slices remain: `confirm_slice` (a fresh typed continuation phrase, refused while anything uncertain or unsafe remains) and `run_bulk_slice` again.
Reconciling an uncertain item is READ-ONLY (`recover_observed`); retrying a mutation does not exist. An execution never advances past an INTENT / UNKNOWN / CONFLICT / rejected item or a
slice without an applied item (the state machine stops it: remaining targets NEVER_ATTEMPTED). `exec_live_mailbox.LIVE_EXECUTION_ENABLED` is False in this build, so `run_bulk_slice`
refuses as its very first statement, BEFORE the index, the credential store, the client file or the network are touched; no environment variable, option or configuration enables it.
"""
import json
from dataclasses import dataclass

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, exec_live_mailbox as live
from gmail_intelligence.cleanup_audit import sha256

SLICE_STATES = ("PENDING", "CONFIRMED", "ACTIVE", "COMPLETED", "STOPPED")


@dataclass(frozen=True)
class SliceResult:
    slice_no: int
    applied: int
    skipped: int
    unknown: int
    not_applied: int
    posts: int                # archive requests made by this call; never more than one per item
    execution_state: str
    stopped: bool


def run_phrase(plan, exec_id, slice_no, size):
    """What the owner must type to RUN one slice (a different prefix and shape from the approval, execution, continuation, canary and undo phrases)."""
    return f"RUN ARCHIVE {size} {cp.short(plan['plan_hash'])} {exec_id} slice {slice_no}"


def _require_enabled():
    if live.LIVE_EXECUTION_ENABLED is not True:  # nothing below is reachable while the switch is off
        raise ce.ExecError("LIVE_DISABLED", "live Gmail execution is disabled in this build; nothing was read or changed")


def describe(index, account, exec_id):
    """Read-only scope and progress of an execution: operation, item count, slice boundaries (sequence numbers), states and what the owner may do next. No ids, labels or accounts."""
    ex = ce.get_execution(index, account, exec_id)
    sls = ce.slices(index, account, exec_id)
    out, first = [], 1
    for s in sls:
        out.append({"slice": s["slice_no"], "size": s["size"], "state": s["state"], "items": [first, first + s["size"] - 1]})
        first += s["size"]
    blockers = ce.continuation_blockers(index, account, exec_id)
    confirmed = [s["slice"] for s in out if s["state"] == "CONFIRMED"]
    pending = [s["slice"] for s in out if s["state"] == "PENDING"]
    if ex["state"] in ("PREPARED", "AWAITING_CONTINUATION") and confirmed:
        nxt = {"action": "RUN", "slice": confirmed[0]}
    elif ex["state"] == "AWAITING_CONTINUATION" and pending and not blockers:
        nxt = {"action": "CONFIRM", "slice": pending[0]}
    elif ex["state"] == "RECONCILIATION_REQUIRED":
        nxt = {"action": "RECONCILE_READ_ONLY", "slice": None}
    else:
        nxt = {"action": "NONE", "slice": None}
    return {"exec_id": exec_id, "operation": ex["action"], "state": ex["state"], "items": ex["item_count"], "slices": out, "item_states": dict(sorted(ce.item_counts(index, account, exec_id).items())),
            "continuation_blockers": blockers, "next": nxt}


def _local_checks(index, account, exec_id, confirmation, now):
    """Everything that must hold, from the index alone (no credentials). Run inside a write transaction. Returns (execution, plan, slice row)."""
    cp._check_clock(index, account, now)
    ex = ce.get_execution(index, account, exec_id)
    if ex["state"] not in ("PREPARED", "AWAITING_CONTINUATION"):
        raise ce.ExecError("BAD_STATE", f"execution is {ex['state']}; only a PREPARED or AWAITING_CONTINUATION execution can run a slice (an interrupted one is never resumed)")
    if ex["action"] != "ARCHIVE":
        raise ce.ExecError("NOT_SUPPORTED", "only ARCHIVE executions can be run; nothing was changed")
    confirmed = [s for s in ce.slices(index, account, exec_id) if s["state"] == "CONFIRMED"]
    if len(confirmed) != 1:
        raise ce.ExecError("SLICE_NOT_CONFIRMED", "exactly one slice must carry a fresh typed confirmation (the first by the execution phrase, later ones by `cleanup exec confirm`)")
    sl = confirmed[0]
    if ce.invariant_problems(index, account, exec_id):
        raise ce.ExecError("INVARIANT_BROKEN", "the execution's slice/lease state is inconsistent; refusing to continue (nothing was changed)")
    plan = cp.get_plan(index, account, ex["plan_id"])
    if cp.integrity_problems(plan) or plan["plan_hash"] != ex["plan_hash"]:
        raise ce.ExecError("PLAN_CHANGED", "the plan no longer matches the execution; nothing was changed")
    approvals = index._q("SELECT status, nonce FROM cleanup_approval WHERE account=? AND plan_id=?", account, ex["plan_id"])
    if len(approvals) != 1 or approvals[0]["status"] != "CONSUMED" or approvals[0]["nonce"] != ex["approval_nonce"]:
        raise ce.ExecError("APPROVAL_NOT_CONSUMED", "the execution's approval is missing or not the one consumed at reservation; nothing was changed")
    if ce.item_counts(index, account, exec_id).get("INTENT") or ce.item_counts(index, account, exec_id).get("UNKNOWN") or ce.item_counts(index, account, exec_id).get("CONFLICT"):
        raise ce.ExecError("OPEN_UNCERTAIN_ITEM", "an item is INTENT, UNKNOWN or CONFLICT; reconcile it read-only first - it is never retried")
    if sl["slice_no"] > 1 and ce.continuation_blockers(index, account, exec_id):
        raise ce.ExecError("CONTINUATION_BLOCKED", "an earlier slice ended unsafely; the execution cannot continue")
    if audit.recent(index, account, ex["plan_id"], ("BULK_REJECTED",), cp._iso(now - cp.LOCKOUT_WINDOW)) >= cp.MAX_FAILED_ATTEMPTS:
        raise ce.ExecError("LOCKED_OUT", "too many failed run confirmations for this plan; try again later")
    if (confirmation or "").strip() != run_phrase(plan, exec_id, sl["slice_no"], sl["size"]):
        raise ce.ExecError("BAD_CONFIRMATION", "run confirmation did not match; nothing was started")
    return ex, plan, sl


def _confirmations(index, account):
    return [json.loads(r["meta"]) for r in index._q("SELECT meta FROM cleanup_audit WHERE account=? AND event_type='BULK_SLICE_CONFIRMED' ORDER BY seq", account)]


def run_bulk_slice(index, account, exec_id, confirmation, store, client_path):
    """Run the ONE confirmed slice of a reserved bulk execution through the live boundary. See the module docstring. Disabled in this build."""
    _require_enabled()  # the very first statement: nothing below is reachable while the switch is off
    now = live._utcnow()
    err, plan_id = None, None
    try:
        with cp._txn(index):  # local checks and the owner's run confirmation: the index only, no credentials
            plan_id = ce.get_execution(index, account, exec_id)["plan_id"]
            _local_checks(index, account, exec_id, confirmation, now)
    except cp.PlanError as exc:
        err = exc
    if err is not None:
        if err.code == "BAD_CONFIRMATION" and plan_id:
            cp._reject(index, account, plan_id, "BULK_REJECTED", cp._iso(now), err.code)
        raise err
    mailbox = live.open_live_mailbox(account, store, client_path)  # credentials: local checks only; a problem here has consumed nothing
    now = live._utcnow()
    with cp._txn(index):  # re-validate EVERYTHING, then record the owner's run confirmation durably (once per slice; a crash right after leaves the slice still CONFIRMED and un-run)
        ex, plan, sl = _local_checks(index, account, exec_id, confirmation, now)
        if not any(m.get("exec") == exec_id and m.get("slice") == sl["slice_no"] for m in _confirmations(index, account)):
            audit.append(index, account, plan_id, "BULK_SLICE_CONFIRMED", cp._iso(now), {"exec": exec_id, "slice": sl["slice_no"], "size": sl["size"],
                                                                                          "phrase_sha256": sha256(confirmation.strip() + exec_id)})
    token = ce.start_slice(index, account, exec_id, sl["slice_no"], now=now)     # CONFIRMED -> ACTIVE under a fresh random lease (the state machine re-checks and never resumes)
    res = cl.execute_live_slice(index, account, exec_id, token, mailbox, _permit=live._BULK_PERMIT)
    counts = {}
    for _seq, item in res.items:
        counts[item.item_state] = counts.get(item.item_state, 0) + 1
    return SliceResult(res.slice_no, counts.get("APPLIED", 0), counts.get("SKIPPED_DRIFT", 0) + counts.get("SKIPPED_GONE", 0), counts.get("UNKNOWN", 0), counts.get("NOT_APPLIED", 0),
                       res.posts, res.execution_state, res.stopped)
