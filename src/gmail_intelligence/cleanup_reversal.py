"""M12D: bulk REVERSAL plans - reversing a finished archive execution in reviewed, approved, bounded slices. Local SQLite only; Gmail is reached only through the unchanged per-item undo engine.

A reversal plan is a fixed, hash-bound selection of items of ONE finished execution. It is NOT a new table and NOT a new engine: its life is a sequence of events in the same hash-chained,
append-only audit log (`cleanup_undo_ledger` derives its state with a strict state machine), and every item is undone by `cleanup_undo._undo_item` with its own per-item ledger, so the
D7 contract of M12C holds:

  * only verified APPLIED archive items (trusted evidence, intact plan and consumed approval, original labels contained INBOX, no open undo) are ever selected; nothing else, and no
    item can be added later: the selection and its digest are frozen by `REVERSAL_PLANNED`; any change (even of the source journal rows) makes the digest differ and refuses the run;
  * its own approval (a typed phrase unlike every archive, execution and single-undo phrase; 24 hours; lockout after repeated wrong phrases);
  * bounded slices (the archive rule: a canary of 25 for more than 100 items, then at most 100), each started only by a FRESH typed slice confirmation, the next one only after the
    previous ended without a stop; a slice that is started cannot be started again, and a slice that never ended is INTERRUPTED (30 minutes) and can only be aborted;
  * before EACH item the engine re-verifies the item, the live message and its whole thread; drift SKIPS that item (nothing sent); UNKNOWN, a provably refused request or any read problem
    STOPS the slice and the whole reversal (the remaining items are never attempted); an ambiguous undo is never retried (reconcile it read-only);
  * F5: a sibling in the same thread counts as intentionally restored only through a completed, trusted RESTORED outcome inside THIS approved plan (see `cleanup_undo._restored_siblings`).
INBOX is the only label ever added; no other label or message is touched. Nothing here changes the archive history.
"""
import json
import secrets
from dataclasses import dataclass
from datetime import timedelta

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_plans as cp, cleanup_undo as cu
from gmail_intelligence import cleanup_undo_ledger as ledger
from gmail_intelligence.cleanup_audit import canonical, sha256

MAX_ITEMS = cp.MAX_PLAN_ITEMS
APPROVAL_TTL = timedelta(hours=24)
FINAL_EXECUTION_STATES = ("EXECUTED", "PARTIAL")
OPEN_ITEM_STATUSES = ("OPEN", "UNKNOWN", "INCONSISTENT")
ReversalError = ce.ExecError


@dataclass(frozen=True)
class SliceResult:
    slice_no: int
    restored: int
    skipped: int
    stopped: bool
    reason: str       # '' or a closed code
    mutations: int    # undo requests made by this call (never more than one per item)
    state: str        # the reversal plan's state afterwards


def approval_phrase(rev, n, digest):
    return f"APPROVE UNDO {n} {digest[:8]} {rev}"


def slice_phrase(rev, slice_no, size, digest):
    return f"UNDO SLICE {slice_no} {size} {digest[:8]} {rev}"


def abort_phrase(rev):
    return f"ABORT REVERSAL {rev}"


def _item_rows(index, account, exec_id, seqs):
    rows = {r["seq"]: dict(r) for r in index._q("SELECT seq, message_id, state, prev_label_ids, evidence_source, evidence_checked FROM cleanup_exec_item WHERE account=? AND exec_id=?", account, exec_id)}
    return [rows.get(s) for s in seqs]


def _digest(index, account, exec_id, seqs, plan_hash):
    """Binds the selection to the exact journal facts of its items (message identity as a hash, original labels, evidence source) and to the source plan."""
    rows = _item_rows(index, account, exec_id, seqs)
    if any(r is None for r in rows):
        return None
    body = {"v": 1, "exec": exec_id, "source_plan": plan_hash,
            "items": [{"seq": r["seq"], "m": sha256(r["message_id"]), "prev": sorted(json.loads(r["prev_label_ids"] or "[]")), "src": r["evidence_source"]} for r in rows]}
    return sha256(canonical(body))


def _plan_event(index, account, rev):
    ev = ledger.reversal_events(index, account, rev)
    if not ev:
        raise ReversalError("NO_SUCH_REVERSAL", "no such reversal plan for this account")
    return ev


def _state(index, account, rev, now=None):
    now = cp._utc(now)
    return ledger.reversal_state(_plan_event(index, account, rev), cp._iso(now))


def create_reversal_plan(index, account, exec_id, exclude_seqs=(), now=None):
    """Select every undoable APPLIED item of a finished execution (minus the owner's exclusions) and freeze it as a reversal plan. Returns its summary. Local only."""
    now = cp._utc(now)
    at = cp._iso(now)
    exclude = list(exclude_seqs or ())
    if any(isinstance(x, bool) or not isinstance(x, int) for x in exclude):
        raise ReversalError("BAD_INPUT", "excluded items must be sequence numbers")
    with cp._txn(index):
        cp._check_clock(index, account, now)
        ex = ce.get_execution(index, account, exec_id)
        if ex["state"] not in FINAL_EXECUTION_STATES:
            raise ReversalError("EXECUTION_NOT_FINISHED", f"execution is {ex['state']}; only a finished (EXECUTED or PARTIAL) execution can be reversed")
        candidates, refused = [], {}
        for r in index._q("SELECT seq FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='APPLIED' ORDER BY seq", account, exec_id):
            seq = r["seq"]
            try:
                cu._original(index, account, exec_id, seq)
            except ce.ExecError as exc:
                refused[exc.code] = refused.get(exc.code, 0) + 1
                continue
            status = ledger.undo_status(index, account, exec_id, seq)
            if status not in ("NONE", "NOT_RESTORED"):
                refused["UNDO_" + status] = refused.get("UNDO_" + status, 0) + 1
                continue
            candidates.append(seq)
        if len(set(exclude)) != len(exclude) or not set(exclude) <= set(candidates):
            raise ReversalError("BAD_EXCLUDE", "every excluded item must be a distinct, currently undoable item of this execution; nothing was created")
        items = [s for s in candidates if s not in set(exclude)]
        if not items:
            raise ReversalError("NO_TARGETS", "no undoable archived item is left to reverse; nothing was created")
        if len(items) > MAX_ITEMS:
            raise ReversalError("TOO_MANY", f"a reversal plan may contain at most {MAX_ITEMS} items; exclude some or reverse in more than one plan")
        digest = _digest(index, account, exec_id, items, ex["plan_hash"])
        rev = "rev-" + secrets.token_hex(4)
        sizes = ce.plan_slices(len(items))
        assign, pos = {}, 0
        for n, size in enumerate(sizes, 1):                           # the plan fixes which item belongs to which slice (flat audit metadata: item seq -> slice number)
            for seq in items[pos:pos + size]:
                assign[str(seq)] = n
            pos += size
        audit.append(index, account, ex["plan_id"], "REVERSAL_PLANNED", at, {"rev": rev, "exec": exec_id, "items": assign, "digest": digest, "slices": {str(n): s for n, s in enumerate(sizes, 1)},
                                                                             "source_plan_hash": ex["plan_hash"], "excluded": len(exclude), "refused": refused})
    return describe(index, account, rev, now)


def describe(index, account, rev, now=None):
    """Read-only summary of a reversal plan (counts and sequence numbers only; no message ids, labels or accounts)."""
    now = cp._utc(now)
    ev = _plan_event(index, account, rev)
    st = ledger.reversal_state(ev, cp._iso(now))
    if st["state"] == "INCONSISTENT":
        return {"rev": rev, "state": "INCONSISTENT"}
    exec_id, sizes, done = st["exec"], st["slices"], st["done"]
    offset = sum(sizes[:done])
    counts = {}
    for seq in st["items"]:
        s = ledger.undo_status(index, account, exec_id, seq)
        counts[s] = counts.get(s, 0) + 1
    nxt = None
    if st["state"] in ("APPROVED", "AWAITING_CONTINUATION") and done < len(sizes):
        nxt = {"slice": done + 1, "size": sizes[done], "items": [offset + 1, offset + sizes[done]]}
    return {"rev": rev, "exec_id": exec_id, "state": st["state"], "items": len(st["items"]), "digest": st["digest"], "slices": sizes, "slices_done": done, "approved": st["approved"],
            "approval_expires": st["approval_expires"], "restored": st["restored"], "skipped": len(st["skipped"]), "item_states": dict(sorted(counts.items())), "next": nxt,
            "blocked_by_uncertain_items": any(counts.get(x) for x in OPEN_ITEM_STATUSES), "excluded_at_planning": ev[0]["meta"].get("excluded", 0), "refused_at_planning": ev[0]["meta"].get("refused", {})}


def _plan_id(index, account, exec_id):
    return ce.get_execution(index, account, exec_id)["plan_id"]


def approve_reversal(index, account, rev, phrase, now=None):
    """The owner's typed approval of a reversal plan (a local ledger entry; it executes nothing). Wrong phrases are recorded and, after repeated failures, locked out."""
    now = cp._utc(now)
    at = cp._iso(now)
    err, plan_id = None, None
    try:
        with cp._txn(index):
            cp._check_clock(index, account, now)
            ev = _plan_event(index, account, rev)
            st = ledger.reversal_state(ev, at)
            plan_id = _plan_id(index, account, st.get("exec")) if st.get("exec") else None
            if st["state"] != "PLANNED":
                raise ReversalError("NOT_APPROVABLE", f"reversal plan is {st['state']}; only a PLANNED plan can be approved")
            if audit.recent(index, account, plan_id, ("REVERSAL_REJECTED",), cp._iso(now - cp.LOCKOUT_WINDOW)) >= cp.MAX_FAILED_ATTEMPTS:
                raise ReversalError("LOCKED_OUT", "too many failed reversal confirmations for this plan; try again later")
            if _digest(index, account, st["exec"], st["items"], ce.get_execution(index, account, st["exec"])["plan_hash"]) != st["digest"]:
                raise ReversalError("PLAN_CHANGED", "the source execution no longer matches this reversal plan; create a new one (nothing was approved)")
            if (phrase or "").strip() != approval_phrase(rev, len(st["items"]), st["digest"]):
                raise ReversalError("BAD_CONFIRMATION", "reversal approval did not match; nothing was approved")
            audit.append(index, account, plan_id, "REVERSAL_APPROVED", at, {"rev": rev, "digest": st["digest"], "phrase_sha256": sha256(phrase.strip() + rev),
                                                                            "expires": cp._iso(now + APPROVAL_TTL)})
    except cp.PlanError as exc:
        err = exc
    if err is not None:
        if err.code == "BAD_CONFIRMATION" and plan_id:
            cp._reject(index, account, plan_id, "REVERSAL_REJECTED", at, err.code)
        raise err
    return describe(index, account, rev, now)


def abort_reversal(index, account, rev, phrase, now=None):
    """The owner abandons a reversal plan that is not running (never rolls anything back: items already restored stay restored)."""
    now = cp._utc(now)
    at = cp._iso(now)
    with cp._txn(index):
        cp._check_clock(index, account, now)
        st = ledger.reversal_state(_plan_event(index, account, rev), at)
        if st["state"] not in ("PLANNED", "APPROVED", "AWAITING_CONTINUATION", "INTERRUPTED", "STOPPED"):
            raise ReversalError("NOT_ABORTABLE", f"reversal plan is {st['state']}; it cannot be aborted now")
        if (phrase or "").strip() != abort_phrase(rev):
            raise ReversalError("BAD_CONFIRMATION", "abort confirmation did not match; nothing was changed")
        audit.append(index, account, _plan_id(index, account, st["exec"]), "REVERSAL_ABORTED", at, {"rev": rev})
    return describe(index, account, rev, now)


def run_slice(index, account, rev, phrase, mailbox):
    """Run the next slice of an approved reversal plan against the FAKE mailbox (the only type this public function accepts). See `_run_slice`."""
    return _run_slice(index, account, rev, phrase, mailbox, "FAKE")


def _skip_code(exc):
    cause = exc.__cause__
    if exc.code == "UNDO_DRIFT":
        return "UNDO_DRIFT"
    if exc.code == "UNDO_PREFLIGHT_FAILED" and getattr(cause, "code", None) == "NOT_FOUND":
        return "UNDO_GONE"        # the message no longer exists: nothing to restore (an unconfirmed 404 or any other read problem is NOT this: it stops)
    return None


def _run_slice(index, account, rev, phrase, mailbox, allow):
    """Run the NEXT slice of an approved reversal plan. Needs a fresh typed slice confirmation. One bounded slice per call; never resumes, never retries.

    Order: gate and local checks (nothing recorded) -> `REVERSAL_SLICE_STARTED` (once; a started slice can never be started again) -> per item, in plan order: authorize (lazily, tied to
    this plan) and run the unchanged single-item undo (account, item, live message and thread are re-verified by the engine right before its own durable intent) -> `REVERSAL_SLICE_DONE`.
    Drifted or vanished items are skipped (nothing sent); an UNKNOWN or refused undo, an uncertain earlier item or any other problem stops the slice AND the reversal."""
    cu._gate(mailbox, allow)
    now = cu._now(mailbox)
    at = cp._iso(now)
    err, plan_id = None, None
    try:
        with cp._txn(index):
            cp._check_clock(index, account, now)
            st = ledger.reversal_state(_plan_event(index, account, rev), at)
            if st["state"] not in ("APPROVED", "AWAITING_CONTINUATION"):
                raise ReversalError("NOT_RUNNABLE", f"reversal plan is {st['state']}; only an APPROVED plan (or one awaiting its next slice) can run a slice")
            exec_id = st["exec"]
            ex = ce.get_execution(index, account, exec_id)
            plan_id = ex["plan_id"]
            if st["approval_expires"] is None or at >= st["approval_expires"]:
                raise ReversalError("APPROVAL_EXPIRED", "the reversal approval has expired; create and approve a new plan")
            if mailbox.account.strip().lower() != account.strip().lower():
                raise ReversalError("ACCOUNT_MISMATCH", "the mailbox belongs to another account; nothing was changed")
            if audit.recent(index, account, plan_id, ("REVERSAL_REJECTED",), cp._iso(now - cp.LOCKOUT_WINDOW)) >= cp.MAX_FAILED_ATTEMPTS:
                raise ReversalError("LOCKED_OUT", "too many failed reversal confirmations for this plan; try again later")
            if any(ledger.undo_status(index, account, exec_id, s) in OPEN_ITEM_STATUSES for s in st["items"]):
                raise ReversalError("OPEN_UNCERTAIN_ITEM", "an item of this plan is OPEN, UNKNOWN or INCONSISTENT; reconcile it (read-only) first - it is never retried")
            if _digest(index, account, exec_id, st["items"], ex["plan_hash"]) != st["digest"]:
                raise ReversalError("PLAN_CHANGED", "the source execution no longer matches this reversal plan; nothing was changed")
            slice_no, size = st["done"] + 1, st["slices"][st["done"]]
            if (phrase or "").strip() != slice_phrase(rev, slice_no, size, st["digest"]):
                raise ReversalError("BAD_CONFIRMATION", "slice confirmation did not match; nothing was started")
            audit.append(index, account, plan_id, "REVERSAL_SLICE_STARTED", at, {"rev": rev, "slice": slice_no, "size": size, "phrase_sha256": sha256(phrase.strip() + rev)})
    except cp.PlanError as exc:
        err = exc
    if err is not None:
        if err.code == "BAD_CONFIRMATION" and plan_id:
            cp._reject(index, account, plan_id, "REVERSAL_REJECTED", at, err.code)
        raise err
    batch = [s for s in st["items"] if st["assign"][s] == slice_no]
    phrase_sha = sha256(phrase.strip() + rev)
    restored = skipped = mutations = 0
    stopped, reason = False, ""
    for seq in batch:
        try:
            if ledger.undo_status(index, account, exec_id, seq) not in ("NONE", "NOT_RESTORED"):
                raise ReversalError("ITEM_STATE", "an item is no longer in a state that can be undone")
            cu.authorize_in_reversal(index, account, exec_id, seq, rev, slice_no, phrase_sha, now=cu._now(mailbox))
            res = cu._undo_item(index, account, exec_id, seq, mailbox, allow)
        except ce.ExecError as exc:
            code = _skip_code(exc)
            if code is None:
                stopped, reason = True, exc.code
                break
            with cp._txn(index):
                audit.append(index, account, plan_id, "REVERSAL_ITEM_SKIPPED", cp._iso(cu._now(mailbox)), {"rev": rev, "slice": slice_no, "item": seq, "code": code})
            skipped += 1
            continue
        mutations += res.mutations
        if res.status == "RESTORED":
            restored += 1
            continue
        stopped, reason = True, res.status        # UNKNOWN (never retried) or a provably refused request: stop the whole reversal
        break
    with cp._txn(index):
        audit.append(index, account, plan_id, "REVERSAL_SLICE_DONE", cp._iso(cu._now(mailbox)), {"rev": rev, "slice": slice_no, "restored": restored, "skipped": skipped,
                                                                                           "stopped": stopped, "reason": reason})
    return SliceResult(slice_no, restored, skipped, stopped, reason, mutations, describe(index, account, rev, cu._now(mailbox))["state"])
