"""Owner-approved undo of an archived item (M4D; live path added in M12C.3 behind its own DISABLED switch). Not reachable from the ordinary CLI.

Two entry modes share ONE state machine and ONE implementation: the public `undo_item` / `reconcile_undo` accept the FAKE test mailbox only; the private `_undo_item` /
`_reconcile_undo` accept exactly one more type, `exec_live_mailbox.LiveUndoMailbox` (undo-only transport), and only through `cleanup_live`, which requires
`exec_live_mailbox.LIVE_UNDO_ENABLED` (False in this build). Archive execution can never authorize or run an undo, and an undo mailbox has no archive operation.

An undo puts INBOX back on ONE message that an execution archived and recorded as APPLIED with a trusted observation. It is NOT an archive and is never recorded as one: the
original item row, its APPLIED history and its evidence are never touched (items of a finished execution are frozen anyway). The undo has its own ledger, and the ledger is the
hash-chained audit log (append-only; no schema change): UNDO_AUTHORIZED -> UNDO_INTENT -> UNDO_RESULT. The current state of one item's undo is derived from those events.

  authorize (owner types a SEPARATE phrase; the archive approval authorizes nothing here; valid for UNDO_AUTH_TTL; one authorization, one attempt)
  -> verify account, original APPLIED + trusted evidence, plan and approval integrity, exact current fake state, whole-thread protections and drift
  -> durable UNDO_INTENT (committed before any mutation) -> at most ONE fake mutation -> independent execution-bound trusted post-read
  -> UNDO_RESULT: RESTORED only for exactly the originally recorded labels; anything unclear is UNKNOWN and is only ever resolved by a fresh observation
     (`reconcile_undo`), never by repeating the mutation.

The real Gmail write policy has exactly one undo request (add INBOX to one message); both mailbox types send it through the same adapter and policy code.
"""
import json
from dataclasses import dataclass
from datetime import timedelta, timezone

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_executor as cx, cleanup_plans as cp, exec_live_mailbox as live
from gmail_intelligence.cleanup_audit import sha256
from gmail_intelligence.cleanup_undo_ledger import RESULTS, STATUSES, UNDO_EVENTS, _ledger, _state, open_undos, undo_status  # noqa: F401 - the read-only ledger lives in its own module
from gmail_intelligence.exec_fake_mailbox import FakeMailbox, wiring_is_fake

UNDO_AUTH_TTL = timedelta(minutes=15)


@dataclass(frozen=True)
class UndoResult:
    status: str  # one of STATUSES
    code: str  # a closed code ('' when none)
    mutations: int  # fake mutation attempts made by this call: 0 or 1


def undo_phrase(plan, exec_id, seq):
    """What the owner must type to authorize the undo of ONE item (by sequence number; no message id). Different from every archive phrase."""
    return f"UNDO {seq} {exec_id} {cp.short(plan['plan_hash'])}"


def _wired(mailbox, allow):
    """True if the mailbox is exactly the type this mode accepts, with intact wiring."""
    if allow == "FAKE":
        return type(mailbox) is FakeMailbox and wiring_is_fake(mailbox)
    if allow == "LIVE":
        return type(mailbox) is live.LiveUndoMailbox and live.live_undo_wiring_ok(mailbox)
    if allow == "OBSERVE":  # reconciliation only (M12C.4): a read-only mailbox that cannot restore anything
        return type(mailbox) is live.LiveObserveMailbox and live.live_observe_wiring_ok(mailbox)
    return False


def _gate(mailbox, allow="FAKE"):
    """The one mailbox check, at the start and again right before the mutation. "FAKE" (the public entry points) accepts only the fake test mailbox; "LIVE" (only `cleanup_live`)
    accepts only a `LiveUndoMailbox` and additionally needs the build's undo switch. Each mode refuses the other's type. A live ARCHIVE mailbox is never accepted."""
    if allow == "LIVE" and type(mailbox) is live.LiveUndoMailbox and live.LIVE_UNDO_ENABLED is not True:
        raise ce.ExecError("LIVE_UNDO_DISABLED", "live archive undo is disabled in this build; nothing was read or changed")
    if allow == "OBSERVE" and type(mailbox) is live.LiveObserveMailbox and live.LIVE_OBSERVE_ENABLED is not True:
        raise ce.ExecError("LIVE_OBSERVE_DISABLED", "live Gmail observation is disabled in this build; nothing was read or changed")
    if not _wired(mailbox, allow):
        raise ce.ExecError("MAILBOX_NOT_ALLOWED", "only the fake test mailbox is accepted in this version; nothing was read or changed" if allow == "FAKE"
                           else "this mailbox is not accepted by the live undo entry point; nothing was read or changed")


def _now(mailbox):
    return mailbox.clock().astimezone(timezone.utc)


def _item_by_seq(index, account, exec_id, seq):
    rows = index._q("SELECT * FROM cleanup_exec_item WHERE account=? AND exec_id=? AND seq=?", account, exec_id, seq) if isinstance(seq, int) and not isinstance(seq, bool) else []
    if not rows:
        raise ce.ExecError("NO_SUCH_ITEM", "no such item in this execution")
    return dict(rows[0])


def _original(index, account, exec_id, seq):
    """The execution, the item and the plan, after checking that the item really is a verified archive: APPLIED with checked trusted-adapter evidence, intact plan and
    approval. Read-only."""
    ex = ce.get_execution(index, account, exec_id)
    if ex["state"] == "EXECUTING":
        raise ce.ExecError("EXECUTION_RUNNING", "the execution is still running; nothing can be undone until it stops")
    item = _item_by_seq(index, account, exec_id, seq)
    if (item["state"] != "APPLIED" or item["evidence_checked"] != 1 or item["evidence_source"] != ce.TRUSTED_EVIDENCE_SOURCE or item["prev_label_ids"] is None
            or "INBOX" not in json.loads(item["prev_label_ids"])):
        raise ce.ExecError("NOT_UNDOABLE", "only an item recorded APPLIED with checked trusted-adapter evidence can be undone")
    plan = cp.get_plan(index, account, ex["plan_id"])
    if cp.integrity_problems(plan) or plan["plan_hash"] != ex["plan_hash"]:
        raise ce.ExecError("PLAN_CHANGED", "the plan no longer matches the execution; nothing was changed")
    approvals = index._q("SELECT status, nonce FROM cleanup_approval WHERE account=? AND plan_id=?", account, ex["plan_id"])
    if len(approvals) != 1 or approvals[0]["status"] != "CONSUMED" or approvals[0]["nonce"] != ex["approval_nonce"]:
        raise ce.ExecError("APPROVAL_NOT_CONSUMED", "the execution's approval is missing or not the one consumed at reservation; nothing was changed")
    return ex, item, plan


# ---------------------------------------------------------------- owner authorization
def authorize_undo(index, account, exec_id, seq, phrase, now=None):
    """The owner's separate, typed authorization to undo ONE archived item. Allowed only while the item has no undo yet (or its last undo ended NOT_RESTORED).

    Returns the item's undo status (AUTHORIZED). Wrong phrases are recorded and, after repeated failures, locked out."""
    now = cp._utc(now)
    at = cp._iso(now)
    err, plan_id = None, None
    try:
        with cp._txn(index):
            cp._check_clock(index, account, now)
            ex, item, plan = _original(index, account, exec_id, seq)
            plan_id = ex["plan_id"]
            if audit.recent(index, account, plan_id, ("UNDO_REJECTED",), cp._iso(now - cp.LOCKOUT_WINDOW)) >= cp.MAX_FAILED_ATTEMPTS:
                raise ce.ExecError("LOCKED_OUT", "too many failed undo confirmations for this plan; try again later")
            status = undo_status(index, account, exec_id, seq)
            if status not in ("NONE", "NOT_RESTORED"):
                raise ce.ExecError("UNDO_NOT_ALLOWED", f"this item's undo state is {status}; a new authorization is not possible")
            if (phrase or "").strip() != undo_phrase(plan, exec_id, seq):
                raise ce.ExecError("BAD_CONFIRMATION", "undo confirmation did not match; nothing was authorized")
            audit.append(index, account, plan_id, "UNDO_AUTHORIZED", at, {"exec": exec_id, "item": seq, "phrase_sha256": sha256(phrase.strip() + exec_id)})
    except cp.PlanError as exc:
        err = exc
    if err is not None:
        if err.code == "BAD_CONFIRMATION" and plan_id:
            cp._reject(index, account, plan_id, "UNDO_REJECTED", at, err.code)
        raise err
    return "AUTHORIZED"


# ---------------------------------------------------------------- the undo itself
def _context(ex, message_id, phase, intent_hash):
    return ce._context(ex, message_id, phase, intent_hash)


def _record(index, account, ex, seq, intent_hash, result, code, via, mailbox, obs=None, seen=None):
    now = _now(mailbox)
    meta = {"exec": ex["exec_id"], "item": seq, "intent": intent_hash, "result": result, "code": code, "via": via, "t": ce._us(now)}
    if obs is not None:
        meta.update({"src": ce.TRUSTED_EVIDENCE_SOURCE, "seen": ce._us(seen)})
    with cp._txn(index):
        cp._check_clock(index, account, now)
        audit.append(index, account, ex["plan_id"], "UNDO_RESULT", cp._iso(now), meta)


def _validated(obs, item, intent_t, context, account, mailbox):
    """Check a trusted observation with the very same rules as archive evidence: exact type, this account and message, unused, bound to `context`, not older than the
    undo intent and not too old. Returns (sorted labels or None, observed time). Consumes nothing."""
    pseudo = {"message_id": item["message_id"], "prev_label_ids": item["prev_label_ids"], "intent_at": intent_t, "state": "INTENT", "result_at": None}
    labels, seen, _ = ce._check_evidence(obs, pseudo, _now(mailbox), account, ce.TRUSTED_EVIDENCE_SOURCE, context)
    return labels, seen


def undo_item(index, account, exec_id, seq, mailbox):
    """Run ONE authorized undo against the FAKE mailbox (the only type this public function accepts). See `_undo_item`."""
    return _undo_item(index, account, exec_id, seq, mailbox, "FAKE")


def _undo_item(index, account, exec_id, seq, mailbox, allow):
    """Run ONE authorized undo. Refusals before the intent raise ExecError and change nothing (the authorization stays until it expires);
    after the intent there is exactly one mutation attempt, and anything unclear is UNKNOWN."""
    if allow not in ("FAKE", "LIVE"):  # a read-only (OBSERVE) mailbox can never mutate
        raise ce.ExecError("MAILBOX_NOT_ALLOWED", "this mailbox is not accepted by this entry point; nothing was read or changed")
    _gate(mailbox, allow)
    if mailbox.account.strip().lower() != account.strip().lower():
        raise ce.ExecError("ACCOUNT_MISMATCH", "the mailbox belongs to another account; nothing was changed")
    ex, item, plan = _original(index, account, exec_id, seq)
    status, auth, _, _ = _state(_ledger(index, account, exec_id, seq))
    if status != "AUTHORIZED":
        raise ce.ExecError("UNDO_NOT_AUTHORIZED", f"this item's undo state is {status}; an undo needs a fresh owner authorization (and runs once)")
    if _now(mailbox) - cp._parse(auth["at"]) > UNDO_AUTH_TTL:
        raise ce.ExecError("UNDO_AUTH_EXPIRED", "the undo authorization has expired; authorize again")
    prev = sorted(json.loads(item["prev_label_ids"]))
    archived = [x for x in prev if x != "INBOX"]
    mid = item["message_id"]
    try:
        mailbox.verify_account()
        state = mailbox.message_state(mid)
        thread = mailbox.thread_state(state.thread_id)
    except Exception as exc:  # noqa: BLE001 - nothing was attempted: refuse, keep the authorization
        raise ce.ExecError("UNDO_PREFLIGHT_FAILED", "the account or the live message could not be verified; nothing was changed") from exc
    snap = next(i for i in cp.snapshot_of(plan)["items"] if i["id"] == mid)
    if state.thread_id != snap["thread_id"]:
        raise ce.ExecError("UNDO_DRIFT", "the message's thread changed; nothing was changed")
    if sorted(state.label_ids) != archived:
        raise ce.ExecError("UNDO_DRIFT", "the message is not in exactly the archived state recorded for it; nothing was changed")
    if cx._thread_problem(index, account, mid, state.thread_id, thread, cx._archived_by_this_execution(index, account, exec_id)):
        raise ce.ExecError("UNDO_DRIFT", "the thread changed or contains a protected message; nothing was changed")

    # ---- durable intent, once per authorization, BEFORE any mutation (serialised by the write transaction)
    now = _now(mailbox)
    with cp._txn(index):
        cp._check_clock(index, account, now)
        status, auth, _, _ = _state(_ledger(index, account, exec_id, seq))
        if status != "AUTHORIZED":
            raise ce.ExecError("UNDO_NOT_AUTHORIZED", f"this item's undo state is {status}; another caller took the authorization")
        intent_hash = audit.append(index, account, ex["plan_id"], "UNDO_INTENT", cp._iso(now),
                                   {"exec": exec_id, "item": seq, "auth": auth["hash"], "t": ce._us(now)})
    intent_t = ce._us(now)

    _gate(mailbox, allow)  # the wiring and (live) the switch are re-checked immediately before the one mutation
    if not _wired(mailbox, allow):
        raise ce.ExecError("MAILBOX_NOT_ALLOWED", "the mailbox is no longer wired as accepted; no request was made")
    try:
        mailbox.restore_inbox(mid)  # the one and only mutation of this authorization; never retried
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "dispatched", None) is False:  # provably refused before any transmission
            _record(index, account, ex, seq, intent_hash, "NOT_RESTORED", "REJECTED", "DIRECT", mailbox)
            return UndoResult("NOT_RESTORED", "REJECTED", 0)
        return _unknown(index, account, ex, seq, intent_hash, mailbox, exc)
    try:
        context = _context(ex, mid, "UNDO_POSTREAD", intent_hash)
        obs = mailbox.observe(mid, context=context)
        labels, seen = _validated(obs, item, intent_t, context, account, mailbox)
    except Exception as exc:  # noqa: BLE001 - no usable independent observation
        return _unknown(index, account, ex, seq, intent_hash, mailbox, exc)
    if labels == prev:
        ce._consume_trusted(obs)
        _record(index, account, ex, seq, intent_hash, "RESTORED", "", "DIRECT", mailbox, obs, seen)
        return UndoResult("RESTORED", "", 1)
    return _unknown(index, account, ex, seq, intent_hash, mailbox, None)


def _unknown(index, account, ex, seq, intent_hash, mailbox, exc):
    code = getattr(exc, "code", None)
    code = code if code in ce.OUTCOME_CODES["UNKNOWN"] else "AMBIGUOUS_RESULT"
    _record(index, account, ex, seq, intent_hash, "UNKNOWN", code, "DIRECT", mailbox)
    return UndoResult("UNKNOWN", code, 1)


# ---------------------------------------------------------------- resolving an uncertain undo from a fresh observation (never from a mutation)
def reconcile_undo(index, account, exec_id, seq, mailbox):
    """Reconcile an undo against the FAKE mailbox (the only type this public function accepts). See `_reconcile_undo`."""
    return _reconcile_undo(index, account, exec_id, seq, mailbox, "FAKE")


def _reconcile_undo(index, account, exec_id, seq, mailbox, allow):
    """Resolve an undo whose intent has no result (interrupted) or whose result is UNKNOWN, from a fresh execution-bound trusted observation. Makes NO mutation.

    Exactly the originally recorded labels -> RESTORED; exactly the archived labels -> NOT_RESTORED (observed unmodified; this does not prove that no write occurred);
    anything else, including an absent message -> CONFLICT."""
    _gate(mailbox, allow)
    if mailbox.account.strip().lower() != account.strip().lower():
        raise ce.ExecError("ACCOUNT_MISMATCH", "the mailbox belongs to another account; nothing was changed")
    ex, item, plan = _original(index, account, exec_id, seq)
    status, _, intent, result = _state(_ledger(index, account, exec_id, seq))
    if status not in ("OPEN", "UNKNOWN"):
        raise ce.ExecError("NOTHING_TO_RECONCILE", f"this item's undo state is {status}; there is nothing to reconcile")
    floor = max(intent["meta"]["t"], result["meta"]["t"] if result else "")
    prev = sorted(json.loads(item["prev_label_ids"]))
    archived = [x for x in prev if x != "INBOX"]
    mid = item["message_id"]
    try:
        mailbox.verify_account()
        context = _context(ex, mid, "UNDO_RECONCILE", intent["hash"])
        obs = mailbox.observe(mid, context=context)
        labels, seen = _validated(obs, item, floor, context, account, mailbox)
    except Exception as exc:  # noqa: BLE001 - no evidence: it stays open
        raise ce.ExecError("NO_EVIDENCE", "no usable fresh observation; the undo stays unresolved") from exc
    ce._consume_trusted(obs)
    outcome = "RESTORED" if labels == prev else "NOT_RESTORED" if labels == archived else "CONFLICT"
    _record(index, account, ex, seq, intent["hash"], outcome, "", "RECONCILE", mailbox, obs, seen)
    return UndoResult(outcome, "", 0)
