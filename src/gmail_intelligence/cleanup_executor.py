"""Single-item cleanup executor (M4C-C2): library only, FAKE MAILBOX ONLY. Not reachable from the CLI; nothing here can touch a real mailbox.

One call processes ONE approved archive item of an already reserved and started execution (exactly one target, one slice):

  verify -> revalidate -> read (message + whole thread) -> durable INTENT -> recheck lease -> at most ONE archive POST -> independent
  trusted post-read -> APPLIED only for the exact expected state, otherwise UNKNOWN -> finish or stop through the state machine.

Safety boundaries, enforced rather than promised:
  * The mailbox must be exactly `exec_fake_mailbox.FakeMailbox` (a final type that accepts no credentials, factory or transport). A real
    `ArchiveAdapter`, a mock or any other object is refused before anything is read or written. A future real port needs its own reviewed change.
  * The executor owns its time: every library call uses `mailbox.clock()` read fresh. `execute_one` has no clock or `now` parameter.
  * A trusted observation must carry the context the state machine derives for THIS execution, plan, approval, message, phase and lease.
  * The intent is committed before the POST; the POST is attempted at most once and never retried; anything not provably undispatched is UNKNOWN.
  * An unexpected exception around the mailbox is never a clean "not applied". Persistence failures after the POST leave the item open (INTENT),
    which lease expiry turns into UNKNOWN (`recover_interrupted`) for reconciliation.
"""
from dataclasses import dataclass
from datetime import timezone

from gmail_intelligence import cleanup_exec as ce, cleanup_plans as cp, cleanup_protect
from gmail_intelligence.cleanup_audit import canonical, sha256
from gmail_intelligence.exec_fake_mailbox import FakeMailbox

TRUSTED = ce.TRUSTED_EVIDENCE_SOURCE
_STOP_BY_CODE = {"ACCOUNT_MISMATCH": "ACCOUNT_MISMATCH", "AUTH_PROBLEM": "AUTH_PROBLEM", "RATE_LIMITED": "RATE_LIMITED"}
_THREAD_REASONS = ("REASON_MIXED_THREAD", "REASON_MISSING_THREAD_ID")


@dataclass(frozen=True)
class ItemResult:
    item_state: str
    code: str
    execution_state: str
    posts: int  # archive requests made by this call: 0 or 1, never more


def _now(mailbox):
    return mailbox.clock().astimezone(timezone.utc)


def _stop_reason(exc):
    return _STOP_BY_CODE.get(getattr(exc, "code", None), "AMBIGUOUS_RESULT")


def _finish(index, account, exec_id, message_id, posts):
    ex = ce.get_execution(index, account, exec_id)
    it = ce._item(index, account, exec_id, message_id)
    return ItemResult(it["state"], it["error_code"] or "", ex["state"], posts)


def _stop(index, account, exec_id, token, message_id, mailbox, reason, posts=0):
    ce.stop_execution(index, account, exec_id, token, reason, now=_now(mailbox))
    return _finish(index, account, exec_id, message_id, posts)


def _skip_and_end(index, account, exec_id, token, message_id, mailbox, kind, reason):
    ce.record_skip(index, account, exec_id, token, message_id, kind, reason, now=_now(mailbox))
    ce.end_slice(index, account, exec_id, 1, token, now=_now(mailbox))
    return _finish(index, account, exec_id, message_id, 0)


def _preconditions(index, account, exec_id, token, message_id, mailbox):
    """Everything checkable locally. Raises ExecError and changes nothing (the lease renewal only extends a lease this process already holds)."""
    ex = ce.get_execution(index, account, exec_id)
    if ex["state"] != "EXECUTING":
        raise ce.ExecError("BAD_STATE", f"execution is {ex['state']}; the executor needs an EXECUTING execution")
    if ex["action"] != "ARCHIVE" or ex["item_count"] != 1 or ex["slice_count"] != 1:
        raise ce.ExecError("NOT_SUPPORTED", "this executor handles exactly one ARCHIVE item in one slice; nothing was changed")
    if ce.invariant_problems(index, account, exec_id):
        raise ce.ExecError("INVARIANT_BROKEN", "the execution's slice/lease state is inconsistent; refusing to continue (nothing was changed)")
    it = ce._item(index, account, exec_id, message_id)
    if it["state"] != "PENDING":
        raise ce.ExecError("BAD_ITEM_STATE", "the item is not PENDING")
    plan = cp.get_plan(index, account, ex["plan_id"])
    if cp.integrity_problems(plan) or plan["plan_hash"] != ex["plan_hash"]:
        raise ce.ExecError("PLAN_CHANGED", "the plan no longer matches the execution; nothing was changed")
    approvals = index._q("SELECT status, nonce FROM cleanup_approval WHERE account=? AND plan_id=?", account, ex["plan_id"])
    if len(approvals) != 1 or approvals[0]["status"] != "CONSUMED" or approvals[0]["nonce"] != ex["approval_nonce"]:
        raise ce.ExecError("APPROVAL_NOT_CONSUMED", "the execution's approval is missing or not the one consumed at reservation; nothing was changed")
    ce.renew_lease(index, account, exec_id, token, now=_now(mailbox))  # a live lease is required before anything is read from the mailbox
    return plan


def _labels_digest(labels):
    return sha256(canonical(sorted(labels)))


def _protected_label(index, account, labels):
    """True if any active protection rule that names a label matches one of these live label ids (or their known names). Conservative."""
    names = {r["id"]: (r["name"] or "").lower() for r in index._q("SELECT id, name FROM labels WHERE account=?", account)}
    have = set(labels) | {names[x] for x in labels if names.get(x)}
    for rule in cleanup_protect.active(index, account):
        if rule.label is not None and (rule.label in have or rule.label.upper() in have or rule.label.lower() in have):
            return True
    return False


def _thread_problem(index, account, message_id, thread_id, thread):
    """A reason code (THREAD_CHANGED / LABELS_CHANGED) when the live thread differs from the indexed one in any way, else None."""
    live = dict(thread)
    local = {r["id"] for r in index._q("SELECT id FROM messages WHERE account=? AND thread_id=?", account, thread_id)}
    if message_id not in live or set(live) != local:
        return "THREAD_CHANGED"  # a missing, unknown or extra message: membership drifted
    indexed = {}
    for r in index._q("SELECT message_id, label_id FROM message_labels WHERE account=? AND message_id IN (%s)" % ",".join("?" * len(local)), account, *sorted(local)):
        indexed.setdefault(r["message_id"], set()).add(r["label_id"])
    for mid, labels in live.items():
        if mid == message_id:
            continue
        if set(labels) != indexed.get(mid, set()) or _protected_label(index, account, labels):
            return "THREAD_CHANGED"  # a sibling changed since the scan, or carries a protected label
    return None


def execute_one(index, account, exec_id, token, message_id, mailbox):
    """Run the single-item flow described in the module docstring. Returns an ItemResult; raises ExecError for refusals that change nothing."""
    if type(mailbox) is not FakeMailbox:
        raise ce.ExecError("MAILBOX_NOT_ALLOWED", "only the fake test mailbox is accepted in this version; nothing was read or changed")
    plan = _preconditions(index, account, exec_id, token, message_id, mailbox)

    # ---- account identity (a live profile read through the mailbox)
    try:
        if mailbox.account.strip().lower() != account.strip().lower():
            return _stop(index, account, exec_id, token, message_id, mailbox, "ACCOUNT_MISMATCH")
        mailbox.verify_account()
    except Exception as exc:  # noqa: BLE001 - an unverifiable account is never a reason to continue
        return _stop(index, account, exec_id, token, message_id, mailbox, _stop_reason(exc))

    # ---- local revalidation (plan freshness, protections, mixed threads): drift is skipped, never attempted
    problems = cp.revalidate(index, account, plan, _now(mailbox), only_ids=[message_id])
    if problems:
        reason = "THREAD_CHANGED" if any(p in _THREAD_REASONS for p in problems) else "STATE_CHANGED"
        return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_DRIFT", reason)

    # ---- live reads: the message, then its whole thread. A read failure here (no intent yet) stops safely; no POST is possible.
    item = next(i for i in cp.snapshot_of(plan)["items"] if i["id"] == message_id)
    try:
        state = mailbox.message_state(message_id)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) == "NOT_FOUND" and getattr(exc, "absent_confirmed", False) is True:
            return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_GONE", "NOT_FOUND")
        return _stop(index, account, exec_id, token, message_id, mailbox, _stop_reason(exc))
    labels = tuple(state.label_ids)
    if state.thread_id != item["thread_id"]:
        return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_DRIFT", "THREAD_CHANGED")
    if "INBOX" not in labels:
        return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_DRIFT", "NOT_IN_INBOX")
    if _labels_digest(labels) != item["labels_sha256"]:  # exact label-state equality with the plan (any difference, even UNREAD, is drift)
        return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_DRIFT", "LABELS_CHANGED")
    try:
        thread = mailbox.thread_state(state.thread_id)
    except Exception as exc:  # noqa: BLE001
        return _stop(index, account, exec_id, token, message_id, mailbox, _stop_reason(exc))
    why = _thread_problem(index, account, message_id, state.thread_id, thread)
    if why:
        return _skip_and_end(index, account, exec_id, token, message_id, mailbox, "SKIPPED_DRIFT", why)

    # ---- durable intent (with the previous labels) BEFORE any POST; a failure here propagates and nothing was sent
    ce.record_intent(index, account, exec_id, token, message_id, labels, now=_now(mailbox))
    ce.renew_lease(index, account, exec_id, token, now=_now(mailbox))  # LEASE_LOST propagates: no POST, the open intent is recovered as UNKNOWN later

    # ---- the single archive attempt: marked BEFORE the call, never retried
    try:
        mailbox.archive_message(message_id)
    except Exception as exc:  # noqa: BLE001 - only a provable pre-dispatch refusal is a clean "not applied"
        if getattr(exc, "dispatched", None) is False:
            ce.record_outcome(index, account, exec_id, token, message_id, "NOT_APPLIED", code="REJECTED", now=_now(mailbox))
            return _stop(index, account, exec_id, token, message_id, mailbox, _stop_reason(exc), posts=0)
        return _unknown(index, account, exec_id, token, message_id, mailbox, exc)

    # ---- independent trusted post-read, bound to this execution, message, phase and lease
    try:
        context = ce.postread_context(index, account, exec_id, token, message_id)
        obs = mailbox.observe(message_id, context=context)
    except ce.ExecError:
        raise
    except Exception as exc:  # noqa: BLE001
        return _unknown(index, account, exec_id, token, message_id, mailbox, exc)
    expected = tuple(sorted(set(labels) - {"INBOX"}))
    if obs.present and tuple(sorted(obs.labels)) == expected:
        try:
            ce.record_outcome(index, account, exec_id, token, message_id, "APPLIED", evidence=obs, now=_now(mailbox), require_source=TRUSTED)
        except ce.ExecError as exc:
            if exc.code not in ("BAD_EVIDENCE", "EVIDENCE_MISMATCH"):
                raise
            return _unknown(index, account, exec_id, token, message_id, mailbox, exc)
        ce.end_slice(index, account, exec_id, 1, token, now=_now(mailbox))
        return _finish(index, account, exec_id, message_id, 1)
    return _unknown(index, account, exec_id, token, message_id, mailbox, None)  # absent, unchanged or different labels: not APPLIED


def _unknown(index, account, exec_id, token, message_id, mailbox, exc):
    """The request may have been sent (or its effect cannot be established): UNKNOWN, stop, reconcile later. Never a retry."""
    code = getattr(exc, "code", None)
    code = code if code in ce.OUTCOME_CODES["UNKNOWN"] else "AMBIGUOUS_RESULT"
    ce.record_outcome(index, account, exec_id, token, message_id, "UNKNOWN", code=code, now=_now(mailbox))
    return _stop(index, account, exec_id, token, message_id, mailbox, _stop_reason(exc), posts=1)


# Persistence errors (sqlite3.Error) are deliberately NOT caught: they propagate and leave the item open for lease-expiry recovery.
__all__ = ["execute_one", "ItemResult"]
