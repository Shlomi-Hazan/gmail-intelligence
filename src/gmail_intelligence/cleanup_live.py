"""Live-execution entry points for approved cleanup executions (M4 live-integration preparation): DISABLED, not reachable from the CLI, never exercised against Gmail.

These are the ONLY functions that accept a `LiveMailbox`; they add nothing to the execution logic. They hand the mailbox to exactly the same per-item flow as the fake-only
batch executor (approval and plan integrity, lease, account verification, local revalidation, live message and whole-thread checks, durable intent before each POST, at most
one archive POST per item, independent execution-bound trusted post-read, UNKNOWN and stop on any ambiguity, no retry, one slice per call) and to the same recovery (fresh
observations only; it never mutates). Every call first requires `exec_live_mailbox.LIVE_EXECUTION_ENABLED`, which is False in this build, so every function raises
`ExecError("LIVE_DISABLED")` before reading or writing anything.

Archive undo (M12C.3) has its OWN entry point, `undo_live`: it accepts only a `LiveUndoMailbox` (an undo-only transport; the archive `LiveMailbox` is refused) and requires
`exec_live_mailbox.LIVE_UNDO_ENABLED`, which is False in this build and independent of `LIVE_EXECUTION_ENABLED`: it raises `ExecError("LIVE_UNDO_DISABLED")` before reading or writing anything.
It hands the mailbox to exactly the same engine as the fake-mailbox undo (`cleanup_undo`). Live RECOVERY and RECONCILIATION (M12C.4) are READ-ONLY and go only through `recover_observed` and
`reconcile_undo_observed` with an observe-only `LiveObserveMailbox` (`LIVE_OBSERVE_ENABLED`, also False); the older entry points that did the same through mutation-capable mailboxes were removed (M12D).
"""
from gmail_intelligence import cleanup_executor as cx, cleanup_recovery as cr, cleanup_reversal as rv, cleanup_undo as cu, exec_live_mailbox as live


def execute_live_batch(index, account, exec_id, token, mailbox, *, _permit=None):
    """Run the single approved canary item of an execution against a live mailbox. See the module docstring; returns a `cleanup_executor.BatchResult`.

    Not a general batch: it refuses any execution that is not exactly one target in one slice with the owner's recorded canary confirmation, and it refuses every caller
    except `cleanup_canary.run_canary`, which alone holds the permit."""
    return cx._execute_batch(index, account, exec_id, token, mailbox, "LIVE", canary_ok=_permit is live._CANARY_PERMIT)


def undo_live(index, account, exec_id, seq, mailbox):
    """Run ONE owner-authorized archive undo through a live undo mailbox: at most one mutation, durable intent first, independent bound post-read, UNKNOWN on any ambiguity, never
    retried. Needs a prior `cleanup_undo.authorize_undo` for this item. Returns a `cleanup_undo.UndoResult`. Disabled in this build."""
    return cu._undo_item(index, account, exec_id, seq, mailbox, "LIVE")


def execute_live_slice(index, account, exec_id, token, mailbox, *, _permit=None):
    """Run the ACTIVE slice of an approved, reserved BULK execution against a live mailbox (M12D): the very same per-item flow as every other execution (approval and plan integrity, lease,
    account verification, local revalidation of EACH item, live message and thread checks, durable intent, at most one archive request per item, independent execution-bound trusted
    post-read, UNKNOWN and stop on any ambiguity, no retry), one bounded slice per call. Needs the owner's per-slice run confirmation, which only `cleanup_bulk.run_bulk_slice` records and
    passes the permit for. Disabled in this build (`LIVE_EXECUTION_ENABLED`)."""
    return cx._execute_batch(index, account, exec_id, token, mailbox, "LIVE", bulk_ok=_permit is live._BULK_PERMIT)


def recover_observed(index, account, mailbox):
    """Recover interrupted work and reconcile UNKNOWN archive items AND open/uncertain undos from fresh execution-bound observations through a READ-ONLY observe mailbox (M12C.4). It can
    only read Gmail and append local audit/journal results: it never mutates Gmail, retries, resumes or continues. Needs `LIVE_OBSERVE_ENABLED` (False in this build; independent of the
    archive and undo switches). Returns a `cleanup_recovery.RecoveryReport`."""
    return cr._recover(index, account, mailbox, "OBSERVE")


def reconcile_undo_observed(index, account, exec_id, seq, mailbox):
    """Resolve ONE open or UNKNOWN undo from a fresh execution-bound observation through a READ-ONLY observe mailbox. Never mutates. Disabled in this build."""
    return cu._reconcile_undo(index, account, exec_id, seq, mailbox, "OBSERVE")


def reverse_slice_live(index, account, rev, phrase, mailbox):
    """Run the next slice of an APPROVED bulk reversal plan through a live undo mailbox (M12D): the unchanged per-item undo engine, one bounded slice per call, a fresh typed slice
    confirmation each time, never resumed or retried. Needs `LIVE_UNDO_ENABLED` (False in this build); an observe-only or archive mailbox is refused."""
    return rv._run_slice(index, account, rev, phrase, mailbox, "LIVE")

