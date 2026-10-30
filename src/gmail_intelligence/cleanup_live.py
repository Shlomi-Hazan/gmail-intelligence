"""Live-execution entry points for approved cleanup executions (M4 live-integration preparation): DISABLED, not reachable from the CLI, never exercised against Gmail.

These are the ONLY functions that accept a `LiveMailbox`; they add nothing to the execution logic. They hand the mailbox to exactly the same per-item flow as the fake-only
batch executor (approval and plan integrity, lease, account verification, local revalidation, live message and whole-thread checks, durable intent before each POST, at most
one archive POST per item, independent execution-bound trusted post-read, UNKNOWN and stop on any ambiguity, no retry, one slice per call) and to the same recovery (fresh
observations only; it never mutates). Every call first requires `exec_live_mailbox.LIVE_EXECUTION_ENABLED`, which is False in this build, so every function raises
`ExecError("LIVE_DISABLED")` before reading or writing anything.

Archive undo (M12C.3) has its OWN pair of entry points below, `undo_live` and `reconcile_undo_live`. They accept only a `LiveUndoMailbox` (an undo-only transport; the archive `LiveMailbox`
is refused) and require `exec_live_mailbox.LIVE_UNDO_ENABLED`, which is False in this build and independent of `LIVE_EXECUTION_ENABLED`: they raise
`ExecError("LIVE_UNDO_DISABLED")` before reading or writing anything. They hand the mailbox to exactly the same engine as the fake-mailbox undo (`cleanup_undo`).
"""
from gmail_intelligence import cleanup_executor as cx, cleanup_recovery as cr, cleanup_undo as cu, exec_live_mailbox as live


def execute_live_batch(index, account, exec_id, token, mailbox, *, _permit=None):
    """Run the single approved canary item of an execution against a live mailbox. See the module docstring; returns a `cleanup_executor.BatchResult`.

    Not a general batch: it refuses any execution that is not exactly one target in one slice with the owner's recorded canary confirmation, and it refuses every caller
    except `cleanup_canary.run_canary`, which alone holds the permit."""
    return cx._execute_batch(index, account, exec_id, token, mailbox, "LIVE", canary_ok=_permit is live._CANARY_PERMIT)


def recover_live(index, account, mailbox):
    """Recover interrupted work and reconcile UNKNOWN items from fresh observations through a live mailbox. Never mutates. Returns a `cleanup_recovery.RecoveryReport`."""
    return cr._recover(index, account, mailbox, "LIVE")


def undo_live(index, account, exec_id, seq, mailbox):
    """Run ONE owner-authorized archive undo through a live undo mailbox: at most one mutation, durable intent first, independent bound post-read, UNKNOWN on any ambiguity, never
    retried. Needs a prior `cleanup_undo.authorize_undo` for this item. Returns a `cleanup_undo.UndoResult`. Disabled in this build."""
    return cu._undo_item(index, account, exec_id, seq, mailbox, "LIVE")


def reconcile_undo_live(index, account, exec_id, seq, mailbox):
    """Resolve an open or UNKNOWN undo from a fresh execution-bound observation through a live undo mailbox. READ-ONLY: it never mutates. Disabled in this build."""
    return cu._reconcile_undo(index, account, exec_id, seq, mailbox, "LIVE")
