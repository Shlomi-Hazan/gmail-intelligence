"""Live-execution entry points for approved cleanup executions (M4 live-integration preparation): DISABLED, not reachable from the CLI, never exercised against Gmail.

These are the ONLY functions that accept a `LiveMailbox`; they add nothing to the execution logic. They hand the mailbox to exactly the same per-item flow as the fake-only
batch executor (approval and plan integrity, lease, account verification, local revalidation, live message and whole-thread checks, durable intent before each POST, at most
one archive POST per item, independent execution-bound trusted post-read, UNKNOWN and stop on any ambiguity, no retry, one slice per call) and to the same recovery (fresh
observations only; it never mutates). Every call first requires `exec_live_mailbox.LIVE_EXECUTION_ENABLED`, which is False in this build, so every function raises
`ExecError("LIVE_DISABLED")` before reading or writing anything.

Undo is NOT available for a live mailbox (deferred): `cleanup_undo` accepts only the fake mailbox and `LiveMailbox` has no undo operation.
"""
from gmail_intelligence import cleanup_executor as cx, cleanup_recovery as cr


def execute_live_batch(index, account, exec_id, token, mailbox):
    """Run the ACTIVE slice of a started multi-item execution against a live mailbox. See the module docstring; returns a `cleanup_executor.BatchResult`."""
    return cx._execute_batch(index, account, exec_id, token, mailbox, "LIVE")


def recover_live(index, account, mailbox):
    """Recover interrupted work and reconcile UNKNOWN items from fresh observations through a live mailbox. Never mutates. Returns a `cleanup_recovery.RecoveryReport`."""
    return cr._recover(index, account, mailbox, "LIVE")
