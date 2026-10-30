# Execution recovery status (M12C.1)

`gmail-intelligence cleanup exec recovery [--json]` is the smallest useful owner-operated recovery capability: a **local, read-only** report of cleanup executions that are open or uncertain (issue #61, coordinating with #41, which stays the tracker for the M4 follow-ups). It is the local half of recovery; the live half is deliberately not built here.

## What already existed (M4D) and what this reuses
The M4D recovery engine (`cleanup_recovery`) composes the execution journal's own functions: interrupted executions become UNKNOWN work, and each UNKNOWN item is reconciled only from a **fresh observation bound to that item's episode**, otherwise it stays UNKNOWN. That engine needs a mailbox object to observe, works only with the in-memory fake mailbox, and is deliberately unreachable from the CLI (a guard test asserts it). It is unchanged.
M12C.1 reuses its report helpers (`ExecutionReport`, outcome counts, which executions are relevant). They were **moved unchanged** into `cleanup_exec_report.py` (the engine imports them from there) so the CLI can show them without importing the recovery or undo engine. There is one implementation, not two.

## What the command shows (counts only; no ids, labels, senders, plan ids or account)
Per open or uncertain execution: its state; **known** outcomes (recorded as applied; known not applied: not applied, never attempted, skipped); **UNKNOWN** outcomes (an attempt may or may not have changed the mailbox); **manual review** (a conflicting observation); pending items; the sequence numbers of items that need you; notes. An `EXECUTING` execution whose lease has expired is reported as interrupted (it is not recovered here).

```
execution exec-e31b39b2: RECONCILIATION_REQUIRED
  known: 1 recorded as applied, 2 known not applied (...)
  UNKNOWN: 1 (an attempt may or may not have changed the mailbox)   manual review: 0   pending: 0
  items needing the owner: 2
OWNER ACTION REQUIRED
```
(synthetic fixture output)

## What it can and cannot determine
It reports what the local journal recorded. It **cannot** resolve an UNKNOWN outcome: that needs a fresh, execution-bound read of the real mailbox compared with the record, and no such live observation exists in this version. Ambiguity therefore stays UNKNOWN, and the report says so. It does not know about changes made by other clients. Undo records (which exist only for the in-memory fake mailbox) are not part of this view.

## Read-only guarantees
Opened through the read-only index handle (a hidden write would fail); no mailbox object is accepted; no Gmail, OAuth or Keychain; no write, retry, resume or continuation; no audit or journal row is added or changed. `LIVE_EXECUTION_ENABLED` stays False and the M4 write-policy boundary is untouched.

## Why nothing is ever retried automatically
A failed or interrupted mutation may already have happened. Repeating it blindly could act twice or act on a message that changed meanwhile. M4 therefore records the outcome as UNKNOWN and lets only a fresh observation (never a guess, never a retry) settle it; any new attempt is a new plan with its own approval.

## Relation to M12D and what needs separate authorization
Before any bulk execution (M12D) is allowed to run live, the following are still needed, each as its own approved increment: the live, read-only observation step for reconciliation (this is the part that needs Gmail reads); real Gmail undo; the consolidated security review; write-token usability. M12D must also revalidate metadata and protections for every message immediately before acting, and must never expand or silently invalidate an approved selection. None of this is authorized or implemented by M12C.1.

## Cost
Zero Additional Cost: standard library only; no schema, scope or dependency change.
