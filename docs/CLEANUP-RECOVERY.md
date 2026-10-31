# Execution recovery status (M12C.1)

`gmail-intelligence cleanup exec recovery [--json]` is the smallest useful owner-operated recovery capability: a **local, read-only** report of cleanup executions that are open or uncertain (issue #61, coordinating with #41, which stays the tracker for the M4 follow-ups). It is the local half of recovery; the live half is deliberately not built here.

## What already existed (M4D) and what this reuses
The M4D recovery engine (`cleanup_recovery`) composes the execution journal's own functions: interrupted executions become UNKNOWN work, and each UNKNOWN item is reconciled only from a **fresh observation bound to that item's episode**, otherwise it stays UNKNOWN. That engine needs a mailbox object to observe, works only with the in-memory fake mailbox, and is deliberately unreachable from the CLI (a guard test asserts it). It is unchanged.
M12C.1 reuses its report helpers (`ExecutionReport`, outcome counts, which executions are relevant). They were **moved unchanged** into `cleanup_exec_report.py` (the engine imports them from there) so the CLI can show them without importing the recovery or undo engine. There is one implementation, not two.

## What the command shows
Counts, states and item sequence numbers. It hides message ids, the account address, labels, senders and other sensitive metadata; it **may include local execution ids** (the `exec-...` identifiers you also see in `cleanup exec list`), which are not message data.
Per open or uncertain execution: its state; **known** outcomes (recorded as applied; known not applied: not applied, never attempted, skipped); **UNKNOWN** outcomes (an attempt may or may not have changed the mailbox); **manual review** (a conflicting observation); pending items; the sequence numbers of items that need you; notes. An `EXECUTING` execution whose lease has expired is reported as interrupted (it is not recovered here). A `PREPARED` execution (not started) or one `AWAITING_CONTINUATION` (later slices need their own confirmation, or an abort) is listed as **open and not settled** and counts as needing an owner decision even when nothing is UNKNOWN.

```
execution exec-e31b39b2: RECONCILIATION_REQUIRED
  known: 1 recorded as applied, 2 known not applied (...)
  UNKNOWN: 1 (an attempt may or may not have changed the mailbox)   manual review: 0   pending: 0
  items needing the owner: 2
OWNER ACTION REQUIRED
```
(synthetic fixture output)

## What it can and cannot determine
It reports what the local journal recorded. It **cannot** resolve an UNKNOWN outcome: that needs a fresh, execution-bound read of the real mailbox compared with the record, and no such live observation exists in this version. Ambiguity therefore stays UNKNOWN, and the report says so. It does not know about changes made by other clients. Since M12C.3 the view also lists every archive-undo ledger (restored, not restored, unresolved, conflict, inconsistent, authorized-but-not-run) from the read-only ledger module, by execution id and item sequence number only; it still contacts no one and changes nothing.

## Read-only guarantees
Opened through the read-only index handle (a hidden write would fail); no mailbox object is accepted; no Gmail, OAuth or Keychain; no write, retry, resume or continuation; no audit or journal row is added or changed. `LIVE_EXECUTION_ENABLED` stays False and the M4 write-policy boundary is untouched.

## Why nothing is ever retried automatically
A failed or interrupted mutation may already have happened. Repeating it blindly could act twice or act on a message that changed meanwhile. M4 therefore records the outcome as UNKNOWN and lets only a fresh observation (never a guess, never a retry) settle it; any new attempt is a new plan with its own approval.

## Relation to M12D and what needs separate authorization
Before any bulk execution (M12D) is allowed to run live, the following are still needed, each as its own approved increment: the live, read-only observation step for reconciliation (this is the part that needs Gmail reads); real Gmail undo; the consolidated security review; write-token usability. M12D must also revalidate metadata and protections for every message immediately before acting, and must never expand or silently invalidate an approved selection. None of this is authorized or implemented by M12C.1.

## Live reconciliation (M12C.4): implemented, DISABLED, synthetic only
`cleanup exec recovery --reconcile` and `cleanup undo reconcile EXEC SEQ` would let the owner settle interrupted/UNKNOWN archive items and open or uncertain undos from FRESH, execution-bound, READ-ONLY Gmail observations, reusing the M4D recovery and undo reconciliation engines unchanged (`recover_observed` / `reconcile_undo_observed`). They are behind their own code-level switch, `LIVE_OBSERVE_ENABLED = False`, independent of the archive and undo switches, and refuse right after argument parsing (exit 2, fixed message) before the index, a credential store or the network is touched. When enabled, each run needs a typed owner phrase; nothing runs automatically, retries or resumes. The observation mailbox (`LiveObserveMailbox`) has an OBSERVE-only transport: it can verify the account and read fixed label projections (no content) and cannot archive or undo. Reconciliation may append LOCAL audit/journal results and never changes Gmail; ambiguity stays UNKNOWN, a conflicting or absent message is a CONFLICT for manual owner review, and wrong-account, stale or cross-phase observations are refused. The local status above remains available with no Gmail connection. Real Gmail behavior is **unverified**; see [M12C-SECURITY-AUDIT.md](M12C-SECURITY-AUDIT.md).

## Cost
Zero Additional Cost: standard library only; no schema, scope or dependency change.
