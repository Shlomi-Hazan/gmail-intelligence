# M4 closeout: Safe Cleanup (reduced scope)

**Status: the owner-approved reduced M4 scope is complete.** One real, single-message, archive-only Gmail canary was executed once under the owner's explicit approval and
succeeded. Live execution is disabled again (`LIVE_EXECUTION_ENABLED = False`, a source constant nothing changes), the write grant was revoked and the local write token removed.
**Real Gmail undo is NOT implemented; it is explicitly deferred.** Any further live use needs a new, separate owner approval.

This document records scope and evidence only. It adds no capability and changes no guarantee.

## 1. What was delivered (and how it differs from the original issue text)
The original GitHub issues (#5, #6) described a broader executor. During implementation the owner approved a smaller, safer scope. The differences are deliberate:

| Original deliverable | Delivered |
|---|---|
| Write adapter: get, `batchModify`, trash, untrash | Archive only: one `messages.modify` that removes `INBOX` from ONE message, plus minimal profile/message/thread reads. No Trash, no `batchModify`, no label creation, no send. |
| Batches of up to 100; canary of 25 plus continuation approval | The slice/continuation state machine and a fake-only batch executor exist and are tested, but **live** execution is restricted to exactly one target in one slice. |
| Intent log, retries, rate limiting, circuit breaker | Durable intent before every request; **no automatic retry by design** (any ambiguity is `UNKNOWN`, stops, and is reconciled from a fresh observation); a per-adapter request budget and stop-on-ambiguity instead of a circuit breaker. |
| Undo as an approval-gated plan (archive: re-add INBOX; Trash: untrash) | A separately authorized, fake-only undo of one archived item (library, never real Gmail). **Real undo: deferred.** |
| Reconciliation of unknown/interrupted executions by reading actual state | Implemented (`recover` / `reconcile`, fresh execution-bound trusted observations, never a mutation). Library-level; no owner command yet. |
| Failure-injection integration tests | Implemented against a fake Gmail (429, 5xx, timeouts, malformed answers, crashes at every transition, concurrency). |
| Final security audit | Every component was independently audited before merge and the findings fixed (see the PR history and `DECISIONS.md`); no open P0/P1 finding is known. A separate, consolidated final audit document does not exist. |

## 2. Acceptance criteria
**Issue #5 (M4C):** (1) the write scope is requested only by the explicit login command (static and runtime tests): met. (2) executor behaviour tested against fake Gmail clients
(partial failures, 429/5xx, timeouts, interruptions): met. (3) no claim of absolute protection against concurrent Gmail changes (preflight and request are not atomic; a change in
between is caught only by the exact post-read): met. (4) the first live verification (archive only) needed a new explicit owner approval: met; it was given and used once.

**Issue #6 (M4D):** (1) interrupted executions recover without widening scope: met (read-only reconciliation, no resume, no retry). (2) undo semantics and limits documented: met
for the fake-only undo; real undo is documented as deferred. (3) final audit with no open P0/P1 findings: met in substance (per-component independent audits), not as one consolidated audit.
**Deliverable not met:** real Gmail undo.

## 3. Evidence of the live canary (owner-reported, redacted)
Reported by the owner at closeout; this change had no access to the mailbox, credentials or the local database and did not re-verify any of it. No message identifier, account
address, OAuth detail or local path is recorded here.

| Item | Reported |
|---|---|
| Plan / execution | `plan-06436536` / `exec-368a660c` (local random identifiers) |
| Target | exactly one message, one slice (a plan carrying the narrow canary exception, see `CANARY.md`) |
| Result | item APPLIED, execution EXECUTED; exactly one archive request |
| Independent check | the owner verified the archived message manually in Gmail |
| Audit chain | 18 events, internally consistent; the previous checkpoint was found; latest checkpoint prefix `581d52ca73ada231` |
| After the run | `LIVE_EXECUTION_ENABLED` restored to `False`; working tree clean |
| Credentials | Google write grant revoked (HTTP 200); local write token removed; the read-only authorization was not touched |

## 4. Guarantees versus best effort
- **Guaranteed by construction and tests (in-process):** archive-only request policy; durable intent before the request; at most one request per item; no automatic retry; an
  independent, execution-bound trusted post-read; anything ambiguous is `UNKNOWN`; live execution disabled by a source constant and reachable only through the owner entry point with
  a separate typed confirmation, one target and one slice.
- **Best effort / limits:** the guards are in-process barriers against mistakes and ordinary callers, not against deliberate monkey-patching in the same process; the audit chain is
  tamper-evident, not tamper-proof; a change by another Gmail client between preflight and request is not prevented; the offline fake is not Gmail (the canary was the first real exercise).

## 5. Deferred (nothing below exists or is approved)
Real Gmail undo (needs its own write-policy change, approval and audit); Trash/untrash and any other mutation class; live execution of more than one message, live slices and continuation;
a retry or circuit-breaker policy (retries were deliberately excluded); an owner command for read-only live recovery and for refreshing the write token; enabling `cleanup execute`;
a consolidated final security audit. M5 to M11 are unaffected.

## 6. Operating rule from now on
`LIVE_EXECUTION_ENABLED` stays `False` in the repository. Any new live use needs a new written owner approval, a fresh backup, a fresh write authorization and the procedure in
`CANARY.md`, and ends with the switch back to `False`.
