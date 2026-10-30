# Safe Cleanup (M4)

M4 will let the owner archive (and eventually Trash) individual messages through staged, approval-gated steps. **M4A and M4B are
implemented**: a local candidate preview with protection rules (M4A) and immutable plans, local approvals and an audit log (M4B). Nothing
in M4A or M4B can change Gmail or execute an action. Decisions: [D27-D35](DECISIONS.md). Phases: M4A candidate engine (this document), M4B immutable plans,
approvals and audit, M4C separate write authorization and executor, M4D recovery/undo and final audit.

## M4A in one paragraph
`cleanup candidates` evaluates every indexed message of one account against its M2 metadata, its **current** M3 rules-based
classification and the user's protection rules, and puts it in exactly one of three groups. The result is computed on demand
and never stored, so changing a protection rule or reclassifying changes the next output (the printed *protection
fingerprint* changes too; M4B will bind plans to it). Eligibility is a **recommendation, not an approval**.

## Outcomes
| Outcome | Meaning | Examples of reasons |
|---|---|---|
| `EXCLUDED` | Never a candidate | hard protections `STARRED`, `SENT`, `DRAFT`, `TRASH`, `SPAM`, `USER_PROTECTED`; unsafe data `MISSING_THREAD_ID`, `MISSING_DATE`, `MISSING_SENDER`, `UNREAD_FLAG_MISMATCH`, `CLASSIFICATION_MISSING`, `CLASSIFICATION_STALE`; nothing to archive `NOT_IN_INBOX`, `TOO_RECENT` |
| `REVIEW_REQUIRED` | Informational only; **not actionable** (a separate individual-review workflow would be a future decision) | `IMPORTANT_LABEL`, `ATTENTION_SIGNAL`, `RISKY_TYPE` (personal/financial/transactional/educational), `UNKNOWN_TYPE`, `TYPE_NOT_APPROVED`, `WEAK_EVIDENCE`, `UNREAD`, `USER_LABEL`, `AI_EVIDENCE`, `AMBIGUOUS_TYPES`, `MIXED_THREAD`, `INDEX_PARTIAL` |
| `ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION` | Recommendation only | read, in INBOX, at least 90 days old, current rules-based classification with MEDIUM+ evidence for `PROMOTIONAL`, `SOCIAL` or `NEWSLETTER`, none of the reasons above |

`AUTOMATED_NOTIFICATION` may accompany an approved type but never suffices alone. A message is eligible only when it has **no**
reason at all, so a protected message can never be promoted by another rule. AI-origin results (`source='ai'`) are never
evidence. There are **no Trash recommendations** in M4A; Gmail categories, Updates or `noreply`-style senders are never enough
for Trash (a future Trash path needs a user-defined HIGH-evidence rule or individual selection, at least 180 days of age and a
separate approval).

## Threads
Execution will be message-level only; a message id is never expanded to its thread. Candidate safety still looks at thread
context using the **local index**: an otherwise eligible message becomes `REVIEW_REQUIRED` (`MIXED_THREAD`) if any other indexed
message of the thread is protected, unsafe, stale/unclassified or itself needs review. Siblings that are merely recent or already
archived are harmless. **Limitation:** the index cannot prove that no newer message arrived after the last scan, and a limited
or interrupted scan cannot show all messages of a thread. Therefore unless the latest full scan is complete, every
otherwise-eligible message is downgraded to `REVIEW_REQUIRED` (`INDEX_PARTIAL`), and a missing `thread_id` excludes the message.
No Gmail lookup is used to fill gaps; M4C will re-validate each message immediately before acting and skip anything that changed,
without claiming protection against concurrent changes.

## Commands (local only; `--account` avoids the Keychain lookup)
```bash
gmail-intelligence cleanup discover [--account EMAIL] [--limit N] [--min-group-size N] [--min-age-days N] [--json]   # M12A: grouped, explained view of the same candidates (read-only; see CLEANUP-DISCOVERY.md)
gmail-intelligence cleanup preview --group DOMAIN [--exclude-id ID] [--show-ids] [--page N] [--json] [--account EMAIL]   # M12B: exact messages of the selected groups (read-only; see CLEANUP-REVIEW.md)
gmail-intelligence cleanup plan create --group DOMAIN [--exclude-id ID] --selection-digest DIGEST [--account EMAIL]      # M12B: freeze that exact selection as a DRAFT plan
gmail-intelligence cleanup candidates --account EMAIL [--limit N] [--review] [--min-age-days N] [--show-ids] [--show-senders] [--by-domain]
gmail-intelligence cleanup protect list    --account EMAIL [--show-values]
gmail-intelligence cleanup protect add     --account EMAIL [--sender ADDRESS] [--domain DOMAIN] [--label LABEL] [--note TEXT]
gmail-intelligence cleanup protect disable|enable|remove RULE_ID --account EMAIL
```
Default output is aggregate: counts, reasons, approving evidence by rule, and anonymized example rows (age bucket and reason
codes). Message ids, sender addresses, domains and rule values appear only with the explicit flags (`--show-ids`, `--show-senders`, `--by-domain`, `--show-values`); the account is always shown as `<account hidden>`, and `protect list` shows `<hidden>` for every stored value. The exclusion summary separates the *decisive* reasons from *accompanying* review signals that an excluded message also carries (they are not why it was excluded). Reason codes and evaluation are unchanged by this presentation.
`--min-age-days` may only be stricter than 90. Run `classify run --all` first so classifications are current.

**Protection rules** use the M3 vocabulary (exact sender, exact domain, label id or name; no wildcards or regex). All conditions
of one rule must match; several rules combine as OR. They are stored per account in the local database, are kept by
`mailbox purge`, and do not alter M3 classifications.

## Storage and migration (schema v3)
One new table, `protect_rules`. Opening a v2 (or v1) index backs the database up first (`index.sqlite3.pre-m4a-backup-<UTC>` or
`pre-m3-backup-...`, mode 600), then adds the missing tables in one transaction; failure leaves the old version intact. M2/M3 data
is untouched. To go back, quit the tool and copy the backup over `index.sqlite3` (an older build cannot open a newer schema).
There is no table for candidates, plans or approvals in M4A.

## M4B: immutable plans, local approvals and audit (offline)
**What an approval is.** An approval is a LOCAL LEDGER RECORD that a person typed a confirmation for an exact plan. It grants no
OAuth permission, makes no Gmail call and cannot execute anything: **execution does not exist in M4B.** Executing (M4C) needs a
write credential, live-state revalidation and a separate owner approval.

**Plan.** A finite set of explicit message ids for one account and the single action `ARCHIVE`, frozen as canonical JSON (sorted
keys, no whitespace) and bound by its full SHA-256 (`plan_hash`). The hash covers: plan id, version and parent, account, action,
creation and expiry time, the M4A policy (version, age threshold, approved types), the M3 ruleset hash, the full protection-rule
digest, the index anchor (completeness and last full scan) and, per target, thread id, date, scan id, unread flag and SHA-256
digests of the sender, the label set and the classification rows. Sender and label text is never stored in clear. Eight hex
characters of the hash are shown only for the typed confirmation. A plan holds at most 500 targets, is selected explicitly
(nothing is selected by default, no wildcards, no thread expansion) and must consist of messages that are *currently*
`ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION`; a single ineligible, unknown or protected id rejects the whole plan (nothing is trimmed
silently). Plans expire after 48 hours.

**Lifecycle (schema-enforced, forward only).** `DRAFT -> REVIEWED -> APPROVED`, and any live state `-> CANCELLED | EXPIRED |
SUPERSEDED`. Content columns, plan items, approvals and audit rows are immutable (triggers); plans are never deleted. Excluding
targets creates a NEW version with a new hash and supersedes the old plan, revoking its approval. States for execution do not exist
yet; M4C will add them with its own migration.

**Commands** (all local; `--account EMAIL` avoids the Keychain lookup):
```bash
gmail-intelligence cleanup candidates --account EMAIL --limit N --export-ids FILE   # optional: private, new file, never inside Git
gmail-intelligence cleanup plan create  --account EMAIL --message-id ID ... | --ids-file FILE [--min-age-days N]
gmail-intelligence cleanup plan list|show PLAN_ID [--page N --page-size N --show-ids]
gmail-intelligence cleanup plan review PLAN_ID      # interactive: every target, page by page, then a typed phrase -> REVIEWED
gmail-intelligence cleanup plan exclude PLAN_ID --message-id ID ...     # new version; old one superseded
gmail-intelligence cleanup approve PLAN_ID          # interactive typed phrase "ARCHIVE <count> <hash8>" -> local approval
gmail-intelligence cleanup approval status PLAN_ID
gmail-intelligence cleanup plan cancel PLAN_ID
gmail-intelligence cleanup audit verify|log [--plan PLAN_ID]
```
Review and approval read the confirmation only from a real terminal: there is no `--yes`/`--phrase` option, piped input and EOF
fail closed. A typed phrase is friction and an intent check, **not strong authentication**.

**Approval rules.** At approval time the whole plan is re-validated against the LOCAL index: stored hash and snapshot integrity,
account, expiry, policy, M3 ruleset, protection digest, index completeness/anchor, every target's digests and its current M4A
eligibility. Any difference fails closed (the plan is never partly approved or trimmed) and the failure is audited. An approval
is single-use, bound to the exact plan hash, action, count and account, has a random nonce, lasts at most 24 hours and never
outlives the plan; the database allows one VALID approval per plan. Expired approvals expire the plan (create a new one).

**Freshness limits.** Local freshness cannot see mailbox changes made after the most recent Gmail scan. Any future executor must
re-validate live Gmail state per message immediately before acting.

**M4B-to-M4C contract (not implemented).** The executor must: run `verify_approved` and refuse on any problem; consume the approval
(VALID -> CONSUMED) atomically with the start of execution, one time only; re-validate each message against live Gmail state and
skip drifted messages; never retry or continue automatically after an ambiguous outcome; never widen the target set; never act
from plan state alone.

**Overlapping plans.** Different plans may reference the same message: M4B does not enforce cross-plan uniqueness of message ids. Each
plan has its own separate approval, bound to that plan's hash, action, count and account, so an approval for one plan can never
authorize another. M4B itself never executes anything. A future executor (M4C) must therefore:
- re-validate each exact message against current Gmail state before acting;
- consume every plan's approval atomically and independently (one plan's execution neither consumes nor implies another's);
- reconcile earlier or concurrent operations that involve the same message, and never blindly repeat an action only because a
  different approved plan also lists that message;
- fail closed on uncertain or conflicting state.

**Audit log and retention.** Every plan, review, approval, rejection, revision, cancellation, expiry and lockout appends an event holding
counts, hashes and state names only (no ids, senders, labels or content), chained to the previous event of the account
(`audit verify`). What this does and does NOT give you:
- Editing or removing an event in the *middle* of the chain is detected.
- **Deleting the newest events, or the whole log, cannot be detected from the database alone.** Only a checkpoint you recorded
  elsewhere reveals it: `audit verify` prints the head hash, `approve` prints it after each approval, and
  `cleanup audit verify --checkpoint HASH_PREFIX` fails if that event is no longer in the chain. Nothing is sent anywhere; storing
  the value outside this computer is up to you.
- Anyone (or any program) controlling this macOS user account can drop the triggers and rewrite or re-chain everything. The log
  is tamper-*evident* at best, never tamper-proof and never authenticated.
Retention: plans, approvals and audit events stay local and are never deleted automatically; `mailbox purge` keeps them; nothing is
purged while a plan is active or unresolved. Deleting or exporting them would be a separate, explicitly reviewed feature.

**Trust boundary.** Direct modification of this database by the local account is OUTSIDE the trust boundary. SQLite triggers and the
cross-checks below protect against bugs and naive edits; they do not authenticate a malicious local user, who can forge a plan, an
approval row, its state change and a correctly chained audit event. Cheap consistency checks that exist: a plan cannot become
APPROVED without a VALID approval row, cannot be REVIEWED without a review time; `verify_approved` also checks the approval's times
(created after the plan, at most 24 h long, never beyond the plan), the audit chain, and that the approval is recorded in the audit
log with the same plan hash and nonce hash. **A future executor must therefore never trust the ledger alone: it must re-validate live
Gmail state per message and ask the owner again, interactively, at execution time.**

**Clock.** Expiry uses the local wall clock. Review, approval, plan creation and revision are refused if the clock is more than
5 minutes earlier than the last recorded event, and `verify_approved` flags an approval created "in the future". A wall clock alone
cannot guarantee real elapsed time against someone who deliberately rolls it back; this only catches mistakes and naive rollbacks.
The 24-hour approval lifetime is unchanged.

**Failed confirmations.** After 10 failed review/approval confirmations for one plan within 15 minutes, further attempts on that plan
(even with the correct phrase) are refused until the window passes; one `ATTEMPTS_LOCKED_OUT` event is logged and refused attempts
write nothing, so the log cannot be flooded. If an audit entry for a failure cannot be written, the error says so.

**Corrupt data.** A plan whose stored snapshot is unreadable or malformed fails closed with a generic message (no raw snapshot or
JSON error text); it can still be cancelled.

**Storage (schema v4).** `cleanup_plan`, `cleanup_item`, `cleanup_approval`, `cleanup_audit`. Opening a v3 index first writes a
private backup (`...pre-m4b-backup-<UTC>`): the file is created exclusively with mode 600 from its first byte (an existing file is
never overwritten; a name clash gets a numeric suffix), verified, and a partial backup that failed to write is removed. The tables
are then added in one transaction; failure leaves v3 intact and keeps the verified backup.

## M4C-A: local execution state (offline foundation; NO Gmail execution)
M4C-A adds only the **local bookkeeping** that a later executor will drive. There is no Gmail client, no write OAuth credential, no
network and no way to archive anything in this version. The only production commands are read-only:
```bash
gmail-intelligence cleanup execute PLAN_ID --dry-run --account EMAIL   # what a reservation would check; writes and consumes nothing
gmail-intelligence cleanup exec list --account EMAIL
gmail-intelligence cleanup exec show EXEC_ID [--show-ids] --account EMAIL
```
`cleanup execute` without `--dry-run` is refused. Reserving, starting, confirming, aborting and reconciling exist as tested library
functions (`cleanup_exec.py`) but have **no CLI**; nothing can consume an approval or reconcile anything from the command line.

**Three separate gates (none substitutes another).** (1) the M4B plan approval (a local record), (2) a fresh typed **execution
confirmation** (`EXECUTE ARCHIVE <slice size> <hash8>`, different from the approval phrase) that is required to reserve an
execution, and (3) a future separate OAuth write authorization (M4C-B). Dry runs, listings and status never consume anything.

**Schema v5** (after an automatic private backup; failure keeps v4): `cleanup_execution`, `cleanup_exec_slice`, `cleanup_exec_item`.
The M4B plan tables stay immutable and unchanged; execution state lives in its own tables, and a plan that has an execution can no
longer be cancelled, revised or expired.

| Level | States (forward only, enforced by triggers) |
|---|---|
| Execution | `PREPARED` -> `EXECUTING` -> `AWAITING_CONTINUATION` (a later slice needs a fresh confirmation) / `PARTIAL` / `EXECUTED` / `FAILED` / `RECONCILIATION_REQUIRED`; `ABORTED` only from `PREPARED` or `AWAITING_CONTINUATION`; `AWAITING_CONTINUATION` -> `EXECUTING` for a confirmed slice |
| Slice | `PENDING` -> `CONFIRMED` -> `ACTIVE` -> `COMPLETED` (or `STOPPED`) |
| Item | `PENDING` -> `INTENT` -> `APPLIED` / `NOT_APPLIED` / `UNKNOWN`; `PENDING` -> `SKIPPED_DRIFT` / `SKIPPED_GONE` / `NOT_APPLIED`; `UNKNOWN` -> `APPLIED` / `NOT_APPLIED` / `CONFLICT` (reconciliation only) |

Terminal execution states and what they mean (all enforced by triggers, so a contradictory final state cannot be written):
`EXECUTED` = no open, unsuccessful or unknown items and at least one `APPLIED` item, every `APPLIED` item having `evidence_checked`; `PARTIAL` = some applied and some
`NOT_APPLIED`/`CONFLICT`, nothing open, nothing left to continue; `FAILED` = nothing applied (also when every target was skipped);
`ABORTED` = the owner abandoned an execution that had not finished. A terminal `PARTIAL` can never be aborted, continued or
re-labelled, and it does not occupy the account. `AWAITING_CONTINUATION` exists only while a later slice is still `PENDING`.

**Reason codes are a closed vocabulary** (validated before any state changes, also a database `CHECK`; free text, e-mail-like
strings and exception messages are never stored): `NEVER_ATTEMPTED` (execution stopped/aborted before the message was touched),
`REJECTED` (Gmail rejected the attempt; known and unmodified), `RECONCILED_UNMODIFIED` (observed equal to its state before the
attempt; this does **not** prove that no write occurred), `RECONCILED_OBSERVED_ARCHIVED` (observed in the expected archived state; **not** attributed to this executor), `RECONCILED_CONFLICT`, `INTERRUPTED` and
`AMBIGUOUS_RESULT`/`TIMEOUT`/`SERVER_ERROR`/`NETWORK_ERROR` (uncertain write), `OVERLAP_ALREADY_APPLIED`, and skip reasons
(`LABELS_CHANGED`, `STATE_CHANGED`, `THREAD_CHANGED`, `NOT_IN_INBOX`, `NOT_FOUND`). `exec show` lists the counts per state and reason
without message ids.

**Leases.** A lease token is generated inside the library (192 random bits), returned only to the caller of `start_slice`, and only its
SHA-256 is stored. Callers cannot choose a token; renewals and every item transition check the token's shape and ownership.

**Clock policy.** Every mutation (reserve, start, intent, outcome, skip, renew, end, stop, recover, abort, confirm, reconcile) is
refused if the local clock is more than 5 minutes earlier than the last recorded event. A local wall clock alone cannot guarantee real
elapsed time against someone who deliberately manipulates it.

**No unverifiable "success"; four things stay distinct.** (1) *Evidence structure accepted*: the library validated the shape of a caller-supplied
`Evidence` (kind `LABEL_OBSERVATION`, message id, labels, `observed_at`, `source`). (2) *Desired Gmail state observed*: the labels equal the previous labels
minus `INBOX` (`APPLIED`, code `APPLIED`; or on reconciliation `RECONCILED_OBSERVED_ARCHIVED`); an observation equal to the previous labels gives
`NOT_APPLIED`/`RECONCILED_UNMODIFIED` and anything else `CONFLICT`. (3) *Response from a trusted Gmail adapter*: established only by a genuine, unused, adapter-issued `TrustedObservation` (see "Trusted observations" below), which the library accepts through a
separate validation branch and stores with the source `TRUSTED_ADAPTER`. Ordinary `Evidence` supports `CALLER_SUPPLIED` only, so a caller cannot claim the trusted source. No production executor
or CLI path uses trusted observations yet. (4) *Mutation attributed to our executor*: **never established**; another client or the owner may have archived the message, so
`APPLIED` means "recorded with evidence-consistent archived state", not proof of who changed it. The column is named `evidence_checked` (not "verified") and is stored
with `evidence_source` and `evidence_observed_at`. Callers cannot assert an outcome; `reconcile_item` derives it. **Local metadata alone cannot prove that a Gmail
mutation occurred.** The state machine has no Gmail client of its own and no production path produces trusted observations yet; tests construct evidence explicitly or use a fake adapter. **Empty label sets.** A message whose previous labels were exactly `INBOX` legitimately has no labels after ARCHIVE. An explicit empty observation `()` is
accepted only for such an item (expected archived state empty; it then yields `APPLIED` / `RECONCILED_OBSERVED_ARCHIVED` like any other matching
observation). For any item whose expected state is non-empty an empty observation is rejected (`BAD_EVIDENCE`), and a non-empty observation of an
item that expects none is a mismatch / `CONFLICT`. Source, timestamp and chronology checks are unchanged. A missing evidence object, a `None`
label list or a malformed one is never read as "empty". **Contract for the future M4C-C adapter:** Gmail omits `labelIds` when a message has none; the adapter
must turn a missing field into an explicit empty tuple ONLY when the API response is otherwise valid and complete (right message id, no error,
no truncated payload). The observation still proves nothing about who made the change.

**Strict evidence chronology.** Intent, result and evidence times are stored with microsecond resolution as UTC in one fixed format
(`YYYY-MM-DDTHH:MM:SS.ffffffZ`; a database `CHECK` enforces the format, so string order is chronological order). Evidence must satisfy
`observed_at >= intent_at` with **no** tolerance (not even one microsecond earlier), and for an `UNKNOWN` item also `observed_at >=` the recorded UNKNOWN
transition; the upper bound is the existing clock policy (at most 5 minutes after "now"). Evidence timestamps need an explicit zone (`Z` or `+-HH:MM`, normalised
to UTC; naive, lower-case, free-form or out-of-range values are refused). Invalid evidence changes nothing (item, execution, approval and audit rows stay
identical). A database trigger repeats the ordering check for direct SQL.

**Evidence is immutable once accepted.** Triggers refuse any change that sets `evidence_checked` back to 0 or alters the stored source or observation time,
and `APPLIED` cannot exist without checked evidence (table `CHECK`). Direct SQL by someone who can edit the file remains outside the guarantee (see M4B limits).

**Trusted observations (M4C-C1; contract only, no executor yet).** A `TrustedObservation` (module `exec_evidence`) is the only way evidence can be recorded with the
source `TRUSTED_ADAPTER`. It can only be issued by an archive adapter that has verified the account, through the existing minimal message read (no new endpoint or
scope): either a PRESENT message with an explicit labels tuple (an omitted `labelIds` in an otherwise complete answer is the explicit empty tuple, valid only where an empty
archived state was expected) or a message definitively ABSENT (only for an unambiguous Gmail not-found document). The state machine accepts it only if it has the exact type, is
bound to this account and this message, was issued by an adapter that still holds its verification, is unused, is not older than five minutes and satisfies the same strict
chronology as other evidence. Ordinary `Evidence(source="TRUSTED_ADAPTER")` is rejected, and `ACCEPTED_EVIDENCE_SOURCES` still lists only `CALLER_SUPPLIED`.
`require_source` can only RESTRICT which kind a call accepts; it never selects the stored source. After full validation the one-time token is consumed BEFORE persistence: if the
database write then fails, the token stays consumed (in memory, for the life of its adapter; nothing claims it survives a restart) and a new observation is needed. A trusted
observation of an absent message reconciles to `CONFLICT`, never to `APPLIED`. Reports state per evidence source what an "applied" record does and does not establish.
**Ordinary evidence is the exact `Evidence` type only (C1 correction).** A subclass is refused: it could compute `source` (or any field) differently on each read. Fields of ordinary
evidence are read once into a snapshot and validated; the stored source is the constant `CALLER_SUPPLIED`, never an attribute of the evidence object.
**Audit completeness for trusted reconciliations.** The item row keeps `evidence_source` and `evidence_observed_at` for every valid trusted observation; `evidence_checked` stays 0
unless the item is `APPLIED` (schema rule, unchanged). The `ITEM_TRANSITION` audit event adds flat metadata `obs` (`ARCHIVED`, `PREVIOUS`, `OTHER_LABELS` or `ABSENT`), `src` and `seen`.
So an observed absence and an observed change of labels, which share the item code `RECONCILED_CONFLICT`, remain distinguishable in the audit history. No message ids or label names
are recorded, no schema or vocabulary changed, and caller-supplied evidence keeps exactly its historical storage. `obs` describes what was observed, not who acted.
**Clock and execution-context assumptions.** The observation time and the five-minute freshness check rest on the clock injected into the adapter. That clock is trusted
infrastructure supplied by the executor or the test harness: a wrong or malicious clock undermines the freshness assertions, and freshness is never cryptographic. Production
executor code must use a controlled UTC clock, not a caller-selected one; injected clocks are for deterministic synthetic tests and carefully controlled internal use.
An observation is bound to its issuing adapter, the verified account, one message id, its observation time and a one-time nonce. It is NOT bound to an execution id or plan id;
strict chronology (not earlier than the item's intent or UNKNOWN transition) and one-time consumption limit accidental reuse. **C2 requirement (implemented below for the fake boundary):** the executor must prevent
cross-execution observation reuse and accept only observations made inside its own active, verified execution context.

**Execution binding and the executor's clock (M4C-C2).** A `TrustedObservation` now carries a mandatory `context`: an opaque SHA-256 over the account, execution, plan, plan hash,
approval nonce, message, phase (`POSTREAD` for the read after the archive attempt, `RECONCILE` for reconciliation) and, for `POSTREAD`, the lease. The adapter's `observe(message_id,
*, context)` requires it, and `record_outcome` / `reconcile_item` recompute the expected context from the stored execution row and refuse any other (an observation made for another
execution, plan, account, message, phase or lease is `BAD_EVIDENCE` and is not consumed). The context binds identity, not secrecy: anyone who can read the database can compute it.
The executor owns its time: it reads `mailbox.clock()` fresh for every library call and has no clock or `now` parameter; `open_archive_adapter` no longer accepts a clock and the
adapter's keyword-only `_clock` is passed only by the fake-only mailbox (a static test enforces it). This restricts the supported surfaces; it does not stop code in the same process from
building an adapter by hand.

**Single-item executor (M4C-C2; library only, fake mailbox only, no CLI).** `cleanup_executor.execute_one` processes ONE approved archive item of a reserved and started
execution that has exactly one item in one slice (anything larger is refused before any change). It accepts only `exec_fake_mailbox.FakeMailbox`, a final type that takes no
credentials, connection factory or transport and answers from memory (a real `ArchiveAdapter`, a mock or any look-alike is refused before anything is read). Flow: local checks and a
live lease; account identity; local revalidation of the plan, protections and mixed threads (drift is skipped, never attempted); live read of the message and the WHOLE thread (exact
label equality with the plan, exact thread membership, siblings unchanged and without a protected label); durable `INTENT` with the previous labels; lease recheck; at most ONE archive
POST; an independent trusted post-read bound to this execution; `APPLIED` only for exactly the previous labels minus `INBOX`, otherwise `UNKNOWN` and reconciliation. A failure proven
to be before any transmission is `NOT_APPLIED`/`REJECTED`; anything that may have been sent (every HTTP error, timeout, redirect, malformed answer or unexpected exception) is `UNKNOWN`
and the execution stops (`RECONCILIATION_REQUIRED`). A read failure before the intent stops safely with no POST. Persistence errors propagate and leave an open intent that lease expiry
turns into `UNKNOWN` (`INTERRUPTED`), which a trusted observation reconciles. Nothing is retried; no new status code, audit event or schema was added.
**Fake-only boundary and its limits.** `FakeMailbox` is immutable (assigning or deleting any attribute raises), and the executor checks at the start and again right before the POST that the
mailbox still routes to its own in-memory service (exact adapter, transport, credential and connection-factory types, all pointing at its own service). That stops supported ordinary use
(attribute assignment, swapping a connection factory) from routing execution to a real adapter; code in the same process that deliberately uses reflection or monkey-patching can still
bypass any such check. The executor does not claim that the preflight and the POST are atomic against other Gmail clients: a change in between is not prevented, it is caught only by the
exact post-read and recorded as `UNKNOWN`.

**Batch execution (M4C-C2b; library only, fake mailbox only, no CLI).** `cleanup_executor.execute_batch` runs the ACTIVE slice of a started multi-item execution by repeating the
single-item flow for each PENDING item in the plan's fixed `seq` order (there is no second mutation path: `execute_one` and `execute_batch` share one per-item function). Before each
item it re-checks the plan, approval and lease (renewing the lease), the exact mailbox type and wiring, then revalidates locally and reads the live message and whole thread; it commits
the intent before that item's single POST and records the outcome from an execution-bound trusted post-read. The account is verified once, before the first item; the adapter then stays
locked against later identity or authorization problems. APPLIED and clearly skipped items (drifted, protected, gone) let the batch go on; anything else stops the execution, the
remaining targets become `NEVER_ATTEMPTED` and nothing is retried. The batch refuses to start while any item is `INTENT`, `UNKNOWN` or `CONFLICT`, handles only one slice per call, and
finishes the slice through `end_slice`: the next slice needs the owner's typed continuation and a new lease. A crash or lost lease is recovered by the existing `recover_interrupted`
(possibly dispatched items become `UNKNOWN`, untouched ones `NEVER_ATTEMPTED`); the batch never resumes anything. Results carry sequence numbers, never message ids.
**Several approved items in one thread.** A sibling that this execution already archived (recorded `APPLIED` with checked evidence) legitimately differs from the indexed labels, so it must now be in exactly its recorded archived state (its indexed labels minus `INBOX`); every other sibling must still equal its indexed labels, membership must be unchanged, and no sibling, archived or not, may carry a protected label. Any other difference is still `THREAD_CHANGED`. The current target keeps its exact preflight checks.

**Real-execution boundary (disabled; tested offline, and exercised live once for the owner-approved canary, see M4-CLOSEOUT.md).** `exec_live_mailbox.LiveMailbox` is a final, immutable port over a genuine `ArchiveAdapter` (archive-only request policy) that
exposes exactly what the executor already uses (`clock`, `account`, `verify_account`, `message_state`, `thread_state`, `archive_message`, `observe`) and nothing else: no undo, no delete, no
Trash, no send, no label creation. `cleanup_live.execute_live_batch` and `recover_live` are the only functions that accept it; they run the very same per-item flow and recovery as the
fake-only API (approval and plan integrity, lease, account verification, local revalidation, live message and whole-thread checks, durable intent before each POST, at most one POST per
item, independent execution-bound trusted post-read, UNKNOWN and stop on any ambiguity, no retry, one slice per call), with no second mutation path. Each entry point accepts only its own
mailbox type: the fake-only APIs refuse a live mailbox and the live APIs refuse a fake mailbox, a raw adapter or any look-alike. **Disabled by default:** `LIVE_EXECUTION_ENABLED` is a
`False` constant in `exec_live_mailbox.py` that nothing in the program changes; construction and every step (including right before each POST) re-read it, so every live function raises
`LIVE_DISABLED` before reading or writing anything. There is no CLI path, no clock, connection-factory or transport parameter on the public constructor, and time is the process's UTC
clock. Tests flip the switch only with a patch and put the real adapter code over the in-memory fake wire. **Live undo is deferred:** `cleanup_undo` accepts only the fake mailbox and
`LiveMailbox` has no undo operation; a real undo needs its own write-policy change and approval.

**Single-message canary entry point (disabled).** `cleanup_canary.run_canary` is the one explicitly gated way to archive ONE approved message through the live boundary: it refuses as its
very first statement while `LIVE_EXECUTION_ENABLED` is `False` (before the index, the credential store, the client file or the network are touched), then requires an `EXECUTING`
single-target single-slice `ARCHIVE` execution under the caller's lease and the owner's separate typed canary confirmation (`canary_phrase`, recorded once per execution as
`CANARY_CONFIRMED`; wrong phrases are `CANARY_REJECTED` and locked out), opens the write credentials locally, and hands the rest to `execute_live_batch` (no second archive path).
No CLI, environment-variable or configuration path exists. Details, the authorization readiness and the owner approvals still needed: [CANARY.md](CANARY.md). Live undo is deferred.

**Canary exception and live restriction (disabled).** A one-message plan can carry a narrow, hashed `canary_exception` (waiving only the age and classification-type rules for that message; `SENT`,
protections, unread, important, user labels, mixed threads, missing classification and every executor check still apply); the ordinary policy and commands are unchanged. Live execution is
only the single approved canary: `execute_live_batch` refuses every caller but `run_canary`, anything but one target in one slice, and anything without the recorded canary confirmation.
Owner entry point: `cleanup_canary_cli`: `describe` and `plan` are local preparation (no Gmail, credentials or network) and work while the switch is off; `run` is disabled with the switch. See [CANARY.md](CANARY.md) section 5.

**Historical checklist (written before the canary; the single owner-approved canary has since been executed, see [M4-CLOSEOUT.md](M4-CLOSEOUT.md), and live execution is disabled again; every item is required again before any future live operation, which needs fresh owner approval):** a separately approved write OAuth login and Google Cloud isolation checklist (M4C-B2); a separately
approved, reviewed entry point and source change enabling the switch; a rehearsal against a single message of a disposable test mailbox with the owner present; verification of the real
Gmail behaviour the fake only imitates (thread read completeness and paging for long threads, the exact not-found and error documents, label omission, quota and the 500-request
transport budget per adapter); a recovery rehearsal and an index backup; and the final M4 security audit.

**Recovery (M4D; library only, fake mailbox only, no CLI).** `cleanup_recovery.recover(index, account, mailbox)` only composes existing primitives: `recover_interrupted` turns executions
whose lease expired into UNKNOWN work (never resumed), every UNKNOWN item is reconciled with `reconcile_item` from a FRESH trusted observation bound to that item's UNKNOWN episode, and
every uncertain undo is reconciled the same way. It performs no mutation (no archive, no undo, no retry). It fails closed: another account raises before anything changes; when anything needs recovery the account is verified BEFORE any local transition, so an
unverifiable account changes nothing; an an authorization problem or a database error stops it and is reported; an item without usable evidence stays UNKNOWN. An execution with a live lease is not touched.
The report (`RecoveryReport`, `format_report`) distinguishes APPLIED, NOT_APPLIED, NEVER_ATTEMPTED, SKIPPED, CONFLICT, UNKNOWN, PENDING and INTENT per execution, says what was resolved
now and which items (by sequence number) need the owner; it never contains message ids, labels, senders, accounts or credentials. `status_report` is the read-only variant.

**Undo (M4D; library only, FAKE mailbox only).** `cleanup_undo` puts INBOX back on ONE message that an execution archived and recorded as APPLIED with a checked trusted-adapter
observation. It is not an archive and is never recorded as one: the original item row, its APPLIED history and evidence, and its audit events are never touched. The undo ledger is the
hash-chained audit log (no schema change): `UNDO_AUTHORIZED` -> `UNDO_INTENT` -> `UNDO_RESULT`, the state of one item's undo being derived from those events by a strict state machine (NONE -> AUTHORIZED -> OPEN -> a result referring to that intent; a new authorization only from NONE or NOT_RESTORED). Any other sequence is `INCONSISTENT`: it authorizes nothing and is reported to the owner. The owner authorizes each
item with a SEPARATE typed phrase (`undo_phrase`; the archive approval and phrases authorize nothing here; wrong phrases are recorded and locked out; the authorization lasts 15
minutes). `undo_item` then verifies the account, the original APPLIED evidence, plan and approval integrity, that the message is in exactly its recorded archived state and the whole
thread (same rules as the executor, protected labels included), commits the intent BEFORE any mutation (once per authorization, serialised by the write transaction), makes at most ONE fake
mutation, and reads back with an independent execution-bound trusted observation: `RESTORED` only for exactly the originally recorded labels (INBOX back, everything else preserved),
anything unclear `UNKNOWN`. An interrupted or unknown undo is resolved only by `reconcile_undo` from a fresh observation (never by repeating the mutation); a proven non-mutation
(`NOT_RESTORED`) allows a new authorization. The real Gmail write boundary stays archive-only: the fake mailbox implements the inverse in memory, with no HTTP route and no policy entry.
**What this does not establish:** the guard is an in-process capability boundary against accidents and ordinary callers, not a cryptographic guarantee against code in the same
process, and an observed desired state never proves that this tool made the change.

**Dispatch metadata (M4C-C1).** Every transport exception carries `dispatched`. It is `False` ONLY where it is raised explicitly before any transmission could begin (policy
refusal, unverified account, request budget, missing or expired credentials); otherwise it is true or unknown, and unknown is treated as possibly sent. It is never inferred
from a counter, an exception class or a received status code. A complete HTTP error answer to a POST (even a well-formed Gmail error document) is NOT proof that the mutation had no
effect, so a future executor must record such an outcome as `UNKNOWN` and reconcile; nothing is retried automatically. The vocabulary and the database are unchanged: the code
`REJECTED` is not reinterpreted, its description now states that it records the recorder's assertion and that this library cannot show whether anything was sent, and
existing records keep that uncertainty.

**ARCHIVE needs `INBOX`.** `record_intent` refuses previous labels without `INBOX` before anything is stored, and the schema repeats it (a `CHECK` on
`prev_label_ids` and the intent trigger). Other labels, including private user labels, are preserved exactly as recorded (sorted JSON array).

**`REPLACE` / `UPSERT` cannot bypass the immutability triggers.** SQLite's `INSERT OR REPLACE` deletes the old row without firing `BEFORE DELETE` unless
`recursive_triggers` is on. `Index` (the only production entry point; the other two `sqlite3.connect` calls only copy and verify a backup) enables
`PRAGMA foreign_keys` and `PRAGMA recursive_triggers` on every connection and refuses to open if the latter is not active; the setting is per connection, never assumed.
Independently of the pragma, the insert guards of `cleanup_execution`, `cleanup_exec_slice` and `cleanup_exec_item` refuse any insert whose primary key already exists, which
also stops `ON CONFLICT DO UPDATE` and `REPLACE INTO`. A refused statement leaves state, approvals and audit unchanged. Someone who can run arbitrary SQL, change PRAGMAs or
use a raw connection to a copy of the file remains outside the trust boundary.

**Cross-row invariant "EXECUTING has exactly one ACTIVE slice (and a lease)".** SQLite triggers fire per statement, so this cannot be enforced as a plain trigger without
breaking the fixed items -> slices -> execution order. It is enforced where it can be: a trigger refuses `EXECUTING` without exactly one `ACTIVE` slice (so `start_slice`
activates the slice first), a partial unique index allows one `ACTIVE` slice per execution, and the library verifies the whole invariant (`invariant_problems`) before
every commit of `start_slice`, `end_slice`, `stop_execution`, `recover_interrupted`, `abort_execution` and before every executor operation, failing with
`INVARIANT_BROKEN`. **Residual limitation:** direct SQL that deactivates the slice under a running execution is not blocked by the database; it is detected on
the next library operation, which then refuses to proceed (recovery via `recover_interrupted` still works).

**Fail-closed continuation.** An ordinary continuation to the next slice is allowed only if every `COMPLETED` slice contains at least one `APPLIED` item and the
execution has no `NOT_APPLIED` (rejected), `CONFLICT`, `UNKNOWN` or `INTENT` item. Safe skips (`SKIPPED_DRIFT`, `SKIPPED_GONE`, overlap pre-skips) never block by
themselves, but a slice made only of skips applied nothing and blocks. `end_slice` therefore finishes the execution instead of awaiting continuation when
the rule is violated: remaining items become `NOT_APPLIED`/`NEVER_ATTEMPTED`, remaining slices `STOPPED`, and the state is `FAILED` (nothing applied) or `PARTIAL`
(never `EXECUTED`). `confirm_slice` re-checks the rule (`CONTINUATION_BLOCKED`) and a trigger refuses `AWAITING_CONTINUATION` in these cases. This is a policy
for the state machine; the live circuit breaker (thresholds, rates, auth problems) belongs to the future executor and is not built here. Continuing after such a stop
needs a new plan, a new approval and a new execution.

*Continuation versus final status.* The rule above only decides whether the NEXT slice may be offered; it is never relaxed. The final status of an execution is a
separate, execution-wide classification: when no slice remains, an execution whose earlier slices reached the observed archived state (`APPLIED`, with checked
evidence) and whose last slice contains only safe skips (nothing attempted, nothing failed) is `EXECUTED`; if nothing was applied anywhere it is `FAILED`. A completed
slice with no application never leads to a further slice, and no further execution is authorized automatically in any case. `EXECUTED` describes recorded, observed state
only; it does not prove that this executor made the change (see the evidence section).

**Approval consumption and reservation (one short transaction).** `reserve_execution` verifies the plan (`verify_approved`),
checks the execution confirmation, refuses if the account already has a non-final execution, refuses overlap with unresolved work
of another execution, then atomically turns the approval `VALID` -> `CONSUMED` (never reversible), creates the execution
(`PREPARED`), its slices (slice 1 `CONFIRMED`) and **all** items. The database rejects an execution without a consumed approval of
an `APPROVED` plan and rejects items that are not exact targets of the plan or are added after reservation. Slices follow the
M4 policy: up to 100 targets in one slice; larger plans start with a canary of 25, then slices of at most 100, each needing its own
fresh typed confirmation (`CONTINUE ...`) and a local re-check of the remaining targets only (the protection/classification
digests stay plan-wide, so any rule change makes the continuation stale). Related rows are always written in the same order:
items, then slices, then the execution.

**Concurrency and overlap.** One running execution per account (a partial unique index over `PREPARED`, `EXECUTING` and
`RECONCILIATION_REQUIRED`); a second reservation fails closed and keeps its own approval `VALID`. Pending work of an
`AWAITING_CONTINUATION` execution still counts as unresolved overlap. Targets already `APPLIED` by another execution are pre-skipped
(`SKIPPED_DRIFT`, code `OVERLAP_ALREADY_APPLIED`), never repeated; targets with unresolved work elsewhere refuse the reservation; a
plan whose targets were all done elsewhere is refused (`NOTHING_TO_DO`) without consuming anything. A later undo (M4D) must record
reversals so that an undone target stops counting as applied.

**Intent, interruption and recovery.** A future executor must commit the item `INTENT` (with the label ids before the change, which
must include `INBOX` and become immutable, for a later undo) before any Gmail call and the outcome after it; SQLite and Gmail cannot
commit atomically, so a crash in between leaves an `INTENT`. Execution holds a short lease; if it expires, `recover_interrupted`
turns every open `INTENT` into `UNKNOWN` (`INTERRUPTED`), never-attempted items into `NOT_APPLIED` (`NEVER_ATTEMPTED`), and the
execution into `RECONCILIATION_REQUIRED`. An execution is **never resumed automatically**, and an execution with unknown work cannot
be aborted. Nothing in M4C-A calls `recover_interrupted`; the future executor must call it at start-up.

**Audit.** Reservation, confirmations, interruption and every execution, slice and item transition append an event (state names,
counts, vocabulary codes, an item sequence number; never message ids) so intended operations, confirmed outcomes and unknown
outcomes are distinguishable. Item rows keep ids, timestamps, vocabulary codes and previous label ids; no message content or
credentials are stored. The chain remains tamper-evident only (see the M4B limits); executions and their history are never deleted
automatically.

**Not in M4C-A (deferred).** The write OAuth client and Keychain item (M4C-B), the guarded Gmail transport, live per-message
re-validation, real archive calls, retries, the circuit breaker and live reconciliation (M4C-C), adversarial tests and live-canary
readiness (M4C-D), and undo (M4D). A continuation after many known rejections is not blocked by the state machine itself: the
executor's circuit breaker and the owner's fresh confirmation decide.

## Audit retention (see M4B above)
Defined in the M4B section above: local, never deleted automatically, kept by `mailbox purge`.

## Status
Implemented and covered by offline tests with synthetic data. Not measured: recommendation quality on a real mailbox. No live
verification has been run; any later one needs a separate owner approval. Zero Additional Cost: no new dependency or service.
