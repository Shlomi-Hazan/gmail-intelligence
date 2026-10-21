# Incremental sync and maintenance (M7) — design contract

> **Status: M7A (#20) and M7B (#21: change/deletion reporting and plan-impact explanation) are IMPLEMENTED against synthetic data only (guards E1-E5, lease, explicit `index upgrade`, schema v7, `mailbox sync`, `mailbox changes`, `cleanup plan impact`); M7C is NOT started, and nothing has run against real Gmail or the owner's index. See sections 16 and 17.** It is the authoritative design for M7A ([#20](https://github.com/Shlomi-Hazan/gmail-intelligence/issues/20)), M7B ([#21](https://github.com/Shlomi-Hazan/gmail-intelligence/issues/21)) and M7C ([#22](https://github.com/Shlomi-Hazan/gmail-intelligence/issues/22)). The owner approved this direction for documentation and synthetic-only implementation planning. It does **not** authorize: any Gmail call, any change to the personal index, any migration, any Gmail write, scheduling, or the M4 code changes in section 9 (those need the owner's explicit approval when M7A is started; they ship in the same PR as the first operational sync path, section 14.1). Decisions are recorded as D129-D146 in [DECISIONS.md](DECISIONS.md).

Tags: **[Implemented]** exists in `main` · **[Design]** decided here, not built · **[Verified]** checked against the cited official Google page on 2026-10-20 · **[Unverified]** an assumption that must be checked before it is relied on · **OWNER-APPROVAL-REQUIRED** changes an existing security contract.

## 1. Goals, scope and non-goals
- Keep the local index fresh without a full rescan: `history.list` incremental sync with a durable checkpoint (M7A), change and deletion detection with tombstones and the effect on M4 plans (M7B), and a user-triggered read-only health report (M7C).
- Fixed constraints: `gmail.readonly` only; metadata only (no subject, snippet, body or attachment); no Gmail write; no new dependency; Zero Additional Cost (D8); `LIVE_EXECUTION_ENABLED` stays `False`; no scheduling; synthetic fixtures only for all tests, PRs and logs.
- Non-goals: automatic repair, automatic rescans, unattended runs, content indexing, any change to the stored plan format, approval semantics, audit history or the execution boundary beyond section 9.

## 2. What exists today (verified in `main` `244184d`)

| Area | Implemented | Not implemented (only proposed in ARCHITECTURE) |
|---|---|---|
| Read adapter `gmail.GmailReader` | `get_profile` (incl. `historyId`), `list_labels`, `list_label_details`, `list_message_ids`, `get_message_metadata`; typed errors incl. `GmailNotFoundError` (404); a test pins the public method set | `history.list`; any checkpoint |
| Full scan `scanner.run_scan` | 500-id pages, resume by page token, `RateLimiter` (4,500 units/min), bounded backoff, prune only after a complete full scan with `failed == 0`; **prune is a hard delete without a tombstone**; pruning and finishing the scan are two separate transactions | recording the profile `historyId`; tombstones; `sync_state`/`sync_run` (ARCHITECTURE sections 3 and 5 are illustrative) |
| Schema v6 | 17 tables; `scans` has no history id; `messages.scan_id INTEGER NOT NULL` without a CHECK | any lease or single-writer mechanism: `start_scan` simply marks an older `running` scan `interrupted` |
| Plan anchor `cleanup_plans._anchor` | `{completeness, last_full_scan}` taken from the last 50 scan rows; item digests include `scan_id`, `unread`, thread, time, sender and label digests and the classification digest | any knowledge of sync |
| Plan freshness `cleanup_plans.revalidate` | the single choke point used by review, approval, `verify_approved` (reserve, dry run), slice continuation and the per-item executor check; fail-closed; one drifted item makes the whole plan stale; `_insert_plan` checks only `completeness` | a sync-health check |
| Rejections | `_guard`, `reserve_execution` write `*_REJECTED` audit events that **count towards a lockout** (10 per 15 minutes) | a way to refuse without audit or lockout |
| Classification freshness | a classification is current only while `message_class.msg_scan_id == messages.scan_id` | - |
| Dashboard | `freshness` from `recent_scans`; `ReadOnlyIndex` refuses any schema other than the current one | sync status |

## 3. Gmail API facts used **[Verified 2026-10-20]**
- `users.history.list` accepts `gmail.readonly`; parameters `startHistoryId` (required), `maxResults` (default 100, max 500), `pageToken`, `historyTypes[]` (`messageAdded`, `messageDeleted`, `labelAdded`, `labelRemoved`); the response has `history[]`, `nextPageToken` and the mailbox's current `historyId`. Records carry message ids (usually `id` and `threadId` only) and, for label events, `labelIds`. `messagesDeleted` means **permanent** deletion; moving a message to Trash is a `labelsAdded` event for `TRASH`.
- History is "typically available for at least a week", "might be significantly shorter" in rare cases. An out-of-range `startHistoryId` returns **HTTP 404** and the client must run a full sync. With no `nextPageToken` there are no further updates; store the returned `historyId`.
- Quota units: `history.list` 2, `messages.list` 5, `messages.get` 20 (metadata), `users.getProfile` 1, `labels.list` 1; limits 6,000 units/minute per user and 1,200,000 per project. The page also lists **80,000,000 units/day per project as a billing threshold** with charges "planned later in 2026". This is recorded as a **blocker for live use** until the owner confirms the current terms (section 12).
- **Not documented, therefore never relied on:** ordering of history records or pages, absence of duplicates, lifetime of a `pageToken`, whether a truncated response can omit `nextPageToken`, that `labels.list` changes appear in history, and whether `messagesTotal` counts Spam/Trash.

## 4. Data model — schema v7 **[Design]**

v7 is purely additive: three new tables, no change to any of the 17 existing tables, no trigger change, M4/M5 data and the audit chain untouched. `SCHEMA_VERSION = 7`; the upgrade runs through the existing migration path (verified private 0600 backup tagged `pre-m7` first, one transaction, rollback by restoring the backup). A v6 binary refuses a v7 file ("unsupported index schema version"), so old and new code can never write the same index.

```sql
CREATE TABLE sync_state (               -- at most one row per account; the trusted checkpoint
  account TEXT PRIMARY KEY,
  history_id TEXT NOT NULL,             -- opaque id; meaning in section 6.3
  source TEXT NOT NULL CHECK (source IN ('PROFILE_BEFORE_FULL_LIST','HISTORY_RESPONSE')),
  basis_scan_id INTEGER NOT NULL,       -- the completed FULL scan this lineage started from
  established_at TEXT NOT NULL, advanced_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('OK','IN_PROGRESS','INTERRUPTED','NEEDS_RECONCILE')),
  reason TEXT                           -- closed vocabulary, section 8.2
) WITHOUT ROWID;
CREATE TABLE sync_run (                 -- one row per run; also the single-writer lease (section 5)
  id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('INCREMENTAL','FULL','LIMITED')),
  status TEXT NOT NULL CHECK (status IN ('running','completed','interrupted','failed','needs_reconcile')),
  started_at TEXT NOT NULL, finished_at TEXT, scan_id INTEGER,          -- scan_id for FULL/LIMITED
  lease_token TEXT NOT NULL CHECK (length(lease_token) = 64), lease_expires_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL,
  start_history_id TEXT, first_history_id TEXT,
  pages INTEGER NOT NULL DEFAULT 0, records INTEGER NOT NULL DEFAULT 0, affected INTEGER NOT NULL DEFAULT 0,
  refreshed INTEGER NOT NULL DEFAULT 0, unchanged INTEGER NOT NULL DEFAULT 0, tombstoned INTEGER NOT NULL DEFAULT 0,
  vanished INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE INDEX sync_run_account ON sync_run (account, id);
CREATE UNIQUE INDEX sync_run_one_running ON sync_run (account) WHERE status = 'running';   -- DB-enforced single writer
CREATE TABLE message_tombstone (        -- deletion record; the message row itself is removed
  account TEXT NOT NULL, message_id TEXT NOT NULL, detected_at TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('HISTORY_DELETED','NOT_FOUND_ON_REFRESH','FULL_RECONCILE')),
  run_id INTEGER, PRIMARY KEY (account, message_id)) WITHOUT ROWID;
```

**Why v6 cannot hold this:** `scans` has no history id and no lease; storing a checkpoint in `scans.error`/`page_token` is unreviewable; `messages` has no deleted state and adding one would change every count; incremental rows in `scans` would push the last completed full scan out of `recent_scans(50)` and break `_anchor`.

### 4.1 The `scan_id` contract
- A row **changed by an incremental run** is stamped `scan_id = -sync_run.id` (negative). `sync_run.id` is AUTOINCREMENT and never reused; `scans.id` is positive; they cannot collide.
- A row whose fetched metadata is identical to the stored row is **not written at all** (its `scan_id` is untouched), so a quiet sync never invalidates anything.
- Verified compatibility (code review of every use): classification, candidate, organization and analytics code compare `msg_scan_id = scan_id` by equality only; `prune_unseen` uses `scan_id <> current`; plan snapshots check item keys, not the sign; there is no CHECK on either column and no join to `scans`. Effects, all intended: a changed message's classification becomes stale automatically; the item digest in any plan changes; a message changed and later changed back keeps a different `scan_id`, so a plan that contained it stays stale.
- A later FULL scan restamps every row it sees with a positive id and prunes the rest, exactly as today.
- M7C reports a negative `scan_id` without a matching `sync_run` and a positive one without a `scans` row.

### 4.2 Deletions
A deleted message's row, labels and classification rows are removed in the same transaction that writes its tombstone (reason `HISTORY_DELETED`, `NOT_FOUND_ON_REFRESH` or `FULL_RECONCILE`). Message ids are never reused by Gmail, so a message id present in both `messages` and `message_tombstone` is an anomaly (`FALSE_DELETION_SUSPECTED`, M7C). M4 rows (`cleanup_item`, executions, audit) are **never** touched: a plan whose message disappeared simply fails revalidation with `ITEM_MISSING`.

## 5. Single-writer ownership (lease) **[Design; mandatory clarification 1]**

Every operation that writes Gmail-derived rows to the index — an INCREMENTAL sync, a FULL scan (baseline or reconciliation) and a LIMITED scan — owns exactly one `sync_run` row with `status='running'` for its whole life. The partial unique index `sync_run_one_running` makes a second active writer **impossible at the database level**; the lease below decides when a `running` row is abandoned.

Constants: `LEASE_TTL = 5 minutes`, heartbeat at every page, every 50-message chunk and at least once per 30 seconds of backoff sleep.

### 5.1 Reap and acquire (T0): how an expired run is taken over
Both steps run inside one `BEGIN IMMEDIATE` transaction. The reap is a fail-closed clean-up that is committed **even when the requester is then refused**; admission is decided afterwards, on the post-reap state, in the same transaction.

**Reap (every acquire attempt starts here)**
1. Read the account's `running` row, if any (the unique index allows at most one). None: nothing to reap.
2. `lease_expires_at > now`: the run is active. Do not reap; refuse with `SYNC_BUSY` ("another sync is active until ..."). An active lease is never taken over.
3. Expired but `now < heartbeat_at`: a clock that moved backwards cannot prove abandonment; refuse with `SYNC_CLOCK_UNCERTAIN`.
4. Otherwise reap with a compare-and-swap (`UPDATE sync_run SET status='interrupted', error='LEASE_EXPIRED', finished_at=? WHERE id=? AND status='running' AND lease_token=?`; the row count must be 1, otherwise another process reaped first and this attempt is refused as `SYNC_BUSY`). In the same transaction: a `running` `scans` row of that run becomes `interrupted`, and an existing `sync_state` row moves `IN_PROGRESS` to `INTERRUPTED` with reason `LEASE_EXPIRED` when the dead run was INCREMENTAL, or `FULL_SCAN_INTERRUPTED` when it was FULL or LIMITED. The checkpoint value (`history_id`) is **never** touched by a reap, and a reap never writes `OK`.

**Admission (after the reap, same transaction)**

| Requester | Required state | Otherwise |
|---|---|---|
| INCREMENTAL | a `sync_state` row exists; `status` is `OK` or `INTERRUPTED` with reason `LEASE_EXPIRED`/`API_QUOTA`/`API_ERROR`; **no unfinished full scan** (derived from `scans`, below); no active M4 execution | refused: `SYNC_CHECKPOINT_MISSING`, `SYNC_NEEDS_RECONCILE`, `SYNC_FULL_SCAN_UNFINISHED` or `SYNC_EXECUTION_ACTIVE`; nothing is read from Gmail |
| FULL (new or `--resume`) | any state | - |
| LIMITED | no `sync_state` row at all (D144) | refused: `SYNC_LIMITED_REFUSED` |

*Unfinished full scan* = any `scans` row of mode `full` or `limited` for the account with status `running`, `interrupted`, `failed` or `incomplete` and an id greater than `sync_state.basis_scan_id` (or any such row at all while no checkpoint exists). This is derived from the tables, independently of the status flag, so a wrong flag cannot let an incremental run start over an unfinished full scan.

On admission: insert the new `running` run (fresh random 256-bit hex lease token), set an existing `sync_state` row to `IN_PROGRESS` (reason cleared), commit. A resumed FULL scan keeps its `scans` row and copies the captured baseline `historyId` from the most recent FULL `sync_run` row of the same scan; if there is none (a scan from before v7) the resumed scan establishes no checkpoint. A replacement INCREMENTAL run starts from `H0 = sync_state.history_id` exactly as last committed (a reaped incremental run never advanced it) and replays the whole range; chunks are idempotent.

Legacy `scans` rows marked `running` without any `sync_run` row can only come from a v6 binary, which cannot open a v7 file; the first v7 acquire marks them `interrupted` and they count as an unfinished full scan.

### 5.2 Fencing: every later write
Every transaction that changes the index on behalf of a run (each chunk, the label refresh, the final transaction, the heartbeat itself) begins with `BEGIN IMMEDIATE` and a **fence**: `SELECT 1 FROM sync_run WHERE id=? AND status='running' AND lease_token=?`. No row means the lease was lost: roll back, write nothing, stop with `SYNC_LEASE_LOST`. Because the fence and the write share one write-locking transaction, a stalled process (laptop sleep, SIGSTOP) that wakes after another process took over **cannot commit anything**, even though it still believes it owns the run. A fenced write also extends `lease_expires_at`/`heartbeat_at`. The process id is never trusted.

### 5.3 Release and recovery
- Success: the final transaction sets the run `completed` (and the state, section 6/7). Clean failure or Ctrl+C: the run is set `interrupted`/`failed` (best effort) and the state per section 8.
- Crash (kill -9, power loss): the `running` row stays; `sync_state` stays `IN_PROGRESS`, which keeps M4 prohibited; other writers see `SYNC_BUSY` until the lease expires (at most 5 minutes), then the next acquire reaps it and takes over (5.1, 5.4).
- `mailbox purge` refuses while an unexpired `running` lease exists.
- Two processes racing T0 or a takeover: SQLite serializes the `IMMEDIATE` transactions and the unique index plus the compare-and-swap leave exactly one winner.

### 5.4 Recovery table (dead run, expired lease)

| Dead run | State after the reap | INCREMENTAL requester | FULL requester | LIMITED requester |
|---|---|---|---|---|
| INCREMENTAL | `INTERRUPTED` / `LEASE_EXPIRED` | admitted; replays from the committed checkpoint; `IN_PROGRESS`, then `OK` only at its final transaction | admitted (new capture) | refused |
| FULL, checkpoint existed before | `INTERRUPTED` / `FULL_SCAN_INTERRUPTED` (the earlier `OK` is not restored) | **refused** `SYNC_FULL_SCAN_UNFINISHED`; no Gmail request, no row changed | admitted; `--resume` reuses the original baseline, a restart captures a new one; `OK` only when it completes | refused |
| FULL or LIMITED, no checkpoint yet | stays MISSING | refused `SYNC_CHECKPOINT_MISSING` | admitted | admitted |
| legacy v6 `running` scan | MISSING or as above | as the row above for its situation | as above | as above |
| `IN_PROGRESS` flag but no `running` run (corruption) | `SYNC_STATE_INCONSISTENT` | refused | admitted (repairs) | refused |

The only way back to `OK` after an unfinished FULL scan is that FULL scan completing (6.2). An incremental run can never bypass it, by three independent checks: the state reason, the derived unfinished-scan rule above, and `sync_health` itself.

## 6. FULL scans: baseline and reconciliation **[Design]**

A FULL scan is the only way to establish or re-establish a checkpoint. "Reconciliation" is a FULL scan started because of `NEEDS_RECONCILE`; there is no separate algorithm and nothing is ever started automatically.

### 6.1 Baseline capture (durable across interruptions)
- Before the first list call the run records the profile `historyId` (`getProfile`, 1 unit) in `sync_run.first_history_id`, **in the same transaction** that creates the `scans` row and the `sync_run` row. A resumed scan re-uses that value and never fetches a new one. A scan created before v7 has no such row: it may finish normally but **establishes no checkpoint** and says so.
- Meaning: "every Gmail change with a history id greater than this value is not guaranteed to be reflected in the listing". Changes made during the listing are therefore replayed by the first incremental sync (harmless overlap, never a gap).

### 6.2 Completion: one transaction, nothing partial
On a complete listing with `failed == 0` and a passing count check (6.4) a single transaction does: prune unseen rows **and write their tombstones** (`FULL_RECONCILE`), finish the `scans` row, write/replace `sync_state` (`history_id` = the captured baseline value, `source='PROFILE_BEFORE_FULL_LIST'`, `basis_scan_id` = this scan, `status='OK'`, `reason` NULL), and mark the run `completed`. Today pruning and finishing are separate transactions; M7A merges them so a crash can never leave "pruned but not finished".

### 6.3 Meaning of the checkpoint
`sync_state.history_id` means: all history events with an id greater than this value have not been applied; all earlier changes are reflected in the index (to the extent the previous run was complete). It is only ever replaced by (a) a completed FULL scan or (b) the final transaction of a completed INCREMENTAL run (section 7).

### 6.4 Prune safety and why 20% alone is not enough
A silently truncated listing (a page without `nextPageToken` that should have had one) is indistinguishable from a real end, and a 20% prune ceiling cannot catch a smaller truncation or a young index. Layered defence:
1. Prune only after a complete listing with `failed == 0` (exists today). LIMITED scans never prune.
2. **Count check** (INFERRED, since it relies on an estimate): compare the number of distinct listed ids with `getProfile.messagesTotal` read after the listing. A difference above `max(50, 1%)` ends the scan `incomplete` with reason `COUNT_MISMATCH`: **no prune, no checkpoint**, `NEEDS_RECONCILE`. It can be overridden only by an explicit `--accept-count-mismatch` after the owner reviews the numbers. Whether `messagesTotal` includes Spam and Trash is **[Unverified]**; the first live acceptance observes it, and until then a mismatch fails closed.
3. Secondary tripwire: a prune of more than 20% of existing rows needs `--allow-large-prune`.
4. Every pruned id gets a tombstone (traceable); a pruned id that later reappears is flagged `FALSE_DELETION_SUSPECTED`.
5. Blast radius is bounded: the index is derived data. A false prune makes plans stale (`ITEM_MISSING`, fail-closed), changes nothing in Gmail and is repaired by the next FULL scan.

## 7. Incremental sync algorithm (M7A) **[Design]**

Principles: events are **hints**, not facts; the truth is a fresh `messages.get` (metadata) for each affected message; ids are collected into a **set**, so duplicates, overlap and ordering are irrelevant; nothing is applied until the whole range has been collected; the checkpoint moves exactly once, at the end. There is **no per-page watermark** and no use of record-id ordering (rejected: ordering is undocumented, a reordered or partial page could silently skip events).

Let `H0 = sync_state.history_id`.

| Step | Action | Writes |
|---|---|---|
| **T0** | acquire the lease (section 5.1); require `sync_state` to exist with `status` in (`OK`,`INTERRUPTED`) and no unfinished FULL/LIMITED scan; verify the profile account equals the stored account and the profile `historyId` is not numerically below `H0` (tripwire only: below means `NEEDS_RECONCILE`). Run row stores `start_history_id = H0`. | commit |
| **1 Collect** | page through `history.list(startHistoryId=H0, maxResults=100, historyTypes=all four, fields=ids only)` until a page has no `nextPageToken`. Build the set `S` of message ids and remember `H1` = the `historyId` of the **first** response. `|S| > MAX_RANGE_IDS (5,000)` → stop with `NEEDS_RECONCILE(RANGE_TOO_LARGE)`. A page-token error (400, or 404 when a token was sent) restarts the collection from `H0` at most twice; a 404 on the very first request (no token) is `HISTORY_EXPIRED`. | none |
| **2 Labels** | `labels.list` (1 unit), then replace this account's `labels` rows in one fenced transaction (label create/rename/delete is not in history). | fenced txn |
| **3 Apply** | for `S` sorted, in chunks of 50: fetch metadata outside any transaction (rate-limited, bounded backoff); then one fenced `BEGIN IMMEDIATE` per chunk: unchanged → no write; changed or new → upsert row and labels with `scan_id = -run.id`; HTTP 404 → delete row, labels, classification and write a tombstone (a 404 for an id never indexed only counts `vanished`); update counters. **No checkpoint movement.** | fenced txns |
| **T_end** | one fenced transaction, only if the collection finished, every chunk committed and `failed == 0`: compare-and-set `sync_state.history_id == H0`; set `history_id = H1` (`source='HISTORY_RESPONSE'`), `advanced_at`, `status='OK'`, `reason` NULL; run `completed`. | **the only checkpoint move** |

**Empty history** (no `history`, no `nextPageToken`): T_end still advances to the response `historyId` so the retention window does not close behind a quiet mailbox; if the response has no `historyId` the checkpoint is left unchanged and the run records a warning.

**Why `H1` is the first response's id:** any event with an id at or below it was returned by the drain; later events are re-read next time. A conservative bound can only cause harmless replay, never a gap.

### 7.1 Failure and recovery table

| Situation | Result |
|---|---|
| Crash or kill before T_end (any step) | checkpoint still `H0`, `sync_state` `IN_PROGRESS` (M4 stays prohibited), lease expires, next run takes over and **replays the whole range**; chunks are idempotent |
| Crash after T_end | checkpoint and `OK` committed together |
| Partial or reordered or duplicated pages | irrelevant: nothing is applied before the set is complete; the set ignores order and duplicates |
| Page-token expiry | collection restarts from `H0`, at most twice, then `INTERRUPTED` |
| HTTP 404/400 on the first request, missing or foreign checkpoint, id below `H0`, `RANGE_TOO_LARGE`, anomaly | `NEEDS_RECONCILE` with a reason; **no automatic FULL scan**; the report recommends one |
| Rate limit / quota exhausted after bounded retries | run `interrupted`, state `INTERRUPTED`, checkpoint unchanged, committed chunks remain valid |
| A permanent per-message error | `failed > 0`: no T_end, state `INTERRUPTED` |
| Lease lost (another process took over) | fenced out; nothing further written |
| A new message arrives during the run | its event id lies beyond `H1`; picked up next run |
| Replay cost | worst case `|S| = 5,000` is about 100,000 units, roughly 22 minutes at the default rate; this is the deliberate price of safe replay over unsafe progress |

**Residual risk (documented, not solved):** a response truncated without `nextPageToken` cannot be detected locally. Mitigations: the count check, FULL reconciliation, the M7C report's recommendation of a periodic reconcile, and the fact that the index is derived data guarded by live reads at execution time.

### 7.2 Partial results in reports and the dashboard
While a run is `IN_PROGRESS`, `INTERRUPTED` or `NEEDS_RECONCILE`, every report and the dashboard `freshness` section show the sync status, the checkpoint age, the last run's counters and an issue code (`SYNC_IN_PROGRESS`, `SYNC_INTERRUPTED`, `NEEDS_RECONCILE`, `CHECKPOINT_STALE`); the index is described as possibly mixed (each row correct as of its own fetch). `report.completeness` keeps looking only at FULL scans, so a partial sync never makes the index look complete or fresh.

## 8. Sync-state machine and the full-scan interlock **[Design; mandatory clarification 2]**

### 8.1 States
`sync_state.status`: `OK`, `IN_PROGRESS`, `INTERRUPTED`, `NEEDS_RECONCILE`; plus the absence of a row (`MISSING`). Rule: **every writer that acquires the lease (INCREMENTAL, FULL, LIMITED) sets an existing row to `IN_PROGRESS` in the same transaction**, and `OK` is written only by a completed INCREMENTAL run (section 7) or a completed FULL scan (6.2). No other code path may write `OK`.

Reason vocabulary (closed): `HISTORY_EXPIRED`, `HISTORY_INVALID`, `RANGE_TOO_LARGE`, `ID_REGRESSION`, `ACCOUNT_MISMATCH`, `FULL_SCAN_INTERRUPTED`, `FULL_SCAN_INCOMPLETE`, `COUNT_MISMATCH`, `LEASE_EXPIRED`, `API_QUOTA`, `API_ERROR`.

### 8.2 Transitions

| From | Event | To |
|---|---|---|
| MISSING | FULL scan completes (6.2) | OK |
| OK | any writer acquires the lease | IN_PROGRESS |
| IN_PROGRESS | INCREMENTAL final transaction | OK (checkpoint `H1`) |
| IN_PROGRESS | FULL scan completes | OK (new checkpoint, new `basis_scan_id`) |
| IN_PROGRESS | clean interrupt, quota, API error, or lease takeover of an INCREMENTAL run | INTERRUPTED |
| IN_PROGRESS | FULL scan interrupted (clean stop or lease takeover) | INTERRUPTED, reason `FULL_SCAN_INTERRUPTED` |
| IN_PROGRESS | FULL scan ended `incomplete`/`failed` (`failed > 0`, `COUNT_MISMATCH`, authorization failure) | NEEDS_RECONCILE, reason `FULL_SCAN_INCOMPLETE` or `COUNT_MISMATCH` |
| IN_PROGRESS | history expired/invalid, `RANGE_TOO_LARGE`, id regression, account mismatch | NEEDS_RECONCILE |
| INTERRUPTED (incremental) | a new INCREMENTAL run | IN_PROGRESS, then OK |
| INTERRUPTED (`FULL_SCAN_INTERRUPTED`) | a FULL scan is **resumed** (or restarted) | IN_PROGRESS, then OK on completion |
| NEEDS_RECONCILE | FULL scan (new or resumed) completes | OK |
| NEEDS_RECONCILE, or INTERRUPTED with an unfinished FULL scan | INCREMENTAL requested | **refused** ("finish the full scan first") |
| any | process crash | unchanged (`IN_PROGRESS`), which stays unhealthy |

**D144 (confirmed by the owner):** `mailbox scan --limit` is refused whenever a `sync_state` row exists, in **any** status (an `INTERRUPTED` or `NEEDS_RECONCILE` row is an untrusted checkpoint, and a partial listing that restamps rows must never run beside it). The supported paths are FULL scans (`mailbox scan --all`, `--resume`) and incremental `mailbox sync`. Before the first checkpoint a limited scan behaves as today and can never create one. The refusal is decided from local state **before any Gmail request**: the account comes from the stored authorization and is re-verified against the profile only after the check; a refused attempt changes no file.

### 8.3 The interlock rules (exact)

| Situation | Sync status | Health | Why |
|---|---|---|---|
| **Active FULL scan**, no earlier checkpoint | MISSING | unhealthy: `SYNC_CHECKPOINT_MISSING`, `SYNC_FULL_SCAN_INCOMPLETE` | nothing to trust yet |
| **Active FULL scan**, earlier healthy checkpoint | flipped `OK` → `IN_PROGRESS` at T0 | unhealthy: `SYNC_IN_PROGRESS`, `SYNC_FULL_SCAN_INCOMPLETE` | the old checkpoint must not authorize M4 while rows are being restamped |
| **Interrupted FULL scan** (clean or crashed) | `INTERRUPTED` / `IN_PROGRESS` | unhealthy | the previous `OK` is **never restored**; only completion can |
| **Failed reconciliation** | `NEEDS_RECONCILE` | unhealthy | no prune, no checkpoint change; the old value is retained but untrusted |
| **Successfully completed reconciliation** | `OK`, new checkpoint | healthy if fresh | one transaction: prune + tombstones + scan finish + state |
| **Healthy checkpoint plus a later incomplete scan** | cannot be `OK` (T0 flipped it) | unhealthy | independently guarded below |

**Defense in depth (two independent guards):** `sync_health` does not trust the status flag alone. It also derives from the tables: it reports `SYNC_FULL_SCAN_INCOMPLETE` when the newest FULL/LIMITED `scans` row is not `completed` or is newer than `basis_scan_id`, when a `running` `sync_run` exists, or when `basis_scan_id` is not the newest completed FULL scan. And the existing M4 `INDEX_NOT_COMPLETE` check (`report.completeness`, "a newer full scan is not completed") fires independently. A forgotten or corrupted status flip therefore still cannot yield a healthy result.

**Immutability:** none of these transitions writes to `cleanup_plan`, `cleanup_item`, `cleanup_approval`, `cleanup_execution*`, `label_plan*` or `cleanup_audit`. A full scan or reconciliation that completes changes the M4 anchor (`last_full_scan`) exactly as it does today, which already makes older plans `INDEX_RESCANNED`; this document changes nothing about that.

## 9. M4 plan-health contract (E1-E5) **[Design; OWNER-APPROVAL-REQUIRED; implemented in the same PR as the first operational sync path (M7A), section 14.1]**

### 9.1 Three different things
| Concept | Meaning | Decided by | Writes? | Reversible? |
|---|---|---|---|---|
| **A plan is stale** | this plan no longer matches the index: a target changed or vanished, eligibility or rules changed, the anchor moved, or it expired | `revalidate` on the plan itself | none; the user creates a new plan | never: a changed message keeps a different `scan_id`, so changing it back does not revive the plan |
| **An immutable approval record continues to exist** | a `cleanup_approval` row is never edited or deleted (triggers); its status changes only through the existing consume/revoke/expire paths | M4 | **sync never touches it**; the approval of a stale plan stays a `VALID` row until it expires and simply cannot pass `verify_approved` | - |
| **An operation is prohibited until sync health is restored** | the account-wide index freshness is uncertain | new `sync_health` | **none**: no plan change, no approval change, no audit event, no lockout count | yes: automatically, when health returns |

After health returns, a plan that is not stale and whose approval has not expired can proceed through the unchanged gates (typed phrases, `revalidate`, live reads). It was never invalidated and is not "newly valid because of sync".

### 9.2 `sync_health(index, account, now)` — new read-only module
Independent of every M4 module (no import cycle), no writes, injectable clock. Returns a list of codes; empty means healthy:
`SYNC_CHECKPOINT_MISSING`, `SYNC_IN_PROGRESS`, `SYNC_INTERRUPTED`, `SYNC_NEEDS_RECONCILE`, `SYNC_FULL_SCAN_INCOMPLETE`, `SYNC_STALE` (last successful sync or FULL scan older than `SYNC_MAX_AGE`, default 24 hours), `SYNC_STATE_INCONSISTENT` (basis mismatch, a `running` run beside `OK`, `advanced_at` in the future).

### 9.3 The smallest change set
| # | Module | Change |
|---|---|---|
| E1 | `cleanup_plans.revalidate` | add the `sync_health` codes to `problems` (one block) |
| E2 | `cleanup_plans._insert_plan` | refuse with `SYNC_NOT_HEALTHY` before creating a plan (covers `create_plan`, `revise_exclude` and the canary path) |
| E3 | `cleanup_plans.mark_reviewed`, `approve` | when every problem is a sync code, raise `SYNC_NOT_HEALTHY` ("prohibited until sync health is restored; the plan is unchanged") instead of `STALE ... create a new plan` |
| E4 | `cleanup_plans._guard` | `SYNC_NOT_HEALTHY` is neither audited nor counted towards the lockout |
| E5 | `cleanup_exec.reserve_execution`, `confirm_slice` | same distinct code and the same audit/lockout exclusion (`RESERVATION_REJECTED`) |

**Not changed:** the stored plan format and anchor, approval semantics, the schema triggers, `cleanup_audit`, the execution boundary (`cleanup_executor`, `cleanup_exec` state machines), `gmail_write*`, OAuth, `LIVE_EXECUTION_ENABLED`, and label plans (M5D has no executor; revisit if one is ever built, D142).

**Executor note:** the per-item `revalidate` inside the executor will also see the sync codes. If it ever did, the item is recorded `SKIPPED_DRIFT`/`STATE_CHANGED` (fail-closed; the label is less precise). That path is effectively unreachable: sync refuses to start while an execution is active and `reserve_execution` is refused while a sync is active, both decided atomically in `BEGIN IMMEDIATE` transactions. Replacing it by a dedicated stop reason would touch the execution boundary and needs a separate decision.

### 9.4 Operations matrix
"Blocked" means refused with `SYNC_NOT_HEALTHY` and no write of any kind.

| Sync condition | Create / revise plan | Review | Approve | Reserve / continue slice | Show, list, status, dry run | Cancel, abort, expire, recovery |
|---|---|---|---|---|---|---|
| MISSING (no checkpoint) | blocked | blocked | blocked | blocked | allowed, shows the code | allowed |
| IN_PROGRESS (running, or crashed until takeover) | blocked | blocked | blocked | blocked | allowed | allowed |
| INTERRUPTED / partially applied | blocked | blocked | blocked | blocked | allowed | allowed |
| NEEDS_RECONCILE | blocked | blocked | blocked | blocked | allowed | allowed |
| Active / interrupted / failed FULL scan, with or without an earlier checkpoint | blocked | blocked | blocked | blocked | allowed | allowed |
| OK but older than `SYNC_MAX_AGE` | blocked | blocked | blocked | blocked | allowed | allowed |
| OK and fresh | allowed | allowed | allowed | allowed (typed phrase, full `revalidate`, live reads still required) | allowed | allowed |

Stopping is always safe, so cancel, abort, expiry and recovery are never blocked.

### 9.5 Consequences accepted by the owner
After the v7 migration every M4 workflow stays blocked until one FULL baseline scan has run (D142); a sync is needed within `SYNC_MAX_AGE` before each cleanup session; the existing M4 tests need one shared helper (`tests/m7_support.seed_healthy_sync`) in the seven files that create plans.

## 10. Maintenance report (M7C) **[Design]**
`mailbox maintenance [--account] [--deep] [--json]`: user-triggered, opens the index through `ReadOnlyIndex`, never repairs, rescans, deletes or contacts Gmail; schedulers are out of scope. Every finding has a severity (`INFO`, `WARN`, `ERROR`, `CRITICAL`), a certainty (`OBSERVED`, `INFERRED`, `UNKNOWN`), a short explanation and a recommended command that the user may run. Output is aggregate: no addresses, label names, ids or paths.

| Check | Notes |
|---|---|
| SQLite | `quick_check` (default) or `integrity_check` (`--deep`); `foreign_key_check` |
| Orphans | labels/classifications without a message; labels referenced but missing (UNKNOWN: label deletion is not in history); plan items whose message is gone (INFO, expected); negative/positive `scan_id` without a run/scan; ids both present and tombstoned |
| Scans and runs | unfinished scans; `running` run with an expired lease; failed counters; no completed FULL scan |
| Checkpoint | present, age (WARN beyond ~5 days, ERROR beyond 7: INFERRED, retention is not guaranteed), status and reason, basis scan exists, lineage consistent |
| Staleness | age of the last successful sync or FULL scan |
| Count check | local count versus `messagesTotal` estimate (INFERRED, warning only) |
| Backups | sibling `*.pre-*-backup-*` files: mode 0600, expected version, `quick_check` on a read-only open; only a tag and timestamp are shown |
| Audit | `verify_chain` and event count (`CRITICAL` if broken) |
| Executions | open or reconciliation-required executions (WARN; never touched) |
| Isolation | no row mixes accounts |

## 11. CLI, modules and code touch list **[Design]**
- New commands: `mailbox sync [--max-units-per-minute N]` (incremental), `mailbox sync --status` (local), `mailbox maintenance`. `mailbox scan --all` becomes the baseline/reconciliation command (no separate command, nothing automatic). `mailbox scan --limit` follows 8.2. New explicit `index upgrade` (14.1, D146): the only way an existing index file is migrated to v7.
- New modules: `sync_health.py`, `sync.py`, `sync_report.py`, `maintenance.py`; tests `fake_history.py`, `m7_support.py`, `test_sync_*`, `test_maintenance.py`.
- Changed: `gmail.py` (read-only `list_history` with a minimal `fields` mask and a typed expired-history error; the public-method test is updated deliberately), `index.py` (v7, atomic baseline start, lease helpers, purge, `find_resumable` by kind), `scanner.py` (baseline capture, atomic completion, tombstones, count check), `report.py`/`analytics.py` (sync status in freshness, additive), `cli.py`, and the E1-E5 files in 9.3 (`cleanup_plans.py`, `cleanup_exec.py`, in the M7A PR).
- Unchanged: `cleanup_executor`, `cleanup_audit`, `gmail_write*`, `oauth*`, `label_plans`.

## 12. Quota and Zero Additional Cost
- Costs per section 3. Incremental run: `2 x pages + 20 x |S| + 2` units (plus 1 for labels); a FULL scan is about `20 x N` units (for example 20,000 messages is about 400,000 units, about 90 minutes at 4,500 units/minute; N for the owner's mailbox is unknown to this document).
- Default pacing 4,500 units/minute; sequential `get` (no HTTP batching, no dependency); retries 429/5xx/403-rate-limit with bounded exponential backoff; exhaustion ends the run `interrupted` with the checkpoint unchanged.
- No paid API, model, service or dependency; nothing here promises that Google stays free. **Blocker for any live use:** the 80,000,000 units/day billing threshold and the announced future charges must be re-read and confirmed by the owner before the first live call. Expected personal usage is orders of magnitude below it, but that is not a billing guarantee.

## 13. Synthetic acceptance matrix
All tests use a fake Gmail (`FakeHistoryMailbox`: ground-truth oracle, monotonic history ids, event log, retention cut-off, injectable duplicates/reordering/truncation, rate limits, crash injection at every transaction boundary) and a temporary SQLite file; synthetic `.test` data only; a tripwire fails any write-capable call; canary strings in fixtures must never appear in output or logs; tests are seeded and deterministic (also under different `PYTHONHASHSEED`).

| ID | Area | Scenarios and required outcome |
|---|---|---|
| S1 | Baseline | profile id captured before listing, in the same transaction as the scan row; resume keeps it; pre-v7 scan establishes no checkpoint; LIMITED never does |
| S2 | Changes | empty history (with and without response id); one new message; many; message added during sync |
| S3 | Labels | add/remove; UNREAD, STARRED, IMPORTANT; several changes to one message; label rename/delete via `labels.list` |
| S4 | Deletion | permanent delete; trash; add-then-delete in range; unknown id (`vanished`, no tombstone); tombstone in the same transaction; reconcile tombstones |
| S5 | Idempotence | replayed pages, duplicate record ids, overlap, shuffled records and pages: final state and digests identical |
| C1 | Crash safety | crash before/after every commit (T0, each chunk, labels, T_end): after one recovery run the index equals the oracle and the checkpoint never moved before T_end |
| C2-C4 | Pagination | page-token expiry restarts from `H0` (twice max); first-request 404 is `HISTORY_EXPIRED`; interrupted pagination |
| C5 | Expiry and invalidity | 404/400, missing or foreign checkpoint, id regression, `RANGE_TOO_LARGE`: `NEEDS_RECONCILE`, no automatic scan, no data change |
| C6 | Rate limit | 429/403/5xx backoff; quota exhaustion leaves the checkpoint and committed chunks intact |
| C7 | **Mutant** | a naive per-page watermark or per-page checkpoint implementation must FAIL C1/C2/S5 (proves the suite detects the rejected design) |
| C8 | Truncation | a silently truncated history response is **not** detected by sync (documented); a truncated full listing is caught by the count check and does not prune |
| L1 | **Concurrency** | two real processes started together: exactly one runs, the other exits `SYNC_BUSY`; 8 racing processes leave one `running` row |
| L2 | Crash recovery | `kill -9` of the holder: others get `SYNC_BUSY` until expiry (injectable clock), then exactly one takes over and completes; the index equals the oracle |
| L3 | Fencing | a holder that stalls past expiry, is superseded, then resumes: its next write is rejected; no row written after takeover (table hashes) |
| L4 | Takeover race | two processes both see the expired lease: one wins, the other `SYNC_BUSY` |
| L5 | Clock | clock moved backwards: takeover refused (`SYNC_CLOCK_UNCERTAIN`) |
| L6 | Interlocks | incremental vs FULL/LIMITED mutual exclusion; `purge` refused while leased; sync vs an active M4 execution in both directions (`BEGIN IMMEDIATE` race) |
| F1 | Full-scan interlock | for every row of 8.3: active, interrupted, failed, completed, and healthy-checkpoint-plus-later-incomplete scans: health result, status, no `OK` restored by anything except completion; the derived guard fires with the status flag deliberately corrupted |
| F2 | Reconciliation | prune + tombstones + scan finish + state in one transaction (crash injected inside it leaves nothing partial); `COUNT_MISMATCH` prevents prune and checkpoint |
| P1 | M4 stale plans | label change, delete, eligibility loss, classification staleness each make the plan stale (`ITEM_CHANGED`/`ITEM_MISSING`/`ITEM_NOT_ELIGIBLE`); no-op sync leaves a plan valid; changed-and-reverted stays stale; new messages do not affect a plan |
| P2 | Approvals | an approval row is never rewritten; a stale plan's approval cannot pass `verify_approved`; sync never makes one valid |
| P3 | Prohibition | every cell of 9.4: refused with `SYNC_NOT_HEALTHY`; **table hashes of all `cleanup_*`/`label_plan*` tables and the audit head are identical before and after**; no lockout count; message never says "create a new plan" |
| P4 | Recovery of health | after a completed sync a non-stale plan and unexpired approval pass again; a touched plan stays stale |
| P5 | Audit | the chain verifies after every scenario |
| RC1 | **Takeover of a dead incremental run** | `kill -9` of the holder after some chunks: before expiry a second process gets `SYNC_BUSY`; after expiry (injected clock) exactly one process reaps and acquires. The recorded state timeline is `IN_PROGRESS` -> `INTERRUPTED(LEASE_EXPIRED)` -> `IN_PROGRESS` (new run) -> `OK`; the checkpoint equals the pre-run value `H0` until the final transaction; the replay starts from `H0`; the final index equals the oracle |
| RC2 | **Dead FULL scan beside an earlier healthy checkpoint** | `kill -9` of a FULL scan: after expiry an INCREMENTAL attempt reaps (state `INTERRUPTED(FULL_SCAN_INTERRUPTED)`), is refused `SYNC_FULL_SCAN_UNFINISHED`, makes **no** Gmail request and changes no message row; `OK` is not restored; `scan --all --resume` reuses the original baseline id and, only on completion, returns `OK`; then an incremental run is admitted |
| RC3 | Derived guard | with the status flag deliberately corrupted to `OK` (or `INTERRUPTED/LEASE_EXPIRED`) while an unfinished full scan exists, INCREMENTAL is still refused and `sync_health` is still unhealthy |
| RC4 | Reap race | two processes see the same expired lease: exactly one reaps (compare-and-swap), the other `SYNC_BUSY`; the state transition is applied once |
| RC5 | Reap without admission | a refused requester still commits the reap; repeating the attempt is idempotent; a reap never writes `OK` and never changes `history_id` |
| RC6 | Stale and legacy | a flag `IN_PROGRESS` with no `running` run is `SYNC_STATE_INCONSISTENT` (incremental refused, FULL repairs); a legacy `running` scan row is reaped and its resume establishes no checkpoint |
| LS1 | **D144** | with a `sync_state` row in each status (`OK`, `IN_PROGRESS`, `INTERRUPTED`, `NEEDS_RECONCILE`) `scan --limit` is refused with `SYNC_LIMITED_REFUSED` before any Gmail request, the database file bytes are unchanged; FULL `--all`/`--resume` and `sync` remain available; with no row a limited scan works as today and writes no checkpoint |
| G2 | **No unguarded intermediate state** | see 14.1: guard-inventory test, mutation test, handshake refusal, upgrade-refusal bytes unchanged |
| M1 | Migration | v1..v6 to v7 on synthetic data: all existing tables byte-identical, backup 0600 and valid, failure mid-way leaves the file unchanged, concurrent migrators, `ReadOnlyIndex` accepts v7 and refuses v6 |
| G1 | Boundaries | read-only scope only; adapter public methods exactly as approved; no write call reachable; metadata-only `fields`; no new dependency; no private data in logs/stdout/stderr; `LIVE_EXECUTION_ENABLED` still `False`; `scan_secrets --all` clean |
| R1 | Maintenance | each check on a corrupted synthetic database; the report changes no byte of the file; output has no paths or private values |

## 14. Implementation order, pull requests and gates
1. **This PR (documentation only).** Owner review and merge.
2. **M7A Draft PR** (#20) — the first usable sync path **and its safety interlocks together**: schema v7 and the explicit `index upgrade`, `list_history`, the lease and recovery, FULL-scan changes (baseline, atomic completion, tombstones, count check), the incremental engine (including deletion handling and tombstones), CLI, fake mailbox, `sync_health`, the **E1-E5** M4 changes (explicit owner approval at the **start of M7A**), the guard handshake, the shared test helper update; S1-S5, C1-C8, L1-L6, RC1-RC6, LS1, F1-F2, P1-P5, M1, G1, G2, U1.
3. **M7B Draft PR** (#21): the change and deletion reporting surface (per-run change summary, tombstone counts, a read-only report of which plans a sync made stale), the extended adversarial plan-anchor matrix and the documentation of the plan effect; depends on M7A.
4. **M7C Draft PR** (#22): `mailbox maintenance`, dashboard freshness fields, R1.
5. Synthetic integration and security verification (inside the last PR).
6. A **separate owner approval** before any real Gmail synchronization, then separate acceptance stages: the v7 upgrade of the real index (backup first), the baseline FULL scan, the first incremental sync, real-index verification. Operational note: do not run an old-version scan during the upgrade; after the merge the dashboard cannot open the real index until it has been upgraded once with `index upgrade`.

Per-increment acceptance: every row of section 13 assigned to it passes; the whole existing suite passes; `git diff --check` and `scripts/scan_secrets.py --all` are clean; no new dependency; no new OAuth scope; no Gmail call in any test; documentation and decision records updated.

### 14.1 No unguarded intermediate merged state (D145, D146)
The risk: a state of `main` in which an operational sync path can change the index while the M4 sync-health interlocks (E1-E5) do not exist yet. Chosen approach, the simplest safe one: **no sync path ships without its guards.** The first PR that adds any operational path that can write Gmail-derived rows with a lease (`mailbox sync`, and the FULL scan changes that write `sync_state`) is the M7A PR, and it contains `sync_health` and E1-E5. The alternative (ship the engine switched off and enable it in M7B) was rejected: it needs a flag whose later flip is itself an unguarded step, and leaves dead code in `main`. Safety does not rest on a promise not to run a command; it is enforced in code and proven by tests:

1. **Guard handshake (code-level).** `cleanup_plans` and `cleanup_exec` each declare `SYNC_GUARD_CONTRACT = 1`. Every lease acquisition (sync, FULL, LIMITED) first checks both constants and that the gate functions exist (a lightweight compatibility check; enforcement itself is proven by behavioural tests, not by reading source); otherwise it refuses with `SYNC_GUARD_MISSING` before touching the database or Gmail. A partial revert or cherry-pick that removes the guards therefore disables the sync path instead of leaving it open. There is no enable flag.
2. **Explicit upgrade of an existing index (D146).** From v7 on, `Index()` refuses to migrate an existing file whose version is below 7; the message tells the owner to run `gmail-intelligence index upgrade`, which makes the verified private `pre-m7` backup, asks for typed confirmation, and migrates. Earlier migrations (v2-v6) were automatic on any command; to v7 it is deliberate, so that merging M7A and then running any ordinary command can never silently change the owner's personal index. `ReadOnlyIndex` keeps refusing older versions. Brand-new index files are created at v7 as before. Existing migration tests pass an explicit `allow_upgrade=True`.
3. **Network gate.** Gmail is contacted only by explicit user commands that need the stored authorization; no test contacts Gmail (fake only), and no import-time or startup path starts a sync.

**Tests (all synthetic):**
- *Guard inventory:* a reflective test lists every public callable of `cleanup_plans` and `cleanup_exec` that creates, revises, reviews, approves, reserves, continues or executes, and requires each to be either on a reviewed "guarded" list (it must refuse with `SYNC_NOT_HEALTHY` when `sync_health` is patched to return a code, with no write and no audit row) or on a reviewed "always allowed" list (cancel, abort, expire, recovery, read-only views). A new public callable not on either list fails the suite.
- *Mutation:* removing the `sync_health` call from `revalidate`, from `_insert_plan`, or the handshake constants makes the matching test fail.
- *Handshake:* with a constant removed or patched, `mailbox sync`, `scan --all` and `scan --limit` refuse with `SYNC_GUARD_MISSING`, make no Gmail request and leave the database file bytes unchanged.
- *Upgrade:* a v6 file opened by every ordinary command (`mailbox status`, `sync`, `scan`, `cleanup ...`) is refused and its bytes (hash) and mtime are unchanged; `index upgrade` without confirmation changes nothing; with confirmation it creates the 0600 backup and migrates; a failed upgrade leaves the file unchanged.
- *Structural:* the CLI registers `sync` only together with the guard modules (single import of `sync_health` in `sync.py` and in `cleanup_plans.py`); a static test forbids importing a write module from any sync module.

## 15. Owner decisions (D1-D14 of the approved plan) and open items
| Plan label | Subject | Record |
|---|---|---|
| D1 | schema v7 (three tables) | D130 |
| D2 | negative `scan_id` | D133 |
| D3 | baseline FULL scan required; M4 blocked until then | D142 |
| D4 | no sync during an active execution | D134 |
| D5 | M4 fail-closed sync-health protections E1-E5 (in the M7A PR) | D135, D145 |
| D6 | prune safety: count check, 20% tripwire, tombstones | D137 |
| D7 | replay design, `MAX_RANGE_IDS = 5,000`, no watermark | D131, D132 |
| D8 | billing-threshold blocker for live use | D140 |
| D9 | read-only `list_history` in the adapter | D141 |
| D10 | sync fields in dashboard freshness | D139 |
| D11 | no scheduling | D129 |
| D12 | `SYNC_MAX_AGE` 24 hours | D143 |
| D13 | executor labels sync refusals `SKIPPED_DRIFT` (no execution-boundary change) | D135 |
| D14 | label plans are not gated | D135 |
| (added by the design PR) | single-writer lease and recovery; full-scan interlock | D134, D136 |
| (added) | LIMITED scans refused while any `sync_state` row exists (**confirmed by the owner**) | D144 |
| (added in the PR #46 correction) | E1-E5 ship with the first operational sync path, no enable flag, guard handshake | D145 (needs the owner's confirmation) |
| (added in the PR #46 correction) | explicit `index upgrade` for the v7 migration | D146 (needs the owner's confirmation) |

**Blockers for live use (not for implementation):** confirmation of the current Gmail billing terms (section 12); a separate approval for the v7 migration, the baseline scan and the first live sync; the unverified `messagesTotal` semantics (observed during the first live acceptance; fails closed until then).

## 16. Implementation notes (M7A)
Where the code made a choice the design left open, or clarified it. Behaviour and security follow sections 1-15.

| Topic | What was implemented |
|---|---|
| Modules | `sync_health.py` (read-only, no M4 imports), `sync_lease.py` (acquire / reap / admission / fence / heartbeat / guard handshake), `sync.py` (incremental engine), `scanner.py` (baseline capture, count check, prune guard, atomic completion), `gmail.py` (`list_history`), `index.py` (schema v7, explicit upgrade, fenced `_write`), `cli.py` (`mailbox sync`, `index upgrade`, scan flags), and E1-E5 in `cleanup_plans.py` / `cleanup_exec.py` |
| Fencing | `Index._write()` begins every Gmail-derived write with the fence while a lease is attached, so even the old scan helpers (`save_batch`, `set_listed`, `finish_scan`, `prune_unseen`, ...) cannot write after the lease was lost. Lease-less callers (fixtures) get a plain `BEGIN IMMEDIATE` |
| Heartbeat | Synchronous, through the same fence: before every network call (once 60 seconds have passed), at every fenced write, and between 30-second slices of every backoff or pacing sleep. It extends the lease only, never touches `sync_state.history_id`, and raises `SYNC_LEASE_LOST` instead of reviving a lost lease. A single Gmail request is bounded by the client's retries and must stay far below the 5-minute lease |
| Reap | Also covers legacy `scans` rows left `running` by code that predates v7; a changed legacy row is committed even if the requester is then refused |
| Order of checks (E2-E5) | Every guarded M4 operation calls `require_sync_health` as the FIRST thing inside its `BEGIN IMMEDIATE` transaction (`create_plan` / `_insert_plan`, `_guard` for review and approval, `reserve_execution`, `confirm_slice`), before the lockout check and before any judgement of the plan's own state. So an unhealthy index yields `SYNC_NOT_HEALTHY` even for an expired, cancelled or unknown plan: no `*_REJECTED` audit event is written and nothing counts towards a lockout. The plan's own problem (`STALE`, `BAD_STATE`, `NOT_EXECUTABLE`) is reported once health is back. `sync_only` remains as a second layer for the read-only `verify_approved` / executor paths: it treats a problem list as a health refusal when it holds a sync code and nothing but the pre-M7 partial-index codes (`INDEX_NOT_COMPLETE`, `REASON_INDEX_PARTIAL`, `ITEM_NOT_ELIGIBLE`) |
| Expiry while unhealthy | Time-driven expiry (`expire_due`, run at the start of create/review/approve) is expressly allowed in every sync condition (section 9.4) and is unchanged: it moves an overdue plan and its approval to `EXPIRED` and appends the usual `APPROVAL_EXPIRED` / `PLAN_EXPIRED` events, exactly as when healthy. The refused request itself adds nothing on top. Plan content, hashes, approval content and earlier audit entries are never touched (the existing triggers forbid it) |
| Prune guard | The 20% ceiling applies only when at least 100 messages are indexed (a tiny index would otherwise be blocked by one deleted message); the count check is always applied, with a tolerance of `max(50, 1%)` and a missing estimate counting as a mismatch |
| Handshake | `sync_lease.guard_ok()` is only a lightweight compatibility check: both `SYNC_GUARD_CONTRACT` constants and the presence of the `require_sync_health` / `sync_codes` gate in `cleanup_plans`. It does NOT read source text and is not evidence of enforcement; enforcement is proven by behavioural tests (`GuardMatrixTests`, `ExpiryUnderUnhealthySyncTests`, `GuardMutationTests`, `ConcurrencyWithSyncTests`). The CLI runs it before the index file, a reader or any request exists. `sync_lease` is the one non-CLI importer of `cleanup_exec` (to read the constant) |
| Rate limiter | `Lease.pace()` takes the budget from the limiter while temporarily replacing the limiter's OWN sleep callback by the lease-aware sliced sleep, so a limiter built by the caller (the CLI builds one with the plain `time.sleep`) can never wait unbroken past the lease, for incremental and full-scan runs alike; the heartbeat stays fenced and never touches the checkpoint |
| Lock contention | `acquire` turns a SQLite "database is locked" (an M4 write transaction held past the busy timeout) into a clean `SYNC_BUSY` refusal |
| Upgrade | `Index()` and `ReadOnlyIndex` refuse any file below v7; `index upgrade` needs a real terminal and the typed word `UPGRADE`, prints no path, and the failure message names the backup file by name only |
| Tests | `tests/test_sync_core.py`, `test_sync_lease.py`, `test_sync_health.py`, `test_sync_m4_guards.py`, `test_sync_upgrade.py`, `test_sync_cli.py`, helpers `fake_history.py`, `sync_support.py`, `sync_worker.py`, `m7_support.py`; existing tests were adapted narrowly (v6 -> v7 expectations, explicit `allow_upgrade=True` in migration tests, a healthy synthetic checkpoint seeded for the M4 fixtures) |

## 17. Change and deletion reporting, and plan impact (M7B)
Two read-only commands; neither contacts Gmail, neither needs an unlocked Keychain, neither writes (they open the index with `ReadOnlyIndex`, i.e. SQLite `mode=ro` + `query_only`, so a hidden write would fail inside SQLite). **No schema change**: they reuse the v7 counters, the linked `scans` row and the tombstones.

### 17.1 `mailbox changes [--runs N] [--json]`
Per run (newest first) plus the checkpoint status, the sync-health codes, the last completed incremental sync and the last completed full scan, and the tombstone totals by reason.

| Reported | Source (stored evidence) | Not claimed |
|---|---|---|
| **collected**: history pages, records, messages affected | `sync_run` counters, written ONCE after the whole history range was read and BEFORE any message is applied; `0` pages means "not recorded" (the run stopped earlier), never "nothing found" | that any of these messages was changed |
| **new or changed** | `sync_run.refreshed` (one combined counter) | **new vs changed is reported as "not recorded"**; it is never derived |
| **applied**: unchanged | `sync_run.unchanged`, written in the same transaction as each chunk | - |
| deleted | `sync_run.tombstoned`, cross-checked against the tombstone rows of that run | a move to Trash is a label change, counted inside "new or changed", never as deleted |
| never indexed and gone | `sync_run.vanished` | - |
| failed refreshes | `sync_run.failed` | - |
| FULL/LIMITED runs: ids listed, fetched or refreshed, failed, removed by reconciliation | the linked `scans` row; removal tombstones (`FULL_RECONCILE`) of that run | new vs changed again unavailable; an unfinished scan removes nothing |
| phase | `COMPLETED`, or `PARTIAL_*` from the run status; a `running` row is `PARTIAL_RUNNING_LEASE_ACTIVE` or `PARTIAL_ABANDONED_LEASE_EXPIRED` judged from the stored lease only | - |

**Collected versus applied.** A partial run can hold collected totals and no applied change at all (it may stop right after collection, before its first chunk). The report therefore keeps the two groups apart: *collected* (pages, records, affected messages), *applied durably* (new or changed, unchanged, deleted, never indexed and gone, failed), and, for a partial run, *not yet applied* = affected minus the applied buckets (every affected message ends in exactly one bucket), which the next run replays. The history checkpoint advanced only for a run that completed (`checkpoint_advanced_by_this_run`). A replayed range counts the same messages as *affected* in both runs, so runs must never be added together; the text says so.

**Stored text is untrusted.** Output is aggregate only: no message ids, senders, label names, account address or paths. Stored free text (`sync_run.error`, `sync_state.reason`, scan mode/status, timestamps) is never echoed: it is mapped through a strict allow-list of the diagnostic codes the sync and scan code writes (plus an HTTP status and a message count parsed from two fixed shapes); anything else is shown only as `UNRECOGNISED`. Character filtering is deliberately not used, because an alphanumeric-only secret would survive it.

### 17.2 `cleanup plan impact [--json]`
For every active plan (DRAFT, REVIEWED, APPROVED) the current local index is compared with the stored plan using the existing checks only (`revalidate`, or `verify_approved` for an approved plan; both only SELECT). It never calls `expire_due`, a `_plan_cmd` helper or anything that writes: it does not expire a plan, consume or revoke an approval, reserve an execution, append an audit event or count towards a lockout.

Reason categories (a plan lists ALL that apply; the headline is only a summary, in the order EXPIRED, STORED_PLAN_INCONSISTENT, STALE_AND_BLOCKED, STALE, BLOCKED_BY_SYNC, NOT_EXECUTABLE_APPROVAL, FRESH; closed plans are `NON_EXECUTABLE`):

| Category | Stored-evidence source |
|---|---|
| `TARGET_CHANGED` | the snapshot digests of a target differ from the current index; the report says WHICH field differs (labels, read state, sender, thread, received time, classification) or that only the scan stamp differs (`rescan_stamp_only`, e.g. after a full rescan) |
| `TARGET_DELETED_OR_ABSENT` | the target is not in the index; split by the recorded tombstone reason, or `NO_TOMBSTONE` when nothing records why |
| `CLASSIFICATION_NOT_CURRENT` | the classification of a target is stale or missing (every message a sync changed needs `classify run` again) or the rule set changed |
| `ELIGIBILITY_OR_RULES_CHANGED` | policy or protection rules changed, or a target stopped being an eligible candidate for another reason |
| `ANCHOR_CHANGED_BY_FULL_SCAN` | the plan anchor (`last_full_scan`) differs from the plan's |
| `INDEX_INCOMPLETE` | an active or unfinished full scan; an `ITEM_NOT_ELIGIBLE` caused only by the partial index is attributed here, not to the plan |
| `SYNC_NOT_HEALTHY` | the `sync_health` codes of section 9 |
| `EXPIRED` | the plan's `expires_at` has passed. If the stored state is still DRAFT/REVIEWED/APPROVED the report says "expiry not yet recorded": recording it is a write that only plan operations perform |
| `APPROVAL_NOT_USABLE` | the approval record fails its checks (past its term, not the single VALID one, audit mismatch) |
| `STORED_PLAN_INCONSISTENT` | the stored plan fails its own integrity check; no target analysis is attempted |

Findings made while the sync state is unhealthy are marked `evidence: UNCERTAIN_INDEX` (observed against an index of uncertain freshness). Approval rows are always reported as retained and immutable: a stale plan's VALID approval "can no longer authorize anything" but is never described as deleted or revoked. Stale plans are never edited or regenerated.

Limits: observations of the LOCAL index only; the executor re-reads live Gmail before any write regardless; the report is a snapshot at the time it runs.
