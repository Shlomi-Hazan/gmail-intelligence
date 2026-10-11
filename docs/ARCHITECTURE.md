# Architecture

Status legend: **[Approved]** decided · **[Proposal]** recommended, awaiting approval · **[Future]** not built · **[Open]** unresolved (tracked in [DECISIONS.md](DECISIONS.md)).

> Nothing described here is implemented. The repository contains documentation and tooling only.
> Gmail API quota numbers and limits below are from general knowledge and **must be re-verified against current Google documentation before M1/M2** **[Open: Q9]**.

## 1. Principles

1. **[Approved]** Local-first: mailbox data is processed and stored on the user's machine.
2. **[Approved]** Read-only first; modification only after the plan/approval/execution architecture (M4) exists.
3. **[Approved]** Analysis, planning, approval and execution are separate stages with separate code paths and, where possible, separate credentials/scopes.
4. **[Approved]** Email content is untrusted input.
5. **[Proposal]** No permanent deletion, ever. "Delete" means move to Trash (recoverable for ~30 days).

## 2. System overview **[Proposal]**

```
                 ┌────────────────────────── local machine ──────────────────────────┐
 Gmail API  ◄──► │ GmailAdapter ─► Indexer/Sync ─► SQLite store ─► Rules + (LLM) ─►   │
 (HTTPS)         │      ▲ read scope     (checkpoints)   (metadata)   Classifier       │
                 │      │                                               │              │
                 │      │                                          Planner ──► Plan (immutable, hashed)
                 │      │                                               │              │
                 │  Executor ◄── verified approval (binds plan hash) ◄──┘ Approval gate │
                 │  (only module holding a modify-capable token)                       │
                 │                                                                     │
                 │  Local API (127.0.0.1)  ◄──►  future React dashboard (M6)           │
                 └─────────────────────────────────────────────────────────────────────┘
```

### Module boundaries (Python, package `gmail_intelligence`) **[Proposal]**

| Module | Responsibility | May call Gmail? |
|---|---|---|
| `gmail` (adapter) | Thin wrapper over Gmail REST; pagination, retry, quota handling, typed errors. Exposes a *read* client and a separate *write* client. | Yes |
| `auth` | OAuth flow, token storage/refresh, scope management | Google OAuth only |
| `store` | SQLite access, migrations, repositories | No |
| `sync` | Full indexing + incremental sync, checkpoints, reconciliation | via read client |
| `classify` | Rules engine; optional LLM classifier behind an interface | No |
| `plan` | Turns classifications/queries into immutable plans (explicit ID lists) | No |
| `approve` | Records human approvals bound to a plan hash | No |
| `execute` | Applies approved plans; the only importer of the write client | via write client |
| `audit` | Append-only log of plans, approvals, executions, undo data | No |
| `api` | Local HTTP API for CLI/dashboard | No (calls modules above) |

Rule **[Proposal]**: only `execute` may import the write client; enforced by an import-linter style test once code exists.

Language/stack: Python 3.12+, `google-api-python-client`/`google-auth-oauthlib`, SQLite (stdlib `sqlite3`), FastAPI for the local API. **[Proposal — dependency choices unreviewed, Q1]**

## 3. OAuth and token handling

- **Scopes [Proposal]**:
  - M1–M3: `gmail.readonly` only. (`gmail.metadata` is lighter but does not support the `q` search parameter, so it cannot serve search-based audits.)
  - M4: add `gmail.modify` (labels, archive, trash). Requires a **new, explicit consent** and a separate token. The read-only token remains the default for all analysis.
  - M5: Filters need `gmail.settings.basic`; requested only when M5 starts.
  - **Never** request `https://mail.google.com/` (full access; the only scope allowing permanent delete).
- **Scope escalation [Proposal]**: incremental authorization; the app refuses write operations when only read scopes are held; the UI/CLI states the exact scopes before the consent redirect. Revocation instructions documented.
- **Flow [Proposal]**: installed-app (loopback) OAuth with PKCE; client ID created by the user in their own Google Cloud project (not part of this repo).
- **Storage [Open: Q3]**: preference is OS keychain (macOS Keychain via `keyring`); fallback encrypted file with 0600 permissions. Refresh tokens are never written to the SQLite DB, logs, or `.env`.
- Google "Testing" status apps have refresh tokens that expire after ~7 days; production verification for sensitive scopes is a consideration **[Open: Q8]**.

## 4. SQLite metadata store **[Proposal]**

- Location outside the repo (e.g. `~/Library/Application Support/gmail-intelligence/`), file mode 0600, WAL mode. **[Open: Q4 encryption at rest]** (rely on FileVault vs SQLCipher).
- Stores **metadata only** by default: message id, thread id, internal date, label ids, size estimate, history id, selected headers (From, To domain, Subject, List-Unsubscribe presence). **No bodies and no attachments** by default **[Proposal]**. Snippets are off by default (privacy).
- Tables (illustrative): `account`, `message`, `thread`, `label`, `sync_state` (last history id, full-sync checkpoint), `sync_run`, `classification`, `rule`, `plan`, `plan_item`, `approval`, `execution`, `execution_item`, `audit_log`.
- Schema migrations are versioned and forward-only; backups before migration.

### Identity

- Primary key `(account_id, gmail_message_id)`. Gmail message IDs are immutable for a message; thread IDs group messages and a thread's message set **changes over time** (new replies).
- RFC `Message-ID` header is stored only as a secondary, non-unique, spoofable attribute; never used as identity.
- Labels are tracked by ID, not name (names are user-editable).

## 5. Full indexing with pagination **[Proposal]**

1. Record current profile `historyId` **before** listing (anchor for later incremental sync, closing the gap for changes during indexing).
2. `messages.list` with `includeSpamTrash=true`, `maxResults=500`, following `nextPageToken`.
3. Fetch details via `messages.get(format=metadata, metadataHeaders=[...])` in bounded batches (batch size and concurrency tuned to quota).
4. Upsert idempotently; after each page persist a **checkpoint** (page token, counts, run id). Page tokens are short-lived, so a resumed run may restart listing and rely on idempotent upserts.
5. Completion: reconcile counts and mark `sync_state` with the anchor `historyId`.

## 6. Incremental sync **[Proposal]**

- `history.list(startHistoryId=…)` with `historyTypes` for messageAdded/Deleted/labelAdded/labelRemoved; page through results; apply to store transactionally; advance `historyId` only after commit.
- If Gmail returns 404 (history too old/invalid) → trigger a **full reconciliation** (re-list and diff against the store) instead of failing.
- Periodic sanity reconcile (count/ID diff) to catch missed events **[Open: Q6 frequency]**.
- Deleted-by-user messages are marked tombstoned locally, not silently dropped, for audit consistency.

## 7. Retry, rate limits, checkpoints

- Exponential backoff with jitter for HTTP 429, 5xx and `rateLimitExceeded`/`userRateLimitExceeded`; honor `Retry-After` when present. Non-retriable 4xx (auth, 404 for a message) surface as typed errors.
- Client-side token-bucket limiter below the per-user per-second quota; adaptive slow-down on throttling. Reads and writes use separate budgets so a sync cannot starve an execution and vice versa.
- Every long operation is a **resumable run** with a persisted state machine (`pending → running → paused/failed → completed`). Crash-safe: restart reads the last committed checkpoint.
- Quota behavior to verify **[Open: Q9]**: per-user per-second limits, per-minute unit budgets, and cost per method (e.g. `messages.get`, `batchModify`).

## 8. Classification

### Rules engine **[Proposal]**
- Deterministic, declarative rules over stored metadata (sender/domain, headers like `List-Unsubscribe`, labels, age, size). Rules have IDs, versions, and are unit-testable with synthetic fixtures.
- Output: `classification(message, category, rule_id, confidence, explanation)`. Rules never act; they only label locally.

### Optional LLM classification **[Proposal; Open: Q2]**
- **Off by default.** Local model preferred. Any external provider requires explicit opt-in, a documented data-minimization profile (e.g. sender domain + subject only; no bodies/attachments), per-run confirmation, and a local log of exactly what was sent (hashes, not content).
- Email text is placed in a delimited data field; model output is parsed against a strict schema (category enum + confidence). The model has **no tools and no ability to create plans**. Its output can only be a *suggestion* that a rule or human confirms.
- Low-confidence or disagreeing results go to a human review queue. Misclassification is expected and measured (sampling audits).

## 9. Analysis → Planning → Approval → Execution

| Stage | Input | Output | Side effects |
|---|---|---|---|
| Analysis | store | stats, classifications | none (local only) |
| Planning | classifications / query | **Plan**: immutable list of explicit message IDs + action, plus summary & hash | none |
| Approval | Plan | Approval record bound to plan hash, expiry, scope of actions | none |
| Execution | approved Plan | Execution record, per-item results, undo data | Gmail writes |

Key rules **[Proposal]**:
- Plans contain **resolved ID snapshots**, never live queries, so what was approved is exactly what runs.
- Approval is invalidated if the plan changes, expires, or the token scope is insufficient.
- Allowed actions (M4): add/remove label, archive (remove `INBOX`), move to Trash, and their inverses. Not allowed: permanent delete, forwarding, sending mail.
- Dry-run is the default mode; execution requires an explicit, separate command/click.
- Size guardrails: large plans require staged execution (e.g. a small canary batch first, then pause for confirmation) **[Open: Q7 thresholds]**.

## 10. Gmail-specific concerns

- **Message vs thread operations.** Gmail labels apply per message; the UI thinks in threads. `threads.modify/trash` affects *all* messages in the thread, including ones that did not match the criteria or arrived after planning. Default: **message-level** operations. Thread-level only if, at execution time, the thread's full message set equals the planned set (verified by re-fetch).
- **Partial thread matches.** A search like `from:x` can match one message in a thread of many. The plan lists matched vs. unmatched messages per thread and flags mixed threads for review.
- **Concurrent mailbox changes (TOCTOU).** Between planning and execution the user or filters may change messages. Executor re-fetches each item (label set / history id) and skips items that drifted, recording them as `skipped_changed`.
- **Partial batch failures.** `batchModify` does not give per-item results; on any error or timeout the executor marks the batch `unknown`, then **reconciles by re-reading** the affected messages before retrying. Operations are idempotent (add/remove label sets), so retry is safe.
- **Quota behavior.** See §7; bulk operations are chunked and paced.
- **No permanent deletion.** Trash only; Trash auto-purge by Gmail after ~30 days is documented as an irreversibility horizon. Empty-trash is never performed by the app.
- **Filters (M5).** `users.settings.filters` apply to *future incoming* mail only (not retroactive), have a per-account maximum count, and criteria are limited. App policy **[Proposal]**: no filters that auto-delete, forward, or skip inbox without an explicit approved plan; every filter creation is previewed and recorded for removal.
- **Search query safety.** Queries are validated and previewed (count + sample) before becoming plans; overly broad queries (empty, `in:anywhere`, bare `*`) are rejected for modifying plans.

## 11. Failure recovery and state reconciliation

- Executions write an **intent log before** calling Gmail and a result after. On restart, any `in_progress` item is reconciled by reading actual state.
- Every modifying execution records **undo data** (previous label set per message). Undo is itself a plan requiring approval. Trash is reversible within Gmail's retention window; permanent loss is not possible via the app.
- Store ↔ Gmail drift is detected by reconcile runs; Gmail is the source of truth.
- Corrupt/lost DB is recoverable by re-indexing (store is a cache of Gmail metadata), except audit logs which are backed up separately.

## 12. Local privacy and retention **[Proposal]**

- Metadata only; configurable retention and a `purge` command; no telemetry; logs contain IDs only, never subjects/addresses by default.
- Exports are explicit, local, and git-ignored.
- See [SECURITY.md](SECURITY.md).

## 13. Dashboard boundary (M6) **[Future]**

- React SPA served locally; talks only to the local API bound to `127.0.0.1` with a per-session token and strict CORS/Origin checks (DNS-rebinding protection). The dashboard holds no Gmail tokens and cannot call Gmail directly. Rendering email-derived strings must escape/sanitize (XSS).

## 14. Unresolved questions

See [DECISIONS.md](DECISIONS.md) §Unresolved (Q1–Q9).
