# Architecture

Status legend: **[Approved]** decided · **[Proposal]** recommended, awaiting approval · **[Future]** not built · **[Open]** unresolved (tracked in [DECISIONS.md](DECISIONS.md)).

Evidence tags: **[Verified]** = checked against the cited official Google page on 2026-10-11 (see §16) · **[Unverified]** = assumption not confirmed by a page read during M0B; must be verified before it is relied on · **[Design]** = our own decision, not a provider fact.

> Implemented to date (offline-tested; the only live Gmail write to date is ONE owner-approved real single-message archive canary that succeeded, see [M4-CLOSEOUT.md](M4-CLOSEOUT.md); live execution is disabled again and the write grant was revoked; real Gmail undo is NOT implemented; general live batch execution is NOT enabled; the list below also describes the offline state before it): read-only OAuth and Keychain storage (M1), resumable metadata scan, SQLite index and local reports (M2), deterministic rules and an optional local-model boundary (M3, real inference not verified), cleanup candidates, immutable plans, local approvals and audit (M4A-M4B), local execution state (M4C-A) and an offline, fake-tested write-authorization and archive-only transport foundation (M4C-B1). **Not implemented:** the executor (M4C-C), the live canary (M4C-D), undo (M4D), label and filter management, the dashboard, history-based sync and everything in M5-M11 (§17). Where this document describes those, it is a proposal or future work.
> **Zero Additional Cost is a mandatory, approved project-wide constraint** (§14). Provider limits and prices can change; nothing here promises that any provider stays free.

## 1. Principles

1. **[Approved]** Local-first: mailbox data is processed and stored on the user's machine.
2. **[Approved]** Read-only first; modification only after the plan/approval/execution architecture (M4) exists.
3. **[Approved]** Analysis, planning, approval and execution are separate stages with separate code paths and, where possible, separate credentials/scopes.
4. **[Approved]** Email content is untrusted input.
5. **[Proposal]** No permanent deletion, ever. "Delete" means move to Trash (Gmail empties Trash after 30 days **[Verified]**, §16).
6. **[Approved]** Zero Additional Cost (§14).

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

## 3. OAuth, scopes and the read/write capability boundary

### 3.1 What the scopes actually permit
- `gmail.readonly` **[Verified]**: read messages and settings; no modification.
- `gmail.modify` **[Verified]**: read, compose **and send**; modify messages/labels; trash. It does **not** allow immediate permanent deletion that bypasses Trash. It is therefore **broader than cleanup**.
- `gmail.settings.basic` **[Verified]**: view and change mail settings and filters.
- `https://mail.google.com/` **[Verified]**: full access including permanent deletion. **Must not be requested** for convenience or any other reason.
- `gmail.metadata` **[Verified]**: headers/labels but not bodies, and the `q` parameter of `messages.list` is **not usable** with it, so it cannot serve search-based audits.
- All of the above are in Google's *Restricted* scope table **[Verified]**; public distribution would require restricted-scope verification. This project targets personal use (Q8).

> **The application's prohibition on sending, forwarding, replying and permanent deletion is an application-level policy. It is NOT enforced by OAuth when `gmail.modify` is granted.** Safety therefore depends on the code boundary below, not on the scope.

### 3.2 Scope plan **[Proposal]**
M1-M3 `gmail.readonly` only · M4 add `gmail.modify` (separate consent, see §3.4) · M5-M11 recommendation phases add **no** scope; `gmail.settings.basic` is considered only if a filter-execution phase is separately approved (§17).

### 3.3 Required design boundaries **[Design; implementation not yet verified]**
**Read boundary**
- Audit, sync and classification components receive only a read-capable interface (a `ReadClient` type exposing `list/get/history/profile`).
- No normal application interface returns a write-capable client to those components; they cannot trigger Gmail modification.

**Write boundary**
- Only the dedicated execution engine may construct or use the write adapter.
- **Implemented at M4C-B1 (offline-tested at that point; the later live canary is recorded in M4-CLOSEOUT.md):** the write transport's allowlist permits exactly one mutation, an individual `messages.modify` that removes `INBOX` from one message (ARCHIVE only, D42), together with the minimal profile, message and thread reads. **Possible future operations are NOT approved and NOT enabled merely by being listed here:** adding or removing other labels, creating or modifying labels, moving to Trash, inverse actions (undo) and, only after a separately approved filter-execution phase (§17), creating or deleting a previewed filter. Each needs its own review, allowlist entry, approval, audit and recovery design (D59). Sending, forwarding, replying, draft sending and permanent deletion (`messages.delete`, `batchDelete`, empty Trash) are **not exposed** and have no code path.
- Every privileged call validates (a) a valid approval bound to the plan hash, (b) the exact message IDs in the plan, and (c) preconditions re-checked at execution time (§10, TOCTOU).
- Every write is preceded by an audit/intent record and followed by a result record, enabling reconciliation (§11).
- Automated test (future): importing the write adapter from any module other than `execute` fails.

### 3.4 Separating read-only and write-capable credentials: alternatives
Facts used **[Verified]**: Google's desktop flow uses a loopback redirect with PKCE and treats the client secret as non-confidential; the installed-app page states incremental authorization is not supported for installed apps; with `include_granted_scopes=true` (web-server flow) the new access token covers previously granted scopes; Testing-status external apps get refresh tokens that expire in 7 days; refresh tokens also die on revocation, 6 months of inactivity, or (with Gmail scopes) a password change; there are limits on refresh tokens per account per client (§16).
What is **not** documented in the pages read **[Unverified]**: exactly which scopes a token from a second authorization on the *same* desktop client carries when `include_granted_scopes` is omitted.

| Criterion | A. Separate grants, one OAuth client | B. Two OAuth clients (read-only client, write client) |
|---|---|---|
| Security boundary | Weak: one client ID can request any scope at runtime; the read-only process could ask for `gmail.modify` | Better: separate client IDs, separate consent records, independently revocable; still not a hard barrier if one process can read both credentials |
| Scope accumulation | Must avoid `include_granted_scopes`; resulting token scopes need verification **[Unverified]** | Natural separation: the read client is only ever authorized for read scopes |
| Token storage | Two Keychain items, same client | Two Keychain items, two clients; write item readable only by the executor |
| Refresh handling | One client's refresh-token limit shared by both grants | Independent per client; but both expire weekly in Testing status |
| Complexity | Lower | Moderate (two Desktop clients in one personal Cloud project, two configs) |
| Desktop compatibility | Loopback + PKCE | Same |
| Failure modes | Accidental scope accumulation silently gives the reader write power | Misconfigured client mix-up; two re-consents when Testing tokens expire |
| UX | One consent app name | Two consents (write consent only needed from M4) |
| Maintainability | Fewer moving parts | Clear naming; explicit mapping client->capability |
| Zero Additional Cost | Free to configure **[Unverified, §14]** | Free to configure **[Unverified, §14]** |

**Recommendation [Proposal, requires implementation validation]:** Alternative **B**, strengthened by process separation: the write client's credential and Keychain item are used only by a separate `execute` process (or at minimum a separate module that is the sole reader of that Keychain item), launched by explicit user action. Two clients alone do **not** stop a compromised single process that can read both credentials, so the Keychain ACL/process split and the code allowlist (§3.3) are part of the control, not optional. No OAuth flow or credential was created in M0B; all of this must be validated in M1/M4 before being relied on.

### 3.5 Flow and storage
- **Flow [Proposal]:** Desktop-app client, loopback redirect (`127.0.0.1`), PKCE with `S256` set explicitly **[Verified]**; the user creates the client in their own Google Cloud project without enabling billing (§14).
- **Token storage [Approved design direction — implementation not yet verified]:** macOS Keychain preferred. Before implementation verify: Python integration compatibility, item accessibility, refresh workflow, access-control behavior, safe error handling. Keychain is **not** a defense against every malicious process running with the user's privileges. Refresh tokens never go to SQLite, logs or `.env`. Fallback (encrypted file) remains an open question (Q3).
- Testing-status expiry (7 days) means weekly re-consent in practice **[Verified]**; publishing status decision remains Q8.

## 4. SQLite metadata store **[Proposal]**

- **[Approved design direction — implementation not yet verified]** SQLite with restrictive file permissions (0600), stored outside the Git repository (e.g. `~/Library/Application Support/gmail-intelligence/`), FileVault protection where available and enabled, no message bodies or attachments by default, and explicit handling of backups (Time Machine) and synchronized folders (keep the data directory out of iCloud/Dropbox-synced paths). SQLCipher is a possible future optional enhancement, not part of M0B (Q4 residual risks documented in SECURITY.md). WAL mode is a design option.
- Stores **metadata only** by default: message id, thread id, internal date, label ids, size estimate, history id, selected headers (From, To domain, Subject, List-Unsubscribe presence). **No bodies and no attachments** by default **[Proposal]**. Snippets are off by default (privacy).
- Tables (illustrative): `account`, `message`, `thread`, `label`, `sync_state` (last history id, full-sync checkpoint), `sync_run`, `classification`, `rule`, `plan`, `plan_item`, `approval`, `execution`, `execution_item`, `audit_log`.
- Schema migrations are versioned and forward-only; backups before migration.

### Identity

- Primary key `(account_id, gmail_message_id)`. Gmail message IDs are immutable for a message; thread IDs group messages and a thread's message set **changes over time** (new replies).
- RFC `Message-ID` header is stored only as a secondary, non-unique, spoofable attribute; never used as identity.
- Labels are tracked by ID, not name (names are user-editable).

## 5. Full indexing with pagination **[Proposal]**

1. Record current profile `historyId` **before** listing (anchor for later incremental sync, closing the gap for changes during indexing).
2. `messages.list` with `includeSpamTrash=true`, `maxResults=500` (documented maximum; default 100 **[Verified]**), following `nextPageToken`. `resultSizeEstimate` is only an estimate **[Verified]**.
3. Fetch details via `messages.get(format=metadata, metadataHeaders=[...])` in bounded batches (batch size and concurrency tuned to quota).
4. Upsert idempotently; after each page persist a **checkpoint** (page token, counts, run id). Page-token lifetime is not specified in the pages reviewed **[Unverified]**, so a resumed run may restart listing and relies on idempotent upserts (design).
5. Completion: reconcile counts and mark `sync_state` with the anchor `historyId`.

## 6. Incremental sync **[Proposal]**

- `history.list(startHistoryId=…)` with `historyTypes` for messageAdded/messageDeleted/labelAdded/labelRemoved, `maxResults` up to 500, following `pageToken`/`nextPageToken` **[Verified]**; apply to store transactionally; advance `historyId` only after commit.
- History is typically available for at least a week, in rare cases only hours; a 404 means the `startHistoryId` is out of range and the client must do a full sync **[Verified]**. On 404 → trigger a **full reconciliation** (re-list and diff against the store) instead of failing.
- Periodic sanity reconcile (count/ID diff) to catch missed events **[Open: Q6 frequency]**.
- Deleted-by-user messages are marked tombstoned locally, not silently dropped, for audit consistency.

## 7. Retry, rate limits, checkpoints

- Exponential backoff with jitter for HTTP 429, 5xx and 403 `rateLimitExceeded`/`userRateLimitExceeded`; start retries at >= 1 s **[Verified]**. Google's error guide does not document a `Retry-After` header **[Unverified]**; the client honors it only if present and otherwise relies on backoff (design). Non-retriable 4xx (auth, 404 for a message) surface as typed errors.
- Keep HTTP batches to <= 50 requests; larger batches and parallelism can trigger the concurrent-request limit **[Verified]**.
- Quota (documented): 1,200,000 units/minute per project and 6,000 units/minute per user **[Verified]**; there is no per-second figure on the quota page. Method costs **[Verified]**: `messages.list` 5, `messages.get` 20, `messages.batchModify` 50, `messages.trash` 20, `history.list` 2, `threads.modify` 10, `settings.filters.create` 5, `getProfile` 1. Design: a client-side token-bucket well below the per-user budget (target <= 50% of 6,000 units/minute), adaptive slow-down on throttling, separate budgets for reads and writes. Limits can change; re-verify at M2.
- Every long operation is a **resumable run** with a persisted state machine (`pending → running → paused/failed → completed`). Crash-safe: restart reads the last committed checkpoint.
- Remaining quota questions (Q9): daily limits, concurrency limit values, and behavior of bulk writes under load.

## 8. Classification

### Rules engine **[Proposal]**
- Deterministic, declarative rules over stored metadata (sender/domain, headers like `List-Unsubscribe`, labels, age, size). Rules have IDs, versions, and are unit-testable with synthetic fixtures.
- Output: `classification(message, category, rule_id, confidence, explanation)`. Rules never act; they only label locally.

### Optional LLM classification **[Approved design direction — implementation not yet verified; provider policy open: Q2]**
- **Disabled by default.** Deterministic local rules are preferred for initial classification. Under the Zero Additional Cost constraint (§14) only free local models are eligible, after performance and privacy review; paid LLM APIs are excluded.
- No private message content may be sent to an external model without explicit consent. Before any transmission the user is shown **what data** will be sent and **to which provider**. This consent is **separate** from ordinary Gmail cleanup approval. Permitted transfers are recorded locally (what category of fields, provider, time, hashes) without retaining the sensitive content itself.
- All email text is untrusted input: it is placed in a delimited data field; model output is parsed against a strict schema (category enum + confidence). The model has **no tools and no ability to create plans**; LLM output can never directly trigger a Gmail modification. It is a *suggestion* that a rule or human confirms.
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
- **Partial batch failures.** `batchModify` accepts up to 1000 IDs per request and returns an empty body on success **[Verified]**; the documentation does not state whether a batch is atomic or whether items can fail independently **[Unverified]**. Design: on any error or timeout the executor marks the batch `unknown`, then **reconciles by re-reading** the affected messages before retrying. Operations are idempotent (add/remove label sets), so retry is safe.
- **Quota behavior.** See §7; bulk operations are chunked and paced.
- **No permanent deletion.** Trash only; Gmail permanently deletes Trash contents after 30 days **[Verified]** (an irreversibility horizon). Empty-trash is never performed by the app.
- **Filters (M5, recommendation-only first).** `users.settings.filters` act on incoming messages and can add/remove labels (including TRASH and INBOX) or forward to verified addresses; only one user-defined label per filter; a filter applies to individual messages, not the whole thread **[Verified]**. Whether filters act retroactively and the maximum filter count are **not stated** in the pages reviewed **[Unverified]**; the required scope for filters is `gmail.settings.basic` per the scopes page **[Verified]**. App policy **[Proposal]**: never create filters that forward or add TRASH, and none that skip the inbox, without an explicit approved plan; every filter creation is previewed and recorded for removal.
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

- A local web SPA (React was an early direction, D5; the technology and toolchain are undecided, Q18) served locally; talks only to the local API bound to `127.0.0.1` with a per-session token and strict CORS/Origin checks (DNS-rebinding protection). The dashboard holds no Gmail tokens and cannot call Gmail directly. Rendering email-derived strings must escape/sanitize (XSS).

## 14. Zero Additional Cost constraint **[Approved — mandatory, project-wide]**

Gmail Intelligence must incur **zero additional financial cost** for setup, development infrastructure, authentication, storage, Gmail API use, AI classification, dashboard, scheduled maintenance and ongoing use. No feature justifies violating this; a feature that needs payment is disabled, replaced with a genuinely free alternative, or deferred.

Architecture consequences **[Design]**:
- Runs on the user's existing Mac: Python, stdlib SQLite, reviewed free/open-source packages, local React dashboard, local automation (no paid hosting, databases, monitoring or automation platforms).
- No Google Cloud Billing, no billing account attached, no paid Cloud services. Google Cloud project + Gmail API + OAuth consent screen are expected to need no billing, but **this is not yet verified**; unknown billing status is a blocker for M1 (the Gmail API guide page read in M0B says nothing about pricing).
- Classification is deterministic and local first. No paid LLM APIs (Anthropic, OpenAI, OpenRouter, others), no pay-as-you-go AI. Optional AI is limited to free local models after performance/privacy review. A Claude subscription is not assumed to give free programmatic API access.
- Claude Code is a development tool, not a runtime dependency; the application never depends on Claude API calls and no API-key billing is configured. Any subscription/usage-limit assumption is external to this objective.
- Gmail API budgets: stay well below published free allowances (§7). Budget alerts are not treated as protection against charges; where no hard cap exists the service stays disabled.
- Every future milestone must include a **Zero Additional Cost verification** in its acceptance criteria (see [ROADMAP.md](ROADMAP.md)).

## 15. Unresolved questions

See [DECISIONS.md](DECISIONS.md) §Unresolved.

## 16. Google documentation consulted (M0B, 2026-10-11)
Only claims tagged **[Verified]** rely on these pages:
- Scopes: https://developers.google.com/workspace/gmail/api/auth/scopes
- Quota units: https://developers.google.com/workspace/gmail/api/reference/quota
- Sync / history: https://developers.google.com/workspace/gmail/api/guides/sync and https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list
- `messages.list`: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list
- `messages.batchModify`: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/batchModify
- `messages.trash` (scopes; no retention stated): https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/trash
- Trash retention (30 days): https://support.google.com/mail/answer/7401
- Filters: https://developers.google.com/workspace/gmail/api/guides/filter_settings
- Errors/backoff: https://developers.google.com/workspace/gmail/api/guides/handle-errors
- OAuth token expiry: https://developers.google.com/identity/protocols/oauth2#expiration
- OAuth web-server / incremental authorization: https://developers.google.com/identity/protocols/oauth2/web-server
- OAuth for desktop apps: https://developers.google.com/identity/protocols/oauth2/native-app

## 17. Roadmap extensions M5-M11 **[Future; planning only, nothing implemented]**

The product direction in [PRODUCT-ROADMAP.md](PRODUCT-ROADMAP.md) adds label organization (M5), a dashboard (M6), incremental sync (M7), an action center (M8), subscription (M9) and attachment (M10) intelligence and question answering (M11). Architectural consequences, stated here so later designs do not drift:
- **Capability boundary unchanged.** Analysis, recommendation, dashboard and question paths read only the local index. They have no Gmail client, no Keychain access and no write path; mutations stay confined to the allowlisted write boundary of M4C, extended one reviewed operation class at a time.
- **The index is metadata-only today.** Subjects, snippets, bodies and attachment information are not stored. Anything content-based (M8B-M8D, M10, M11 semantic search) requires the content-indexing decision (Q15) and, for headers or attachment part metadata, a reviewed read-adapter extension (Q17), still within `gmail.readonly`.
- **Untrusted content.** Every extractor and any local model treats message-derived text as data (D61); retrieval for questions is delimited, tool-less, schema-validated and read-only.
- **Sync and plans.** Incremental sync (M7) changes the index anchor that M4 plans are bound to; its design must define how an anchor change affects approved plans before it ships.
- **Local presentation.** The dashboard stays behind §13; nothing is exposed beyond loopback.
- **Cost.** Every added dependency (frontend, parsers, local models) must pass the Zero Additional Cost review (§14).
