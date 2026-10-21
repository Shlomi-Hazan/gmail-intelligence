# Mailbox index and reports (M2)

**Status:** implemented; covered by offline tests with synthetic data; live behavior confirmed by the owner (see "Live verification" below). Everything here is read-only: the only OAuth scope is `gmail.readonly`, and the Gmail adapter has no method that can send, modify, label, trash or delete (enforced by tests).

## Commands (project venv; see [SETUP-GMAIL.md](SETUP-GMAIL.md))
```bash
gmail-intelligence mailbox scan --limit 100   # recommended first run: newest 100 messages
gmail-intelligence mailbox scan --all         # whole mailbox; long-running; needs your explicit go-ahead
gmail-intelligence mailbox scan --resume      # continue an interrupted scan
gmail-intelligence mailbox status             # scan history + whether the index is COMPLETE or PARTIAL (local)
gmail-intelligence mailbox report             # overview, categories, labels, years/months, top sender domains (local)
gmail-intelligence mailbox top-senders [--unread] [--domains] [--limit N]   # sender addresses (local)
gmail-intelligence mailbox purge              # delete this account's locally indexed data (asks first)
```
```bash
gmail-intelligence mailbox sync               # M7A: apply recent Gmail changes from the saved history checkpoint (read-only; needs a completed `scan --all` first)
gmail-intelligence mailbox sync --status      # sync state, last runs (aggregates only) and whether cleanup plan operations are allowed (local)
gmail-intelligence index upgrade              # M7A: explicitly upgrade an older local index to schema v7 (real terminal, type UPGRADE; a private backup is made first)
gmail-intelligence mailbox changes [--runs N] [--json]   # M7B: what each sync/scan run changed (aggregates; partial runs labelled; local, read-only)
gmail-intelligence mailbox maintenance [--account EMAIL] [--deep] [--json]   # M7C: local integrity + backup + audit + sync health report (read-only; advisory; Gmail is never contacted)
gmail-intelligence cleanup plan impact [--json]          # M7B: how the current index affects stored plans (every reason listed; read-only, changes nothing)
```
`scan` and `sync` contact Gmail (history is read through `history.list`, ids only, with the existing `gmail.readonly` scope). Nothing runs in the background or on a schedule. **Cleanup plans cannot be created, reviewed, approved or executed unless the sync state is fresh** (a completed `scan --all` or `sync` within 24 hours, no run or full scan unfinished, no `NEEDS_RECONCILE`); see [SYNC.md](SYNC.md). `scan --limit` is refused once a checkpoint exists. `scan --all` has two review flags, `--accept-count-mismatch` and `--allow-large-prune`, for the cases its safety checks stop on.

Only `scan` and `sync` contact Gmail. `status`, `report`, `top-senders`, `purge`, `doctor` and `auth status` never do, and nothing starts a scan implicitly. Exit codes: 0 ok, 1 failure/incomplete, 2 usage, 130 interrupted (resume with `--resume`).

## What is requested from Gmail, stored, and displayed
| Gmail call | Fields requested | Stored locally | Shown |
|---|---|---|---|
| `labels.list` | label id, name, type | same (user label names included) | counts per label |
| `messages.list` (spam/trash included, 500 per page) | message ids, `nextPageToken` | ids only | no |
| `messages.get` (`format=metadata`, header `From` only) | id, threadId, internalDate, labelIds, sizeEstimate, `From` header | message id, thread id, date, size estimate, **sender address (lower-cased, no display name)**, unread flag, label ids | aggregated counts; addresses only in `top-senders` |

Never requested or stored: bodies, snippets, subjects, attachments, raw MIME, recipients, authentication headers, tokens. `report` shows sender *domains* only; full addresses appear only when you run `top-senders` (use `--domains` to avoid them). Subjects are deliberately not collected; adding them would be a separate, explicit decision.

## Where the data lives
`~/Library/Application Support/gmail-intelligence/index.sqlite3` (directory 700, file 600; override with `GMAIL_INTELLIGENCE_HOME`), outside Git. The sender addresses and label names in it are personal data: **Time Machine and other backups will contain this file**. It is not encrypted beyond FileVault (SQLCipher is a possible later option). Data is keyed by account; reports show only the logged-in account's rows. Remove your data with `mailbox purge`, or delete the database file to remove everything.

## Scan behavior
- Newest messages first. `--limit N` indexes the newest N; the index is then **PARTIAL by design**. `--all` pages with `nextPageToken` until the end.
- Progress is committed every 50 messages. A saved page token marks the page in progress; messages already fetched in the same scan are skipped on resume. If the saved token is rejected, the scan re-lists from the start and still skips what it already fetched.
- Ctrl+C or repeated API failures end the scan as `interrupted` (never `completed`); resume with `--resume`. Authorization failures end it as `failed` without retries.
- A **full scan completes only if every message was indexed**; then rows no longer present in Gmail are removed (Gmail is the source of truth). A scan with permanently failing messages is `incomplete` and removes nothing. Limited and interrupted scans never delete rows.
- `resultSizeEstimate`/profile totals are estimates and are not used as exact counts.

## Quota and rate limits (units are not money)
Gmail "quota units" are rate limits, not charges; no billing account is involved (see SETUP-GMAIL.md §1 for what is and is not verified). Documented costs: `messages.list` 5, `messages.get` 20 units; documented per-user budget 6,000 units/minute. The scanner spends at most 4,500 units/minute (`--max-units-per-minute`), so a mailbox of tens of thousands of messages needs on the order of an hour of fetching. Transient failures (429, 5xx, network) back off 2, 4, 8, 16 seconds (max 5 attempts) on top of the Google client's own retries; permanent errors are not retried.

## Reports
Message counts are not thread counts. Label totals overlap (a message can have several labels), so they can exceed the number of messages. Size is the sum of Gmail's `sizeEstimate`, **not** your account storage usage. Reports carry no recommendation to delete anything; cleanup belongs to M4 and requires explicit approvals.

## Live verification (maintainer-reported)
The maintainer ran a limited scan and then a full scan on their own mailbox using the read-only connection; this is their report, not something the automated tests executed. Both completed with no failures and no removed rows, the limited scan was correctly labelled PARTIAL and the full scan COMPLETE, reports were produced from the local index without contacting Gmail, and no Gmail write operation was performed. A full scan of a typical personal mailbox took on the order of an hour at the default request budget. Mailbox statistics are intentionally not published.

Known environment issue (not an M2 defect): on macOS folders synced by iCloud, an editable install can lose its `.pth` file to the hidden flag; use `pip install .` or `PYTHONPATH=src python -m gmail_intelligence ...` ([SETUP-GMAIL.md](SETUP-GMAIL.md) §7).

## Not in M2
AI classification (M3), cleanup/labels/filters (M4/M5), dashboard (M6), history-based incremental sync (M7).

M3 note: the index is schema v2 (adds `class_rules` and `message_class`; upgraded automatically with a backup, see [CLASSIFICATION.md](CLASSIFICATION.md)). `mailbox purge` also deletes stored classifications but keeps your user rules.

M4A note: the index is schema v3 (adds `protect_rules`; upgraded automatically with a backup, see [CLEANUP.md](CLEANUP.md)). `mailbox purge` keeps protection rules.

M4B note: the index is schema v4 (adds plan, approval and audit tables; upgraded automatically with a backup, see [CLEANUP.md](CLEANUP.md)). `mailbox purge` keeps plans, approvals and the audit log.

M4C-A note: the index is schema v5 (adds local execution tables; upgraded automatically with a backup, see [CLEANUP.md](CLEANUP.md)). `mailbox purge` keeps execution records.
