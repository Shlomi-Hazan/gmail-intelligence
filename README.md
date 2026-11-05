# Gmail Intelligence

A local-first command-line tool that connects to **your own Gmail account with read-only access**, builds a private metadata index on your Mac, and reports on your mailbox (volume, senders, labels, age). It is read-only by default: the only mailbox changes it can make are separately gated, owner-typed archive and undo steps that are disabled in `main` (see *Current status at a glance*).

> **Independent project.** Gmail Intelligence is not affiliated with, endorsed by, or sponsored by Google. Gmail and Google Cloud are trademarks of Google LLC. Released under the [MIT License](LICENSE).

## Current status at a glance (2026-11-05; authority: [docs/MASTER-PLAN.md](docs/MASTER-PLAN.md))
| Capability | Real-Gmail status |
|---|---|
| Read-only scan, index, incremental sync, local reports and dashboard | used on the owner's real mailbox (metadata only); ordinary read-only use |
| Single-message archive (remove `INBOX`), owner-typed, plan-bound | **real acceptance PASSED (2026-11-04)**, run from a temporary, never-merged acceptance branch; scope: one dedicated test message |
| Archive undo of one message (add `INBOX` back), owner-typed, per item | **real acceptance PASSED (2026-11-05)**: the dedicated test message was restored to the Inbox with its original labels; again from a temporary, never-merged acceptance branch |
| Read-only observation of the recorded canary messages (account check and one labels read per record; no modification request) | **real acceptance PASSED (2026-11-05)** from a temporary, never-merged acceptance branch; the `UNKNOWN`-reconciliation decision logic is verified with synthetic data only |
| Bounded bulk archive, bulk reversal | implemented, verified with synthetic data only, **DISABLED**, **NOT accepted against real Gmail** |
| Trash, deletion, `batchModify`, label execution, content features | not implemented |
All three live gates (`LIVE_EXECUTION_ENABLED`, `LIVE_UNDO_ENABLED`, `LIVE_OBSERVE_ENABLED`) are `False` in `main`. This is early-stage software, not declared production-ready.

## What works today (milestones M0-M6 complete in their approved scopes)
- **M0** foundation, security model, documentation, local secret scanner.
- **M1** Google OAuth (desktop flow, `gmail.readonly` only), tokens in the macOS Keychain, `auth` and `gmail check` commands.
- **M2** resumable read-only mailbox scan into a local SQLite index (message ids, dates, size estimates, label ids, sender address; no bodies, subjects or attachments) and local reports: `mailbox scan | status | report | top-senders | purge`.
- **M3** offline rules and classification of the local index (`classify ...`); an optional loopback-only local model boundary, tested with a fake backend only (real inference not verified).
- **M4** safe cleanup in an owner-approved reduced scope: candidate engine, protection rules, immutable hash-bound plans, typed one-time local approvals, a hash-chained audit log, local execution state, recovery and a fake-tested executor. One owner-approved real single-message archive canary succeeded at M4 closeout, and a second one passed the M12 acceptance (2026-11-04); live execution is **disabled** in `main` (`LIVE_EXECUTION_ENABLED = False`). Single-message archive undo later passed real acceptance (2026-11-05) from a temporary, never-merged acceptance branch and is disabled in `main` (M4 closeout, a historical snapshot: [docs/M4-CLOSEOUT.md](docs/M4-CLOSEOUT.md)).
- **M5** intelligent inbox organization, **local and read-only** (`labels ...`): label hygiene report, label recommendations, proposed classification rules with the M3 preview, Gmail filter *suggestions* (text only), and offline label-change plans with typed local approvals and audit. Nothing in M5 changes Gmail, creates a label or filter, or can execute a plan ([docs/LABELS.md](docs/LABELS.md)). Upgrading an existing index to schema v6 creates an automatic backup first.

- **M6** a local, **read-only dashboard** (`dashboard serve`) and aggregate analytics (`mailbox insights`): overview, trends, senders, cleanup recommendations and history, label organization, and honest data-freshness indicators. English and Hebrew (RTL), light/dark, desktop and mobile. It listens on `127.0.0.1` only with a per-launch token, opens the index read-only, has no action buttons and needs no new dependency ([docs/DASHBOARD.md](docs/DASHBOARD.md)).
## Implemented with synthetic verification, disabled, or planned
M5F (executing label changes), M8B-M8D (content-gated), M9B (header-gated), M10 and M11B (and any local model). **Implemented and merged (synthetic verification; M7 sync and scan were also run once, read-only, on the owner's real mailbox):** M7A (incremental sync), M7B (change and deletion reporting), M7C (maintenance report) ([SYNC.md](docs/SYNC.md)) M8A-1 (the attention engine and `mailbox attention`, [ATTENTION.md](docs/ATTENTION.md); experimental weights, not validated on a real mailbox) M8A-3 (the read-only Action Center screen of the dashboard, [DASHBOARD.md](docs/DASHBOARD.md)) and M8A-2 (an inert and UNVERIFIED Gmail link contract, [GMAIL-LINK-CONTRACT.md](docs/GMAIL-LINK-CONTRACT.md); used by nothing, **no Gmail link exists anywhere**). M9A (`mailbox subscriptions`, a metadata-only, read-only review of possible low-value subscriptions that never contacts a sender, [SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md)). M11A (`mailbox ask`, deterministic answers to a fixed set of metadata questions, no model, [ASK.md](docs/ASK.md)). **Immediate priority:** M12 — Smart Bulk Cleanup, expanding M4. M12A (merged) is `cleanup discover`, a read-only grouping of the existing cleanup candidates ([CLEANUP-DISCOVERY.md](docs/CLEANUP-DISCOVERY.md)). M12B (merged): a local review of those groups (`cleanup preview`, exclusions, an exact preview and a selection digest) that freezes the reviewed selection as an ordinary M4B DRAFT plan ([CLEANUP-REVIEW.md](docs/CLEANUP-REVIEW.md)); approval is a typed local record and **nothing executes**. M12C.1 (merged): `cleanup exec recovery`, a local read-only status of open or uncertain executions ([CLEANUP-RECOVERY.md](docs/CLEANUP-RECOVERY.md)). M12C.3 (merged): the complete archive-undo infrastructure, **disabled in `main`** (`LIVE_UNDO_ENABLED = False`, one additional fixed write-policy request, a gated `cleanup undo` CLI and an explicit `auth refresh-write`); the single-message undo passed real acceptance on 2026-11-05, bulk reversal did not ([M12C-UNDO-DESIGN.md](docs/M12C-UNDO-DESIGN.md)). M12C.4 (merged): a separate read-only live-observation boundary for recovery and undo reconciliation (`LIVE_OBSERVE_ENABLED = False`, disabled) and the consolidated security audit ([M12C-SECURITY-AUDIT.md](docs/M12C-SECURITY-AUDIT.md)); single-message undo and read-only observation of settled records later passed real acceptance (2026-11-05); `UNKNOWN` reconciliation has not been run on real data. **Merged (M12D, M12E):** M12E (#63), the read-only Cleanup area of the dashboard covering the whole lifecycle ([CLEANUP-DASHBOARD.md](docs/CLEANUP-DASHBOARD.md)); M12D, controlled bulk archive execution and bulk reversal plans (with a strict thread rule), **implemented but DISABLED**, synthetic verification only ([M12D-BULK-EXECUTION.md](docs/M12D-BULK-EXECUTION.md)). Real-Gmail acceptance exists **only** for the single-message archive (PASS, 2026-11-04) the single-message undo (PASS, 2026-11-05) and read-only observation of settled records (PASS, 2026-11-05); bounded bulk archive and bulk reversal have **not** passed it, and live execution, undo and observation stay disabled in `main` (all three gates `False`). Any feature that changes a mailbox needs its own explicit design, owner approval and, where required, extra OAuth scopes.

## Requirements and limitations
- macOS (tokens use the macOS Keychain), Python 3.10+, and a Google account.
- **You must create your own Google Cloud project and OAuth client** (free; do not link a billing account). No credentials are shipped or shared; follow [docs/SETUP-GMAIL.md](docs/SETUP-GMAIL.md).
- Personal apps in Google's Testing mode get refresh tokens that expire after 7 days, so you re-run `auth login` weekly.
- The local index contains sender addresses and label names; it is not encrypted beyond FileVault and will appear in backups ([docs/MAILBOX.md](docs/MAILBOX.md)).
- Early-stage software: no stability guarantees.

## Local-first and privacy
Mailbox data stays on your machine. Nothing is sent to third-party services, and no AI service is used. Email content is treated as untrusted input. Never share OAuth files, tokens or index files; see [SECURITY.md](SECURITY.md).

## Quick start
```bash
git clone https://github.com/Shlomi-Hazan/gmail-intelligence.git && cd gmail-intelligence
git config core.hooksPath .githooks            # optional: local secret-scan hook for contributors
python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/gmail-intelligence doctor            # offline prerequisite check
.venv/bin/python -I -m unittest discover -s tests   # offline tests, no Google account needed
```
Then connect Gmail ([docs/SETUP-GMAIL.md](docs/SETUP-GMAIL.md)) and run `mailbox scan --limit 100`.

## Zero additional cost
The project is designed to cost nothing: no billing accounts, paid APIs, paid dependencies or hosting. Free tiers can change; nothing promises that a provider stays free ([docs/DECISIONS.md](docs/DECISIONS.md) D8).

## Documentation
[Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [Development](docs/DEVELOPMENT.md) · [Gmail setup](docs/SETUP-GMAIL.md) · [Mailbox index](docs/MAILBOX.md) · [Labels (M5)](docs/LABELS.md) · [Dashboard (M6)](docs/DASHBOARD.md) · [Cleanup in the dashboard (M12E)](docs/CLEANUP-DASHBOARD.md) · [Master plan](docs/MASTER-PLAN.md) · [Real Gmail acceptance plan](docs/REAL-GMAIL-ACCEPTANCE-PLAN.md) · [Sync (M7 design)](docs/SYNC.md) · [Skills](docs/SKILLS.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md)
