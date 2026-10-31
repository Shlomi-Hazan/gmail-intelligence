# Gmail Intelligence

A local-first command-line tool that connects to **your own Gmail account with read-only access**, builds a private metadata index on your Mac, and reports on your mailbox (volume, senders, labels, age). It never changes your mailbox.

> **Independent project.** Gmail Intelligence is not affiliated with, endorsed by, or sponsored by Google. Gmail and Google Cloud are trademarks of Google LLC. Released under the [MIT License](LICENSE).

## What works today (milestones M0-M6 complete in their approved scopes)
- **M0** foundation, security model, documentation, local secret scanner.
- **M1** Google OAuth (desktop flow, `gmail.readonly` only), tokens in the macOS Keychain, `auth` and `gmail check` commands.
- **M2** resumable read-only mailbox scan into a local SQLite index (message ids, dates, size estimates, label ids, sender address; no bodies, subjects or attachments) and local reports: `mailbox scan | status | report | top-senders | purge`.
- **M3** offline rules and classification of the local index (`classify ...`); an optional loopback-only local model boundary, tested with a fake backend only (real inference not verified).
- **M4** safe cleanup in an owner-approved reduced scope: candidate engine, protection rules, immutable hash-bound plans, typed one-time local approvals, a hash-chained audit log, local execution state, recovery and a fake-tested executor. One owner-approved real single-message archive canary succeeded; **live execution is disabled again** (`LIVE_EXECUTION_ENABLED = False`), the write grant was revoked, and real Gmail undo is **not implemented** ([docs/M4-CLOSEOUT.md](docs/M4-CLOSEOUT.md)).
- **M5** intelligent inbox organization, **local and read-only** (`labels ...`): label hygiene report, label recommendations, proposed classification rules with the M3 preview, Gmail filter *suggestions* (text only), and offline label-change plans with typed local approvals and audit. Nothing in M5 changes Gmail, creates a label or filter, or can execute a plan ([docs/LABELS.md](docs/LABELS.md)). Upgrading an existing index to schema v6 creates an automatic backup first.

- **M6** a local, **read-only dashboard** (`dashboard serve`) and aggregate analytics (`mailbox insights`): overview, trends, senders, cleanup recommendations and history, label organization, and honest data-freshness indicators. English and Hebrew (RTL), light/dark, desktop and mobile. It listens on `127.0.0.1` only with a per-launch token, opens the index read-only, has no action buttons and needs no new dependency ([docs/DASHBOARD.md](docs/DASHBOARD.md)).
## Planned, not implemented
M5F (executing label changes), M8B-M8D (content-gated), M9B (header-gated), M10 and M11B (and any local model). **Implemented and merged, verified against synthetic data only:** M7A (incremental sync), M7B (change and deletion reporting), M7C (maintenance report) ([SYNC.md](docs/SYNC.md)) M8A-1 (the attention engine and `mailbox attention`, [ATTENTION.md](docs/ATTENTION.md); experimental weights, not validated on a real mailbox) M8A-3 (the read-only Action Center screen of the dashboard, [DASHBOARD.md](docs/DASHBOARD.md)) and M8A-2 (an inert and UNVERIFIED Gmail link contract, [GMAIL-LINK-CONTRACT.md](docs/GMAIL-LINK-CONTRACT.md); used by nothing, **no Gmail link exists anywhere**). M9A (`mailbox subscriptions`, a metadata-only, read-only review of possible low-value subscriptions that never contacts a sender, [SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md)). M11A (`mailbox ask`, deterministic answers to a fixed set of metadata questions, no model, [ASK.md](docs/ASK.md)). **Immediate priority:** M12 — Smart Bulk Cleanup, expanding M4. M12A (merged) is `cleanup discover`, a read-only grouping of the existing cleanup candidates ([CLEANUP-DISCOVERY.md](docs/CLEANUP-DISCOVERY.md)). M12B (merged): a local review of those groups (`cleanup preview`, exclusions, an exact preview and a selection digest) that freezes the reviewed selection as an ordinary M4B DRAFT plan ([CLEANUP-REVIEW.md](docs/CLEANUP-REVIEW.md)); approval is a typed local record and **nothing executes**. M12C.1 (merged): `cleanup exec recovery`, a local read-only status of open or uncertain executions ([CLEANUP-RECOVERY.md](docs/CLEANUP-RECOVERY.md)). M12C.3 (merged): the complete archive-undo infrastructure, **implemented but DISABLED** (`LIVE_UNDO_ENABLED = False`, one additional fixed write-policy request, a gated `cleanup undo` CLI and an explicit `auth refresh-write`); synthetic verification only, real Gmail behavior unverified ([M12C-UNDO-DESIGN.md](docs/M12C-UNDO-DESIGN.md)). **In development (Draft PR):** M12C.4, a separate read-only live-observation boundary for recovery and undo reconciliation (`LIVE_OBSERVE_ENABLED = False`, disabled) and the consolidated security audit ([M12C-SECURITY-AUDIT.md](docs/M12C-SECURITY-AUDIT.md)); no real Gmail access has occurred. Real Gmail acceptance has NOT occurred; upgrading a personal index and live scanning are NOT approved; Gmail write execution remains disabled (`LIVE_EXECUTION_ENABLED = False`). Any feature that changes a mailbox needs its own explicit design, owner approval and, where required, extra OAuth scopes.

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
[Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [Development](docs/DEVELOPMENT.md) · [Gmail setup](docs/SETUP-GMAIL.md) · [Mailbox index](docs/MAILBOX.md) · [Labels (M5)](docs/LABELS.md) · [Dashboard (M6)](docs/DASHBOARD.md) · [Sync (M7 design)](docs/SYNC.md) · [Skills](docs/SKILLS.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md)
