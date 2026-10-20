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
M5F (executing label changes), M7 incremental sync and later milestones. Any feature that changes a mailbox needs its own explicit design, owner approval and, where required, extra OAuth scopes.

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
