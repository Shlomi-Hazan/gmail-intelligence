# Gmail Intelligence

> **Status: M1 — read-only Gmail connection (in review). Owner-reported live verification succeeded (see docs/SETUP-GMAIL.md). No mailbox features exist yet.**
> No application code exists yet. This repository currently contains documentation and project scaffolding only.

## Vision

A local-first, AI-assisted Gmail management system for mailbox auditing, intelligent classification, safe bulk cleanup, Labels and Filters management, analytics, and ongoing maintenance.

## Planned core capabilities (future, not implemented)

- Read-only Gmail connection via OAuth
- Mailbox audit and local indexing
- Rule-based and AI-assisted classification
- Safe bulk cleanup with dry-run, explicit approval, and rollback
- Labels and Filters management
- Local dashboard and analytics
- Incremental sync and ongoing maintenance

## Local-first philosophy

Mailbox data is processed and stored on the user's machine. Nothing is uploaded to third-party services by default. Any future use of an external AI service must be an explicit, documented, opt-in decision (see `docs/DECISIONS.md`).

## Quick start (offline; no Gmail access)
```bash
git config core.hooksPath .githooks
python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/gmail-intelligence doctor
.venv/bin/python -I -m unittest discover -s tests
```
Setup details, Skills and the PR workflow: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Connecting Gmail (read-only, free): [docs/SETUP-GMAIL.md](docs/SETUP-GMAIL.md).

## Milestones

| Milestone | Scope |
|-----------|-------|
| M0 | Foundation & Security (M0A: GitHub bootstrap — current) |
| M1 | Gmail OAuth & Read-Only Connection |
| M2 | Mailbox Audit & Local Indexing |
| M3 | Rules & AI Classification |
| M4 | Safe Bulk Cleanup |
| M5 | Labels & Filters Management |
| M6 | Local Dashboard |
| M7 | Incremental Sync & Maintenance |

See `docs/ROADMAP.md` for details.

## Zero Additional Cost (mandatory)
The project must incur zero additional financial cost: no billing accounts, paid APIs or LLMs, paid dependencies, paid hosting or paid GitHub features. It is designed to run on the user's own Mac. A feature that would require payment is disabled, replaced with a genuinely free alternative, or deferred. Free tiers can change; nothing promises any provider stays free. See `docs/DECISIONS.md` (D8).

## Security and privacy commitments

- The repository is private and must never contain credentials, tokens, or mailbox data.
- Emails are treated as untrusted input.
- No modification of real Gmail data without a separately approved execution workflow.
- Least-privilege Gmail scopes; read-only first.

See `docs/SECURITY.md`. Docs index: [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Development](docs/DEVELOPMENT.md) · [Skills plan](docs/SKILLS.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md).
