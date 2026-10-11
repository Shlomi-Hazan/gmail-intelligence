# Gmail Intelligence

> **Status: M0B — architecture, security and workflow documentation (in review). Gmail integration is NOT implemented.**
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

## Security and privacy commitments

- The repository is private and must never contain credentials, tokens, or mailbox data.
- Emails are treated as untrusted input.
- No modification of real Gmail data without a separately approved execution workflow.
- Least-privilege Gmail scopes; read-only first.

See `docs/SECURITY.md`. Docs index: [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Development](docs/DEVELOPMENT.md) · [Skills plan](docs/SKILLS.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md).
