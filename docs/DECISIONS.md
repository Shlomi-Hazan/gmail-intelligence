# Decisions

Status: **Approved** (owner decision) · **Proposed** (recommended, awaiting owner approval) · **Unresolved**.

## Approved
| ID | Decision | Origin |
|----|----------|--------|
| D1 | Private GitHub repo `Shlomi-Hazan/gmail-intelligence`, default branch `main`. | M0A |
| D2 | Local-first design. | M0A |
| D3 | Feature branches + PRs; no force-push; no auto-merge. | M0A |
| D4 | No Gmail access or application code during M0A/M0B. | M0A/M0B |
| D5 | Python local application; future React dashboard (M6). | M0B brief |
| D6 | SQLite as the local metadata store. | M0B brief |
| D7 | Branch ruleset `main-pr-only` on `main` (PR required, no force-push, no deletion, 0 required approvals). Verified enforced. | M0B |

## Proposed (in PR for review)
| ID | Decision |
|----|----------|
| P1 | Scopes: `gmail.readonly` through M3; `gmail.modify` only at M4 via new consent; `gmail.settings.basic` only at M5; never `https://mail.google.com/`. |
| P2 | No permanent deletion; "delete" = Trash. |
| P3 | Plans are immutable snapshots of explicit message IDs; approval binds to plan hash. |
| P4 | Message-level operations by default; thread-level only when verified equal at execution time. |
| P5 | Metadata-only local store (no bodies/attachments by default), stored outside the repo with 0600 permissions. |
| P6 | LLM classification optional, off by default, suggestion-only, no tools, strict schema. |
| P7 | Only the `execute` module may use the write-capable Gmail client. |
| P8 | Local dependency-free secret scanner (`scripts/scan_secrets.py`) + opt-in pre-commit hook. |
| P9 | Skills plan in [SKILLS.md](SKILLS.md); Skills never grant permissions. |

## Unresolved
| ID | Question |
|----|----------|
| Q1 | Final stack/dependency review (Python version, Gmail client libs, FastAPI vs alternatives). |
| Q2 | External LLM policy: allowed at all? which fields? which provider? |
| Q3 | Token storage: OS keychain vs encrypted file. |
| Q4 | Encryption at rest for the SQLite DB (FileVault only vs SQLCipher). |
| Q5 | Retention defaults and purge policy for local metadata and audit logs. |
| Q6 | Frequency of periodic reconcile runs. |
| Q7 | Execution guardrails: max plan size, canary batch size, mandatory pause points. |
| Q8 | Google Cloud app publishing status (Testing vs verified) and refresh-token expiry implications. |
| Q9 | Verify Gmail API quotas, method costs and limits against current documentation. |
| Q10 | Whether to adopt a third-party scanner (e.g. gitleaks) in addition to the local one, after review. |
| Q11 | GitHub secret scanning / push protection are unavailable for this private repo on the current plan; accept the gap or upgrade/make tooling alternatives. |
