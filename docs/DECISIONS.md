# Decisions

Status: **Approved** (owner decision) · **Approved design direction** (owner-approved direction; implementation not yet verified) · **Proposed** (recommended, awaiting approval) · **Unresolved**.

## Approved
| ID | Decision | Origin |
|----|----------|--------|
| D1 | Private GitHub repo `Shlomi-Hazan/gmail-intelligence`, default branch `main`. | M0A |
| D2 | Local-first design. | M0A |
| D3 | Feature branches + PRs; no force-push; no auto-merge. | M0A |
| D4 | No Gmail access or application code during M0A/M0B. | M0A/M0B |
| D5 | Python local application; future React dashboard (M6). | M0B |
| D6 | SQLite as the local metadata store. | M0B |
| D7 | Branch ruleset `main-pr-only` exists and is active on `main` (rules: deletion, non_fast_forward, pull_request with 0 approvals). **Evidence level:** configuration observed; deletion rule enforcement verified only through an equivalent temporary ruleset/branch; direct-push and force-push rejection on `main` expected from GitHub documentation but **not directly tested**. See SECURITY.md §5.1. | M0B |
| D8 | **Zero Additional Cost is a mandatory project-wide constraint.** No billing accounts, paid services, paid APIs/LLMs, paid dependencies, paid GitHub features or subscriptions; a feature needing payment is disabled, replaced by a genuinely free alternative, or deferred. Every milestone's acceptance criteria include a Zero Additional Cost verification. Claude Code is a development tool outside this objective. | M0B correction |

## Approved design directions — implementation NOT yet verified
| ID | Direction | Must be verified before implementation |
|----|-----------|----------------------------------------|
| A1 | **Token storage:** macOS Keychain preferred. Keychain is not a defense against every malicious process running with the user's privileges. | Python integration compatibility; item accessibility; token refresh workflow; access-control behavior; safe error handling |
| A2 | **Local database:** SQLite with restrictive file permissions, stored outside the Git repo, FileVault where available/enabled, no message bodies or attachments by default, explicit handling of backups and synchronized folders. SQLCipher is a possible future optional enhancement (not in M0B). | Permission enforcement; backup/sync exclusion; residual-risk documentation |
| A3 | **LLM privacy:** external LLM classification disabled by default; deterministic local rules preferred; no private content to an external model without explicit consent; show what data and which provider before transmission; consent separate from cleanup approval; permitted transfers recorded locally without retaining sensitive content; email text is untrusted; LLM output never directly triggers Gmail modifications. Zero-cost: only free local models are eligible. | Provider/model policy (Q2); local-model performance and privacy review |
| A4 | **GitHub security:** accept the absence of native secret scanning for the private repo; keep repo PRIVATE; keep the local scanner as defense in depth; hooks can be bypassed (documented); Gitleaks is a possible future enhancement requiring dependency review; do not upgrade the GitHub plan. | Dependency review if Gitleaks is considered (Q10) |

## M2 decisions
| ID | Decision |
|----|----------|
| D15 | Local SQLite index (`index.sqlite3` in the app-data dir, 700/600, schema version 1 via `PRAGMA user_version`, no migration framework). Tables: `messages`, `message_labels` (needed for label/category counts), `labels`, `scans`. All keyed by account. |
| D16 | Collection policy: ids, dates, size estimate, label ids, unread flag and the lower-cased `From` address only. No bodies, snippets, subjects, attachments or other headers. Reports show sender domains; addresses only via `top-senders`. Subjects deferred until explicitly approved. |
| D17 | Scans: newest first, 500 ids/page, one metadata fetch per message under a 4,500 units/minute budget (75% of the documented 6,000), checkpoints every 50 messages, resume via saved page token with a safe restart fallback. Rows are pruned only after a COMPLETE full scan. |
| D18 | `*.sqlite3`/`*.db` stay git-ignored; iCloud conflict copies (`* 2.*`) are ignored too. |

## M1 decisions
| ID | Decision |
|----|----------|
| D12 | M1 uses a **single read-only Desktop OAuth client** with exactly the `gmail.readonly` scope (PKCE, loopback, no `include_granted_scopes`). The separate write client from the M0B recommendation (P6) is deferred to M4. Granted scopes are verified and anything broader is rejected. |
| D13 | Tokens live in the macOS Keychain via `keyring` (verified at runtime to be the macOS backend; no plaintext fallback). The OAuth client file is stored with mode 600 under `~/Library/Application Support/gmail-intelligence/`. Live behavior: the owner reported a successful login with tokens stored in the Keychain (their terminal output; not independently reproduced). |
| D14 | Reviewed free dependencies: `google-api-python-client`, `google-auth-oauthlib`, `keyring`. The Gmail adapter exposes only `get_profile` and `list_labels` (label ids/types, no names). |
| Q12 update | See docs/SETUP-GMAIL.md §1: still no official statement that a personal Gmail OAuth app is free; no official page requires billing. The live setup is a manual checkpoint: stop if any billing prompt appears. |

## M0C decisions
| ID | Decision |
|----|----------|
| D9 | Package `gmail_intelligence` (src layout, stdlib-only, `unittest`, argparse CLI with `version` and offline `doctor`). Approved by the M0C brief. |
| D10 | CI workflow is committed but **manual-trigger only** until the owner confirms the account has no payment method / $0 Actions budget (private-repo minutes beyond the free quota bill when a payment method exists; the API did not expose billing settings). Free quota per GitHub docs: 2,000 min/month on GitHub Free. |
| D11 | Four read-only/advisory project Skills; no Gmail-operational Skills until the functionality exists. |

## Proposed (from M0B PR #11, awaiting owner approval)
| ID | Proposal |
|----|----------|
| P1 | Scopes: `gmail.readonly` through M3; `gmail.modify` only at M4; `gmail.settings.basic` only at M5; never `https://mail.google.com/`. Note: `gmail.modify` also permits sending, so the no-send rule is an application policy. |
| P2 | No permanent deletion; "delete" = Trash. |
| P3 | Plans are immutable snapshots of explicit message IDs; approval binds to plan hash. |
| P4 | Message-level operations by default; thread-level only when verified equal at execution time. |
| P5 | Read/write capability boundary: read-only interfaces for audit/classify; write adapter with a strict operation allowlist used only by `execute`; no send/forward/reply/permanent-delete code path. |
| P6 | **OAuth separation: Alternative B** — two Desktop OAuth clients (read-only and write), separate Keychain items, write credential reachable only by the executor (preferably a separate process). Alternative A (one client, separate grants) rejected as a weaker boundary and dependent on undocumented scope behavior. Full comparison in ARCHITECTURE.md §3.4. Requires validation in M1/M4. |
| P7 | Local dependency-free secret scanner + opt-in pre-commit hook, with the stdlib regression suite. |
| P8 | Skills plan in SKILLS.md; Skills never grant permissions. |
| P9 | Only the `execute` module may use the write-capable client. |

## Unresolved
| ID | Question |
|----|----------|
| Q1 | Final stack/dependency review (Python version, Gmail client libs, FastAPI vs alternatives) — each dependency must be free. |
| Q2 | Which (free, local) LLM, if any; what fields may ever be sent externally, if at all. |
| Q3 | Keychain implementation checks (see A1); fallback if Keychain proves unsuitable (encrypted file?). |
| Q5 | Retention defaults and purge policy for local metadata and audit logs. |
| Q6 | Frequency of periodic reconcile runs. |
| Q7 | Execution guardrails: max plan size, canary batch size, mandatory pause points. |
| Q8 | Google Cloud app publishing status (Testing vs other); weekly refresh-token expiry in Testing status; restricted-scope verification applies to public distribution. |
| Q9 | Remaining quota facts: daily limits, concurrency limit values, behavior under bulk writes. Verified per-minute quotas and method costs are recorded in ARCHITECTURE.md §7/§16. |
| Q10 | Whether to adopt Gitleaks later (dependency review, free licence). |
| Q12 | **Billing status (M0C research, still not proven).** Official pages read: Google's "create a project" guide lists billing as optional and says only that you *might* need it depending on the APIs used; the Gmail API guide pages and quota page say nothing about pricing or billing; the consent-screen help says an unpublished (Testing) app needs no verification. So: no evidence that a personal Gmail OAuth app needs billing, but no official statement that it is free. **M1 blocker/gate:** before creating anything, the Cloud console flow for creating the project, enabling the Gmail API and configuring the consent screen must complete without any billing prompt; if a billing account or card is requested at any step, stop and report. |
| Q13 | Validate OAuth separation (A vs B): token scope behavior of a second authorization on the same desktop client is undocumented in pages read. |
| Q14 | Claude Code subscription/usage-limit assumptions (external to the application's zero-cost objective). |

Resolved in this correction: Q4 → A2 (approved direction); Q11 → A4 (accepted gap, no upgrade).
