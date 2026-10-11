# Security

See also: [ARCHITECTURE.md](ARCHITECTURE.md), [DECISIONS.md](DECISIONS.md), [DEVELOPMENT.md](DEVELOPMENT.md).

Nothing here is implemented yet except repo-level controls (§5). Application controls are **[Proposal]** until built and tested.

## 1. Principles
- Repository is PRIVATE and must remain so. No secrets, tokens, mailbox data or personal messages in Git.
- Email content is untrusted input; it is data, never instructions.
- Least privilege: read-only first; modification scopes only when needed and separately consented.
- No permanent deletion by the application.
- Skills/agents/LLMs do not grant permissions (§6).

## 2. Assets
OAuth refresh/access tokens · local SQLite metadata (reveals contacts, habits, subjects) · audit logs · Google Cloud client credentials · the user's real mailbox · repository integrity.

## 3. Reversibility classification
| Operation | Reversible? | Notes |
|---|---|---|
| Local analysis, classification, planning | Yes | No external effect |
| Add/remove label | Yes | Undo data recorded |
| Archive (remove INBOX) | Yes | Re-add INBOX |
| Move to Trash | Yes, within ~30 days | After Gmail auto-purge: **irreversible** |
| Create Filter | Yes (delete filter) | Effects on already-routed future mail are not retroactively undone |
| Permanent delete / empty Trash | **No** | **Forbidden** in app |
| Sending/forwarding mail | **No** | **Forbidden** |
| Disclosure to external AI provider | **No** (cannot be recalled) | Off by default, opt-in |
| Token leaked | Revocable, but exposure window is irreversible | Rotate/revoke |

## 4. Threat model
Controls: **P**reventive · **D**etective · **R**ecovery.

| # | Threat | Likelihood / Impact | Controls |
|---|---|---|---|
| T1 | **OAuth token theft / refresh-token exposure** (malware, backups, logs, repo) | Med / High | P: OS keychain storage (Q3), never in DB/logs/.env, read-only token default, separate write token, scanner + `.gitignore`. D: log token use by scope, alert on unexpected scope. R: revoke at myaccount.google.com/permissions, rotate client secret. |
| T2 | **Sensitive local DB exposure** (stolen laptop, cloud sync of folder, backup) | Med / High | P: DB outside repo and outside synced folders, 0600, FileVault required, metadata-only (Q4). D: startup permission check. R: purge command, revoke tokens. |
| T3 | **Secrets committed accidentally** | Med / High | P: `.gitignore`, pre-commit scanner (`scripts/scan_secrets.py`), PR checklist, PR-only `main`. D: periodic `--all` scan, review. R: rotate immediately; history rewrite only with owner approval. *GitHub secret scanning/push protection unavailable on current plan.* |
| T4 | **Prompt injection via email content** (instructions in subject/body targeting an LLM or agent) | High / High | P: LLM has no tools and cannot create plans; delimited data fields; strict output schema; Claude/agents instructed to treat email as data; plans built by deterministic code from IDs. D: flag anomalous classifications; human review of low confidence. R: undo plans. |
| T5 | **Malicious senders / spoofed metadata** (forged From, display names, Message-ID) | High / Med | P: identity by Gmail IDs not headers; don't trust `From` for destructive decisions alone; consider auth results headers; protected-senders list. D: mismatch flags. R: undo. |
| T6 | **LLM misclassification** | High / Med | P: suggestion-only; confidence thresholds; rules take precedence; protected categories never auto-actioned. D: sampling audits, review queue. R: undo/trash recovery. |
| T7 | **Dangerous search queries** (overly broad, `in:anywhere`, matching starred/important) | Med / High | P: query validation, mandatory preview (count + sample), exclusion defaults (starred, important, recent), plans store resolved IDs. D: size anomaly alerts. R: undo. |
| T8 | **Accidental bulk archive/trash** | Med / High | P: dry-run default, plan/approval separation, size caps and canary batch (Q7), explicit confirm text. D: audit log. R: stored undo data; Trash window. |
| T9 | **TOCTOU races** (mailbox changes between plan and execution) | High / Med | P: executor re-validates each item, skips drift; plan expiry; approval bound to hash. D: `skipped_changed` counts. R: re-plan. |
| T10 | **Interrupted executions / retries** | Med / Med | P: intent log before write, idempotent ops, resumable runs, reconcile by re-reading after unknown outcomes. D: stale `in_progress` detection. R: resume or undo. |
| T11 | **Insufficient Gmail API permissions** | Med / Low | P: capability check before execution; fail closed. D: typed 403 errors. R: re-consent with explicit scope disclosure. |
| T12 | **Incomplete rollback** (Trash purged, labels renamed/deleted, drift after execution) | Med / High | P: undo data per message, label IDs not names, rollback window documented. D: verify-after-undo reconcile. R: accept residual risk, document. |
| T13 | **Accidental disclosure to external AI providers** | Med / High | P: off by default, per-run opt-in, data minimization profile, no bodies/attachments, local send log, provider allowlist (Q2). D: send log review. R: none for disclosed data — treat as irreversible. |
| T14 | **Local dashboard attack** (CSRF, DNS rebinding, XSS from email strings) | Low-Med / High | P: bind 127.0.0.1, session token, Origin checks, output escaping, CSP. D: tests. |
| T15 | **Supply-chain / dependency compromise** | Low-Med / High | P: minimal, pinned and reviewed dependencies; no unreviewed Skills/MCP servers. D: dependency audit in CI (future). |
| T16 | **AI agent overreach during development** (agent runs destructive Gmail ops) | Med / High | P: no Gmail access until M1 approved; AGENTS.md rules; write client importable only by `execute`; development uses synthetic data. D: PR review. |

## 5. Repository-level controls (actual state, verified in M0B)
| Control | Type | State |
|---|---|---|
| Repo visibility private | Enforced by GitHub | Verified |
| Ruleset `main-pr-only` (PR required, no force-push, no deletion) | **Enforced** | Verified by rejected test deletion on a temporary branch |
| Required approvals / status checks | — | Intentionally none (solo maintainer; no checks exist yet) |
| Secret scanning, push protection | **Unavailable** on current plan (API: "not available for this repository") | Not enabled |
| Local pre-commit scanner | **Convention** (opt-in per clone: `git config core.hooksPath .githooks`) | Self-tested with synthetic strings |
| No auto-merge | Convention (auto-merge not enabled) | |
| Draft PRs, review checklist, scope boundaries | **Convention** | See DEVELOPMENT.md |

The local scanner is a best-effort regex check; it can miss secrets and can be bypassed (`--no-verify`, unconfigured clone). It is not a substitute for rotation discipline.

## 6. Skills and agents policy
A Claude Skill is instructions and helper tooling. It **does not grant Gmail API permissions**; permissions derive only from OAuth scopes held by the application's tokens. Any Skill that can cause modification must go through the plan → approval → execution architecture, may not hold or request write tokens itself, and must not bypass dry-run. See [SKILLS.md](SKILLS.md).

## 7. Incident response (outline)
1. Revoke OAuth access in the Google account; delete local tokens.
2. Rotate Google Cloud client secret if exposed.
3. If a secret was committed: treat as compromised, rotate first; ask the owner before any history rewrite.
4. Record the incident in `docs/` (without secret values).

## 8. Open items
Q2 (external LLM), Q3 (token storage), Q4 (DB encryption), Q5 (retention), Q7 (guardrails), Q10–Q11 (scanner / GitHub scanning gap) — see [DECISIONS.md](DECISIONS.md).
