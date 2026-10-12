# Security

See also: [ARCHITECTURE.md](ARCHITECTURE.md), [DECISIONS.md](DECISIONS.md), [DEVELOPMENT.md](DEVELOPMENT.md).

Nothing here is implemented yet except repo-level controls (§5). Application controls are **[Proposal]** or **[Design]** until built and tested. Evidence tags follow [ARCHITECTURE.md](ARCHITECTURE.md): **[Verified]** (checked against a cited official page), **[Unverified]**.

## 1. Principles
- Repository is PRIVATE and must remain so. No secrets, tokens, mailbox data or personal messages in Git.
- Email content is untrusted input; it is data, never instructions.
- Least privilege: read-only first; modification scopes only when needed and separately consented.
- No permanent deletion by the application.
- Skills/agents/LLMs do not grant permissions (§6).
- **Zero Additional Cost is mandatory and approved** (§1a).

## 1a. Zero Additional Cost policy (approved)
The project must incur zero additional financial cost. Security-relevant consequences: no Google Cloud Billing or billing account, no paid Cloud services, no paid LLM/AI APIs, no paid GitHub features (including the plan upgrade that would unlock native private-repo secret scanning), no paid hosting/monitoring/databases, no paid dependencies. A budget alert is **not** protection against charges; if a service has no hard spending cap and its billing status is unknown, it stays disabled. Claude Code is a development tool outside this objective; the application never depends on Claude API calls. Provider free tiers can change; nothing here promises any provider stays free. Cost verification is a mandatory acceptance criterion for every milestone ([ROADMAP.md](ROADMAP.md)).

## 1b. Gmail scope and capability facts
- `gmail.readonly` reads data and has no modification ability **[Verified]**.
- `gmail.modify` also allows composing and **sending** mail **[Verified]**. Our ban on sending, forwarding, replying and permanent deletion is therefore **an application policy, not an OAuth-enforced limit**. Permanent deletion is not exposed; `https://mail.google.com/` is never requested.
- A separate token file does not by itself create a reliable capability boundary. The required controls (read-only client types, execute-only write adapter with an operation allowlist, separate credentials, approval/plan validation) are specified in [ARCHITECTURE.md](ARCHITECTURE.md) §3 as a design requiring implementation validation.

## 2. Assets
OAuth refresh/access tokens · local SQLite metadata (reveals contacts, habits, subjects) · audit logs · Google Cloud client credentials · the user's real mailbox · repository integrity.

## 3. Reversibility classification
| Operation | Reversible? | Notes |
|---|---|---|
| Local analysis, classification, planning | Yes | No external effect |
| Add/remove label | Yes | Undo data recorded |
| Archive (remove INBOX) | Yes | Re-add INBOX |
| Move to Trash | Yes, until Gmail empties Trash after 30 days **[Verified]** | After auto-purge: **irreversible** |
| Create Filter | Yes (delete filter) | Effects on already-routed future mail are not retroactively undone |
| Permanent delete / empty Trash | **No** | **Forbidden** in app |
| Sending/forwarding mail | **No** | **Forbidden by application policy** (not OAuth-enforced under `gmail.modify`) |
| Disclosure to external AI provider | **No** (cannot be recalled) | Off by default, opt-in |
| Token leaked | Revocable, but exposure window is irreversible | Rotate/revoke |

## 4. Threat model
Controls: **P**reventive · **D**etective · **R**ecovery.

| # | Threat | Likelihood / Impact | Controls |
|---|---|---|---|
| T1 | **OAuth token theft / refresh-token exposure** (malware, backups, logs, repo) | Med / High | P: macOS Keychain (approved direction; not a defense against any malicious process running as the user), never in DB/logs/.env, two OAuth clients with the write credential reachable only by the executor (ARCHITECTURE §3.4), read-only token default, separate write token, scanner + `.gitignore`. D: log token use by scope, alert on unexpected scope. R: revoke at myaccount.google.com/permissions, rotate client secret. |
| T2 | **Sensitive local DB exposure** (stolen laptop, cloud sync of folder, backup) | Med / High | P: DB outside repo and outside synced/backed-up-to-cloud folders, 0600, FileVault where enabled, metadata-only, no bodies/attachments. Residual risk: no encryption at rest beyond FileVault until/unless SQLCipher is adopted; Time Machine backups copy the DB. D: startup permission check. R: purge command, revoke tokens. |
| T3 | **Secrets committed accidentally** | Med / High | P: `.gitignore`, local pre-commit scanner (`scripts/scan_secrets.py`, bypassable), PR checklist, PR-only `main`. D: periodic `--all` scan, review. R: rotate immediately; history rewrite only with owner approval. *GitHub secret scanning/push protection unavailable on current plan.* |
| T4 | **Prompt injection via email content** (instructions in subject/body targeting an LLM or agent) | High / High | P: LLM has no tools and cannot create plans; delimited data fields; strict output schema; Claude/agents instructed to treat email as data; plans built by deterministic code from IDs. D: flag anomalous classifications; human review of low confidence. R: undo plans. |
| T5 | **Malicious senders / spoofed metadata** (forged From, display names, Message-ID) | High / Med | P: identity by Gmail IDs not headers; don't trust `From` for destructive decisions alone; consider auth results headers; protected-senders list. D: mismatch flags. R: undo. |
| T6 | **LLM misclassification** | High / Med | P: suggestion-only; confidence thresholds; rules take precedence; protected categories never auto-actioned. D: sampling audits, review queue. R: undo/trash recovery. |
| T7 | **Dangerous search queries** (overly broad, `in:anywhere`, matching starred/important) | Med / High | P: query validation, mandatory preview (count + sample), exclusion defaults (starred, important, recent), plans store resolved IDs. D: size anomaly alerts. R: undo. |
| T8 | **Accidental bulk archive/trash** | Med / High | P: dry-run default, plan/approval separation, size caps and canary batch (Q7), explicit confirm text. D: audit log. R: stored undo data; Trash window. |
| T9 | **TOCTOU races** (mailbox changes between plan and execution) | High / Med | P: executor re-validates each item, skips drift; plan expiry; approval bound to hash. D: `skipped_changed` counts. R: re-plan. |
| T10 | **Interrupted executions / retries** | Med / Med | P: intent log before write, idempotent ops, resumable runs, reconcile by re-reading after unknown outcomes. D: stale `in_progress` detection. R: resume or undo. |
| T11 | **Insufficient Gmail API permissions** | Med / Low | P: capability check before execution; fail closed. D: typed 403 errors. R: re-consent with explicit scope disclosure. |
| T12 | **Incomplete rollback** (Trash purged, labels renamed/deleted, drift after execution) | Med / High | P: undo data per message, label IDs not names, rollback window documented. D: verify-after-undo reconcile. R: accept residual risk, document. |
| T13 | **Accidental disclosure to external AI providers** | Med / High | P: off by default, explicit consent showing data and provider, consent separate from cleanup approval, data minimization, local transfer record without sensitive content, no paid providers (zero-cost), provider policy open (Q2). D: send log review. R: none for disclosed data — treat as irreversible. |
| T14 | **Local dashboard attack** (CSRF, DNS rebinding, XSS from email strings) | Low-Med / High | P: bind 127.0.0.1, session token, Origin checks, output escaping, CSP. D: tests. |
| T15 | **Supply-chain / dependency compromise** | Low-Med / High | P: minimal, pinned and reviewed dependencies; no unreviewed Skills/MCP servers. D: dependency audit in CI (future). |
| T16 | **AI agent overreach during development** (agent runs destructive Gmail ops) | Med / High | P: no Gmail access until M1 approved; AGENTS.md rules; write client importable only by `execute`; development uses synthetic data. D: PR review. |
| T17 | **Scope misuse / capability confusion** (`gmail.modify` can send mail; reader obtaining write capability) | Med / High | P: read-only client interfaces, execute-only write adapter with strict operation allowlist, separate OAuth clients and credentials, import test (ARCHITECTURE §3). D: audit log of every privileged call. R: revoke the write client's grant. |
| T18 | **Unintended cost** (billing enabled, paid API used) | Low / Med | P: Zero Additional Cost policy; no billing account; no paid APIs/dependencies; unknown billing status blocks activation. D: per-milestone cost check. R: disable the feature. |

## 5. Repository-level controls (actual state)

### 5.1 GitHub ruleset `main-pr-only`
| Level | Statement |
|---|---|
| **Observed configuration** | Ruleset id 24874820 is `active`, targets `refs/heads/main`, has no bypass actors, and contains rules `deletion`, `non_fast_forward` and `pull_request` (0 required approvals, no status checks). GitHub also lists these three rule types for `main` via the rules API. |
| **Verified through an equivalent temporary test** | In M0B a *temporary* ruleset with the same rule set was applied to a *temporary* branch; deleting that branch was rejected ("push declined due to repository rule violations"). Both were removed. This shows rulesets are enforced for this private repository on the current plan. |
| **Expected from GitHub documentation (not tested here)** | Pull-request rule: changes reach `main` only through a PR, so direct pushes are rejected; `non_fast_forward`: force-pushes rejected. |
| **Not directly tested on `main`** | Direct-push rejection and force-push rejection against `main`; deletion rejection against `main` itself. No destructive tests were run against `main`. |
| **Not configured** | Required reviews, required status checks, signed commits, auto-merge restrictions beyond "auto-merge not enabled". |

### 5.2 Other controls
| Control | Type | State |
|---|---|---|
| Repo visibility private | Enforced by GitHub | Observed |
| Secret scanning, push protection | Native GitHub features | **Unavailable** for this private repo on the current plan (API: "not available for this repository"). **Accepted gap** (decision); the plan is not upgraded (zero-cost). |
| Local metadata index (M2): outside Git, 700/600 permissions, metadata only, account-keyed, `purge` command | Application control | Implemented, offline-tested; **backups (Time Machine) will contain sender addresses and label names**; no encryption beyond FileVault |
| macOS Keychain token storage, read-only scope check (M1) | Application control | Implemented and offline-tested; the owner reported a successful live login and read-only check (not independently reproduced by the assistant) |
| Local pre-commit scanner | **Convention** (opt-in per clone: `git config core.hooksPath .githooks`) | Covered by a 27-test regression suite (§5.3) |
| No auto-merge, Draft PRs, review checklist | **Convention** | See DEVELOPMENT.md |
| GitHub CI | Workflow file exists but is **manual-trigger only** (billing could not be verified; see DEVELOPMENT.md) | The scanner does not run automatically on PRs, so no server-side protection is claimed |

### 5.3 Local scanner: behavior and limits
- Scans the **exact staged blobs** from the Git index (not the working tree), enumerating with NUL-delimited Git output and rename/copy detection disabled, so every added/modified/type-changed entry is scanned under its destination path regardless of Git's rename/copy classification. Deleted entries are skipped.
- Fails closed: Git failures, unreadable blobs, size mismatches, unmerged index entries and unexpected exceptions exit with status 2 and block the commit. Findings exit 1.
- Output contains only an escaped path, line number and rule name; never matched content.
- Symlinks are not followed (their target text is scanned); submodule and other unusual entry types are blocked; blobs over 5 MiB are blocked (deterministic, not skipped); binary blobs are scanned as bytes and never printed.
- Sensitive filenames are matched case-insensitively (`.env*`, token/credential/client-secret JSON, keys/certificates, mail exports, SQLite files). The placeholder exemption applies only when the *entire* assigned value is an obvious placeholder.
- **Remaining bypass risks:** `git commit --no-verify`; clones where the hook is not enabled; secrets not matching the regex rules (custom formats, split/obfuscated, base64, compressed/archived content, non-UTF-16 exotic encodings); entropy-based detection is absent; low-entropy passwords; the hook runs only locally and not in CI. It reduces risk and is not a guarantee. Gitleaks may be evaluated later (dependency review required; Q10).
- Tests: `python3 -I -m unittest discover -s tests` (stdlib only, temporary repos, synthetic data).

## 6. Skills and agents policy
A Claude Skill is instructions and helper tooling. It **does not grant Gmail API permissions**; permissions derive only from OAuth scopes held by the application's tokens. Any Skill that can cause modification must go through the plan → approval → execution architecture, may not hold or request write tokens itself, and must not bypass dry-run. See [SKILLS.md](SKILLS.md).

## 7. Incident response (outline)
1. Revoke OAuth access in the Google account; delete local tokens.
2. Rotate Google Cloud client secret if exposed.
3. If a secret was committed: treat as compromised, rotate first; ask the owner before any history rewrite.
4. Record the incident in `docs/` (without secret values).

## 8. Open items
Q2 (external LLM provider policy), Q3 (Keychain implementation checks), Q5 (retention), Q7 (guardrails), Q8 (OAuth publishing status), Q9 (remaining quota facts), Q12 (billing status of Google Cloud project), Q13 (OAuth separation validation) — see [DECISIONS.md](DECISIONS.md).
