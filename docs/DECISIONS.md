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
| A4 | **GitHub security:** native secret scanning was unavailable in the original private repository (accepted, no plan upgrade); enable GitHub secret scanning and push protection on the public repository only if they are free; keep the local scanner as defense in depth; hooks can be bypassed (documented); Gitleaks is a possible future enhancement requiring dependency review; do not upgrade the GitHub plan. | Dependency review if Gitleaks is considered (Q10) |

## Public-release preparation decisions
| ID | Decision |
|----|----------|
| D19 | Project license: **MIT** (owner decision). Dependencies are Apache-2.0, MIT and BSD-3-Clause (no publication constraint found). |
| D20 | Before public release, commit author/committer email addresses were replaced with the maintainer's GitHub noreply address (messages, timestamps and file contents unchanged) and the cleaned history was published as a fresh repository; the original private development repository is kept as an archive. |

## M4 decisions (owner-approved direction for M4; M4A, M4B, M4C-A and M4C-B1 are merged)
| ID | Decision |
|----|----------|
| D27 | **Scope of operations.** Message-level only; no thread-wide execution. Archive and Trash are the eventual operations; the first live verification is archive only. No permanent deletion, send, forward, reply or draft operation. This narrows the broader M0B allowlist (labels, thread-level when verified, ARCHITECTURE §3/§9, P4) for M4. |
| D28 | **Eligibility policy.** Default archive age 90 days (users may only be stricter), Trash age 180 days. Unread messages are never recommended. Important, financial, educational, transactional, personal, uncertain and LOW-evidence messages are never automatic recommendations; they need a separate individual-review workflow and explicit selection if ever made actionable. STARRED, SENT, DRAFT and user-protected messages are hard-excluded. Details: [CLEANUP.md](CLEANUP.md). |
| D29 | **Trash evidence.** Gmail category or sender automation alone is never sufficient for Trash. AI output is never sufficient evidence for any cleanup eligibility. A future Trash path needs a user-defined HIGH-evidence rule or individually selected targets, age >= 180 days and a separate approval. No Trash recommendations in M4A. |
| D30 | **Approvals** bind the exact account, action, target set and canonical plan hash, expire after 24 hours and are single-use. Any change of targets or action requires a new approval. (M4B) |
| D31 | **Batching.** Maximum execution batch 100. Plans over 100 items start with a canary of 25 and need a separate continuation approval. (M4C) |
| D32 | **Audit** data stays local. A retention policy must be defined (M4B) before any live execution; recovery-relevant history is never deleted automatically. |
| D33 | **Credentials.** Separate read and write OAuth clients and Keychain entries (P6, Alternative B). The write client is not created and `gmail.modify` is not requested during M4A. |
| D34 | **Revalidation.** Gmail state is re-checked immediately before execution and drifted messages are skipped. The documentation never claims absolute protection against concurrent Gmail changes. (M4C) |
| D35 | **Constraints.** Zero Additional Cost is mandatory. No Gmail write access or live verification without a new explicit owner approval. M4A is local-only; its only schema change is v3 (`protect_rules`); candidate results are computed on demand, never stored. |

## M4B decisions (implemented; merged in public PR #8)
| ID | Decision |
|----|----------|
| D36 | **Plan model.** A plan is explicit message ids for one account and `ARCHIVE` only, frozen as canonical JSON and bound by its full SHA-256 covering every security-relevant field (ids, versions, times, policy, M3 ruleset, protection digest, index anchor, per-target digests). Targets must be currently ELIGIBLE (M4A); any ineligible id rejects the whole plan; max 500 targets; 48 h lifetime. Changes create a new version (new hash) and supersede the old plan. |
| D37 | **Approval = local ledger record only.** Typed `ACTION COUNT HASH8` bound to the reviewed version, from a real terminal only (no `--yes`, EOF/piped input fail closed), after full local re-validation; random nonce, <= 24 h, never beyond the plan, single-use, one VALID approval per plan (unique index). It authorizes no Gmail access; M4C needs a separate owner approval. A typed phrase is not strong authentication. |
| D38 | **Audit and retention.** Append-only per-account hash chain (counts/hashes only), tamper-evident under the stated assumptions: mid-chain edits are detected, deleting the newest events or the whole log is NOT detectable without an owner-recorded checkpoint (`audit verify --checkpoint`), and nothing is protected against the same OS user. Plans, approvals and audit stay local, are never deleted automatically and survive `mailbox purge`. |
| D39 | **Schema v4** adds `cleanup_plan`, `cleanup_item`, `cleanup_approval`, `cleanup_audit` with immutability/forward-only triggers and foreign keys, after an automatic private backup. No execution states exist until M4C adds them in its own migration. |
| D40 | **M4B-to-M4C contract.** The executor must call `verify_approved`, consume the approval atomically at execution start, re-validate live Gmail state per message, skip drifted messages, never auto-retry or continue after ambiguity, never widen targets, and never act from plan state alone. Overlapping plans (the same message in several plans) are allowed in M4B; each plan keeps its own approval, which the executor must consume atomically and independently, reconciling earlier or concurrent operations on the same message instead of repeating an action, and failing closed on conflicting state (see [CLEANUP.md](CLEANUP.md)). |
| D41 | **Hardening after the independent audit** (no P0-P2 findings). Backups are created exclusively with mode 600 and verified, partial ones removed; unrelated constraint errors are not reported as duplicate approvals; plan/approval state is cross-checked cheaply (triggers, approval-vs-audit) while stating that a database writer is outside the trust boundary; clock rollback is refused beyond a 5-minute tolerance; failed confirmations lock a plan for 15 minutes after 10 attempts; audit limits are validated; malformed snapshots fail with clean errors. Remaining limits are documented in [CLEANUP.md](CLEANUP.md). |

## M4C decisions (owner design direction; M4C-A merged in public PR #9 and M4C-B1 in public PR #10; M4C-C onward is not approved or started)
| ID | Decision |
|----|----------|
| D42 | **M4C scope.** ARCHIVE only. Future live calls are individual `messages.modify` (remove `INBOX` only) with a read-only `messages.get`/`threads.get(format=minimal)` check; no `batchModify` (it returns no per-message result), no trash/untrash, no thread writes. This narrows the original M4C issue text. |
| D43 | **Execution state is separate from plan state.** Plan tables stay immutable; schema v5 adds `cleanup_execution`, `cleanup_exec_slice` and `cleanup_exec_item`. A plan with an execution can no longer change state. |
| D44 | **Independent confirmations.** Plan approval (M4B), a fresh typed execution confirmation per slice (M4C), and a separate write OAuth authorization (M4C-B) are three different gates; none substitutes another. The approval is consumed atomically with the reservation of an execution and never becomes valid again. |
| D45 | **Interruption and ambiguity.** (Hardened after the M4C-A audit: `AWAITING_CONTINUATION` is separate from the final `PARTIAL`; closed reason-code vocabulary; library-generated hashed lease tokens; one clock policy; stronger schema invariants; `APPLIED` only with structured evidence.) Intent is committed before a Gmail call and the outcome after it; a crash or lost lease yields `UNKNOWN` items and `RECONCILIATION_REQUIRED`; nothing resumes or retries automatically; unknown work blocks the account until reconciled from observed state. |
| D46 | **Overlap and concurrency.** One non-final execution per account; overlapping plans never cause automatic duplicate operations (already-applied targets are pre-skipped, unresolved overlap refuses). |
| D48 | **Honest evidence terminology and strict chronology (final M4C-A micro-correction).** `verified` became `evidence_checked` (+ `evidence_source`, `evidence_observed_at`); `RECONCILED_APPLIED` became `RECONCILED_OBSERVED_ARCHIVED`; only `CALLER_SUPPLIED` evidence is accepted and `TRUSTED_ADAPTER` is reserved for M4C-C; a mutation is never attributed to our executor. Evidence may not predate the intent (or the UNKNOWN transition) by even a microsecond; times are microsecond UTC. v5 was changed directly (unmerged, no real v5 database exists; no v6). |
| D49 | **Fail-closed continuation and cross-row invariant.** No ordinary continuation after a slice with no applied item or with rejected/unknown/conflicting items (the execution finishes `FAILED`/`PARTIAL`). `EXECUTING` needs one `ACTIVE` slice: enforced at entry by trigger and unique index, at commit by the library; direct-SQL breakage is detected, not prevented. ARCHIVE intents must include `INBOX` (library and SQL). |
| D50 | **REPLACE bypass and empty label sets (final P2 correction).** `recursive_triggers` is enabled and verified on every `Index` connection and the execution insert guards refuse existing keys (also stops UPSERT); an explicit empty label observation is valid only when the previous labels were exactly `INBOX`; reports qualify "applied" as recorded, unauthenticated, unattributed observation and show the `UNSAFE_SLICE` stop. |
| D51 | **Separate write authorization (M4C-B1, offline).** A separate OAuth client file, Keychain service/item and exact `gmail.modify` scope check; the scope string exists only in `oauth_write.py`; the read-only OAuth path and token are unchanged and no command other than `auth *-write` touches the write item. Nothing is authorized live. |
| D52 | **Archive-only transport allowlist.** A thin stdlib HTTPS transport (no discovery client, no batch) behind a pure policy that permits only profile read, message/thread reads and the single mutation "remove INBOX from one message"; it is an application policy, not an OAuth-enforced limit. Checked before building and again immediately before dispatch; no redirects, proxies, automatic retries or refreshes in the transport. `httplib2` is not imported, so no dependency was added. |
| D53 | **Refresh, revocation and logout.** Refresh/revocation use a separate pinned OAuth request; the access token must have 10 minutes left before an execution; local logout never claims to revoke; `revoke-write` is explicit. Writing the refreshed token only to the write item. |
| D54 | **Executor verification.** The future executor uses the write token for its own live account verification and reads; the existing read commands stay read-only. Account verification against Google is a separately approved live step. |
| D55 | **Hardening after the M4C-B1 audit.** Rejected logins best-effort revoke the fresh grant (three reported outcomes, never when it might share a stored grant); strict revoke-response classification; post-dispatch ambiguity is always UNCERTAIN (UNKNOWN); mandatory minimal `fields` on every request and exact argument types; archive requires a successful live `verify_account()`; refresh results are scope-validated before anything is stored. |
| D56 | **Final OAuth isolation correction (M4C-B1).** The write client must be attested to live in a separate Google Cloud project (revocation is project-wide): offline fail-closed verification of recognized client-id formats, different project numbers and a fingerprint-bound attestation before any login, revoke or cleanup. Only HTTP 200 confirms a revocation. The oauthlib scope-change `Warning` payload is used (validated) to revoke an unwanted grant. Responses must be fully framed. The account-verification gate lives in the transport. |
| D57 | **Merge-preparation closeout (M4C-B1).** Project numbers must be canonical (no leading zero); the optional `installed.project_id` is validated and compared when present on both sides (equal ids contradict "separate", malformed fails closed, absent is never invented) and is bound into the attestation; a manual Google Cloud verification checklist is documented as a prerequisite of the future M4C-B2 and does not authorize login; post-consent failures are documented as possibly leaving a grant active. |
| D66 | **Trusted observation contract (M4C-C1).** Evidence with the source `TRUSTED_ADAPTER` exists only as an exact-type, final `TrustedObservation` issued by an archive adapter that verified the account, in the neutral stdlib module `exec_evidence`; the state machine handles it in a separate branch, `ACCEPTED_EVIDENCE_SOURCES` stays `("CALLER_SUPPLIED",)` and ordinary `Evidence` can never carry the trusted source. It is an in-process capability guard, not a cryptographic guarantee. |
| D67 | **One-time consumption.** An observation is validated completely, then its token is consumed before persistence; after a database failure it stays consumed and a new observation is required. Tokens are in memory only, so no crash-persistent uniqueness is claimed. |
| D68 | **Freshness and states.** Strict chronology as for other evidence, a five-minute maximum age, an explicit present/absent state, an explicit empty labels tuple only where an empty archived state is expected, and a trusted absence reconciles to `CONFLICT`. |
| D69 | **Dispatch ambiguity.** `dispatched=False` is set only at explicit pre-transmission raise sites; unknown is possibly sent; a complete HTTP error to a POST does not prove non-effect, so it is `UNKNOWN` and reconciled; no automatic POST retry. |
| D70 | **Historical `REJECTED`.** The vocabulary and schema are unchanged and existing records are not reinterpreted; the description states the recorder's assertion and the uncertainty about transmission. |
| D71 | **Reporting.** Reports distinguish caller-supplied from trusted-adapter evidence and state that an observed desired state is not proof of who made the change. |
| D72 | **C1 scope.** Only the contract, the adapter observation, dispatch metadata, reporting and fake-only tests; no executor, no orchestration, no CLI, no canary, no recovery orchestration (C2-C5 each need separate approval). |
| D73 | **Exact ordinary evidence (C1 audit correction).** Only `type(ev) is Evidence` is ordinary caller-supplied evidence; its fields are read once into a snapshot and the persisted source is the constant `CALLER_SUPPLIED`. This closes a demonstrated bypass in which a subclass with a stateful `source` property persisted `TRUSTED_ADAPTER` through `require_source`. |
| D74 | **Trusted reconciliation audit.** A valid trusted observation leaves its source and time on the item row (checked flag unchanged) and `obs`/`src`/`seen` in the `ITEM_TRANSITION` event, distinguishing archived, previous, other labels and absence without a new code or schema change. Caller-supplied storage is unchanged. |
| D75 | **Clock and binding assumptions.** The injected clock is trusted infrastructure (production: controlled UTC clock); freshness is not cryptographic. Observations are not bound to an execution or plan id; C2 must prevent cross-execution reuse. |
| D47 | **Retention.** Execution, intent and audit records are local and never deleted automatically (compatible with M4B and a later undo). |


## Product roadmap decisions (owner-approved direction; planning only, nothing implemented)
| ID | Decision |
|----|----------|
| D58 | **Product direction.** Gmail Intelligence expands beyond cleanup into a local-first platform for understanding, organizing, protecting and maintaining Gmail: M5 Intelligent Inbox Organization, M6 Inbox Intelligence Dashboard, M7 Incremental Sync & Smart Maintenance (these three expand the original M5-M7 commitments), and new M8 Important Mail & Action Center, M9 Subscription Intelligence, M10 Attachment Intelligence, M11 Ask Your Inbox. M0-M4 and every approved security requirement are preserved. Scope and gates: [PRODUCT-ROADMAP.md](PRODUCT-ROADMAP.md). |
| D59 | **Recommendation first, one execution boundary per operation class.** Each capability ships as read-only, explainable recommendations before any execution exists. Label changes, filter creation or any other mutation each need their own separately approved allowlist entry, plan, approval, audit and recovery design (the M4 pattern); nothing is created, merged, renamed or deleted automatically. |
| D60 | **Explainability.** Findings show why they appeared, their source message(s) and a confidence/uncertainty indicator, and are phrased as recommendations, never as guaranteed detections. |
| D61 | **Email content is untrusted input** for every analysis, extraction and model: never executed, never treated as instructions, no tool access, model output schema-validated, and no Gmail mutation as a side effect of analysis, a question, a dashboard view or a scheduled job. |
| D62 | **Content indexing is a separate explicit decision (Q15).** The index is metadata-only today. Subjects, snippets, bodies and attachment content are indexed only per data class with owner consent, locally, with stated retention and at-rest protection. |
| D63 | **No paid services and no external AI disclosure.** No paid API, model, dependency or hosting; optional free local inference only; nothing is sent to an external model without explicit per-use consent; attachment contents are never sent externally. |
| D64 | **Subscriptions are recommendation-only.** No automatic unsubscribe request, link visit, one-click POST or unsubscribe e-mail (sending stays forbidden); unsubscribe links are stored as host and presence flags only. |
| D65 | **Scopes and scheduling.** The recommendation phases of M5-M11 request no new OAuth scope. `gmail.settings.basic` (filters) is considered only for a separately approved filter-execution phase. Scheduled analysis is opt-in persistent configuration, read-only, with no access to write credentials. |

## M3 decisions
| ID | Decision |
|----|----------|
| D21 | Classification is local and offline over the M2 index only. Taxonomy: multi-valued **type**, separate **attention** signal, and **evidence** (LOW/MEDIUM/HIGH, not a probability). User rules always beat built-ins; ties keep compatible types and flag conflicts `REVIEW_NEEDED`. Details: [CLASSIFICATION.md](CLASSIFICATION.md). |
| D22 | Rules are plain data (exact sender/domain/label + optional unread); no regex or code execution. User rules live in SQLite (`class_rules`, per account), outside Git; `mailbox purge` keeps them. |
| D23 | Index schema v2 adds `class_rules` and `message_class` (additive). Upgrade is automatic on first open, after a private backup copy, in one transaction; no framework, no rescan. |
| D24 | Results carry the ruleset hash and scan id; a changed ruleset or rescan makes them stale. `run` is explicit (`--limit`/`--all`); `preview` never writes. Reports show domains, not addresses, unless `--show-senders`. |
| D25 | Local AI is optional, disabled by default, loopback-only, opt-in via `ai.json` plus `--ai`, domain/system-label input only, strict output schema, LOW-evidence additions only for weak messages, never above user rules. `ai_http.py` is the single module allowed to import `urllib`. Real inference NOT VERIFIED. |
| D26 | Subject/body-based classification is out of scope for M3 (the index does not store them, D16); it needs a separate collection-policy decision. |

## M2 decisions
| ID | Decision |
|----|----------|
| D15 | Local SQLite index (`index.sqlite3` in the app-data dir, 700/600, schema version 1 via `PRAGMA user_version`, no migration framework; v2 added in M3 (D23), v3 in M4A (D35), v4 in M4B (D39), v5 in M4C-A (D43)). Tables: `messages`, `message_labels` (needed for label/category counts), `labels`, `scans`. All keyed by account. |
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

## Proposed (from the private archive M0B PR #11, awaiting owner approval)
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
Note: the row labelled `Q12 update` is a historical supplement to Q12 (billing status), not a separate question; the repeated Q12 identifier is a known historical quirk and is intentionally left unchanged.

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
| Q15 | **Content-indexing scope** (M8, M10, M11): which data classes (subject, snippet, body, attachment text) may be indexed locally, with what consent, retention and at-rest protection (the SQLite index is not encrypted). |
| Q16 | **Build order** of M5-M11 after M4 (a recommendation is in PRODUCT-ROADMAP.md section 5; not binding). |
| Q17 | **Read-adapter extensions:** extra headers (`List-Unsubscribe`, `List-Id`) for M9B and attachment part metadata without body data for M10A; feasibility to be verified, each reviewed separately. |
| Q18 | **Frontend toolchain** for M6C: every dependency free, reviewed for license and supply chain (extends Q1). |
| Q19 | **Scheduling** of read-only analysis (M7 stretch): mechanism, consent and logging. |

Resolved in this correction: Q4 → A2 (approved direction); Q11 → A4 (accepted gap, no upgrade).
