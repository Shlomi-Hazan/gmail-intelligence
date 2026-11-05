# Master plan (single authoritative roadmap)

**Status of this document: planning and status record only.** It authorizes no feature, no live Gmail operation, no OAuth scope, no dependency and no change to any security boundary. Every item below that touches Gmail, credentials or the personal index still needs its own written owner approval. It does **not** declare production readiness.

**Baseline:** `main` at `b332a601da1cf8d338573eb55cc7063836b6d346` (2026-11-05). Local suite and last CI: 1,781 tests, 1 skipped (CI run 41297708619 on the M12E head; later changes to `main` were documentation only). `LIVE_EXECUTION_ENABLED`, `LIVE_UNDO_ENABLED` and `LIVE_OBSERVE_ENABLED` are all `False` in `main`.

**Authority and precedence.** This file is the status authority. Older documents ([ROADMAP.md](ROADMAP.md), [PRODUCT-ROADMAP.md](PRODUCT-ROADMAP.md), [M4-CLOSEOUT.md](M4-CLOSEOUT.md), [REAL-GMAIL-ACCEPTANCE-PLAN.md](REAL-GMAIL-ACCEPTANCE-PLAN.md), the per-milestone design documents) keep their historical and design content, but where they disagree on *current status* this file wins. Decisions stay in [DECISIONS.md](DECISIONS.md); the security model stays in [SECURITY.md](SECURITY.md).

---
## 1. How status is recorded (four separate levels)
A capability is never described by one word. Each is tracked on four independent levels:

| Level | Meaning | Evidence that counts |
|---|---|---|
| **IMPL** | The code is merged in `main` | merged PR, source |
| **SYNTH** | Verified with synthetic data, fake Gmail wire and mocked credentials; no real mailbox | automated tests in CI, local runs |
| **REAL** | Exercised once or more against the owner's real Gmail under written authorization | owner-reported or owner-confirmed evidence, redacted (counts and safe codes only; local audit log stays on the owner's machine) |
| **ACCEPT** | Final product acceptance: the capability meets its acceptance criteria in a defined scope and is cleared for use in v1.0 | an acceptance record signed off by the owner |

"Implemented but disabled" means IMPL and SYNTH only. Nothing is at ACCEPT as a whole product yet; individual acceptance results are recorded in section 5.

## 2. The eight stages
| # | Stage | Purpose |
|---|---|---|
| 0 | Foundations & Security | repository, tooling, OAuth boundaries, secret handling, security model, zero-cost rule |
| 1 | Gmail Data & Sync | read-only access, local metadata index, incremental sync, integrity |
| 2 | Intelligence & Recommendations | classification and all recommendation engines (read-only) |
| 3 | Dashboard & Review Experience | the local read-only UI and review workflows |
| 4 | Safe Live Operations | every Gmail mutation path, its gates, recovery and real-Gmail acceptance |
| 5 | Product Hardening | security audit, performance, backup/retention, packaging, operations |
| 6 | Personal Product v1.0 | integration, owner dogfooding and the v1.0 sign-off |
| 7 | Advanced Intelligence v2.0 | content-gated and other features that need new decisions |

### Stage 0 — Foundations & Security
- **Done (IMPL+SYNTH, M0 and M1 REAL):** repository, Skills, tests, secret scanner and local hook, one manual CI workflow (`workflow_dispatch`, `contents: read`), architecture and security model, read-only OAuth (`gmail.readonly`) with Keychain storage, separate write OAuth client/project and Keychain item, project-wide Zero Additional Cost rule, consolidated security audit ([M12C-SECURITY-AUDIT.md](M12C-SECURITY-AUDIT.md): no Critical or High finding).
- **Remaining:** decide OAuth app publishing status (Q8: Testing mode revokes refresh tokens after 7 days, observed in practice); retention and purge policy (Q5); optional external audit-head checkpoint routine for F4; dependency/licence review before v1.0 (Q1, Q10); billing status wording (Q12) stays "no billing account exists".
- **Gate:** G0 (below).

### Stage 1 — Gmail Data & Sync
- **Done:** M2 metadata index and reports (REAL: limited and full scans, owner-reported); M7A incremental sync with checkpoint, M7B change/deletion reporting, M7C maintenance report (IMPL+SYNTH). **REAL, 2026-11-01 to 2026-11-04:** schema v6 to v7 migration of the personal index with verified backups; limited scans; one full read-only scan (completed, zero failures, guarded prune accounted by tombstones); one incremental sync (completed, zero failures).
- **Remaining:** M9B (`List-Unsubscribe`/`List-Id` headers) and M10A (attachment metadata) need read-adapter extensions (Q17); scheduled or opt-in periodic analysis (Q19, deferred, never unattended mutation); `--resume` and reconcile paths are SYNTH only.
- **Gate:** G1.

### Stage 2 — Intelligence & Recommendations
- **Done (IMPL+SYNTH, all read-only):** M3 rules and optional local-AI boundary (real inference NOT verified); M5A-M5E labels, recommendations, rule proposals, filter suggestions, offline label plans; M8A-1 attention engine; M9A subscription review; M11A metadata question answering; M12A cleanup discovery, M12B review and plan creation.
- **Remaining:** M5F (executing label changes, not implemented); content-gated M8B-M8D, M10B, M11B (blocked on the content-indexing decision Q15, therefore Stage 7); evaluation of the engines on the owner's real data (ATTENTION-EVALUATION.md describes the method); M9B and M10A after Q17.
- **Gate:** G2.

### Stage 3 — Dashboard & Review Experience
- **Done (IMPL+SYNTH):** M6A-M6C analytics, loopback token-protected read-only API, bilingual RTL/LTR light/dark UI; M8A-3 Action Center; M12E Cleanup area (seven read-only tabs). REAL: the dashboard was exercised in a browser on synthetic data only.
- **Remaining:** M11A dashboard integration; a real-data usability, performance and accessibility pass on the personal index (the cold-load fix was measured on synthetic 17k indexes); a launch/packaging story (Stage 5).
- **Gate:** G3.

### Stage 4 — Safe Live Operations
- **Done:** M4 archive-only write boundary, immutable plans, typed approvals, durable intent, independent post-read, executor, recovery; M12C archive undo, read-only observation and reconciliation (both IMPL+SYNTH, gates off); M12D bounded bulk archive and bulk reversal (IMPL+SYNTH, gate off); **REAL: two single-message archive canaries on the personal account (M4, 2026-10; M12 acceptance, 2026-11-04, PASS, section 5).**
- **Remaining (critical path):** real single-message **Undo** (issue #41), real **Observation/reconcile**, a fixed bounded multi-message test mechanism (the canary exception covers exactly one message), real **bounded bulk archive** (up to 25 dedicated messages) and **bulk reversal**, write-token usability decisions, audit-tail checkpoint routine (F4). Trash/untrash, deletion, `batchModify` and any other mutation class are **out of scope for v1.0**.
- **Gate:** G4 (the most important), per-capability sub-gates G4a-G4d.

### Stage 5 — Product Hardening
- **Remaining:** final security review of the exact release candidate; failure-injection and long-run behavior against real Gmail (rate limits, token expiry mid-slice, laptop sleep); backup/restore and retention procedure and a tested restore; log/privacy review; dependency freeze and licence check; packaging and a documented install/run path (venv today); user guide (CLEANUP, DASHBOARD, SETUP) refreshed to final behavior; runbook for UNKNOWN/CONFLICT recovery; decision on enabling CI on pull requests (needs billing certainty, see DEVELOPMENT.md).
- **Gate:** G5.

### Stage 6 — Personal Product v1.0
- Integration of Stages 0-5 for one owner and one account: read-only intelligence plus bounded, owner-typed archive cleanup with verified undo and recovery. Owner dogfooding period, v1.0 acceptance record, tagged release. Definition of Done in section 9.
- **Gate:** G6.

### Stage 7 — Advanced Intelligence v2.0
- Everything that needs a new decision, new data classes or a new mutation class. Backlog in section 10.

## 3. Mapping of historical milestones and issues to stages
History is preserved: milestone and issue numbers do not change.

| Historical item | Stage | Status (IMPL / SYNTH / REAL / ACCEPT) | Refs |
|---|---|---|---|
| M0A-M0C foundation, security, Python, tests, Skills | 0 | Y / Y / n.a. / done | private archive PRs |
| M1 OAuth read-only | 0, 1 | Y / Y / Y / done | private archive PR |
| M2 audit and index | 1 | Y / Y / Y / done | private archive PR |
| M3 rules and AI classification | 2 | Y / Y / rules only; local inference NOT verified | #1, PR #2 |
| M4A-M4D safe cleanup, closeout | 4 (foundations 0) | Y / Y / one real archive canary / reduced scope accepted | #3-#6, PRs #7-#10, #33-#40, [M4-CLOSEOUT.md](M4-CLOSEOUT.md) |
| M4 deferred follow-ups | 4 | tracker, open | #41 |
| M5A-M5E labels and organization | 2 | Y / Y / not run on real data / n.a. | #12-#16, PR #42 |
| M5F label execution | 4 (post-v1.0 unless promoted) | not implemented | no issue |
| M6A-M6C dashboard | 3 | Y / Y / not on real data | #17-#19, PRs #43-#45 |
| M7A-M7C sync and maintenance | 1 | Y / Y / real sync and full scan run once | #20-#22, PRs #46-#50 |
| M7 scheduled analysis | 1 (deferred) | not implemented | Q19; milestone M7 is still open |
| M8A-1/2/3 attention engine, link contract, Action Center | 2, 3 | Y / Y / not run on real data | #23, #51-#53, PRs #54-#56 |
| M8B-M8D deadlines, replies, documents | 7 | content-gated, not started | #24-#26 |
| M9A subscription review | 2 | Y / Y / no | #27, PR #57 |
| M9B list headers | 1 then 2 | not started | #28 |
| M10A-M10B attachments | 1 / 7 | not started | #29, #30 |
| M11A metadata Q&A | 2 | Y / Y / no | #31, PR #58 |
| M11B semantic search | 7 | content-gated | #32 |
| M12A discovery | 2 | Y / Y / not run on real data | #59, PR #64 |
| M12B review and approval | 2, 4 | Y / Y / canary plan lifecycle only (group preview not run) | #60, PR #65 |
| M12C recovery, undo, observation, audit | 4 | Y / Y / **not yet** (undo, observation) | #61, PRs #66-#69 |
| M12D bounded bulk and bulk reversal | 4 | Y / Y / **not yet** | #62, PR #70 |
| M12E cleanup experience | 3 | Y / Y / synthetic browser only | #63, PR #71 |
| Real Gmail acceptance plan | 4 | plan merged; Phases A, B1, B2, C executed | PR #72, [REAL-GMAIL-ACCEPTANCE-PLAN.md](REAL-GMAIL-ACCEPTANCE-PLAN.md) |

## 4. Status and evidence matrix (capabilities)
| Capability | IMPL | SYNTH | REAL | ACCEPT |
|---|---|---|---|---|
| Read-only OAuth, Keychain, account checks | Y | Y | Y | partial (Testing-mode expiry open, Q8) |
| Metadata index, scan, sync, maintenance | Y | Y | Y (limited scan, full scan, incremental sync, v7 migration) | not signed off |
| Classification (rules) | Y | Y | rules run on real index | no |
| Local-AI classification | Y (boundary) | fake backend only | no | no |
| Labels/recommendations/filters/label plans (M5) | Y | Y | no | no |
| Analytics and read-only dashboard (M6, M8A-3, M12E) | Y | Y | no | no |
| Attention queue, subscriptions, Ask (M8A, M9A, M11A) | Y | Y | no | no |
| Cleanup discovery, review, plans, approvals, audit | Y | Y | Y (one real plan, review, approval) | no |
| Archive execution, one message (canary) | Y | Y | **Y (M4, M12 acceptance)** | **single-message scope: PASS (section 5)** |
| Bounded bulk archive | Y | Y | no | no |
| Archive undo (single item) | Y | Y | no | no |
| Bulk reversal | Y | Y | no | no |
| Live observation / reconciliation | Y | Y | no | no |
| Recovery status (local, read-only) | Y | Y | Y (read-only status on real journal) | no |
| Label execution (M5F), Trash, delete, batchModify | no | no | no | not in v1.0 |
| Content-gated features, local semantic search | no | no | no | v2.0 |

## 5. Acceptance results to date
**M12 single-message archive acceptance: PASS (2026-11-04).** Scope: exactly one dedicated test message in the owner's personal account, sent from a different address; planned with the narrow canary exception; plan, review and approval typed by the owner; one archive request removing `INBOX` only; independent post-read recorded as trusted evidence; execution `EXECUTED`, one item `APPLIED`, zero `UNKNOWN`/`CONFLICT`; audit chain intact; the owner independently confirmed in Gmail that the message left the Inbox, remained in All Mail and that no other label changed, and that the command reported one archive request. Evidence is the owner's confirmation plus local journal and audit log (never published). Run from a temporary local acceptance branch that was deleted and never merged; `main` kept all gates `False`.

What this does **not** show: Undo, Observation, bulk archive, bulk reversal and any multi-message behavior have **not** passed real-Gmail acceptance. The acceptance test message remains archived until the Undo acceptance restores it. This result does not make the product production-ready.

## 6. Critical path to v1.0
Dependencies are strict: an item cannot start before its predecessors pass their gate. Estimates are **indicative owner-approved working sessions** (one session is one approved block of work with review), not commitments; elapsed time depends on review turnaround.

| # | Item | Stage | Depends on | Deliverables | Estimate |
|---|---|---|---|---|---|
| P0 | Merge this master plan and focused doc corrections; recommended issue structure (section 12) | 0 | none | MASTER-PLAN.md, corrected docs | 1 session |
| P1 | Real single-message **Undo** acceptance (reuse #41) | 4 | M12 archive PASS, fresh checkpoint, write login | acceptance branch with only `LIVE_UNDO_ENABLED` change (plus bulk and archive kept blocked), reversal of the already-archived test message, independent Gmail verification, closeout | 2 sessions |
| P2 | Real **Observation/reconcile** acceptance | 4 | P1 (a settled item to observe) | `LIVE_OBSERVE_ENABLED` branch, read-only observation of the restored message, zero mutation requests | 1-2 sessions |
| P3 | Design and review of a bounded **multi-message test mechanism** (<= 25 dedicated messages, same hard protections) | 4 | P1 | design note, reviewed code change, synthetic tests; no live use | 3-4 sessions |
| P4 | Real **bounded bulk archive** (up to 25 dedicated messages) | 4 | P3 and P2 | acceptance branch, 25 prepared test messages, per-slice phrases, post-checks | 2 sessions |
| P5 | Real **bulk reversal** of that set (F5 thread rule) | 4 | P4 | reversal plan run, verification | 1-2 sessions |
| P6 | Operational hardening: token UX and Q8 publishing decision, F4 checkpoint routine, retention, backup/restore test, runbooks | 5 | P1 (informs) | doc and small code items, tested restore | 3-4 sessions |
| P7 | Real-data dashboard and engine review (usability, performance, accessibility, recommendation quality) | 3, 2 | P0 | findings list, fixes | 3-5 sessions |
| P8 | Packaging, install path and user guide | 5 | P6, P7 | documented install, refreshed guides | 2 sessions |
| P9 | Final security audit of the release candidate and **v1.0 acceptance** | 5, 6 | P1-P8 | audit report, signed acceptance record, tagged release | 2-3 sessions |

Indicative total: about 20-28 sessions, roughly 8-14 weeks at the current cadence. P7 and P6 can run in parallel with P3-P5. Real-Gmail items (P1, P2, P4, P5) each repeat the Phase A-C pattern of the acceptance plan (offline preflight, backup, fresh checkpoint, typed phrases, independent verification, branch deletion) and always need fresh written approvals.

## 7. Explicit security gates
Each gate must be passed in writing by the owner before the next stage item may run. None is passed implicitly by merging code.

| Gate | Condition |
|---|---|
| G0 | Secret scan clean, zero-cost check, OAuth separation verified, no real data in the repository |
| G1 | Index schema stable and backed up; sync health `OK` and fresh before any plan operation |
| G2 | Recommendations never mutate; content data classes decided (Q15) before any content feature |
| G3 | Dashboard loopback-only, token-protected, GET-only, no mutation endpoint |
| G4 | For each live capability separately: written authorization, gate enabled only in a temporary local acceptance branch (never merged), typed phrases by the owner, no automatic retry, independent post-read, owner's independent Gmail check, branch deleted afterwards. Sub-gates: **G4a** undo, **G4b** observation, **G4c** bounded bulk archive, **G4d** bulk reversal |
| G5 | Final security review of the release candidate; no open Critical/High finding |
| G6 | v1.0 Definition of Done met and signed by the owner |
All three `LIVE_*` constants stay `False` in `main` until the owner approves a reviewed code change that enables a capability for ordinary use. That decision is **not** part of this plan and would be a separate post-acceptance change.

## 8. Prioritized execution backlog
Order follows the critical path. "Existing issue" means reuse; new issues are proposed in section 12 only where none fits.

| Priority | Item | Existing issue |
|---|---|---|
| 1 | P0 documentation consolidation | none needed |
| 2 | Real Undo acceptance (P1) | #41 |
| 3 | Real Observation acceptance (P2) | #41 |
| 4 | Multi-message test mechanism design (P3) | #62 (reopen) or new child |
| 5 | Real bounded bulk archive and reversal (P4-P5) | #62 / #41 |
| 6 | Hardening items (P6) | new tracking issue |
| 7 | Real-data dashboard and engine review (P7) | #19 / #23 comments or new |
| 8 | Packaging and guides (P8) | new |
| 9 | v1.0 audit and acceptance (P9) | new |
| deferred | M5F, M7 scheduling, M9B, M10A | #28, #29, none |
| v2.0 | content-gated work | #24-#26, #30, #32 |

## 9. Version 1.0 Definition of Done
v1.0 is a **personal, single-account, local-first** product. It is done when all of the following hold and the owner has signed the acceptance record:
1. **Safety:** no code path can mutate Gmail without a typed owner confirmation; all mutation classes are limited to archive (remove `INBOX`) and undo (add `INBOX`); no Trash, deletion, send, draft, label creation or `batchModify` exists.
2. **Real-Gmail acceptance passed** for: single-message archive (done), single-message undo, read-only observation/reconcile, bounded bulk archive (<= 25 dedicated messages) and its reversal; each with independent owner verification in Gmail.
3. **Recovery:** UNKNOWN and CONFLICT outcomes are shown, never auto-retried, and a documented recovery runbook has been exercised at least in synthetic form and read-only observation in real form.
4. **Privacy:** metadata-only index (no subjects, snippets, bodies, recipients, attachment content); nothing personal in the repository, CI logs or issues; backups private.
5. **Cost:** Zero Additional Cost verified (no billing account, no paid service or dependency).
6. **Security:** final audit of the release candidate with no open Critical or High finding; dashboard boundary tests pass; secret scan clean; the gates in `main` are either `False` or deliberately enabled by a separate reviewed, approved change.
7. **Quality:** full test suite green in CI for the tagged commit; documentation (user guide, runbook, security, decisions) consistent with behavior; known limitations listed (F4 audit-tail truncation, `gmail.modify` breadth F6, Testing-mode token expiry unless resolved).
8. **Usability:** the owner has used the read-only dashboard and recommendations on the real mailbox for an agreed dogfooding period and accepted the results.
Explicitly **not** required for v1.0: content-based features, local semantic search, scheduled unattended analysis, label execution, multi-account.

## 10. Version 2.0 backlog (not started, each needs its own decision)
- Content indexing decision (Q15) and the gated features: deadlines and payments (#24), awaited replies and follow-up (#25), important documents (#26), per-item attachment content analysis (#30), local semantic search (#32).
- Real local-model inference (Q2): validation on real data, privacy review, free licence.
- Executing label changes (M5F) and filter creation, each with its own write-policy review.
- Opt-in scheduled read-only analysis (Q19) with consent and logging; never unattended mutation by default.
- Subscription interaction (unsubscribe) as recommendation-only guidance; no automatic visits.
- Attachment metadata search (M10A) and duplicates (needs Q17).
- Multi-account support; richer reporting and export; optional encryption of the local index (SQLCipher).

## 11. Open decisions and blockers
| # | Decision / blocker | Needed for | Owner |
|---|---|---|---|
| D-1 | OAuth app publishing status vs weekly token expiry (Q8) | P1+, P6 | owner |
| D-2 | Approach for a bounded multi-message test set (P3) | P4 | owner + review |
| D-3 | Whether v1.0 includes bulk archive or stops at single-message plus bounded batch | scope | owner |
| D-4 | Content-indexing scope (Q15) | v2.0 | owner |
| D-5 | CI on pull requests (billing certainty, DEVELOPMENT.md) | P6, P9 | owner |
| D-6 | Retention/purge policy (Q5) and audit-head checkpoint routine (F4) | P6 | owner |
| D-7 | Local-model choice (Q2) | v2.0 | owner |
| D-8 | Packaging form (venv vs installer) | P8 | owner |
| B-1 | Real Undo/Observation untested: no ordinary use of those paths | v1.0 | resolved by P1-P2 |
| B-2 | M7 milestone still open although all its issues are closed; M7 scheduling is the only deferred part | tracking | see section 12 |
| B-3 | The acceptance test message remains archived | P1 | resolved by P1 |
| B-4 | The write authorization created for the acceptance is still stored locally (its access token expires within the hour, the Testing-mode refresh token after 7 days); the owner decides to revoke now (`auth revoke-write`) or keep it for P1 | security hygiene | owner, before P1 |

## 12. Recommended minimal GitHub structure (not created in this change)
Reuse existing issues and avoid duplicates:
- **Reopen #62** (or keep it closed and use child comments) only when P3 starts; alternatively track P3-P5 under #41.
- **Keep #41 open** as the single tracker for real Undo, Observation and bulk acceptance (P1, P2, P4, P5); add a checklist comment mirroring section 6 instead of new issues.
- **Create one milestone "v1.0 Personal Product"** that holds only items without an existing issue: one issue "Hardening (P6, P8)" and one issue "v1.0 audit and acceptance (P9)", and attach #41 to it.
- **Create one milestone "v2.0 Advanced Intelligence"** and move the content-gated issues #24, #25, #26, #30, #32 (and #28, #29) into it instead of keeping them in M8-M11.
- **Close milestone M7** (all issues closed; scheduling is deferred under v2.0 backlog), keep M8-M11 for history or retitle after the move.
- No new issues per stage name; the stage names live in this document.
These steps are recommendations; each GitHub change needs the owner's go-ahead.

## 13. Documentation consistency report
**Corrected in this change (focused edits):**
1. `ROADMAP.md` M12 line was stale and duplicated ("M12D in development", "M12E in development", duplicate M12D text). Replaced by current status and a pointer to this file.
2. `README.md` described M12E as "In development (Draft PR)"; corrected to merged, with the real-Gmail status.
3. `CANARY.md` said opening the index "upgrades a v4 index to v5 after an automatic verified backup"; since D146 no implicit upgrade exists (`index upgrade` is explicit). Corrected, and added the missing requirement that a fresh sync checkpoint is needed for plan, approval and execution.
4. `M12D-BULK-EXECUTION.md` and `M12C-SECURITY-AUDIT.md` said acceptance would use a "throwaway account"; the owner decided to use dedicated test messages in the existing account. Aligned and pointed to the acceptance plan.
5. `REAL-GMAIL-ACCEPTANCE-PLAN.md` said "plan only"; added an execution record (Phases A, B1, B2, C done; D not run).
6. `PRODUCT-ROADMAP.md` carries a banner that this file supersedes it for status.

**Remaining (proposed, not applied here):**
- `PRODUCT-ROADMAP.md` section 1 baseline and section 6 "Proposed GitHub tracking (NOT created)" are outdated (the issues exist). Proposed fix: shrink section 1 to a pointer and rewrite section 6 as "created; see MASTER-PLAN section 3".
- `M4-CLOSEOUT.md` and `ARCHITECTURE.md` state "the write grant was revoked": true at M4 closeout; the M12 acceptance created and then left a new write authorization stored locally. Proposed: add "as of 2026-11-04 a write authorization is stored locally; its Testing-mode refresh token expires in 7 days; revoke after use".
- `SECURITY.md` section 8 (open items) should list F4, F6 and the Testing-mode expiry; check wording against `M12C-SECURITY-AUDIT.md`.
- `DECISIONS.md`: add a D156 recording that the real archive acceptance used a temporary unmerged acceptance branch and that the personal account was used.
- `docs/DEVELOPMENT.md` should link this file and describe the acceptance-branch pattern.
- Milestone M7 remains open on GitHub (section 12).
