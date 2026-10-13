# Roadmap

No dates are assigned. Everything below M0A is **future** and requires approval to start.

- **M0 — Foundation & Security** (M0A bootstrap: done; M0B architecture/security/workflow: merged in private archive PR #11; M0C Python foundation, tests, Skills: merged in private archive PR #13). **M0-M2 are complete.**
- **M1 — Gmail OAuth & Read-Only Connection** (merged in private archive PR #14; owner-reported live check succeeded)
- **M2 — Mailbox Audit & Local Indexing** (merged in private archive PR #15; owner-reported limited and full scans succeeded)
- **M3 — Rules & AI Classification** (merged in [PR #2](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/2); offline rules, local store and CLI verified; the optional local-AI boundary is tested with a fake backend only, real inference NOT VERIFIED - see [CLASSIFICATION.md](CLASSIFICATION.md))
- **M4 — Safe Cleanup** (dry-run, approvals, rollback). Phases M4A candidate engine and protection rules (merged in [PR #7](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/7)), M4B plans/approvals/audit (merged in [PR #8](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/8)), M4C write authorization and executor (M4C-A local execution state merged in [PR #9](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/9); M4C-B1 offline write-auth and transport foundation merged in [PR #10](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/10), no live setup; M4C-B2/B3 client configuration and authorization, M4C-C executor and M4C-D live canary pending and separately gated), M4D recovery/undo/audit.

**Product direction (owner-approved; planning only, nothing below is implemented).** After M4 the project grows from mailbox cleanup into a local-first platform
for understanding, organizing, protecting and maintaining Gmail. Every item ships recommendation-first and read-only; any mutation needs its own separately
approved execution boundary. Each milestone is split into small increments and has its own approval gates. Details, MVP/stretch scope, dependencies, privacy
and security boundaries, acceptance criteria and the proposed GitHub tracking are in [PRODUCT-ROADMAP.md](PRODUCT-ROADMAP.md).

- **M5 — Intelligent Inbox Organization** (expands the original *Labels & Filters Management*): label hygiene report, smart label and tag recommendations, suggested rules with preview, nested-label and duplicate/unused-label detection, then (separately approved) label-change plans and audited execution. Recommendation-only first.
- **M6 — Inbox Intelligence Dashboard** (expands the original *Local Dashboard*): explainable, aggregated, privacy-safe overview, top senders, newsletters and notifications, trends and cleanup outcomes; local, read-only.
- **M7 — Incremental Sync & Smart Maintenance** (expands the original *Incremental Sync & Maintenance*): incremental indexing, change and deletion detection, integrity checks, user-triggered or opt-in scheduled read-only analysis, maintenance recommendations. No unattended Gmail mutation by default.
- **M8 — Important Mail & Action Center** (new): possibly important messages, deadlines and payments, outstanding replies and registrations, documents, a source-linked review queue with explanations and uncertainty. Findings are recommendations, not guaranteed detections; content-based parts are gated by the content-indexing decision.
- **M9 — Subscription Intelligence** (new): newsletter and mailing-list discovery, grouping, frequency, low-value subscriptions, suggested unsubscribe opportunities. Recommendation-only: no automatic unsubscribe, link visit or sender interaction.
- **M10 — Attachment Intelligence** (new): attachment metadata, receipts and invoices, duplicates, search; content analysis only with explicit per-item permission and never sent to external AI; no bulk download.
- **M11 — Ask Your Inbox** (new): natural-language, source-linked, evidence-based questions over the local index with uncertainty handling, prompt-injection defenses and no Gmail side effects; free local inference only.

Suggested build order (not binding): finish M4, then M7, then M6A/M5A-M5C, then M9A/M8A, then the content-indexing decision, then the content-gated parts, with M11 last. The original numbering is kept for continuity.

## Zero Additional Cost acceptance criterion (all milestones)
**Approved, mandatory:** every milestone's acceptance criteria must include a *Zero Additional Cost verification*: no billing account or paid service enabled, no paid API/LLM, no paid dependency, no paid GitHub feature, official free-tier terms for any external service checked and recorded, unknown billing status treated as a blocker. M1 additionally requires resolving Q12 (billing status of the Google Cloud project) before any Cloud setup. If free operation cannot be established, the affected feature is disabled or deferred.

Tracking is done via GitHub Milestones and Issues. **Pull-request references.** `PR #n` with a link points to this public repository (for example [PR #2](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/2) and [PR #7](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/7) to [#10](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/10)); the roadmap expansion is public [PR #11](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/11). References written "private archive PR #11, #13, #14, #15" (M0B, M0C, M1, M2) belong to the original private development repository, which is kept as an archive and from which the public history was published fresh; they are not public pull requests, and private archive PR #11 is unrelated to public PR #11.
