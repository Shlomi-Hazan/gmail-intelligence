# Product roadmap: M5-M11 (planning only)

> **Status: direction approved by the owner. M5A-M5E (see [LABELS.md](LABELS.md)) and M6A-M6C (see [DASHBOARD.md](DASHBOARD.md)) are implemented as local, read-only features; M5F and M7-M11 are NOT implemented.** It adds product direction to the planning documents. It does
> not authorize implementing any feature, any live Gmail operation, any new OAuth scope, any new dependency or any change to an existing security
> boundary. Every milestone below needs its own explicit owner approval to start, and every increment needs its own Draft PR and review.
> **Authority:** this document grants no authority to start M5-M11 or to perform any live Gmail operation. **Current M4 status (M4 closeout, [M4-CLOSEOUT.md](M4-CLOSEOUT.md)):** one owner-approved real single-message archive canary succeeded; live execution is disabled again (`LIVE_EXECUTION_ENABLED = False`); the write grant was revoked; real Gmail undo is NOT implemented; general live batch execution is NOT enabled; any future live operation needs fresh owner approval. The stage names M4C-B2/B3, M4C-C, M4C-D and M4D below are HISTORICAL: they describe how M4 was staged, not what remains.
> Any access to real Gmail, OAuth, Keychain or the real index needs its own explicit owner approval. Tracking lives in GitHub Milestones and Issues; the proposals in section 6 have **not** been created there. See [ROADMAP.md](ROADMAP.md) for the
> short list, [DECISIONS.md](DECISIONS.md) (D58-D65, Q15-Q19) for the decisions and [ARCHITECTURE.md](ARCHITECTURE.md) section 17 for the architecture notes.

## 1. Where the project actually stands (baseline, not aspiration)

| Area | Implemented today | Not implemented |
|---|---|---|
| Index | Metadata only: message/thread ids, dates, size, sender address, Gmail label ids and label names, unread flag. **No subject, snippet, body, recipients or attachment information is stored.** | Content indexing of any kind |
| Classification (M3) | Deterministic rules and user rules; an optional loopback-only local model sees only a sender domain and Gmail system labels (real inference **not verified**) | Content-aware classification |
| Cleanup (M4) | Candidate engine and protection rules; immutable plans, typed approvals and audit; local execution state; an archive-only write transport; a fake-tested executor, recovery and fake-only undo; a disabled live boundary; **one owner-approved real single-message archive canary (succeeded; evidence in [M4-CLOSEOUT.md](M4-CLOSEOUT.md))** | Real Gmail undo; general live batch execution (live execution is limited to one message and is disabled again, the write grant was revoked); Trash and every other mutation class. `cleanup execute` is still unavailable. Any future live operation needs fresh owner approval |
| Dashboard / sync | A design note only ([ARCHITECTURE.md](ARCHITECTURE.md) sections 6 and 13) | Everything |

Historically no mailbox had been modified; the only mailbox change to date is the one owner-approved real single-message archive canary (see M4-CLOSEOUT.md), after which live execution was disabled again. Nothing in M5-M11 may be described as available until it is merged, verified and
documented as such.

## 2. Product-wide principles

Existing and approved (preserved unchanged): local-first; read-only by default; least privilege; human approval for every change; privacy-safe audit
trails; Zero Additional Cost; clear recovery limitations; the separate, allowlisted write boundary of M4C.

Added by this direction (see D58-D65):
1. **Recommendation first.** Every capability ships as read-only, explainable recommendations before any execution exists. An execution boundary is
   approved per operation class (for example label changes, filter creation) with its own plan, approval, audit and recovery design.
2. **Explainability and uncertainty.** Every finding shows why it appeared, which source message(s) it is based on, and a confidence or uncertainty
   indicator. Findings are recommendations, never guaranteed detections; the absence of a finding proves nothing.
3. **Email content is untrusted input** everywhere: parsed defensively, never executed, never treated as instructions, never given tool access.
4. **Content indexing is a separate, explicit decision** (Q15). The index is metadata-only today; subjects, snippets, bodies and attachment content may
   be indexed only per data class, with owner consent, locally, with stated retention and at-rest protection.
5. **No paid services or APIs and no external AI disclosure** without explicit, per-use consent. Free local inference is optional and never required.
6. **No Gmail mutation as a side effect** of analysis, a question, a dashboard view or a scheduled job. Scheduled work is read-only by default and cannot
   reach write credentials.

## 3. Milestones

Each milestone is split into small increments that ship as separate Draft PRs. "MVP" is the first coherent release; "stretch" is optional later work.
Every milestone carries the project-wide **Zero Additional Cost verification** ([ROADMAP.md](ROADMAP.md)): no billing account or paid service, no paid
API or model, no paid dependency, free-tier terms of any external service checked and recorded, unknown billing treated as a blocker.

### M5 — Intelligent Inbox Organization (expands the original "Labels & Filters Management")
- **Status:** M5A-M5E implemented (local, read-only, offline plans; schema v6; documented in [LABELS.md](LABELS.md)); **M5F not implemented.** The text below is the original plan.
- **Goal and value:** make the label system understandable and tidy, and suggest how to classify mail, without touching the mailbox.
- **MVP (M5A-M5C):** label inventory and hygiene report (duplicates and near-duplicates, unused labels, over-deep or inconsistent nesting, orphaned
  parents); label and tag recommendations from existing classification and sender patterns; suggested classification rules with an impact preview
  (reusing the M3 rule preview). All local, read-only, no network.
- **Stretch:** label-change plans (create, rename, nest, merge) as immutable plans with typed approvals and audit, offline (M5D); filter suggestions
  with preview (M5E); an execution milestone only after separate approval (M5F). **M5F is intentionally deferred and is NOT proposed for GitHub
  tracking in section 6:** it would be proposed only after M5D has been designed and reviewed, M4 is complete and the execution class is separately approved.
- **Dependencies:** M2 index and labels; M3 classification; M4B plan/approval pattern. Execution additionally needs a generalized, newly allowlisted write
  boundary, the M4C-C/D executor pattern and M4D recovery. Filters need the `gmail.settings.basic` scope, which does not exist in the project today.
- **Privacy:** label names are private user content and never go to GitHub, logs or fixtures; recommendations use metadata only; any local model sees
  no more than M3 allows.
- **Security boundaries:** recommendation phases request no new scope and make no Gmail call. Label creation, rename, merge or deletion and filter
  creation are separate execution classes, each needing its own allowlist entry, plan, approval, audit and recovery review. Recovery limits must be
  documented before approval: deleting a label removes it from messages; a created filter's effect on already-routed mail is not retroactively undone
  ([SECURITY.md](SECURITY.md)). Filters that forward, trash or skip the inbox stay forbidden without an explicit approved plan.
- **Recovery and undo expectations:** the recommendation phases (M5A-M5C) change nothing, so there is nothing to undo. For later executed changes,
  recovery is promised only where technically feasible and is documented per operation class before approval. Adding or removing a label on a message
  can be inverted if the previous label set was recorded first (the M4 pattern). Deleting a label cannot be undone because the messages lose it, so a
  merge is irreversible unless every affected message's previous labels were recorded and can be re-applied; the effect of a created filter on mail it
  already routed is not retroactively undone, and deleting a filter only stops future effects ([SECURITY.md](SECURITY.md)). How renaming a parent label
  affects nested children is not verified and must be checked against Google's documentation before any rename is approved.
- **Zero Additional Cost:** no paid service, API, model or dependency; recommendations use local code and the free local-model boundary of M3.
- **Acceptance (MVP):** reproducible, explained, local-only recommendations; synthetic fixtures only; no write scope or Gmail call; Zero Additional
  Cost verified.
- **Owner approval gates:** start of M5; plan-and-approval design (M5D); each execution class; the filter scope.

### M6 — Inbox Intelligence Dashboard (expands the original "Local Dashboard")
- **Status:** M6A-M6C implemented (local, read-only; zero new dependencies; documented in [DASHBOARD.md](DASHBOARD.md)). The text below is the original plan; the frontend toolchain question (Q18) was resolved by D126.
- **Goal and value:** an at-a-glance, explainable picture of the mailbox and of what cleanup achieved.
- **MVP (M6A-M6C):** aggregate analytics library and CLI/JSON reports first; then a local API bound to `127.0.0.1` with a per-session token; then a
  read-only local web UI: inbox overview, top senders, newsletter and notification share, category and volume trends, cleanup recommendations and
  outcomes (from the M4 audit).
- **Stretch:** inbox growth and reduction timeline; aggregate-only, privacy-safe export.
- **Dependencies:** M2, M3, M4 audit data; M7 for freshness of trends; a frontend toolchain dependency review (Q1), since none exists yet. The UI technology is undecided: D5 recorded a React dashboard only as an early direction, no stack is approved here, and the toolchain is open question Q18.
- **Privacy:** aggregated and explainable by default; sender addresses masked unless the owner asks; no telemetry, no remote fonts, scripts or CDN assets;
  nothing leaves the machine.
- **Security boundaries:** the API listens on loopback only with a per-session token and strict Origin/CORS checks (ARCHITECTURE section 13); no mutation
  endpoints in the MVP; the dashboard holds no Gmail tokens and cannot reach Gmail; strict escaping and a content security policy for email-derived text.
- **Acceptance:** loopback-only (tested), no tokens in the UI process, read-only endpoints, escaped output, synthetic data, license and cost review of
  every frontend dependency.
- **Zero Additional Cost:** no hosted service; every frontend dependency must be free and reviewed (license, supply chain) before approval; no paid fonts, CDNs or telemetry.
- **Owner approval gates:** start; frontend dependency set; API design; any future action button (for example "create a cleanup plan").

### M7 — Incremental Sync & Smart Maintenance (expands the original "Incremental Sync & Maintenance")
- **Goal and value:** a fresh, trustworthy local index without full rescans, plus health checks.
- **MVP (M7A-M7C):** `history.list`-based incremental indexing with checkpoints and a full-rescan fallback when the history id has expired; change and
  deletion detection; local integrity checks (database integrity, orphaned rows, scan completeness, backup verification); user-triggered maintenance
  reports and recommendations.
- **Stretch:** opt-in scheduled analysis (for example a user-installed launchd job) that is read-only; periodic maintenance recommendations; safe review
  workflows.
- **Dependencies:** M2 and ARCHITECTURE sections 6-7. Needs a design for how incremental sync interacts with M4 plans, which are bound to an index anchor:
  sync must neither silently invalidate nor silently validate an approved plan.
- **Privacy:** metadata only; schedule logs are privacy-safe.
- **Security boundaries:** `gmail.readonly` only; **no unattended Gmail mutation by default**; scheduled jobs run without access to the write Keychain item
  or write client; a schedule is persistent configuration and needs explicit approval.
- **Acceptance:** resumable and idempotent sync, deletion detection tested with fakes, no write capability reachable, Zero Additional Cost verified
  (quota use stays within documented free limits).
- **Zero Additional Cost:** only the existing free Gmail API quota (documented limits in ARCHITECTURE section 7); scheduling uses the owner's own Mac, with no paid automation or hosting.
- **Owner approval gates:** start; the plan-anchor interaction design; any scheduling.

### M8 — Important Mail & Action Center (new)
- **Goal and value:** surface messages that may deserve attention, in a source-linked review queue.
- **MVP (M8A, metadata only):** attention candidates from already indexed signals (starred, Gmail "important", unread age, personal versus automated
  sender) with explanations, uncertainty indicators and a source-linked review queue.
- **Stretch (all content-gated, only after Q15 is decided), as three small deliverables:** M8B upcoming deadlines and payments; M8C outstanding
  registrations, awaited replies and messages possibly needing follow-up; M8D important documents (linking to M10 once it exists).
- **Dependencies:** M3 classification; M7 for freshness; the content-indexing decision (Q15); M10 for documents.
- **Privacy:** subjects and snippets are sensitive; store minimal extracted facts rather than text where possible, with stated retention; local only.
- **Security boundaries:** deterministic extraction first; a local model only through a strict output schema and never with tools; findings never trigger
  Gmail changes; no automatic replies (sending is forbidden project-wide).
- **Acceptance:** each finding shows explanation, confidence and source link; wording says "possibly", never "detected"; measured on synthetic fixtures
  including adversarial email text; no Gmail write.
- **Zero Additional Cost:** deterministic extraction first; any model is a free local one; no paid API or service.
- **Owner approval gates:** start; the content-indexing scope; any model use.

### M9 — Subscription Intelligence (new)
- **Goal and value:** understand newsletters and mailing lists, and see which subscriptions look inactive or low value.
- **MVP (M9A, metadata only):** group senders, analyse frequency and volume, estimate low-value subscriptions from unread ratio and age, and list
  suggested unsubscribe opportunities for the owner to act on manually.
- **Stretch (M9B, header-gated):** recognize legitimate `List-Unsubscribe` and `List-Id` metadata. Today only the `From` header is fetched, so this needs a
  reviewed extension of the read adapter and index (still `gmail.readonly`) and a rescan.
- **Dependencies:** M2, M3; M7 for refreshing headers; M6 for display.
- **Privacy:** unsubscribe links often carry per-user tokens: store only presence flags and the host, never full links.
- **Security boundaries:** **recommendation-only.** No automatic unsubscribe request, link visit, one-click POST or unsubscribe e-mail (sending is
  forbidden). Links are never fetched; classification is by syntax only; displayed links carry warnings. Any future active path needs its own threat
  model and approval.
- **Acceptance:** no network or Gmail write in the recommendation phase, hosts only, synthetic fixtures, Zero Additional Cost verified.
- **Zero Additional Cost:** local analysis only; no paid service; no sender interaction.
- **Owner approval gates:** start; the header extension; any active unsubscribe (not planned).

### M10 — Attachment Intelligence (new)
- **Goal and value:** find receipts, invoices and documents, and spot duplicates.
- **MVP (M10A):** attachment metadata only (file name, type, size, part count) indexed through a reviewed read-adapter extension; local search; duplicate
  candidates by metadata. The feasibility of fetching part metadata without any body data must be verified first.
- **Stretch (per-item permission):** optional local content analysis, exact-duplicate detection by hash, receipt and invoice extraction.
- **Dependencies:** M7 (sync), the content-handling decision (Q15, Q17), M6 for display, M8 for the documents link.
- **Privacy:** **do not download all attachments by default** and never transmit attachment content to external AI. Content is fetched on demand, only
  with explicit per-item permission, kept in 0600 temporary storage and deleted afterwards. Sensitive documents (identity, tax, medical and similar) are
  flagged, excluded from analysis and from any model, and never indexed by content.
- **Security boundaries:** attachments are untrusted files: never opened or executed; size limits; any parser (for example PDF) needs a dependency
  review and isolation; read-only scope.
- **Acceptance:** metadata-only MVP with no download path; the content path blocked behind explicit permission and tested; synthetic files only.
- **Zero Additional Cost:** only free, open-source local parsers, and only after dependency review; no paid OCR, storage or API.
- **Owner approval gates:** start; the read-adapter extension; each class of content analysis; parser dependencies.

### M11 — Ask Your Inbox (new)
- **Goal and value:** ask natural-language questions about the indexed mailbox and get source-linked, evidence-based answers.
- **MVP (M11A):** a deterministic question-to-query layer over the existing metadata index (counts, senders, dates, labels). An optional local model may
  only propose a *validated query plan*, never SQL or an action. Answers list their sources and the evidence used, and say plainly when the evidence is
  insufficient.
- **Stretch (content-gated):** local semantic search with free local embeddings and optional free local inference, hybrid retrieval and transparent
  retrieval logs; only after Q15 and the model choice are decided.
- **Dependencies:** M6 (interface), M7 (fresh data), M8/M10 for content-derived data, an evolution of the M3 local-model boundary.
- **Privacy:** questions, retrieved text and answers stay local; retrieval logs are privacy-safe; no external model.
- **Security boundaries:** **prompt-injection defense**: retrieved email text is delimited data, instructions inside it are ignored, the model has no tools
  and no network, outputs are schema-validated, the database handle is read-only; the question path has no Gmail client, no Keychain access and no write
  path, so asking can never change the mailbox.
- **Acceptance:** adversarial-email test suite, source-linked answers, calibrated "insufficient evidence" behavior, no network (tested), no paid model.
- **Zero Additional Cost:** free local embeddings and inference only; no paid or external model or API.
- **Owner approval gates:** start; the model; content retrieval; any follow-up feature that acts on an answer (not planned).

## 4. Cross-cutting gates

| Gate | Needed before |
|---|---|
| **Content-indexing decision (Q15):** which data classes (subject, snippet, body, attachment text), consent, retention, at-rest protection (the SQLite file is not encrypted; FileVault or an encrypted container is the available protection) | M8B-M8D, M10 content, M11 semantic search |
| **Read-adapter extension review:** additional headers (M9B) and attachment part metadata (M10A) | M9B, M10A |
| **Execution boundary per operation class** (plan, approval, audit, recovery, allowlist, scope) | any mutation in M5 and later |
| **Dependency review** (frontend toolchain, parsers, local models, embeddings: licenses, supply chain, cost) | M6, M10 parsers, M11 |
| **Scheduling approval** (persistent configuration) | M7 stretch |
| **M4 completion** (done in its reduced scope; historically each stage was separately authorized: M4C-B2/B3 client and authorization, M4C-C executor, M4C-D live canary, M4D recovery) | any execution class in M5 |

## 5. Dependencies and priority recommendation

Numbering is kept for continuity; it is not the recommended build order.

1. **M4 (the only mutation path) is complete in its owner-approved reduced scope** (see [M4-CLOSEOUT.md](M4-CLOSEOUT.md)): one real single-message archive canary succeeded under explicit
   approval; live execution is disabled again; the write grant was revoked; real Gmail undo is NOT implemented; general live batch execution is NOT enabled; any future live operation
   needs fresh owner approval. *Historical (kept for the record):* this item once read "complete M4 under its own approvals", when only M4A, M4B, M4C-A and M4C-B1 were merged and the
   M4C-C implementation, the M4C-B2/B3 client and authorization, the M4C-D canary and M4D were still future work, each needing separate authorization. That has been done and is
   superseded; this roadmap still grants no authority for any new live Gmail operation.
2. **M7 early:** every later milestone depends on a fresh index; design the plan-anchor interaction first.
3. **M6A (aggregate analytics) and M5A-M5C (label hygiene and recommendations):** read-only, offline, quick wins on data that already exists.
4. **M9A and M8A:** metadata-only first releases.
5. **Decide Q15**, then M9B, M10A and the content-gated parts of M8.
6. **M6B-M6C (API and UI)** once a first useful set of reports exists.
7. **M11 last:** it depends on the index quality and on the untrusted-content defenses built in earlier milestones.

Rough dependency graph: M2/M3/M4 -> M7 -> {M5, M6, M8A, M9A} -> {M9B, M10A} -> content decision -> {M8B-M8D, M10 content} -> M11. M4 proceeded, and any future live use proceeds, only through separately approved stages.

## 6. Proposed GitHub tracking (NOT created)

No GitHub Milestone or Issue has been created or changed by this document. At the time of writing the repository has Milestones #1 "M3 — Rules & AI
Classification" (closed) and #2 "M4 — Safe Cleanup" (open), and Issues #1, #3, #4 (closed) and #5, #6 (open). The earlier milestones M0-M2 have no
GitHub Milestone (they predate the public repository). There is no title or scope collision with the proposals below. Pull-request and issue numbers share
one ever-growing sequence in the public repository, so this document does not name a "highest" or "next" number.

**How pull requests are cited.** Public pull requests of this repository are written as PR #n and link to `https://github.com/Shlomi-Hazan/gmail-intelligence/pull/n`: [#2](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/2) (M3), [#7](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/7) (M4A),
[#8](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/8) (M4B), [#9](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/9) (M4C-A), [#10](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/10) (M4C-B1) and [#11](https://github.com/Shlomi-Hazan/gmail-intelligence/pull/11) (the roadmap expansion). The pull requests that [ROADMAP.md](ROADMAP.md)
records for M0B, M0C, M1 and M2 belong to the original **private archive repository** and are written there as "private archive PR #11, #13, #14, #15";
they are not public pull requests, and private archive PR #11 is unrelated to public PR #11.

Proposed milestones (titles only; created later, one at a time, with the owner's approval): *M5 — Intelligent Inbox Organization*; *M6 — Inbox
Intelligence Dashboard*; *M7 — Incremental Sync & Smart Maintenance*; *M8 — Important Mail & Action Center*; *M9 — Subscription Intelligence*;
*M10 — Attachment Intelligence*; *M11 — Ask Your Inbox*. Each milestone description repeats its goal, the recommendation-first rule, the Zero Additional
Cost criterion and the owner gates above.

The seven milestones group **21 proposed Issues**, one per named increment except the deliberately deferred M5F: the plan names 22 increments (M5A-M5F,
M6A-M6C, M7A-M7C, M8A-M8D, M9A-M9B, M10A-M10B, M11A-M11B) and the table has 21 rows (M5: 5, M6: 3, M7: 3, M8: 4, M9: 2, M10: 2, M11: 2).

Proposed issues (each: description = the increment named; acceptance = the stated criterion plus "synthetic data only", "no new scope or Gmail write
unless stated", "Zero Additional Cost verified"):

| Milestone | Proposed issue | Acceptance (specific part) |
|---|---|---|
| M5 | M5A Label inventory and hygiene report | duplicates/unused/nesting findings with explanations; no network |
| M5 | M5B Label and tag recommendations | each recommendation shows evidence and confidence |
| M5 | M5C Suggested rules with impact preview | preview counts match the M3 preview; nothing is saved without approval |
| M5 | M5D Label-change plans and approvals (offline) | immutable plan, typed approval, audit; no execution |
| M5 | M5E Filter suggestions (recommendation only) | no filter created; forbidden filter kinds rejected |
| M6 | M6A Aggregate analytics library and reports | explainable aggregates; masked senders by default |
| M6 | M6B Local read-only API | loopback-only, token and Origin checks tested |
| M6 | M6C Local web UI | escaped output; no external assets; dependency review done |
| M7 | M7A Incremental indexing from history | checkpoints, idempotent, expired-history fallback |
| M7 | M7B Change/deletion detection and plan-anchor design | plans neither silently invalidated nor validated |
| M7 | M7C Integrity checks and maintenance report | read-only; user-triggered |
| M8 | M8A Metadata attention queue | explanation, uncertainty and source link per finding |
| M8 | M8B Deadlines and payments (content-gated) | blocked until Q15 is approved; findings carry source, explanation and uncertainty |
| M8 | M8C Registrations, awaited replies and follow-up (content-gated) | blocked until Q15 is approved; recommendation only, no replies sent |
| M8 | M8D Important documents (content-gated) | blocked until Q15 is approved; links to M10 only when it exists |
| M9 | M9A Subscription grouping and frequency | recommendation-only; no network |
| M9 | M9B List-Unsubscribe/List-Id metadata | header extension reviewed; hosts and flags only; nothing fetched |
| M10 | M10A Attachment metadata index and search | no download path; duplicate candidates by metadata |
| M10 | M10B Optional per-item content analysis | explicit permission; temporary 0600 storage; sensitive documents excluded |
| M11 | M11A Metadata question answering | validated query plans only; sources and insufficient-evidence answers |
| M11 | M11B Local semantic search (content-gated) | prompt-injection suite; no network; free local model |

## 7. Decisions still needed from the owner

See [DECISIONS.md](DECISIONS.md) Q15-Q19: the content-indexing scope and at-rest protection; the build order; the read-adapter extensions; the
frontend toolchain; scheduling. Also: when to create the GitHub Milestones and Issues above.
