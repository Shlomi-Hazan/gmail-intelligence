# Roadmap

No dates are assigned. Everything below M0A is **future** and requires approval to start.

- **M0 — Foundation & Security** (M0A bootstrap: done; M0B architecture/security/workflow: merged in PR #11; M0C Python foundation, tests, Skills: merged in PR #13). **M0-M2 are complete.**
- **M1 — Gmail OAuth & Read-Only Connection** (merged in PR #14; owner-reported live check succeeded)
- **M2 — Mailbox Audit & Local Indexing** (merged in PR #15; owner-reported limited and full scans succeeded)
- **M3 — Rules & AI Classification** (merged in PR #2; offline rules, local store and CLI verified; the optional local-AI boundary is tested with a fake backend only, real inference NOT VERIFIED - see [CLASSIFICATION.md](CLASSIFICATION.md))
- **M4 — Safe Cleanup** (dry-run, approvals, rollback). Phases M4A candidate engine and protection rules (merged in PR #7), M4B plans/approvals/audit (merged in PR #8), M4C write authorization and executor (M4C-A local execution state implemented offline, in review; M4C-B/C/D pending), M4D recovery/undo/audit.
- **M5 — Labels & Filters Management**
- **M6 — Local Dashboard**
- **M7 — Incremental Sync & Maintenance**

## Zero Additional Cost acceptance criterion (all milestones)
**Approved, mandatory:** every milestone's acceptance criteria must include a *Zero Additional Cost verification*: no billing account or paid service enabled, no paid API/LLM, no paid dependency, no paid GitHub feature, official free-tier terms for any external service checked and recorded, unknown billing status treated as a blocker. M1 additionally requires resolving Q12 (billing status of the Google Cloud project) before any Cloud setup. If free operation cannot be established, the affected feature is disabled or deferred.

Tracking is done via GitHub Milestones and Issues. Pull-request and issue numbers mentioned in these docs refer to the project's original private development repository, which is kept as an archive; the public history was published fresh from it.
