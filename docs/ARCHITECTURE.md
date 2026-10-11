# Architecture

Legend: **Approved** = decided; **Proposal** = suggested, not decided; **Future** = not built; **Open** = unresolved.

**Nothing in this document is implemented.** M0A contains no application code.

## Approved
- Local-first: data stays on the user's machine.
- Read-only Gmail access first; modifying operations only after the safety architecture exists (M4).
- Private repository; feature-branch + PR workflow.

## Proposals (not decided)
- Layered design: Gmail client → local store → classification engine → cleanup planner → UI.
- Local SQLite store (git-ignored).
- Separation of "plan" (dry-run) and "execute" stages with explicit approval between them.

## Future capabilities
OAuth connection (M1), audit/indexing (M2), classification (M3), safe cleanup (M4), Labels/Filters (M5), dashboard (M6), incremental sync (M7).

## Open questions
- Implementation language(s) and framework.
- Whether any external AI service may be used, and what data may be sent.
- Dashboard technology.
- Token storage mechanism (OS keychain vs. encrypted file).
