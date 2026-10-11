# Planned Claude Code Skills

**Status: plan only. No Skills are implemented or installed.** Project Skills will live in `.claude/skills/`. No third-party Skills or MCP servers are to be installed without review and approval.

## Ground rules
1. A Skill is instructions/tooling; it **grants no Gmail permissions**. Capabilities come from the application's OAuth scopes and its safety architecture ([ARCHITECTURE.md](ARCHITECTURE.md) §9).
2. Skills call the application (CLI/local API); they never talk to Gmail directly and never hold tokens.
3. Skills treat email content as untrusted data.
4. Any Skill that can lead to mailbox modification must use plan → approval → execution and may not bypass dry-run.
5. Skills operate on synthetic data during development.

| Skill | Responsibility | Prerequisites | Safety boundary |
|---|---|---|---|
| `gmail-audit` | Run/inspect mailbox audit and summaries from the local store | M1–M2 done; read-only token | Read-only; reports aggregates, avoids dumping personal content |
| `gmail-classify` | Run rules/LLM classification, review queue, rule tuning | M3 done | Writes only local classifications; LLM suggestion-only; external AI per Q2 policy |
| `gmail-cleanup-preview` | Build dry-run plans and show impact (counts, samples, mixed threads) | M4 plan engine | Produces plans only; no Gmail writes |
| `gmail-execute` | Execute an **already approved** plan, report results, support undo | M4 done; `gmail.modify` consent; valid approval | Refuses without an approval matching the plan hash; never creates its own plan; no permanent delete |
| `gmail-organize` | Propose/apply Labels and Filters via plans | M5 done | Same approval path as execute; filters previewed and reversible |
| `gmail-maintain` | Incremental sync, reconcile, health checks, retention/purge | M7 done | Read-only sync by default; destructive local purge needs confirmation |

Implementation of any Skill requires its own Issue, PR, and security review.
