# Cleanup in the dashboard (M12E, issue #63)

The **Cleanup** screen of the local dashboard (`gmail-intelligence dashboard serve`) is a **read-only** view of the whole cleanup lifecycle:
Discovery → Review → Plan → Approval → Execution → Recovery / Undo. It is built from this computer's own records only.

## What it is not

- It is **not a control surface**. It cannot create, change, approve, reserve, run, resume, retry, confirm, abort, undo or reconcile anything. There is no such button, form or endpoint.
- It **never contacts Gmail** and uses no OAuth, no credentials and no Keychain. Opening or refreshing a page runs no scan and writes nothing.
- **Live Gmail operations are disabled in this build** (`LIVE_EXECUTION_ENABLED`, `LIVE_UNDO_ENABLED`, `LIVE_OBSERVE_ENABLED` are all `False`) and **real Gmail acceptance has not taken place**. Everything shown comes from the local index and local audit log; an item "recorded as archived" means the local journal says so, not that Gmail was checked.
- Approvals, execution, undo and reconciliation stay in the owner-operated command line ([CLEANUP-REVIEW.md](CLEANUP-REVIEW.md), [CLEANUP-RECOVERY.md](CLEANUP-RECOVERY.md), [M12D-BULK-EXECUTION.md](M12D-BULK-EXECUTION.md)), each behind typed confirmations, and are currently disabled.

## Tabs

| Tab | Shows |
|---|---|
| Overview | the lifecycle strip with local counts, summary cards, plans/executions/reversal plans by state, and a notice when something waits for the owner |
| Discovery | possible candidates (M12A data): groups by sender domain, size, age, the rule that classified them, why each is suggested, the "needs your review" and "protected" reasons; honest empty/partial states. Suggestions only. |
| Plans | each plan's status (draft, reviewed, approved-not-executed, approval expired, execution recorded…), item count, short hash, approval records and linked execution. An approved plan has **not** been executed unless an execution is listed. |
| Executions | per execution: plan and hash, status, slices with item ranges and states, archived / skipped / unknown / conflicting / open-intent / pending counts, owner-action flag and local audit times. Shown as completed **only** when nothing is unresolved. |
| Undo | bulk reversal plans and single-item undo records: source execution, approval state, slices, restored / not restored / never attempted / authorized-not-run / uncertain / conflicting / inconsistent counts and skip reasons. No restore control. |
| Recovery | interrupted executions, open intents, UNKNOWN/CONFLICT items, inconsistent ledgers and reversal plans needing the owner, with the last known status and the plain-language next safe command-line step. Calm wording, no alarms, no auto-reconcile. |
| History | the M4 audit history (unchanged), with the audit-chain status |

## Read-only API (GET only, token-protected, same checks as every other route)

`cleanup/overview`, `cleanup/discovery` (`limit=1..50`, `min_group=1..1000`), `cleanup/plans`, `cleanup/executions`, `cleanup/reversals`, `cleanup/recovery`; `cleanup/summary` and `cleanup/history` are unchanged.
They are produced by `cleanup_view.py` with SELECT statements over the read-only index handle (the dashboard process must not import the plan, execution, undo or live-adapter modules; a test pins this). They return aggregate counts, safe state codes and local plan/execution/reversal ids only: **no** account address, message or thread id, sender address, label name, subject, snippet, attachment or token.

## Language and layout

All text is in the existing English and Hebrew catalogs (`cx.*` keys, enforced for parity and placeholders). Layout uses logical CSS properties only; ids, hashes, counts and dates are isolated so they render correctly inside right-to-left text. Tabs wrap on narrow screens, tables scroll inside their container, and every control is keyboard reachable.

## Recurring cleanup recommendations (prepared, not built)

A future increment could remind the owner to run discovery periodically. It is **documented only**: no scheduled scan, background job, automatic plan creation or approval, or unattended execution exists, and adding any of these needs its own design and explicit owner approval.

## Verification

`tests/test_dashboard_cleanup.py` (synthetic M12 fixtures through a real loopback server): no-data state; approved/unapproved plans; multi-slice, partial, awaiting-continuation, interrupted executions; UNKNOWN/CONFLICT blocking "completed"; pending, completed, interrupted and inconsistent reversals; account isolation; no sensitive data; non-GET refused and nothing changes; no scripts with network/mutation primitives; he/en completeness; all three gates `False`.
