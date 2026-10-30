# Cleanup review and approval (M12B)

Part of M12 — Smart Bulk Cleanup (issue #60). It lets you review the M12A discovery groups, exclude single messages, preview the exact effect and freeze **exactly that selection** as an ordinary M4B plan. It extends the existing `cleanup` commands; there is no new subsystem, no second eligibility engine and no change to M4 plan, approval or audit semantics.

**Approval does not execute anything.** An approval is a local ledger record of a typed confirmation. There is no execution path in this milestone, Gmail is never contacted, and `LIVE_EXECUTION_ENABLED` stays False.

## Commands
```
gmail-intelligence cleanup preview --group DOMAIN [--group ...] [--exclude-id ID ...] [--page N] [--page-size N] [--show-ids] [--min-age-days N] [--json]
gmail-intelligence cleanup plan create --group DOMAIN [--group ...] [--exclude-id ID ...] --selection-digest DIGEST [--min-age-days N]
```
Then the existing `cleanup plan show | review | exclude | cancel`, `cleanup approve` and `cleanup approval status`.

## How a selection is made safe
- Groups are the sender domains listed by `cleanup discover`. Nothing is selected by default.
- The selection is taken **only** from the messages `cleanup_candidates.evaluate_all` currently finds eligible. A protected message, a message that needs review, or a message from an unknown domain can never enter; a group with no eligible messages is refused. Other messages of the same domains are counted as "not eligible" and never included.
- Exclusions must name messages inside the selection (an unknown, protected or malformed id is refused; duplicates are ignored and counted). Excluding everything is refused.
- The preview prints a **selection digest** that covers the exact message set, their sizes and facts, the classification rules, your protection rules and the policy. `plan create` recomputes it and refuses (nothing created) if anything changed since the preview, or if the groups or exclusions differ. So a changed selection is always a new preview, a new plan and a new approval.
- Plan creation calls the existing `cleanup_plans.create_plan`, which re-validates every message against the M4 protections inside its own transaction and checks sync health; the created plan must equal the reviewed set.
- A plan holds at most 500 messages (the existing M4B limit, unchanged). A larger selection is refused with a clear message; narrow it. Raising that limit would be an M4 semantics change and needs a separate decision.

## Archive, Trash, permanent deletion
Only **ARCHIVE** (remove from the inbox) can be planned. **TRASH** is unavailable pending a separate design, write-policy review and owner authorization. **Permanent deletion** is never offered. `--action trash|delete` is refused with a fixed message.

## Privacy
Message ids stay local and appear only with `--show-ids` (or in `plan review`, as before). Output has no addresses, links or subjects; errors are fixed text and never echo the input.

## Synthetic walkthrough (fixture data)
```
$ gmail-intelligence cleanup discover --account owner@example.invalid
  1. big.example.test | 8 messages in 8 threads, ~16 KB | ... classified by rule: promotional/medium x8
  2. mid.example.test | 6 messages ...
$ gmail-intelligence cleanup preview --group big.example.test --exclude-id m1 --page-size 3
action: ARCHIVE - remove from the inbox (archive); nothing is trashed or deleted. TRASH: unavailable ... PERMANENT DELETE: never offered.
7 message(s) in 7 thread(s), estimated 14 KB, from 1 group(s); 1 excluded by you.
  group big.example.test: 7 selected, 1 excluded by you
page 1/3 (ids hidden; --show-ids to see them):
     1. big.example.test | 200 days old | 2000 bytes ...
selection digest: 6be03f65...85ee7a            # the full 64 characters are printed
$ gmail-intelligence cleanup plan create --group big.example.test --exclude-id m1 --selection-digest <digest>
Plan plan-xxxxxxxx created as DRAFT from the reviewed selection: 7 target(s), action ARCHIVE, hash 9e0379cc.
$ gmail-intelligence cleanup plan review plan-xxxxxxxx        # existing M4B: walk every target, type the phrase
$ gmail-intelligence cleanup approve plan-xxxxxxxx            # existing M4B: typed phrase; a LOCAL record only
$ gmail-intelligence cleanup approval status plan-xxxxxxxx    # state APPROVED, one-time record; nothing executed
```
Changing any group or exclusion (or any underlying data) gives a different digest and therefore a new plan that needs its own review and approval.

## Not in this milestone
Recovery and undo (M12C, with #41), execution (M12D), and dashboard screens (M12E).

## Cost
Zero Additional Cost: standard library only, no new dependency, scope or schema.
