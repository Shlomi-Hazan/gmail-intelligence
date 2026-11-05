# P3 — Bounded multi-message test set: design (design only)

**Status: design proposal for owner review. No code is written, no gate changes, and nothing here authorizes any Gmail, OAuth, Keychain or index access or any live operation.** It belongs to critical-path item P3 of [MASTER-PLAN.md](MASTER-PLAN.md) (tracker: issue #41). All three `LIVE_*` gates stay `False` in `main`. Real-Gmail status at the time of writing: single-message archive **PASS**, single-message undo **PASS**, read-only observation of settled records **PASS**; `UNKNOWN` reconciliation, bounded bulk archive and bulk reversal are **not** accepted against real Gmail.

## 1. Goal and non-goals
**Goal:** a reviewed mechanism that lets the owner run bounded bulk archive (P4) and bulk reversal (P5) against **up to 25 dedicated test messages** in the existing personal account, so that ordinary personal mail can never be a target of a live mutation.
**Non-goals:** no change to the archive/undo/observe write policy, transport, executor, confirmation phrases or OAuth scopes; no new mutation class; no selection by query, label, age or classification; no automatic or unattended execution; no weakening of any ordinary-policy rule for ordinary mail.

## 2. Why the existing canary exception cannot simply be reused
The canary exception (`cleanup_candidates.CANARY_WAIVED`, `cleanup_canary`, snapshot field `canary_exception`) is intentionally a one-message device. Verified in the source:
1. **Hard cardinality:** `cleanup_plans._insert_plan` refuses a canary plan with other than one id, and `integrity_problems` rejects `canary_exception` unless the snapshot has exactly one item and version 1; `revalidate` applies the waiver only when `len(items) == 1`.
2. **Id-typed binding:** the plan is bound by a single message id the owner types, with a phrase derived from that one id. Typing 25 ids by hand is error-prone, and a typo would target an ordinary message, with nothing in the plan proving that a message is a *dedicated test message*.
3. **No notion of "dedicated":** the waiver removes only age and classification-type reasons; it does not say *why* this message deserves it. For one hand-checked message that is acceptable; for 25 it needs machine-checked evidence (declared sender, time window, own thread).
4. **Run path is single-target:** `run_canary` requires one target in one slice and a recorded `CANARY_CONFIRMED`; the bulk path (`cleanup_bulk`) has no concept of waivers at all and would refuse the fresh messages through the ordinary 90-day and classification rules.
5. **Slicing:** `plan_slices(25) = [25]`: a 25-item plan runs as **one** slice with no smaller first slice (accepted limitation G5), so a first live bulk step must be staged (section 6) rather than being 25 messages at once.
6. **Staleness anchor:** a plan is anchored to the index scan state (`INDEX_RESCANNED`); a `mailbox sync` or scan between planning and execution makes it stale. The workflow must be a short, uninterrupted sequence.

## 3. Proposed mechanism: the *dedicated test-set exception* (v1)
A plan may carry `policy.test_set_exception` (a new marker, distinct from `canary_exception`, which keeps its exact current meaning and checks). Everything else about the plan stays as it is: immutable snapshot, hash, review, one-time approval, expiry, audit, bulk executor.

**3.1 What the exception waives (and nothing more):** exactly the reasons the canary exception waives today (`TOO_RECENT`, `UNKNOWN_TYPE`, `RISKY_TYPE`, `TYPE_NOT_APPROVED`, `WEAK_EVIDENCE`, `AMBIGUOUS_TYPES`), and only for the ids frozen in this plan. No hard protection is waived: `SENT`, `STARRED`, `DRAFT`, `TRASH`, `SPAM`, user protection rules, `IMPORTANT`, unread, user labels, attention/AI signals, missing or stale classification, unsafe data, not-in-inbox, mixed threads.

**3.2 Eligibility of each message (machine-checked at plan creation, review, approval, reservation and again per item at run time):**
- the message id is in the owner's explicit list (a private file, never a query result), at most **25**, no duplicates;
- **sender binding:** the sender address of every message equals the single *declared test sender* recorded in the plan (stored as a keyed digest, never in clear text, and never the personal account itself: a self-sent message carries `SENT` and stays refused);
- **time window:** every message's internal date is at or after a `not_before` timestamp recorded in the plan (set when the test messages are sent, so no older message can qualify) and not in the future;
- **own thread:** each message is the only message in its thread (so the F5 thread rule is not involved and a protected sibling cannot exist);
- **labels:** only `INBOX` plus Gmail category labels; read; not important, starred, in Trash/Spam; no user label;
- **account binding:** the plan's account equals the index account and the live profile account (verified before any request, as today);
- **freshness:** sync checkpoint fresh and index not rescanned since planning; classification current.
Any failure refuses the **whole** plan: nothing is trimmed, widened or substituted.

**3.3 Selection and confirmation:** a local, read-only helper lists *candidates* (messages from the declared sender since `not_before`, own thread, read) for the owner to compare with the number of messages actually sent; the owner writes the ids file from that list. The plan phrase is derived from the account, the sorted-id digest and the count (`TEST SET <count> <digest prefix>`), so a changed list needs a new phrase. No id appears in GitHub, logs or default output.

**3.4 Execution:** unchanged executor and M12D bulk path (per-slice typed run phrase, durable intent per item, one request per item at most, independent post-read, `UNKNOWN`/`CONFLICT` stop everything, no retry, no resume). The only difference is that `revalidate` evaluates the frozen ids with the test-set waiver. The shared gate stays `False` in `main`; live use happens only in a temporary, never-merged acceptance branch as in P1/P2, which opens `LIVE_EXECUTION_ENABLED` and keeps `LIVE_UNDO_ENABLED` and `LIVE_OBSERVE_ENABLED` closed (the single-message canary path stays unused).

**3.5 Reversal (P5):** the existing bulk reversal plan over the finished execution (verified `APPLIED` items only, never more), run in an acceptance branch with only `LIVE_UNDO_ENABLED` open. Because every message has its own thread, success means every message is back with its recorded original labels.

## 4. Required code changes (not made in this change)
| Area | Change |
|---|---|
| `cleanup_candidates` | accept a per-plan waiver id set for `test_set_exception` in addition to `canary_ids` |
| `cleanup_plans` | policy marker, snapshot fields (declared-sender digest, `not_before`, count), integrity rules (1..25 items, version 1, marker immutable), `revalidate` support, creation refused for any other marker combination |
| `cleanup_canary` (or a new `cleanup_testset`) | `describe_set`, `candidates` (read-only listing), `create_test_set_plan` with the set phrase |
| `cleanup_canary_cli` | `candidates`, `describe-set`, `plan-set` (local only; `run` untouched) |
| acceptance branch only | the gate change for P4 (bulk archive) plus the existing temporary blocks of single-message canary and undo, as in P1/P2 |
Unchanged: executor, write transport and policy, confirmation phrases, OAuth, audit log schema (no new table; new fields live in the plan snapshot, new audit event names only if reviewed).

## 5. Synthetic test plan (no Gmail, no credentials)
Creation refused for: 0 or 26 ids, duplicates, an id outside the declared sender, outside the time window, in a shared thread, unread, important, starred, user-labeled, `SENT`, not in inbox, stale or missing classification, stale checkpoint, rescanned index, a mismatched phrase or digest; plan immutable and hash-bound; review and approval as for any plan; execution over the fake wire archives exactly the 25 and nothing else, sends no other request kind, stops on `UNKNOWN`/`CONFLICT`, never retries; a message that changes between approval and run is skipped or stops the run as today; a plan with the new marker cannot be created by the ordinary path and an ordinary plan can never use the waiver; `canary_exception` behavior is byte-for-byte unchanged; the reversal restores exactly the archived set; an adversarial case (a personal message id swapped into the file) is refused by sender/time/thread checks. Full suite unchanged for everything else.

## 6. Staged live acceptance (P4, P5; separate approvals, none given)
- **Stage S1: 3 dedicated messages**, one slice of 3: proves the new plan type and the bulk path on real Gmail with a tiny blast radius; verify, then reverse (P5 on 3).
- **Stage S2: up to 25 dedicated messages**, one slice (G5 accepted): archive, verify every message left the Inbox and remained in All Mail, then bulk reversal and verify every message is back with its original labels.
- Each stage: offline preflight and backup, fresh checkpoint (uninterrupted plan → review → approval → run, no sync in between), write-token refresh, typed phrases by the owner, no retries, owner's independent Gmail check, branch deleted, optional `revoke-write`.
- **Stop conditions** (any): account mismatch, expired authorization/token/lease, drift or unexpected label, a shared thread, `UNKNOWN`, `CONFLICT`, transport error, count mismatch, owner's check disagrees. Nothing is retried; uncertainty is settled only by read-only observation or by hand.

## 7. Owner preparation of the test messages (when the time comes)
Send each test message from a **different address** (never the personal account), each with a **unique, unrelated subject** (Gmail groups same-subject messages from one sender into one thread, which would break the own-thread rule), generic content, one message per intended target; open and read each once; confirm none is marked important (Gmail may do it automatically; remove the marking manually) and that no Gmail filter touches them; do not touch them afterwards. Record the declared sender and the send start time privately.

## 8. Risks and decisions for the owner
| Risk | Mitigation |
|---|---|
| a typo or stray id selects an ordinary message | sender, time-window and own-thread checks; id list from a read-only candidate listing; whole-plan refusal |
| the waiver is abused for ordinary mail | marker is plan-immutable, ids frozen, ordinary creation path cannot set it, hard protections never waived |
| one 25-item slice has no smaller first slice | staged S1 of 3 before S2 |
| plan staleness (sync between steps) | short uninterrupted sequence; documented |
| Gmail auto-marks tests important or groups them | unique subjects; manual unmarking; machine check refuses otherwise |
Open decisions: (a) stage sizes (3, then up to 25); (b) whether a later, separate stage should include one deliberate two-message thread to exercise the F5 sibling rule on real Gmail (not part of this design); (c) whether to build the helper `candidates` listing in the first increment.
