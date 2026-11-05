# P3 — Bounded dedicated test set: design (design only)

**Status: design for owner review, revised after the owner's decisions. No code is written, no gate changes, and nothing here authorizes any Gmail, OAuth, Keychain or index access, any real test message, or any live operation.** Critical-path item P3 of [MASTER-PLAN.md](MASTER-PLAN.md) (tracker: issue #41). All three `LIVE_*` gates stay `False` in `main`. Real-Gmail status when written: single-message archive **PASS**, single-message undo **PASS**, read-only observation of settled records **PASS**; `UNKNOWN` reconciliation, bounded bulk archive and bulk reversal are **not** accepted against real Gmail. Every live capability and every execution below needs its own separate written owner authorization.

**Owner decisions applied:** (1) a dedicated, explicitly bounded test-set exception for up to 25 messages in the existing account; (2) staging S1 (3 messages) then S2 (up to 25, conditional on S1); (3) F5 thread rule covered by comprehensive synthetic tests, no live shared-thread experiment now, remaining F5 coverage recorded in section 13; (4) the read-only `candidates` helper is part of the first increment; (5) no OAuth or Keychain access in P3.

## 1. Goal and non-goals
**Goal:** a reviewed mechanism that lets the owner run bounded bulk archive (P4) and bulk reversal (P5) on up to 25 dedicated test messages so that ordinary personal mail can never become a live mutation target.
**Non-goals:** no change to the write policy, transport, executor, confirmation phrases or OAuth scopes; no new mutation class (still only archive = remove `INBOX`, undo = add `INBOX`); no selection by query, label, age or classification; no unattended or automatic execution; no relaxation of any rule for ordinary mail; no new dependency or cost.

## 2. Why the single-message canary exception cannot be reused as is
Verified in the source (`cleanup_candidates.CANARY_WAIVED`, `cleanup_plans`, `cleanup_canary`, `cleanup_bulk`):
1. **Hard cardinality:** `_insert_plan` refuses a canary plan with other than one id; `integrity_problems` rejects `canary_exception` unless the snapshot has exactly one item and version 1; `revalidate` applies the waiver only when the plan has one item.
2. **Hand-typed single id:** the canary binds one id typed by the owner; 25 hand-typed ids invite a typo that would aim at an ordinary message, and nothing in the plan proves a message is a *dedicated test message*.
3. **No notion of "dedicated":** the waiver removes only the age and classification-type reasons. For one hand-checked message that suffices; for a set it needs machine-checked and owner-verifiable provenance (section 4).
4. **Single-target run path:** `run_canary` needs one target, one slice and a recorded `CANARY_CONFIRMED`; the bulk path has no concept of waivers and would refuse fresh messages by the ordinary 90-day and classification rules.
5. **Slicing:** `plan_slices(25) = [25]`: a 25-item plan is **one** slice with no smaller first slice (accepted limitation G5). Hence the staging S1 then S2.
6. **Plan freshness:** the plan is anchored to the last completed **full** scan (`INDEX_RESCANNED` if a new full scan completes), the sync checkpoint must be at most 24 hours old, and every item is re-checked against its frozen state (section 6).

## 3. Final architecture and trust boundaries
```
 owner (typed phrases, private ids file, Gmail UI)      <- the only source of authority
   │
   ├─ local, read-only:  candidates helper ──► review sheet (suggested, NOT selected)
   │
   ├─ local, writes only plan/approval/audit rows:  plan-set (frozen ids) → review → approve
   │      plan snapshot: ids, declared-sender digest, time window, N, provenance tier, set digest, marker test_set_exception
   │
   ├─ unchanged executor / M12D bulk path (per-item revalidation, durable intent, post-read, no retry)
   │      └─ unchanged write transport + policy (archive: remove INBOX; undo: add INBOX; nothing else)
   │
   └─ Gmail: untrusted until the independent post-read; the owner's Gmail check is the final witness
```
**Trust boundaries.** (a) *Owner → plan:* only the owner's typed set phrase and approval create authority; suggestions never do. (b) *Plan → executor:* the executor trusts only the immutable, hash-bound plan and re-derives eligibility per item from local facts and live reads. (c) *Executor → Gmail:* the unchanged allowlist transport; a transport holds exactly one capability. (d) *Gmail → record:* a request result is never proof; the execution-bound trusted post-read decides. (e) *Repository → real data:* no ids, addresses, subjects or label names in GitHub, CI or default output.
**Where the exception lives:** only in the plan layer (marker, integrity rules, revalidation waiver set) and in the eligibility evaluation that consumes it. The executor core, transport and policy are untouched.

## 4. Eligibility and provenance model
**4.1 Waived reasons (nothing more):** the same set the canary exception waives: `TOO_RECENT`, `UNKNOWN_TYPE`, `RISKY_TYPE`, `TYPE_NOT_APPROVED`, `WEAK_EVIDENCE`, `AMBIGUOUS_TYPES`, and only for the ids frozen in the plan. **Never waived:** `SENT`, `STARRED`, `DRAFT`, `TRASH`, `SPAM`, user protection rules, `IMPORTANT`, unread, user labels, attention/AI signals, missing or stale classification, unsafe data, not-in-inbox, mixed or risky threads.

**4.2 Per-message eligibility, checked at creation, review, approval, reservation and again per item at run time** (all must hold; one failure refuses the whole plan, nothing is trimmed, widened or substituted):
| Check | Rule |
|---|---|
| membership | the id is in the frozen list; list size 1..25 (S1: exactly 3); no duplicates; the list equals the helper's candidate set exactly |
| account | plan account = index account = live profile account (verified before any request) |
| declared sender | the indexed sender equals the declared test sender (stored as a salted digest, never in clear text); it is **not** the personal account (that would carry `SENT`) |
| time window | internal date within `[not_before, not_after]` recorded in the plan; never in the future |
| own thread | the message is alone in its thread, now and at run time (so no sibling exists) |
| labels | only `INBOX` plus Gmail category labels; read; no user label; none of the protected labels |
| metadata unchanged | the frozen per-item facts digest (the plan already stores one per message) matches the current local facts and, at run time, the live message and thread reads |
| freshness | sync checkpoint at most 24 h old; no full scan completed since planning; classification current; plan and approval not expired |
| hard protections | all existing protections evaluated exactly as for ordinary mail |

**4.3 Provenance: how a message is established as "a dedicated test message".** Sender and timestamp alone are *not* treated as proof. Provenance is layered, and the plan records which layers were used:
- **Layer 1, machine-checked (Tier A, preferred): unique sender token.** The test messages are sent from an address whose local part carries a fresh random token chosen privately for this test set (a provider alias or plus-address, if the sending provider supports it as the From address). The indexed `messages.sender` field already stores the full lowercase From address, so this needs no reader change. A message qualifies only if its sender equals the declared token address exactly; collision with ordinary mail is negligible.
- **Layer 1b, machine-checked (Tier B, fallback): declared fixed sender plus exact count.** If no token address is possible, the declared sender must yield **exactly N** messages inside the window (more or fewer is ambiguous and refuses), in addition to the checks above. Earlier messages from that sender outside the window do not count.
- **Layer 2, owner-verifiable (both tiers): the review sheet.** For each candidate the helper prints an ordinal, the received time to the second (UTC), size, labels, thread size and a short keyed fingerprint of the id. The owner sends the messages one at a time in a known order with unique, unrelated subjects that include the ordinal (for example `T<ordinal> <random words>`), then confirms in Gmail that ordinal, arrival time and subject match. **Honest limit:** the index stores no subject, so the subject token is *owner*-verified, not machine-verified; it is evidence for the owner, never trusted by the software.
- **Layer 3, bound at approval:** the plan hash covers the sorted ids, the sender digest, the window, N, the tier and the set digest; the typed phrase is derived from the account, count and digest prefix. The owner can no longer change the set without a new plan, review and approval.
- **Possible Gmail link for the per-message UI check:** whether an API message id opens the right message in the Gmail web UI is **unverified** and the project's link contract is deliberately inert (`GMAIL-LINK-CONTRACT.md`); the design does not depend on it (time, size, ordinal and subject are the review evidence).
**4.4 The ordinary path can never acquire the exception.** The marker `policy.test_set_exception` is part of the hash-covered snapshot, is created only by `create_test_set_plan`, is rejected by the ordinary `cleanup plan create` and `preview` paths, is rejected together with `canary_exception`, and a snapshot that gains the marker after creation fails the hash check. `revalidate` derives the waiver set solely from a hash-valid snapshot that carries the marker, with every id also covered by the per-item digest. Nothing reads the marker from an environment variable, option or config. The existing `canary_exception` keeps its exact current meaning and checks.

## 5. Candidate-review workflow (local, read-only until the plan is typed)
1. **Prepare (owner):** declare privately the sender (or token address), N, and the send start time; send the messages (section 12 owner notes). Nothing real is sent as part of P3.
2. **Index them (separately authorized read, outside P3):** after delivery an incremental `mailbox sync` indexes the new messages. This is the same read-only sync as before and needs its own written authorization at P4 time.
3. **`candidates` (local, read-only):** lists messages that match the declared sender and window, with the review sheet; header banner: **SUGGESTED CANDIDATES: NOT SELECTED, NOTHING IS PLANNED OR CHANGED**. It reports mismatches loudly (count != N, a shared thread, an unread or important message, an unexpected extra match). It can write the candidate ids to a **new private file with restrictive permissions, never inside Git** (the same pattern as `cleanup candidates --export-ids`).
4. **Individual review (owner):** the owner opens each message in Gmail and ticks off each ordinal against the sheet. Any doubt means stop and fix the messages, not the policy.
5. **`describe-set` (local, read-only):** takes the ids file and shows the per-id verdicts (eligible/refused with safe reason codes), the set digest and the exact typed phrase; creates nothing.
6. **`plan-set` (local, owner types the set phrase):** creates one DRAFT plan; refused unless the ids file equals the candidate set exactly. Then the ordinary `cleanup plan review` (shows every exact id on the owner's terminal) and `cleanup approve` (typed). Suggested candidates and approved targets are different objects: only the frozen, reviewed, approved plan can ever be executed.
7. **No `sync` or scan between steps 3 and the run.** A new full scan completes → `INDEX_RESCANNED`; an incremental sync does not move the anchor, but any change it applies to a target (labels, a joined thread message, deletion) makes that item stale, and a checkpoint older than 24 h blocks everything (`SYNC_STALE`). The plan is therefore short-lived by design: plan expiry 48 h, approval 24 h, practical window a single sitting.

## 6. Immutable plan and approval invariants
1. The snapshot (account, ids sorted, per-item digest, policy marker and fields, classification ruleset hash, protection digest, index anchor, expiry) is canonical JSON hashed with SHA-256; any change is a new plan, a new review and a new approval.
2. A plan has 1..25 items, version 1, no parent or revision; the marker and its fields are immutable and mutually consistent (tier, window, count, digest).
3. Approval is one-time, typed, bound to plan hash, action and item count, valid 24 h, never longer than the plan; wrong phrases are recorded and locked out; an approval never executes anything.
4. Account binding: the plan's account must equal the index account at every step and the live profile account before the first request.
5. Audit: creation, review, approval, reservation, slice and item transitions and results are hash-chained, append-only events; no ids, labels or phrases in the events.
6. The exception waives nothing outside the frozen ids; an id outside the plan is never reachable; extra or missing ids refuse.

## 7. Execution and partial-failure behavior (unchanged executor; made explicit)
Path: reserve (typed execution phrase consumes the approval) → confirm slice → run slice (separate typed run phrase) in the bulk path of M12D, in an acceptance branch with only the archive switch open. Per item: lease check, live account check (once), local revalidation, live message and whole-thread read, durable intent, **at most one** archive request, execution-bound independent post-read.
| Event | Exact behavior |
|---|---|
| drift (labels, thread, state changed) or message gone | the item is **skipped, nothing sent for it** (`SKIPPED_DRIFT` / `SKIPPED_GONE`); the batch goes on; reported as skipped, never as archived |
| definite rejection by Gmail | item `NOT_APPLIED`; the execution **stops**; the remaining items become `NEVER_ATTEMPTED`; end state `PARTIAL` if something was applied before, else `FAILED` |
| `UNKNOWN` (timeout, 5xx, network error, ambiguous result) | item `UNKNOWN`; the execution stops (`RECONCILIATION_REQUIRED`); remaining items `NEVER_ATTEMPTED`; only a fresh read-only observation (separate gate) can settle it; **never retried** |
| `CONFLICT` after observation | final and visible; never presented as success |
| account mismatch or authorization problem at start | refused before any request |
| token or authorization expiry mid-run | the transport refuses further requests; items already `APPLIED` stay applied; the rest are not attempted |
| lease expiry or interruption (crash, Ctrl-C, sleep) | an item with an intent and no result is `OPEN`/`UNKNOWN` work for read-only reconciliation; the execution is **never resumed** |
**Partial execution is never reported as an atomic rollback.** After one or more successful archives, a later refusal ends the run as `PARTIAL` with exact counts (archived, skipped, not applied, unknown, never attempted); earlier archives are **not** undone automatically. Undoing is only an explicit, separately authorized reversal plan (section 8). Reports and the dashboard show "completed" only when nothing is unresolved.

## 8. Reversal behavior and F5 safeguards (P5)
- A reversal plan (M12D) is created locally from a finished (`EXECUTED` or `PARTIAL`) execution and includes **only** items recorded `APPLIED` with checked trusted-adapter evidence whose recorded previous labels contain `INBOX`, with no open undo; skipped, `NOT_APPLIED`, `UNKNOWN` and never-attempted items are excluded, and the plan can never grow. An item that observation later proves `APPLIED` needs a **new** reversal plan.
- Each item runs through the unchanged per-item undo engine: typed approval of the plan (24 h) and a typed phrase per slice; live preflight (exact archived state recorded for that message, same thread, no changed or protected sibling); durable intent; **one** `INBOX`-add request; independent post-read. `RESTORED` only if the observed labels equal **exactly** the originally recorded label set, otherwise `UNKNOWN`; nothing is retried.
- **F5 and mixed threads:** a test-set message must be alone in its thread at planning and at run time, so no sibling exists and the F5 sibling-trust rule is not exercised by the live acceptance. If a message nevertheless gains a sibling, the archive refuses it as drift and the undo refuses it as drift; a sibling carrying `SENT`, `STARRED`, `DRAFT`, `TRASH`, `SPAM` or a protected label blocks the thread in both directions; a sibling is trusted as "restored" only through the strict F5 conditions (approved plan, strict `RESTORED` ledger, authorization carrying this plan's id).

## 9. Synthetic test matrix (no Gmail, no credentials; fake wire and temporary SQLite)
"Existing" = covered by the current suite (reviewed in `test_bulk_reversal` 29 tests, `test_bulk_execution` 14, `test_cleanup_batch` 28, `test_cleanup_executor` 49, `test_canary_exception` 21, `test_cleanup_canary` 18, `test_undo_infrastructure`); "New" = to be added in the increments of section 11. Existing thread/sibling coverage includes sibling-archived-together, protected sibling blocks the thread, protected archived sibling not ignored, sibling changed by someone else, vanished or unknown sibling skipped, siblings restored by another plan not trusted, forged reversal id never relaxes the thread rule.
| Scenario | Expected | Coverage |
|---|---|---|
| 0, 1, 3, 25, 26 selected ids | 0 and 26 refused; 1, 3, 25 accepted (S1 profile requires exactly 3) | New |
| duplicate or substituted id (a personal id swapped in) | refused (sender, window, thread, digest checks) | New |
| unexpected sender; timestamp outside the window or in the future | refused whole plan | New |
| shared thread; protected sibling; message later gains a sibling | refused at creation; skipped as drift at run | Existing mechanisms + New for the marker |
| `SENT`, `IMPORTANT`, `STARRED`, `DRAFT`, unread, user label, protection rule, Trash/Spam, not in inbox | refused (never waived) | Existing for the rules + New for the set |
| account mismatch (index vs plan vs live) | refused before any request | Existing + New |
| stale checkpoint; new full scan after planning; plan or approval expired | `SYNC_STALE`, `INDEX_RESCANNED`, expiry refusals | Existing + New |
| changed ids file; changed set digest; wrong or old set phrase; forged marker in a hash-valid snapshot | refused; hash mismatch | New |
| ordinary `plan create`/`preview` with the marker; ordinary plan using the waiver | impossible | New |
| drift between creation, review, approval, reservation and run | refused or skipped, never executed | Existing + New |
| partial success then failure (rejection after k archives) | `PARTIAL`, exact counts, no rollback claim, remaining never attempted | Existing + New wording |
| `UNKNOWN`, then `CONFLICT` | stop, `RECONCILIATION_REQUIRED`, never retried | Existing |
| interrupted run; expired lease; expired token; transport failure | open item, never resumed; refusals before requests | Existing + New |
| exactly the frozen set mutated; no request outside it; request kinds only archive | request log equals the frozen ids and one kind | New |
| reversal contains only the verified archived subset; skipped/unknown excluded; labels restored exactly; wrong labels give `UNKNOWN` | as stated | Existing + New |
| single-message canary behavior unchanged (byte-for-byte policy for `canary_exception`) | unchanged | Existing, re-run unchanged |
| `candidates` helper: read-only (no writes, no Gmail), refuses ambiguous counts, never creates a plan | as stated | New |
Existing tests are reviewed first, then only the gaps are added; no existing assertion is weakened or skipped.

## 10. Staged acceptance (S1, then S2): each step needs its own written authorization
**S1 (3 dedicated messages).** (1) Offline preflight and backup. (2) Owner sends the 3 messages (Tier A if possible), reads each once. (3) Authorized read-only `mailbox sync` indexes them. (4) `candidates`, per-message review, `describe-set`, `plan-set`, review, approve (all local). (5) Archive: temporary local acceptance branch with only the archive switch (single-message canary, undo and observation blocked or off), write-token refresh, typed phrases, one slice of 3. (6) Verify locally and in Gmail: all 3 left the Inbox and remain in All Mail, nothing else changed. (7) Reversal: local reversal plan and typed approval; temporary branch with only the undo switch; one slice; verify locally and in Gmail: all 3 back with their original labels. (8) Close-out: main, gates `False`, branches deleted, evidence kept.
**S2 (up to 25 dedicated messages).** Only after S1 passes and is documented; same protections, a fresh set (new token address, new `not_before`), separate approvals, one slice of up to 25 (accepted G5), same verification on every message.
**Acceptance criteria (each stage):** every selected message archived exactly once; zero skipped except by an explained, expected cause; zero `UNKNOWN`/`CONFLICT`; request count equals the number of applied items; audit chain and database intact; after reversal every message is `RESTORED` with its exact original labels; no request outside the frozen set; owner's independent Gmail verification of each message.
**Stop conditions (any, no retry):** account mismatch; any candidate count different from N; shared thread, protected or unexpected label, unread/important; stale checkpoint, rescanned index, expired plan/approval/lease/token; drift on any item; `UNKNOWN`, `CONFLICT`, transport error, rate limit; the owner's Gmail check disagrees with the record; any unexpected output. Uncertainty is settled only by read-only observation (its own authorization) or by hand.

## 11. Minimal implementation sequence (each increment: Draft PR, review, offline only)
| # | Increment | Content |
|---|---|---|
| I1 | read-only `candidates` helper and review sheet | local only; no plan, no writes, no marker; tests of ambiguity refusals and read-only behavior |
| I2 | plan layer | marker, snapshot fields, integrity rules, `_insert_plan` path, `create_test_set_plan`, ordinary-path rejections, hash/forgery tests |
| I3 | eligibility and revalidation | waiver set consumed by `cleanup_candidates`/`revalidate`; per-item digest checks; creation/review/approval/reservation drift tests |
| I4 | execution and reversal integration | bulk path honors the marker; partial-failure wording; request-log assertions; reversal-subset tests; canary regression suite |
| I5 | CLI and owner tooling | `describe-set`, `plan-set` (local), private S1/S2 scripts and acceptance-branch runners (as in P1/P2); user guide |
Only then, at P4, the live stages. Unchanged throughout: executor, transport, policy, phrases, OAuth, audit schema.

## 12. Owner notes for preparing messages (later), limitations and owner decisions
**Preparing messages (later, not now):** send each from an address that is **not** the personal account; one message per intended target; **unique unrelated subject** per message that includes its ordinal (Gmail groups same-subject messages from one sender into one thread, which would break the own-thread rule); generic content; open and read each once; make sure none is marked important (remove it manually if Gmail did) and that no filter touches them; do not touch them afterwards; record the declared sender/token, N and the send start time privately.
**Limitations:** subject evidence is owner-verified only; a token address needs provider support; Gmail may auto-classify or auto-mark messages (a machine check refuses, it does not repair); one slice of 25 has no smaller first slice (hence S1); a plan is short-lived by design; `UNKNOWN` reconciliation on real Gmail stays unexercised unless an `UNKNOWN` occurs, which is a stop condition.
**Owner decisions still needed (only these):** (a) whether a token sender address is available (Tier A) or Tier B must be used; (b) the F5 decision of section 13.

## 13. F5 coverage record (before v1.0 acceptance)
Real-Gmail F5 behavior (several messages in one thread, a protected or `SENT` sibling, restoring one of several) is **not** exercised by S1/S2 and will not be exercised in the current acceptance scope. It is covered synthetically by the existing M12D tests plus the new test-set cases above. **Recorded requirement:** before v1.0 acceptance the owner must either (1) accept synthetic-only F5 evidence and document the limitation in the user guide (bulk reversal of multi-message threads is unverified on real Gmail), or (2) authorize a later, separate live shared-thread experiment (not part of P3 through P5 as scoped). The design recommends (1) for v1.0 together with a documented operating note, and revisiting (2) only if real multi-message-thread reversals become part of intended use.
