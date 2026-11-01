# Real Gmail acceptance plan (personal account, dedicated test messages)

**Status: PLAN ONLY. Nothing here is authorized, scheduled or executed.** Writing or merging this document does not authorize any Gmail, OAuth, Keychain or index access, any live gate change, or any message to be created. `LIVE_EXECUTION_ENABLED`, `LIVE_UNDO_ENABLED` and `LIVE_OBSERVE_ENABLED` stay `False` in `main`. M12 is complete as *development and synthetic verification*; it is **not** production-ready and no real-mailbox validation of undo, observation or bulk execution exists (see [M12C-SECURITY-AUDIT.md](M12C-SECURITY-AUDIT.md), [M12D-BULK-EXECUTION.md](M12D-BULK-EXECUTION.md), [CANARY.md](CANARY.md); tracker: issue #41).

**Owner decision (recorded):** no separate Gmail account is created or used. Acceptance uses the owner's existing personal account, with dedicated, clearly identifiable test messages inside it. Consequences are handled in section 2 (the SENT rule) and section 9 (what must change first).

## 0. Ground rules for every phase
1. **Each phase is a separate written owner approval** (a checkpoint, section 8). Approval of one phase never approves the next; approval is per use and expires (default: the session in which it was given).
2. **Never auto-select personal mail for mutation.** Only the dedicated test set (section 2) may ever be a target. If a plan contains anything else, STOP.
3. **Prefer synthetic coverage.** Anything that does not need Gmail's real behavior stays in the offline suite; live steps test only what the fake cannot: Gmail's real answers, quotas, consistency, labels and thread behavior.
4. **Privacy in GitHub.** Public artifacts (issues, PRs, comments, CI logs, this repository) record only: phase name, pass/fail, counts, safe state codes and local plan/execution ids. Never message ids, thread ids, addresses, subjects, label names, content, snippets, tokens or mailbox counts. Local evidence stays on the owner's machine (index, backups, audit log).
5. **No automatic retries** after any ambiguous mutation. Ambiguity is `UNKNOWN` and is settled only by a fresh read-only observation or by the owner by hand.
6. **No unattended runs, background jobs or schedules.** The owner is present for every live step; every mutating step is typed at a terminal.
7. **No new mutation class.** Only ARCHIVE (remove `INBOX`) and UNDO (add `INBOX`); never Trash, delete, `batchModify`, send, draft, label creation or any generic modification.
8. **Flags.** All three gates stay `False` until a separate explicit owner approval AND a reviewed code change (section 6). They are switched on in a short-lived acceptance branch that is never merged into `main`.
9. **Zero Additional Cost.** No billing account or paid Google Cloud resource; stop if the Console asks for one.

## 1. Phase A — offline preflight (no Gmail, no OAuth, no Keychain)
Goal: prove the exact commit that will be used is sound before any credential is touched.
- Record the commit SHA under test; confirm it equals a reviewed `main` HEAD (or the reviewed acceptance branch, section 6).
- Run, locally: full `unittest`, `compileall`, `scan_secrets --all`, `git diff --check`; confirm the three gate constants by source inspection.
- Confirm CI for that SHA passed.
- Back up the local index file (copy plus checksum) and note the Python and tool versions. Do not open the personal index for any other purpose.
- Confirm the dashboard cannot mutate (it is GET-only; no change needed).
- **Exit:** all green, backup verified. **Checkpoint 1** is the owner's go for Phase B.

## 2. The dedicated test-message set
Purpose: a set that can never be mistaken for ordinary mail and never expands.
- **Origin.** Each test message is sent to the personal account from an address that is **different from the personal Gmail account under test** (this is the requirement in [CANARY.md](CANARY.md) §5). No separate test account is created or required. Acceptable senders: an existing, different Gmail address the owner already has; an existing non-Gmail address; or a trusted person who sends a dedicated test message at the owner's request. A message sent from the personal account itself carries the `SENT` label, a hard protection that the canary exception deliberately never waives (`CANARY_SELF_SENT`): **never use a self-sent message, and never weaken `SENT` or any other canary eligibility rule.** If the received message turns out to carry `SENT` (or any other protection), it is unusable; stop and send another from a different address.
- **Identity.** A unique random marker generated for this run (for example a long random token) placed in the subject and body, plus a plain statement that it is a software test. The marker is kept only locally; it is never put in GitHub. The token must not resemble any real sender, brand or personal content.
- **Eligibility the owner prepares by hand** (all must hold, or `describe` refuses): the message is in the Inbox; read exactly once; not starred, not marked important, no user labels, no other label than the standard inbox/category ones; not in a thread with any other message; not matched by an existing Gmail filter that would label, archive or mark it (check the owner's filters beforehand). Gmail may mark a message important or sort it into a category on its own; if `describe` reports ineligible, stop and discuss rather than editing the tool's policy.
- **Quantity.** Stage 1 uses ONE message. Up to 25 only after a separate approval (Checkpoint 8), each individually created, individually verified as eligible, each in its own thread.
- **Target binding.** The tool operates only on message ids the owner types or confirms locally from the marker match; nothing is chosen by query, label, age or classification.

## 3. Phase B — first real Gmail read (narrowest supported path; scope is fixed here)
Uses only the existing read-only path (`gmail.readonly`), no write or undo capability and **no new CLI feature**. This phase does **not** authorize a full mailbox scan or full synchronization; those are separate (Phase B2).

**What the existing commands do (from `MAILBOX.md`, `SYNC.md`, `cli.py`, `scanner.py`, `sync_health.py`):**
- `mailbox scan --limit N` indexes the **newest N messages** by listing and fetching metadata; the index is then PARTIAL by design; it never prunes or deletes rows. A freshly received test message is among the newest, so a small N (the owner picks it, no larger than needed) reliably includes it **provided** fewer than N other messages arrive after it. Verify afterwards that the test message is indexed.
- **When a limited scan is supported:** only while the local index has **no** sync-checkpoint row for the account (`SYNC_LIMITED_REFUSED` otherwise, decided locally before any Gmail request). In practice: a fresh or never-fully-scanned index, or after `mailbox purge`.
- **When the checkpoint makes it unavailable:** once a completed full scan has established a sync checkpoint, `--limit` is refused. The only supported alternatives are then `mailbox sync` (applies changes since the checkpoint; reads metadata of every message changed since then, not just the test message, and ends in `NEEDS_RECONCILE`, requiring a full scan, if the history is too old) or `mailbox scan --all` (the whole mailbox). The software cannot narrow either to one message.
- **Whether the owner's real index already has a checkpoint is unknown to this plan and is not inspected here.** The owner states it (or runs the local-only `mailbox sync --status`, which does not contact Gmail) before Checkpoint 2.

**Personal metadata read and persisted locally by `scan`/`sync` (never put in GitHub):** from `labels.list`: label ids, names (user label names included) and types; from `messages.list`: message ids; from `messages.get` (metadata format, `From` header only): message id, thread id, internal date, label ids, size estimate, sender address (lower-cased) and the unread flag. Never requested or stored: bodies, snippets, subjects, attachments, recipients, raw content, tokens. The data is written to the local index (`index.sqlite3`, outside Git; Time Machine and other backups will contain it). Subjects are not read, so the test message is identified by its message id, which the owner records locally (section 2), not by its subject marker.

**Phase B1 (limited read; only if no checkpoint exists).** Authorization: **Checkpoint 2.** Verify account identity locally first (the stored account equals the account the owner typed; on mismatch, STOP before any read). Then `mailbox scan --limit N`, `classify run` (local) and `cleanup_canary_cli describe` (local). Exit: the test message is indexed and `describe` reports it eligible.
- **Limit of B1:** `describe` is local and works on a partial index, but **creating, reviewing, approving and running a cleanup plan are refused unless the sync state is fresh** (`cleanup_plans.revalidate` → `sync_health.problems`: no checkpoint gives `SYNC_CHECKPOINT_MISSING`; a checkpoint older than 24 hours gives `SYNC_STALE`). A limited scan cannot create a checkpoint (only a completed full scan can). So B1 alone can never lead to the archive canary.

**Phase B2 (baseline for Phase C; broader read; separate approval).** The archive canary (Phase C) needs a fresh checkpoint: either a completed `mailbox scan --all` followed by the canary within 24 hours, or, if the owner's index already holds a checkpoint, a `mailbox sync` completed within 24 hours of the plan, review, approval and run. Both read the metadata listed above **for the whole mailbox, or for every message changed since the checkpoint**, and persist it locally. That is materially larger than reading the one test message and needs its own owner approval: **Checkpoint 2b**, independent of Checkpoint 2. If the owner does not approve it, Phase C and later cannot proceed; the freshness rule is not weakened and no narrower command is invented.
- **Owner decision before Checkpoint 2b:** (a) the index already has a checkpoint, so run only `mailbox sync`; (b) approve `mailbox scan --all` (long-running, on the order of an hour per `MAILBOX.md`, read-only; rows no longer in Gmail are pruned only after a complete listing); or (c) stop at B1.
- What is pasted to GitHub from any read: pass/fail and counts of operations only; no mailbox counts, ids, addresses or label names.

## 4. Phase C — single-message archive canary
Requires Phase B2. Authorization: **Checkpoint 3** (write OAuth setup/login), **Checkpoint 4** (flip the execution gate in the acceptance branch), **Checkpoint 5** (run).
1. Verify the separate write project and consent exist per `SETUP-GMAIL.md` §5c; if the earlier write authorization was revoked or expired, redo it with the owner present (`auth setup-write ... --confirm-separate-project`, then `auth login-write --expect-account EMAIL`). Access tokens live about an hour, nothing refreshes them, and an unpublished (Testing) OAuth app's refresh token expires weekly (Q8): log in shortly before the run.
2. Confirm the sync state is fresh (Phase B2, within 24 hours). `cleanup_canary_cli plan` (typed canary-plan phrase), `cleanup plan review`, `cleanup approve` (typed). The plan contains exactly one message.
3. In the acceptance branch only, set `LIVE_EXECUTION_ENABLED = True` (reviewed, section 6). `auth status-write` must show at least ten minutes of token life.
4. `cleanup_canary_cli run` with the typed execution phrase and the separate canary phrase. At most one archive request is sent (remove `INBOX` only). The executor performs the live account check, whole-thread preflight, durable intent, one request and an independent execution-bound post-read.
5. **Independent verification** (section 7): the owner confirms in the Gmail interface that the one message left the Inbox and still exists in All Mail with no other label change, and `cleanup exec show` / `cleanup audit verify` agree.
6. Revert the gate (acceptance branch deleted or reset), `auth logout-write`/`revoke-write` per the owner's choice.
- **Exit criteria:** execution `EXECUTED`, one item `APPLIED`, zero unknown/conflict, audit chain intact, the owner's independent check matches.

## 5. Phase D — single-message undo, then observation
Authorization: **Checkpoint 6** (undo gate and undo run), **Checkpoint 7** (observation gate). Each is separate from Phase C.
- **Undo.** Create a one-message reversal plan from the finished canary execution (`cleanup undo reversal create`), review, `approve` (typed), then run one slice (typed). Gate `LIVE_UNDO_ENABLED = True` in the acceptance branch only, plus a fresh `auth refresh-write`/login (the undo transport is separate). One request adds `INBOX` back; the independent post-read must show the message restored to its original labels. Expected final state: back in the Inbox, original label set (section 7).
- **Observation / reconciliation.** `LIVE_OBSERVE_ENABLED = True` in the acceptance branch only. Run `cleanup exec recovery --reconcile` on the completed canary and on the completed undo: expected result is no change and no mutation request. Observation uses the write-scoped credential (Google offers no narrower scope that fits, F6), so it is read-only by application policy and by the transport's capability, not by Google's scope.
- **Not rehearsable live:** an `UNKNOWN` outcome cannot be produced safely on purpose. UNKNOWN/CONFLICT handling stays verified by the synthetic suite only; on any real occurrence follow section 10.

## 6. Reviewed code and gate procedure (when, not now)
- Gates are flipped only in a dedicated acceptance branch created from the exact reviewed `main` SHA, containing nothing except the constant change and the test adjustments it forces, reviewed by the owner before use, never merged into `main`, and discarded after the run. `main` always keeps all three `False`.
- Each gate is flipped independently, only for the phase that needs it, and its own checkpoint is recorded first.
- After each phase: confirm `main` still shows all three `False`.

## 7. Verifying the original state afterwards
For each test message record locally (not in GitHub) its labels before any step. After undo, and again after a fresh read-only observation, all must match: in the Inbox, same label set, same thread, unread/read state as before, not starred, not important, not in Trash or Spam, message still present. Also confirm: audit chain intact, execution and reversal finished with zero unresolved items, local index backup unchanged apart from the expected appended records. If the owner's own Gmail view disagrees with the tool's record, the Gmail view wins and the result is `FAIL` (STOP, section 10).

## 8. Owner-approval checkpoints (each written, each separate, none implied by another)
| # | Approves exactly | Does not approve |
|---|---|---|
| 1 | Offline preflight results; moving to Phase B | any Gmail access |
| 2 | Limited read-only Gmail read (`scan --limit N`), only if no checkpoint exists | a full scan, a sync, any write, any gate |
| 2b | Baseline for Phase C: `mailbox sync` or `mailbox scan --all` (broader metadata read), as the owner chooses | any write, any gate |
| 3 | Write-credential setup/login (real OAuth consent) | flipping any gate, any mutation |
| 4 | The reviewed acceptance branch with `LIVE_EXECUTION_ENABLED = True` | undo, observation |
| 5 | The single archive canary on the named, verified test message | more than one message |
| 6 | Undo gate and one single-message undo | bulk undo |
| 7 | Observation gate and read-only reconciliation | any mutation |
| 8 | A bounded test of up to 25 dedicated messages (requires section 9, item 3 first) | anything beyond that set |
| 9 | Declaring the acceptance result and what, if anything, may be enabled afterwards | production use |

## 9. Prerequisites, owner decisions and preparatory code (nothing implemented in this task)
1. **A different sender (no code).** The test message must come from an address different from the personal account (section 2): another existing Gmail address, a non-Gmail address, or a trusted person. No separate account is created. `SENT` is not relaxed.
2. **A fresh checkpoint for the canary (owner decision, no code).** The existing software cannot limit the read that establishes the freshness the canary plan requires: only a completed full scan creates a checkpoint, and `sync` reads all changes since it. The owner decides between (a) `mailbox sync` on an existing checkpoint, (b) `mailbox scan --all`, or (c) not proceeding past Phase B1. This is Checkpoint 2b and is never implied by Checkpoint 2.
3. **A fixed, bounded test set beyond one message (code, before Checkpoint 8 only).** The ordinary cleanup policy needs mail at least 90 days old with a MEDIUM+ rules classification, so fresh test messages cannot be planned, and the canary exception covers exactly one named message. A 25-message acceptance needs a separately designed, reviewed mechanism (for example a multi-message variant of the canary exception, explicitly listing owner-confirmed ids, same hard protections, hard cap 25) or an agreed alternative. Not needed for the single-message phases.
4. **Nothing else is required in code before Phase B1** (the read-only scan, classify and describe paths exist).

## 10. STOP conditions and decision tree
Immediately stop (no further request, no retry, no gate left on) and report only the phase and a safe state code when:
- **Account mismatch:** the stored, typed or live-profile account differs.
- **Stale authorization:** token under ten minutes of life, approval or plan expired, slice confirmation stale (the 30-minute slice window), phrase rejected or locked out.
- **Unexpected labels / drift:** any label other than the recorded ones, a changed thread, a sibling message, the message starred/important/unread/in a user label.
- **UNKNOWN:** an item that may have been dispatched without trusted proof.
- **CONFLICT:** observation contradicts the recorded outcome or the message vanished.
- **Transport error:** timeout, 5xx, quota/rate answer, redirect, anything not an exact expected response.
- **Inconsistent record:** broken audit chain, inconsistent reversal ledger, count other than the planned one.
- **Owner's independent check disagrees** with the tool.

Decision tree after a stop:
1. *Did a mutation request possibly leave the machine?* No → fix the cause (credential, eligibility), re-plan from the relevant checkpoint; nothing to recover. Yes → continue.
2. *Do not retry.* Switch the gate back to `False`, log out of the write session.
3. Run read-only observation (needs its own gate approval, Checkpoint 7) or inspect the message in the Gmail interface by hand.
4. *Observed state = original (still in Inbox)?* Record `NOT_APPLIED`; the phase may be re-planned only with a new plan and a fresh approval (never a repeat of the old execution).
5. *Observed state = archived as intended?* Record the outcome as verified by observation; continue only through the planned next phase.
6. *Observed state = anything else (labels changed, thread differs, message gone)?* `CONFLICT`: stop the whole acceptance, restore by hand through the Gmail interface if safe, preserve the local index and audit log unmodified, open an incident note (no mailbox data), and require a new review before any further live step.
7. If nothing can be established, the item remains `UNKNOWN` and the whole acceptance stays paused; it is never rewritten as success.

## 11. Risks (and their handling here)
| Risk | Handling |
|---|---|
| The write scope (`gmail.modify`) is broader than the allowlisted requests (F6) | application allowlist plus capability-separated transports; single test message; owner present; revoke after the run |
| Gmail answers differ from the fake (consistency, paging, quotas, error documents) | one message first; UNKNOWN on any deviation; no retry |
| Audit-log tail truncation or rewrite is undetectable by the hash chain (F4) | backup before; `cleanup audit verify --checkpoint` before and after; file permissions |
| Long-running slices vs token lifetime | single message only until Checkpoint 8; fresh login; 10-minute floor |
| Unpublished-app refresh token expires weekly (Q8) | log in the same day; no reliance on a stored refresh token |
| A test message becomes ineligible or is auto-modified by a Gmail filter/classifier | check filters first; STOP rather than weakening policy |
| A baseline scan/sync reads and stores metadata of far more than the test message | separate Checkpoint 2b; owner chooses sync vs full scan; metadata only (no bodies or subjects); local index only |
| Personal data leaking into GitHub | public record limited to phase, pass/fail, counts and safe codes |
| Reversal of a stopped plan cannot continue (G6); stopped/interrupted work is never resumed | by design; new plan and approval |

## 12. Readiness verdict (current `main`)
- **First explicitly authorized read-only Gmail test (Phase B1: a limited scan of the newest N messages, then local `describe`): ready with no code change**, but only if the owner's index has no sync checkpoint (otherwise `--limit` is refused), and after the written Checkpoint 2 and the offline preflight. If a checkpoint exists, the narrowest supported read is `mailbox sync` (Checkpoint 2b), which is broader.
- **Single-message archive canary (Phase C): ready in code**, procedurally blocked until the owner (a) supplies a different sender, (b) approves the baseline read (Checkpoint 2b) so a fresh checkpoint exists, (c) redoes the write-OAuth steps and (d) approves the acceptance branch.
- **Undo and observation (Phase D): implemented but never run against real Gmail**; ready only after Phase C passes and separate approvals.
- **25-message test: not ready**; needs the design and code in section 9, item 3.
- Nothing here is a claim of production readiness.
