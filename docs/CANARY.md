# Live canary readiness (M4)

**Status: the canary was executed ONCE under the owner's explicit approval and succeeded (evidence summary in [M4-CLOSEOUT.md](M4-CLOSEOUT.md)); live execution is NOT approved for
anything further.** `LIVE_EXECUTION_ENABLED` is `False` in the repository and nothing changes it. The procedure below is kept as the required process for any future live use, which needs a
new written owner approval. A canary archives **one** message the owner chose, once.

## 1. The entry point (code, disabled)
`cleanup_canary.run_canary(index, account, exec_id, token, confirmation, store, client_path)` is a library function, not a command. It is not reachable from the CLI (`cleanup execute`
stays disabled and the CLI never imports the module), and no environment variable, configuration value or option enables it.

1. **Switch first.** While `exec_live_mailbox.LIVE_EXECUTION_ENABLED` is `False` it raises `LIVE_DISABLED` as its first statement: the index, the credential store, the client file and the
   network are not touched.
2. **Local checks (index only).** The execution is `EXECUTING` under the caller's live lease, `ARCHIVE`, with exactly **one** target in **one** slice (reserved from an approved plan of
   one message), and the owner typed the separate canary confirmation `cleanup_canary.canary_phrase` (`CANARY ARCHIVE 1 <execution id> <plan hash prefix>`), which is none of the
   approval, execution-confirmation or undo phrases. Wrong phrases are recorded (`CANARY_REJECTED`) and locked out.
3. **Credentials, locally.** `open_live_mailbox` loads the write authorization (no refresh, no network, no prompt). A credential problem does not consume the confirmation.
4. **One confirmation per execution.** `CANARY_CONFIRMED` is recorded durably before anything is requested; a second confirmation for the same execution is refused.
5. **The shared executor does the rest** (`cleanup_live.execute_live_batch`, no second archive path): approval and plan integrity, live account verification, protections and drift,
   live message and whole-thread preflight, durable intent, **at most one** archive request (remove `INBOX` only), an independent execution-bound trusted post-read, `UNKNOWN` on any
   ambiguity (never retried), recovery by fresh observation only. Policy is unchanged: no delete, no Trash, no send, no label creation, no undo.

## 2. Authorization readiness (what exists, what is needed)
- **Scope.** Exactly `https://www.googleapis.com/auth/gmail.modify`, defined in one module (`oauth_write.py`). It is broader than archiving; the restriction to "remove INBOX from one
  message" is an application policy enforced by the transport (`gmail_write_policy.py`), not by the scope. The read-only path keeps `gmail.readonly` and is unchanged.
- **Google Cloud configuration (manual, owner, not done).** A **separate Google Cloud project**, dedicated to this write client and holding nothing else (revocation at Google is
  project-wide); the Gmail API enabled; an OAuth consent screen with the owner's account as the test user; a **Desktop** OAuth client; **no billing account or paid resource** (stop if the
  Console asks for one; this keeps the project at Zero Additional Cost). The checklist is `SETUP-GMAIL.md` section 5c. Passing it does not authorize login.
- **Separation from read-only credentials.** Separate client file (`client_secret_write.json`, imported with `auth setup-write --import FILE --confirm-separate-project`, never the
  read-only `client_secret.json`), separate Keychain item (service `gmail-intelligence-write`, item `oauth-token:gmail.modify`), no fallback to or from the read-only token, and an
  offline isolation check (recognized client-id format, different project numbers, the owner's recorded attestation) before any login, revoke or cleanup.
- **Account identity.** `auth login-write --expect-account EMAIL` stores nothing unless the authorized account matches. At run time three checks apply: the stored authorization must be
  for the expected account (`open_archive_adapter`), the access token must have at least ten minutes of life, and `verify_account()` compares the live Gmail profile with the expected
  account before any modification; any later authorization problem locks the adapter again.
- **Nothing is printed** except status and counts; tokens, codes, secrets and message identifiers are never shown or logged.

## 3. What the owner must approve before a live canary (each separately, in writing)
1. The Google Cloud verification checklist, then `auth setup-write` and `auth login-write --expect-account ...` (real OAuth consent; a separate approval).
2. The target: one message in a disposable or low-value part of the mailbox, with the owner present, and a backup of the local index beforehand.
3. A reviewed source change that sets `LIVE_EXECUTION_ENABLED = True` together with a reviewed command or script that calls `run_canary` (neither exists now).
4. Reservation of the single-message execution and the typed canary confirmation at run time.
5. A recovery rehearsal plan (what to do if the result is `UNKNOWN`) and the decision that a real undo is out of scope (live undo is deferred).
6. The final M4 security audit of the enabling change.

## 4. Remaining blockers before a live canary
Items 1, 3 and 6 above; verification of real Gmail behaviour the offline fake only imitates (thread read completeness and paging for long threads, exact not-found and error documents,
label omission, quotas); and the weekly refresh-token expiry of an unpublished OAuth app (owner decision on publishing status, Q8).

## 5. The canary exception and the owner entry point (this version; still disabled)
**Why an exception.** The ordinary cleanup policy needs a message at least 90 days old with an approved, MEDIUM+ rules classification, so a fresh test message can never be planned. A
narrow exception exists for exactly ONE explicitly named message: `cleanup_canary.create_canary_plan` (after the owner's separate typed phrase `CANARY PLAN <12 hex>`, derived from the
account and the message id). It waives ONLY `TOO_RECENT` and the classification-type reasons (`UNKNOWN_TYPE`, `RISKY_TYPE`, `TYPE_NOT_APPROVED`, `WEAK_EVIDENCE`, `AMBIGUOUS_TYPES`)
for that message (`cleanup_candidates.CANARY_WAIVED`). It never changes `cleanup candidates` or `cleanup plan create`, whose output is identical with or without it. The plan records
`canary_exception` in its hashed snapshot (one message, version 1, enforced by the integrity check); every later check (review, approval, reservation, per-item revalidation) honours
the same marker for that one message and nothing else.

**What still refuses it (never waived):** `SENT`, `STARRED`, `DRAFT`, `TRASH`, `SPAM`, user protection rules, not-in-inbox, `IMPORTANT`, unread, user labels, attention and AI signals,
missing or stale classification (run `classify run` first), unsafe data, and a mixed thread (a risky sibling). The live preflight (exact labels, whole-thread membership, siblings
unchanged, no protected label) and every executor safeguard apply as for any item.

**The SENT complication (assessed, not bypassed).** A message you sent from the SAME account carries the `SENT` label, a hard protection. The exception does not waive it:
`create_canary_plan` refuses with `CANARY_SELF_SENT` and `describe` says so. **A self-sent test message cannot be used.** Send the disposable message from a DIFFERENT account (any other
address) to the primary one, open and read it once (unread is also refused), and do not touch it between the scan and the run.

**Live execution is only this canary.** `cleanup_live.execute_live_batch` refuses every caller except `run_canary` (a private permit), any execution that is not exactly one target in one
slice, and any execution without the owner's recorded `CANARY_CONFIRMED`. Recovery stays read-only (fresh observations, no mutation). There is no second archive implementation.

**Owner-operated entry point.** `python -m gmail_intelligence.cleanup_canary_cli` (`describe`, `plan`, `run`), separate from the ordinary CLI. Preparation and execution are
separated: `describe` and `plan` are LOCAL (the index only: no Gmail, no OAuth, no Keychain, no network, no mailbox change) and work while `LIVE_EXECUTION_ENABLED` is `False`, because
nothing can be executed without the switch; `plan` still needs the typed phrase and the plan still needs the ordinary review and approval. `run` is execution: while the switch is `False` it
refuses right after the arguments are parsed, before the index, a reservation or any credential store. The account is always explicit, only counts and codes are printed, and there is no
environment or configuration path. (Opening the real index with this build upgrades a v4 index to v5 after an automatic verified backup, like every other command; back it up first.)

**Eventual sequence (each step needs the owner's separate approval; none is done):**
Steps 1-5 are local and need NO live switch; only step 7 does.
1. Back up the index (it is also upgraded v4 to v5 on first open, after an automatic verified backup).
2. `mailbox scan --limit 50`, then `classify run` (ordinary read-only commands; the first one talks to Gmail read-only).
3. `python -m gmail_intelligence.cleanup_canary_cli describe --account EMAIL --message-id ID` (must show `canary: ELIGIBLE...` and `SENT protection: not triggered`).
4. `python -m gmail_intelligence.cleanup_canary_cli plan --account EMAIL --message-id ID` (type the printed phrase).
5. `cleanup plan review PLAN_ID`, then `cleanup approve PLAN_ID` (ordinary commands).
6. A short-lived reviewed commit sets `LIVE_EXECUTION_ENABLED = True` (and a second one reverts it after the run).
7. `auth login-write --expect-account EMAIL` shortly before, then `auth status-write` (the access token needs at least ten minutes of life; nothing refreshes it); then
   `python -m gmail_intelligence.cleanup_canary_cli run --account EMAIL --plan-id PLAN_ID` (type the execution phrase, then the canary phrase).
8. Verify (`cleanup exec show`, `cleanup audit verify`, and the mailbox itself), then revert the switch and decide whether to `auth logout-write` / `auth revoke-write`.
