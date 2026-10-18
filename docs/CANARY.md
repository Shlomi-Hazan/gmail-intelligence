# Live canary readiness (M4)

**Status: prepared offline; live access and execution are NOT approved.** Nothing in this document has been done: no Google Cloud change, no OAuth consent, no Keychain item, no
Gmail request. `LIVE_EXECUTION_ENABLED` is `False` and nothing changes it. A canary archives **one** message the owner chose, once.

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
