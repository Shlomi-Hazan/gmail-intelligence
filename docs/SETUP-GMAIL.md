# Gmail read-only connection: setup and usage (M1)

**Verification status:** the code is covered by offline tests (synthetic credentials, fake Keychain, mocked Google responses). **Live verification:** the project owner reported, from their own terminal output, that OAuth login succeeded, tokens were stored in the macOS Keychain, `gmail check` returned profile counts and the label count, nothing in the mailbox was modified, and Google Cloud billing stayed disabled during setup. This is the owner's report; it was not independently performed or reproduced by the assistant that wrote the code.

Scope requested, exactly one: `https://www.googleapis.com/auth/gmail.readonly`. The app cannot modify, send or delete mail with it, and the code contains no such calls.

## 1. Zero Additional Cost gate (research summary, 2026-10-11)
What the official pages say / do not say:
- Creating a project: billing is listed as **optional**; the page says only that you *might* need it depending on the APIs/features (https://developers.google.com/workspace/guides/create-project).
- Enabling Workspace APIs, creating OAuth clients, the Gmail quickstart and the consent-screen guide: **no billing requirement or cost is mentioned** (https://developers.google.com/workspace/guides/enable-apis, .../create-credentials, .../configure-oauth-consent, https://developers.google.com/workspace/gmail/api/quickstart/python).
- Gmail API pages and the quota page give **no price** and describe quota units only (https://developers.google.com/workspace/gmail/api/reference/quota: 1,200,000 units/min per project, 6,000 units/min per user).
- Testing status: up to 100 test users; authorizations and refresh tokens **expire after 7 days** (https://support.google.com/cloud/answer/15549945).
- A project with no linked billing account shows "This project has no billing account" and has billing disabled (https://docs.cloud.google.com/billing/docs/how-to/verify-billing-enabled).

**Conclusion:** no official page says a personal Gmail OAuth app needs billing, but none states the Gmail API is free forever either. Treat "no billing account ever linked" as the safety condition and **stop immediately** if Google asks for a card, a billing account or "Link a billing account" at any step. Budget alerts are not a spending cap and are not a substitute. Pricing can change; nothing here is a promise.

## 2. One-time Google Cloud setup (manual, you do this)
1. Open https://console.cloud.google.com, create a new project (any name). **Do not link a billing account.**
2. APIs & Services > Library > **Gmail API** > Enable.
3. Google Auth platform > Branding: app name, support email. Audience: **External** (Internal is for Workspace organizations). Publishing status stays **Testing**. Add **your own Gmail address as the only test user**.
4. Data access > Add or remove scopes: add only `.../auth/gmail.readonly` (it is a restricted scope; fine in Testing for yourself).
5. Clients > Create client > Application type **Desktop app** > download the JSON.
6. Verify billing is disabled: Console > Billing must say the project has no billing account, or run `gcloud beta billing projects describe PROJECT_ID` and expect no `billingAccountName` and not `billingEnabled: true`.
7. Import the client file (copies it to a private location outside Git, mode 600), then delete the download:
```bash
.venv/bin/gmail-intelligence auth setup --import ~/Downloads/<downloaded-file>.json
```

## 3. Commands (project venv: `python3 -m venv .venv && .venv/bin/pip install .`)
Use `pip install .` (a normal install) if you only want to run the CLI; use `pip install -e .` only when developing (see the first row of §7 if the editable install stops working). Re-run `pip install .` after pulling code changes.
| Command | What it does | Contacts Google? |
|---|---|---|
| `gmail-intelligence auth setup [--import FILE]` | Shows these steps / validates and stores the client file | no |
| `gmail-intelligence auth login [--expect-account EMAIL] [--no-browser]` | Browser consent (loopback + PKCE), verifies granted scopes are exactly read-only, reads your profile email, asks you to confirm, stores tokens in the macOS Keychain | yes |
| `gmail-intelligence auth status` | Local state only: client file, token present, scope | no |
| `gmail-intelligence gmail check` | Refreshes the token if needed, reads profile counts and the label count | yes |
| `gmail-intelligence auth logout [--yes]` | Removes only this app's Keychain item | no |

Exit codes: 0 success; 1 operational failure (not configured, not logged in, auth/API/storage error, declined); 2 usage error.

## 4. What is stored and where
- OAuth client file: `~/Library/Application Support/gmail-intelligence/client_secret.json` (directory 700, file 600; override with `GMAIL_INTELLIGENCE_HOME`). For Desktop apps Google treats this secret as non-confidential, but it is still kept private and never committed.
- Tokens: one macOS Keychain item (service `gmail-intelligence`) via the `keyring` library. **No plaintext fallback**: if the macOS Keychain backend is unavailable the commands refuse. The first access may show a macOS Keychain prompt; "Always Allow" applies to the Python binary running the tool. The Keychain does not protect against other malicious processes running as you.
- Nothing is printed except the account email, counts and status messages. Tokens, codes and secrets are never printed or logged.

## 5. Disconnect
`auth logout` deletes the local item only. To revoke Google's side, remove the app at https://myaccount.google.com/permissions. Delete the client file manually if you want it gone.

## 5b. Write authorization (M4C-B; NOT set up yet)
The archive feature needs a SEPARATE write authorization that does not exist yet. Do not create it before the live stage is approved. When it is: use a **separate Google Cloud project** (free; stop if any billing prompt appears), a separate Desktop client, `auth setup-write --import FILE --confirm-separate-project` (the read-only client must already be set up; the flag is your attestation that the write client lives in a different project, because Google's revocation is project-wide), then `auth login-write --expect-account EMAIL` (shows the risks of the broad permission and needs a typed confirmation). `auth status-write` is local only. `auth logout-write` removes only the local token; `auth revoke-write` revokes at Google. The read-only commands and their token are unchanged and never touch these.

## 5c. Manual Google Cloud verification checklist (for a future, separately approved M4C-B2 step)
Nothing here is to be done yet. The tool's offline checks (recognized client-id format, different project numbers, a consistent optional `project_id`, and your `--confirm-separate-project` declaration) are preconditions only: they cannot see Google's side, and **your declaration is not sufficient evidence by itself**. Before any real authorization, verify by hand in the Google Cloud Console and in your Google Account that:
1. The write OAuth client belongs to a **dedicated** Google Cloud project.
2. The read-only project number and the write project number are **different** (compare the numbers shown in the Console, not just the client ids).
3. The write project is **not shared with unrelated applications**, other clients or other people.
4. The write OAuth configuration (consent screen, test user, Gmail API, the single scope) matches the intended account and application.
5. The write credential file is a **separate file** from the read-only credential file (`client_secret_write.json` versus `client_secret.json`).
6. You understand that **revoking the write authorization may affect all grants of the write project** (Google's revocation is project-wide), which is why the project must hold nothing else.
7. **No billing account or paid resource** is enabled; stop if the Console asks for one, and do not enable any without explicit approval.
8. You know where to inspect and revoke access manually: your Google Account > Security > Third-party access, for the write project's app.

**Passing this checklist does not authorize `auth login-write`.** Real OAuth consent requires a separate, explicit approval.

## 6. What the live check reads (verified by the owner, see top)
`auth login` will request only the read-only scope, show the authorized email and ask for confirmation. `gmail check` then makes exactly two read calls: `users.getProfile` (email, message/thread totals) and `users.labels.list` (only the label **count** is shown; names are not displayed). No message, subject, body or attachment is read.

## 7. Common problems
| Symptom | Cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'gmail_intelligence'` from the installed command, but `PYTHONPATH=src python3 -m gmail_intelligence` works | **Cause:** an editable install relies on a `.pth` file in the venv; on macOS folders synced by iCloud (e.g. `~/Documents`) the file can acquire the *hidden* flag, and Python 3.13+ deliberately ignores hidden `.pth` files. Confirm: `ls -lO .venv/lib/python3.13/site-packages/*.pth` shows `hidden`, and `gmail-intelligence doctor` warns. **Fix:** `chflags nohidden .venv/lib/python3.13/site-packages/*.pth`, or avoid the problem with a normal install: `.venv/bin/pip install .` |
| "stored authorization is expired or revoked" after about a week | Testing-status refresh tokens expire after 7 days: run `auth login` again |
| "Google did not return a refresh token" | Revoke the app at myaccount.google.com/permissions, then `auth login` |
| "unexpected OAuth scopes granted" | Credentials with broader scopes are rejected on purpose; remove extra scopes in the consent configuration |
| "must be of type 'Desktop app'" | You created a Web client; create a Desktop app client |
| "Access blocked / app not verified" | Your address must be listed as a test user; the unverified-app warning is expected for yourself in Testing |
| "Keychain ... failed" | Keychain locked or access denied; unlock it and retry |
| "rate limit exceeded" | Wait and retry; requests are already retried with backoff |

## 8. Dependencies (all free, open source)
`google-api-python-client` (official Gmail client), `google-auth-oauthlib` (official OAuth installed-app flow), `keyring` (macOS Keychain access). Resolved with their transitive dependencies in the project venv at implementation time: google-api-python-client 2.201.0, google-auth 2.61.0, google-auth-oauthlib 1.5.0, keyring 25.7.0 (plus httplib2, requests, oauthlib and others). Nothing is installed globally.
