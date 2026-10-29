# M8A-2: the inert Gmail link contract (tracking issue #52, umbrella #23)

> **Status: INERT and UNVERIFIED.** The module [`gmail_link_contract.py`](../src/gmail_intelligence/gmail_link_contract.py) exists only as a tested contract. Nothing in the CLI, the dashboard API or the dashboard UI uses it, no interface has a link flag, an `href` or a link button, and in production it never produces a URL. **Real Gmail was never contacted; no Gmail web address has been tried.** Every statement below about how Gmail's addresses behave is **NOT VERIFIED**. Enabling any link needs a separate live verification stage and **separate owner authorization**.

## 1. Purpose
The attention list (`mailbox attention`, the dashboard Action Center) shows no message identifier and no link, so a message is found by date and sender. A future, verified link could open the right conversation in the user's own Gmail. Because the facts below are unknown, this milestone only fixes the *rules* a link would have to follow and proves, with synthetic tests, that the code refuses by default.

## 2. How it behaves today
`build_link(index_account, confirmed_account, thread_id, *, requested, excluded, deleted)` returns
* in production (`CONTRACT_STATUS = "UNVERIFIED"`): `{"status": "UNAVAILABLE", "reason": "CONTRACT_UNVERIFIED"}` for **every** input, valid or not. The inputs are not examined, nothing is echoed, and there is no `href`.
* only when a test overrides the constant to `"VERIFIED"`, the gates below run in this order, and the first failing gate decides:

| Order | Gate | Reason when it fails |
|---|---|---|
| 0 | the status is exactly `"VERIFIED"` | `CONTRACT_UNVERIFIED` |
| 1 | the caller requested a link (`requested is True`) | `LINKS_DISABLED` |
| 2 | the message is not excluded and not deleted (anything but a plain `False` counts as excluded) | `LINKS_DISABLED` |
| 3 | the owner-confirmed account equals the index account **exactly** (no case folding, no trimming) | `ACCOUNT_NOT_CONFIRMED` |
| 4 | the account passes the strict ASCII address rule (lowercase, at most 254 characters, no `/ ? # %`, backslash, space, quote or control character, no non-ASCII character) | `ACCOUNT_FORMAT_UNSAFE` |
| 5 | a thread id is present | `THREAD_ID_MISSING` |
| 6 | the thread id is lowercase hexadecimal, 1 to 32 characters | `THREAD_ID_INVALID` |

Reason codes (a closed vocabulary): `LINKS_NOT_IMPLEMENTED` (what every interface answers today; the attention engine's `link` field), `LINKS_DISABLED`, `ACCOUNT_NOT_CONFIRMED`, `ACCOUNT_FORMAT_UNSAFE`, `THREAD_ID_MISSING`, `THREAD_ID_INVALID`, `CONTRACT_UNVERIFIED`. A refusal never contains an input.

## 3. Restrictions
* A fixed host and a fixed path template only (`https://mail.google.com/mail/u/{account}/#all/{thread}`), filled with the two validated values and nothing else.
* **No sender-controlled text can reach a link**: the function has no sender, subject, label or domain parameter.
* **No positional account index** (`/u/0/`, `authuser=`) is ever produced: `/u/0/` would address "the first signed-in account", which is not necessarily the index's account.
* The module imports only `re` and is imported by nothing in the product (tests prove both).
* The host name is assembled from parts in the source, because two repository guards (`tests/test_auth.py`, `tests/test_cleanup.py`) forbid the literal text of the full-access OAuth scope anywhere in `src/`, and a web address starts with that text. The guards were not changed or weakened. This is a web address, never a scope, and nothing here requests any permission.
* The confirmed account is personal data: it must never be logged, cached or put into an error.
* No link flag in the CLI, no `href` in any API payload, no link button or anchor in the dashboard.

## 4. What is NOT VERIFIED (all of it)
| Behaviour | Status |
|---|---|
| `https://mail.google.com/mail/u/<address>/#all/<id>` opens the intended conversation | NOT VERIFIED |
| a thread id from the Gmail API is accepted by the web address, including for a message that is not the first of its thread | NOT VERIFIED |
| `/u/<address>/` selects the account by address even when several accounts are signed in, in any order | NOT VERIFIED |
| `#all` opens archived messages (a starred message that is no longer in the Inbox) | NOT VERIFIED |
| aliases, `googlemail.com` addresses and Google Workspace accounts behave the same way | NOT VERIFIED |
| what Gmail shows for a deleted or trashed message | NOT VERIFIED |
| whether the address and the fragment survive Gmail's own redirects and sign-in screens | NOT VERIFIED |

## 5. Live-verification checklist (a future, separately authorized stage; not performed)
1. One signed-in account: the template opens the right conversation.
2. Several signed-in accounts, in different orders: the address, not the position, selects the account.
3. An archived starred message: `#all` finds it.
4. A message that is not the first of its thread: the API thread id opens the conversation.
5. A deleted message: the behaviour is understood and the link is refused or harmless.
6. An alias or a `googlemail.com` address.
7. A Google Workspace account.

## 6. Activation requires separate owner authorization
Setting `CONTRACT_STATUS` to `"VERIFIED"`, wiring the contract into the attention engine, the CLI or the dashboard, adding any link flag or rendering any link are **not** part of M8A-2. Each needs the live-verification evidence, a design review and the owner's explicit authorization in writing. Until then the answer is, and must stay, `CONTRACT_UNVERIFIED`.
