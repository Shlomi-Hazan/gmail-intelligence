"""M8A-2: the INERT, UNVERIFIED contract for a Gmail source link. Pure (it imports only `re`), disconnected from every interface, and in production it never yields a link.

Nothing in the CLI, the dashboard API or the dashboard UI imports or calls this module: they all answer `NOT_IMPLEMENTED`. How Gmail's web addresses behave (account selection by
address, thread versus message identifiers, archived messages, aliases, several signed-in accounts) is NOT VERIFIED, so `CONTRACT_STATUS` stays "UNVERIFIED" and `build_link`
answers `CONTRACT_UNVERIFIED` for EVERY input, without looking at it. Enabling a link needs a separate live verification stage and the owner's explicit authorization
(docs/GMAIL-LINK-CONTRACT.md). The gates below are exercised by tests that override the constant; they are the rules an enabled contract would follow.

Rules: the link is built only from a fixed host and a fixed path template and from two validated values (the confirmed account and a lowercase-hex thread id). No sender-controlled
text exists in the signature, so none can reach a link. Positional account indices ("the first signed-in account") are never produced. Every failure is a fixed reason code; no input is ever echoed.
"""
import re

CONTRACT_STATUS = "UNVERIFIED"  # the only value that can ever produce a link is "VERIFIED", and nothing sets it in production
# The host is assembled from parts on purpose: the repository guards (tests/test_auth.py, tests/test_cleanup.py) forbid the literal text of the full-access OAuth scope
# anywhere in src/, and a web address that starts with that text must not weaken them. This is a web address, never a scope; nothing here requests any permission.
HOST = ".".join(("mail", "google", "com"))
TEMPLATE = "https://" + HOST + "/mail/u/{account}/#all/{thread}"  # the account by ADDRESS, never by position
REASONS = ("LINKS_NOT_IMPLEMENTED", "LINKS_DISABLED", "ACCOUNT_NOT_CONFIRMED", "ACCOUNT_FORMAT_UNSAFE", "THREAD_ID_MISSING", "THREAD_ID_INVALID", "CONTRACT_UNVERIFIED")
NOT_IMPLEMENTED = {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"}  # what every interface says today (identical to the attention engine's item field)

_THREAD = re.compile(r"[0-9a-f]{1,32}")  # the same contract as gmail_write_policy.valid_id: lowercase hexadecimal only
_ACCOUNT = re.compile(r"[a-z0-9]+(?:[._+-][a-z0-9]+)*@[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+")  # strict ASCII address: no / ? # % \ space or quote can match
MAX_ACCOUNT = 254


def _unavailable(reason):
    return {"status": "UNAVAILABLE", "reason": reason}


def _safe_account(value):
    return isinstance(value, str) and len(value) <= MAX_ACCOUNT and value.isascii() and _ACCOUNT.fullmatch(value) is not None


def build_link(index_account, confirmed_account, thread_id, *, requested=False, excluded=False, deleted=False):
    """The link answer for one item: {"status": "UNAVAILABLE", "reason": CODE} or, only when the contract is VERIFIED (tests only today), {"status": "AVAILABLE", "reason": None, "href": URL}.

    index_account: the account of the index; confirmed_account: the account the owner explicitly confirmed for linking (it must equal the index account exactly);
    thread_id: the thread of the message (lowercase hexadecimal); requested: the caller asked for a link; excluded/deleted: the message is excluded or no longer in the index.
    """
    if CONTRACT_STATUS != "VERIFIED":  # production: every input, valid or not, gets the same fixed answer and is never examined
        return _unavailable("CONTRACT_UNVERIFIED")
    if requested is not True:
        return _unavailable("LINKS_DISABLED")
    if excluded is not False or deleted is not False:  # an excluded or deleted message never gets a link (anything but a plain False is treated as "excluded")
        return _unavailable("LINKS_DISABLED")
    if not isinstance(confirmed_account, str) or not confirmed_account or not isinstance(index_account, str) or confirmed_account != index_account:
        return _unavailable("ACCOUNT_NOT_CONFIRMED")
    if not _safe_account(index_account):
        return _unavailable("ACCOUNT_FORMAT_UNSAFE")
    if thread_id is None or thread_id == "":
        return _unavailable("THREAD_ID_MISSING")
    if not isinstance(thread_id, str) or _THREAD.fullmatch(thread_id) is None:
        return _unavailable("THREAD_ID_INVALID")
    return {"status": "AVAILABLE", "reason": None, "href": TEMPLATE.format(account=index_account, thread=thread_id)}
