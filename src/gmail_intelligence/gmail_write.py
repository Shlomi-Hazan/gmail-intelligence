"""Archive-only Gmail write transport and the narrow adapter built on it (M4C-B1). NOT used by any production command yet.

Design:
  * A thin stdlib HTTPS transport (http.client) - no discovery client, no batch support, no generic service object.
  * Every request is checked by gmail_write_policy BEFORE building and again immediately before dispatch.
  * No redirect is ever followed, no proxy is read from the environment, nothing is retried (a mutation is sent at most once per call),
    nothing is refreshed here. An expired token stops the call; refresh/revocation are separate OAuth operations (oauth_write).
  * The adapter exposes archive_message / message_state / thread_state / profile_email only - never the connection, token or credentials.
  * Failures map to fixed codes; messages never contain tokens, ids, URLs or account identifiers.
  * Before-dispatch refusals (policy, budget, expired token) are definite: nothing was sent. Once dispatch may have begun, EVERY unclear
    result of the single mutation request (timeout, interruption, redirect, oversized/malformed/unexpected answer, any unexpected
    exception) is reported as UncertainOutcome, which the future executor must record as UNKNOWN and reconcile; it is never retried
    here and never turned into "not applied". Only a validated Gmail error document (matching status and JSON error object) is a
    definite rejection. Nothing here proves WHO changed a message.
  * An adapter cannot archive anything until `verify_account()` has succeeded against the live profile; any identity or authorization
    problem afterwards locks it out again.
"""
import http.client
import re
import ssl

from gmail_intelligence import gmail_write_policy as policy
from gmail_intelligence.gmail_write_policy import Denied  # noqa: F401  (re-exported)

TIMEOUT = 30
USER_AGENT = "gmail-intelligence-write/1"
_UNCERTAIN_CODES = ("TIMEOUT", "SERVER_ERROR", "NETWORK_ERROR", "AMBIGUOUS_RESULT")  # subset of cleanup_exec.OUTCOME_CODES["UNKNOWN"]


class WriteTransportError(Exception):
    code = "WRITE_ERROR"
    text = "Gmail write transport error"

    def __init__(self, code=None):
        super().__init__(self.text)
        self.code = code or self.code


class WriteAuthError(WriteTransportError):
    code, text = "AUTH_PROBLEM", "the write authorization is missing, expired or rejected"


class AccountMismatch(WriteTransportError):
    code, text = "ACCOUNT_MISMATCH", "the authorized account is not the expected account"


class AccountNotVerified(WriteTransportError):
    code, text = "ACCOUNT_NOT_VERIFIED", "the account has not been verified against Google; nothing may be modified"


class MessageNotFound(WriteTransportError):
    code, text = "NOT_FOUND", "the message or thread no longer exists"


class RateLimited(WriteTransportError):
    code, text = "RATE_LIMITED", "Gmail rate limit; the request was not processed"


class RequestRejected(WriteTransportError):
    code, text = "REJECTED", "Gmail rejected the request"


class ReadFailure(WriteTransportError):
    code, text = "READ_FAILED", "a Gmail read failed or returned an unusable answer"


class UncertainOutcome(WriteTransportError):
    """The mutation may or may not have happened. Record UNKNOWN with `.code`; never retry automatically."""
    code, text = "AMBIGUOUS_RESULT", "the outcome of the request is uncertain"


def _gmail_error(status, data):
    """True only for a well-formed Gmail error document whose error.code equals the HTTP status (a proxy or portal page never qualifies)."""
    body = policy.parse_json(data)
    err = body.get("error") if body else None
    return isinstance(err, dict) and err.get("code") == status and isinstance(err.get("message"), str)


def _reasons(data):
    body = policy.parse_json(data) or {}
    err = body.get("error")
    items = err.get("errors") if isinstance(err, dict) else None
    return {e.get("reason") for e in items if isinstance(e, dict)} if isinstance(items, list) else set()


def _default_connection():
    return http.client.HTTPSConnection(policy.HOST, timeout=TIMEOUT, context=ssl.create_default_context())


class _Transport:
    """Private. Holds the credentials and the connection factory; the only place that can reach the network."""
    __slots__ = ("_creds", "_factory", "_sent")

    def __init__(self, creds, connection_factory=None):
        self._creds, self._factory, self._sent = creds, connection_factory or _default_connection, 0

    def _authorization(self):
        token = getattr(self._creds, "token", None)
        if not token or not getattr(self._creds, "valid", False):
            raise WriteAuthError()  # no refresh here: an expired token stops the caller
        return "Bearer " + token

    def perform(self, method, url, body=None):
        """Policy check -> credentials -> second policy check -> ONE dispatch. Returns (kind, (status, bytes)).

        Everything up to the call of `_dispatch` is BEFORE dispatch: failures there are definite (nothing was sent).
        """
        headers = {"accept": "application/json", "user-agent": USER_AGENT}
        if body is not None:
            headers["content-type"] = "application/json"
        kind = policy.check_request(method, url, headers, body)  # before anything else; the credential header is never part of this check
        if self._sent >= policy.MAX_REQUESTS:
            raise Denied("DENIED_BUDGET")
        headers["authorization"] = self._authorization()
        return kind, self._dispatch(method, url, body, headers)

    def _dispatch(self, method, url, body, headers):
        kind = policy.check_request(method, url, headers, body, allow_authorization=True)  # the check that guards the wire itself (still pre-dispatch)
        mutation = kind == "MESSAGE_MODIFY"
        self._sent += 1
        conn = None
        # ---- from here on dispatch may have begun: creating the connection is NOT assumed to be harmless
        try:
            conn = self._factory()
            conn.request(method, url[len(policy.BASE):], body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(policy.MAX_RESPONSE + 1)
            status = resp.status
        except (TimeoutError, ssl.SSLError, http.client.HTTPException, OSError) as exc:
            code = "TIMEOUT" if isinstance(exc, TimeoutError) else "NETWORK_ERROR"
            raise (UncertainOutcome(code) if mutation else ReadFailure(code)) from None
        except Exception:  # noqa: BLE001 - anything unexpected after dispatch began is unclear by definition
            raise (UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure()) from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - closing must never mask the real outcome
                    pass
        try:
            policy.check_response(status, len(data))
        except Denied:
            if mutation:  # the request was sent: a redirect or oversized answer says nothing about whether the change happened
                raise UncertainOutcome("AMBIGUOUS_RESULT") from None
            raise
        return status, data


def _interpret(kind, status, data):
    """Map a response to a parsed JSON object or a typed error. For the mutation, anything unclear is UNCERTAIN, never success or rejection."""
    mutation = kind == "MESSAGE_MODIFY"
    unclear = UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure()
    if type(status) is not int:
        raise unclear
    if status == 200:
        obj = policy.parse_json(data)
        if obj is None:
            raise unclear
        return obj
    if status >= 500:
        raise UncertainOutcome("SERVER_ERROR") if mutation else ReadFailure("SERVER_ERROR")
    if status in (400, 401, 403, 404, 429) and _gmail_error(status, data):  # a definite answer only when it is a real Gmail error document
        if status == 401:
            raise WriteAuthError()
        if status == 403:
            raise RateLimited() if _reasons(data) & {"rateLimitExceeded", "userRateLimitExceeded"} else WriteAuthError()
        if status == 404:
            raise MessageNotFound()
        if status == 429:
            raise RateLimited()
        raise RequestRejected()
    raise unclear


class MessageState:
    __slots__ = ("thread_id", "label_ids")

    def __init__(self, thread_id, label_ids):
        self.thread_id, self.label_ids = thread_id, label_ids

    def __repr__(self):
        return "<MessageState>"


class ArchiveResult:
    """What Gmail's answer to the mutation said: the labels after the call. NOT proof that this tool made the change."""
    __slots__ = ("label_ids", "inbox_removed")

    def __init__(self, label_ids):
        self.label_ids = label_ids
        self.inbox_removed = "INBOX" not in label_ids

    def __repr__(self):
        return "<ArchiveResult>"


def _labels(value):
    if value is None:
        return ()  # the API omits labelIds when a message has none; valid only because the answer is otherwise complete (checked by callers)
    if not isinstance(value, list) or len(value) > 100 or not all(isinstance(x, str) and 0 < len(x) <= 64 and x.isascii() for x in value):
        raise ReadFailure()
    return tuple(sorted(set(value)))


_PROFILE = policy.BASE + "/gmail/v1/users/me/profile?fields=emailAddress"


class ArchiveAdapter:
    """The only object a future executor receives. Public API: verify_account, message_state, thread_state, archive_message.

    `archive_message` is refused until `verify_account()` succeeded; a later identity/authorization problem locks it again.
    """
    __slots__ = ("_t", "_expected", "_verified")

    def __init__(self, transport, expected_account):
        self._t, self._expected, self._verified = transport, expected_account, False

    def __repr__(self):
        return "<ArchiveAdapter>"

    def _call(self, method, url, body=None):
        try:
            kind, (status, data) = self._t.perform(method, url, body)
            return _interpret(kind, status, data)
        except WriteAuthError:
            self._verified = False  # an authorization problem invalidates the verified state
            raise

    def _get(self, url):
        return self._call("GET", url)

    def _profile_email(self):
        email = self._get(_PROFILE).get("emailAddress")
        if type(email) is not str or not email:
            raise ReadFailure()
        return email

    def verify_account(self):
        """LIVE check against Google (one profile read). Not called by any M4C-B1 code path; a later approved live stage uses it.

        Success unlocks `archive_message`; a mismatch, a failed or malformed lookup, or a missing expected account locks it.
        """
        self._verified = False
        try:
            email = self._profile_email()
        except WriteTransportError:
            raise
        except Exception:  # noqa: BLE001 - never leave a half-verified state
            raise ReadFailure() from None
        if not isinstance(self._expected, str) or not self._expected.strip() or email.strip().lower() != self._expected.strip().lower():
            raise AccountMismatch()
        self._verified = True

    def message_state(self, message_id):
        obj = self._get(f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}?format=minimal&fields=id,threadId,labelIds")
        if obj.get("id") != message_id or not isinstance(obj.get("threadId"), str):
            raise ReadFailure()
        return MessageState(obj["threadId"], _labels(obj.get("labelIds")))

    def thread_state(self, thread_id):
        obj = self._get(f"{policy.BASE}/gmail/v1/users/me/threads/{policy.valid_id(thread_id)}?format=minimal&fields=id,messages/id,messages/labelIds")
        msgs = obj.get("messages")
        if obj.get("id") != thread_id or not isinstance(msgs, list) or not msgs:
            raise ReadFailure()
        out = []
        for m in msgs:
            if not isinstance(m, dict) or not isinstance(m.get("id"), str):
                raise ReadFailure()
            out.append((m["id"], _labels(m.get("labelIds"))))
        return tuple(out)

    def archive_message(self, message_id):
        """Remove INBOX from exactly one message (a single POST, never retried). Returns ArchiveResult or raises a typed error.

        Raises Denied/AccountNotVerified/WriteAuthError/RequestRejected/MessageNotFound/RateLimited for definite non-mutations (nothing happened),
        and UncertainOutcome whenever the result is unclear after dispatch may have begun.
        """
        if not self._verified:
            raise AccountNotVerified()
        url = f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}/modify?fields=id,threadId,labelIds"
        try:
            obj = self._call("POST", url, policy.MODIFY_BODY)
            if obj.get("id") != message_id:
                raise UncertainOutcome("AMBIGUOUS_RESULT")
            return ArchiveResult(_labels(obj.get("labelIds")))
        except (Denied, AccountNotVerified, WriteAuthError, RequestRejected, MessageNotFound, RateLimited, UncertainOutcome):
            raise  # definite non-mutations (refused before dispatch, or a validated Gmail error document) and already-uncertain outcomes
        except Exception:  # noqa: BLE001 - any other failure (including an unusable answer) after dispatch may have begun is never a clean "not applied"
            raise UncertainOutcome("AMBIGUOUS_RESULT") from None


def fetch_profile_email(creds, connection_factory=None):
    """One allowed profile read with fresh credentials (used by `auth login-write` to learn which account was authorized)."""
    return ArchiveAdapter(_Transport(creds, connection_factory), None)._profile_email()


def open_archive_adapter(expected_account, store, client_path, now=None, connection_factory=None):
    """Build the adapter from the stored write authorization. LOCAL checks only: no refresh, no network, no prompt.

    Needs: a stored record, a matching client file, the exact scope, the same OAuth client, the expected account and at least ten minutes of
    access-token life. The adapter is NOT verified: `verify_account()` (a live profile read, a separately approved step) must succeed
    before `archive_message` is possible. The expected account is compared with the live profile AND was bound to the stored record.
    """
    from gmail_intelligence import oauth_write

    blob = store.load()
    if blob is None:
        raise oauth_write.AuthError("no write authorization is stored; run `auth login-write`")
    client = oauth_write.load_write_client_config(client_path)
    creds = oauth_write.blob_to_write_credentials(blob, client)
    if (blob.get("account") or "").strip().lower() != (expected_account or "").strip().lower():
        raise AccountMismatch()
    oauth_write.require_validity(creds, now)
    return ArchiveAdapter(_Transport(creds, connection_factory), expected_account)
