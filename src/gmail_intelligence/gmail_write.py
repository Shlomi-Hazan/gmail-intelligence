"""Archive-only Gmail write transport and the narrow adapter built on it (M4C-B1). NOT used by any production command yet.

Design:
  * A thin stdlib HTTPS transport (http.client) - no discovery client, no batch support, no generic service object.
  * Every request is checked by gmail_write_policy BEFORE building and again immediately before dispatch.
  * No redirect is ever followed, no proxy is read from the environment, nothing is retried (a mutation is sent at most once per call),
    nothing is refreshed here. An expired token stops the call; refresh/revocation are separate OAuth operations (oauth_write).
  * The adapter exposes archive_message / message_state / thread_state / profile_email only - never the connection, token or credentials.
  * Failures map to fixed codes; messages never contain tokens, ids, URLs or account identifiers.
  * An uncertain outcome of the mutation (timeout, 5xx, network error, malformed answer) is reported as UncertainOutcome, which the
    future executor must record as UNKNOWN (never retry blindly). Nothing here proves WHO changed a message.
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
        """Policy check -> credentials -> second policy check -> ONE dispatch. Returns (kind, (status, bytes))."""
        headers = {"accept": "application/json", "user-agent": USER_AGENT}
        if body is not None:
            headers["content-type"] = "application/json"
        kind = policy.check_request(method, url, headers, body)  # before anything else; the credential header is never part of this check
        if self._sent >= policy.MAX_REQUESTS:
            raise Denied("DENIED_BUDGET")
        headers["authorization"] = self._authorization()
        return kind, self._dispatch(method, url, body, headers)

    def _dispatch(self, method, url, body, headers):
        policy.check_request(method, url, headers, body, allow_authorization=True)  # the check that guards the wire itself
        self._sent += 1
        conn = None
        try:
            conn = self._factory()
            conn.request(method, url[len(policy.BASE):], body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(policy.MAX_RESPONSE + 1)
            status = resp.status
        except (TimeoutError, ssl.SSLError, http.client.HTTPException, OSError) as exc:
            raise UncertainOutcome("TIMEOUT" if isinstance(exc, TimeoutError) else "NETWORK_ERROR") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - closing must never mask the real outcome
                    pass
        policy.check_response(status, len(data))
        return status, data


def _interpret(kind, status, data):
    """Map a response to a parsed JSON object or a typed error. For the mutation, anything unclear is UNCERTAIN, never success."""
    mutation = kind == "MESSAGE_MODIFY"
    if status == 200:
        obj = policy.parse_json(data)
        if obj is None:
            raise UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure()
        return obj
    if status == 401:
        raise WriteAuthError()
    if status == 403:
        raise RateLimited() if _reasons(data) & {"rateLimitExceeded", "userRateLimitExceeded"} else WriteAuthError()
    if status == 404:
        raise MessageNotFound()
    if status == 429:
        raise RateLimited()
    if status == 400:
        raise RequestRejected()
    if status >= 500:
        raise UncertainOutcome("SERVER_ERROR") if mutation else ReadFailure("SERVER_ERROR")
    raise UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure()


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
        return ()  # the API omits labelIds when a message has no labels; valid only because the answer is otherwise complete (checked by callers)
    if not isinstance(value, list) or len(value) > 100 or not all(isinstance(x, str) and 0 < len(x) <= 64 and x.isascii() for x in value):
        raise ReadFailure()
    return tuple(sorted(set(value)))


class ArchiveAdapter:
    """The only object a future executor receives. Public API: profile_email, verify_account, message_state, thread_state, archive_message."""
    __slots__ = ("_t", "_expected")

    def __init__(self, transport, expected_account):
        self._t, self._expected = transport, expected_account

    def __repr__(self):
        return "<ArchiveAdapter>"

    def _get(self, url):
        kind, (status, data) = self._t.perform("GET", url)
        return _interpret(kind, status, data)

    def profile_email(self):
        email = self._get(policy.BASE + "/gmail/v1/users/me/profile").get("emailAddress")
        if not isinstance(email, str) or not email:
            raise ReadFailure()
        return email

    def verify_account(self):
        """LIVE check against Google (one profile read). Not called by any M4C-B1 code path; a later approved live stage uses it."""
        if self.profile_email().strip().lower() != (self._expected or "").strip().lower():
            raise AccountMismatch()

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
        """Remove INBOX from exactly one message (a single POST, never retried). Returns ArchiveResult or raises a typed error."""
        url = f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}/modify?fields=id,threadId,labelIds"
        kind, (status, data) = self._t.perform("POST", url, body=policy.MODIFY_BODY)
        obj = _interpret(kind, status, data)
        if obj.get("id") != message_id:
            raise UncertainOutcome("AMBIGUOUS_RESULT")
        try:
            return ArchiveResult(_labels(obj.get("labelIds")))
        except ReadFailure:
            raise UncertainOutcome("AMBIGUOUS_RESULT") from None


def fetch_profile_email(creds, connection_factory=None):
    """One allowed profile read with fresh credentials (used by `auth login-write` to learn which account was authorized)."""
    return ArchiveAdapter(_Transport(creds, connection_factory), None).profile_email()


def open_archive_adapter(expected_account, store, client_path, now=None, connection_factory=None):
    """Build the adapter from the stored write authorization. LOCAL checks only: no refresh, no network, no prompt.

    Needs: a stored record, a matching client file, the exact scope, the same OAuth client, the expected account and at least ten minutes of
    access-token life. The live account verification (`verify_account`) is a separate, later, explicitly approved step.
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
