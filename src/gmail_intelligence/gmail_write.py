"""Archive (and, separately, archive-undo) Gmail write transport and the narrow adapter built on it (M4C-B1, M12C.3). NOT used by any production command yet.

Design:
  * A thin stdlib HTTPS transport (http.client) - no discovery client, no batch support, no generic service object.
  * Every request is checked by gmail_write_policy BEFORE building and again immediately before dispatch.
  * No redirect is ever followed, no proxy is read from the environment, nothing is retried (a mutation is sent at most once per call),
    nothing is refreshed here. An expired token stops the call; refresh/revocation are separate OAuth operations (oauth_write).
  * The adapter exposes verify_account / message_state / thread_state / observe / archive_message / restore_inbox only - never the connection, token or credentials.
  * Archive and undo are SEPARATE capabilities fixed when the transport is built: `archive_message` needs "ARCHIVE", `restore_inbox` needs "UNDO", and the transport itself refuses
    (before any dispatch) the mutation kind its capabilities do not include. A transport holds EXACTLY ONE capability (never both): `open_archive_adapter` -> ARCHIVE, `open_undo_adapter` -> UNDO.
  * Failures map to fixed codes; messages never contain tokens, ids, URLs or account identifiers.
  * Once dispatch may have begun, EVERY unclear result of the single mutation request (timeout, interruption, redirect, oversized/malformed/
    unexpected answer, any unexpected exception) is reported as UncertainOutcome, which the executor must record as UNKNOWN and reconcile; it
    is never retried here. A complete, well-formed Gmail ERROR answer to the POST (400/401/403/404/429) is typed for the caller but is NOT proof
    that the mutation had no effect, so it too is marked as possibly dispatched. Nothing here proves WHO changed a message.
  * Every exception carries `dispatched`: False ONLY where it is raised explicitly BEFORE any transmission could begin (policy check, unverified
    account, request budget, missing or expired credentials); True or None (unknown: treat as possibly sent) everywhere else. It is never
    inferred from a counter, an exception class or a received status code. `definitely_not_dispatched(exc)` is the only test a caller should use.
  * Nothing can be MODIFIED until `verify_account()` has succeeded against the live profile: the gate is a flag on the private transport that
    both `perform` and `_dispatch` check before a MESSAGE_MODIFY, so even the adapter's private helpers cannot bypass it (only code that
    deliberately writes the flag can, which is a convention-level boundary like every underscore in Python). Any identity or authorization
    problem afterwards locks it out again.
  * Responses must be completely and unambiguously framed: a body shorter than its Content-Length, a truncated chunked body, both
    Content-Length and Transfer-Encoding, repeated or malformed Content-Length, a transfer or content coding other than chunked/identity, or a
    non-bytes body is never accepted (UNCERTAIN for the mutation, a read error for reads).
"""
import http.client
import re
import ssl
from datetime import datetime, timezone

from gmail_intelligence import exec_evidence, gmail_write_policy as policy
from gmail_intelligence.gmail_write_policy import Denied  # noqa: F401  (re-exported)

_SEAL = exec_evidence.claim_adapter_seal()  # only this module can create observation issuers (first and only claim)

TIMEOUT = 30
USER_AGENT = "gmail-intelligence-write/1"
_UNCERTAIN_CODES = ("TIMEOUT", "SERVER_ERROR", "NETWORK_ERROR", "AMBIGUOUS_RESULT")  # subset of cleanup_exec.OUTCOME_CODES["UNKNOWN"]


def _utcnow():
    return datetime.now(timezone.utc)


def _mark(exc, dispatched):
    """Record, at the raise site, whether any transmission can have begun (False) or may have (True)."""
    exc.dispatched = dispatched
    return exc


def definitely_not_dispatched(exc):
    """True only for a failure explicitly raised before any transmission could begin. Everything else may have been sent."""
    return getattr(exc, "dispatched", None) is False


class WriteTransportError(Exception):
    code = "WRITE_ERROR"
    text = "Gmail write transport error"
    dispatched = None  # unknown unless the raise site says otherwise; unknown is treated as possibly sent

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
    absent_confirmed = False  # True only when the 404 body is an unambiguous Gmail "not found" document


class RateLimited(WriteTransportError):
    code, text = "RATE_LIMITED", "Gmail rate limit; the request was not processed"


class RequestRejected(WriteTransportError):
    code, text = "REJECTED", "Gmail rejected the request"


class ReadFailure(WriteTransportError):
    code, text = "READ_FAILED", "a Gmail read failed or returned an unusable answer"


class UncertainOutcome(WriteTransportError):
    """The mutation may or may not have happened. Record UNKNOWN with `.code`; never retry automatically."""
    code, text = "AMBIGUOUS_RESULT", "the outcome of the request is uncertain"
    dispatched = True  # an uncertain outcome only exists once transmission may have begun


def _absent(data):
    """True for a Gmail not-found document: the error status NOT_FOUND or the reason notFound (the body is already known to be a well-formed Gmail error)."""
    err = (policy.parse_json(data) or {}).get("error")
    return isinstance(err, dict) and (err.get("status") == "NOT_FOUND" or "notFound" in _reasons(data))


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


class _BadFraming(Exception):
    pass


def _check_framing(resp, data, status):
    """Raise unless the response is completely and unambiguously framed. Called inside the dispatch try/except (so it classifies, never leaks)."""
    if type(data) is not bytes or type(status) is not int:
        raise _BadFraming()
    headers = resp.getheaders()
    if not isinstance(headers, list):
        raise _BadFraming()
    named = {}
    for item in headers:
        if not (isinstance(item, tuple) and len(item) == 2 and type(item[0]) is str and type(item[1]) is str):
            raise _BadFraming()
        named.setdefault(item[0].lower(), []).append(item[1].strip())
    length, coding, content = named.get("content-length", []), named.get("transfer-encoding", []), named.get("content-encoding", [])
    if len(length) > 1 or len(coding) > 1 or len(content) > 1 or (length and coding):
        raise _BadFraming()  # repeated or contradictory framing
    if coding and coding[0].lower() != "chunked":
        raise _BadFraming()
    if content and content[0].lower() != "identity":
        raise _BadFraming()
    if length and re.fullmatch(r"[0-9]{1,9}", length[0], re.ASCII) is None:
        raise _BadFraming()
    if len(data) > policy.MAX_RESPONSE:
        return  # size is judged by the policy; a capped body is not "incomplete"
    if length:
        if resp.length != 0:
            raise _BadFraming()  # fewer bytes than Content-Length announced
    elif coding:
        if not resp.isclosed():
            raise _BadFraming()  # the chunked body did not reach its terminating chunk


class _Transport:
    """Private. Holds the credentials and the connection factory; the only place that can reach the network."""
    __slots__ = ("_creds", "_factory", "_sent", "_allowed", "_bound", "_caps")

    def __init__(self, creds, connection_factory=None, capabilities=("ARCHIVE",)):
        # Archive and undo are STRICTLY separate: a transport holds exactly ONE capability. Empty, unknown, repeated, string or combined sets are refused.
        if type(capabilities) not in (tuple, list, frozenset) or len(capabilities) != 1 or next(iter(capabilities)) not in ("ARCHIVE", "UNDO"):
            raise ValueError("a transport takes exactly one capability: ARCHIVE or UNDO")
        self._caps = frozenset(capabilities)  # which mutation kind this transport may send; fixed at construction
        self._creds, self._factory, self._sent = creds, connection_factory or _default_connection, 0
        self._bound = False  # a transport (its credentials and its verified state) belongs to exactly one adapter
        self._allowed = False  # mutations stay locked until the adapter's verify_account() unlocks them

    def _require_capability(self, kind):
        """Archive and undo are separately authorized: a transport built for one can never send the other (checked before any dispatch, twice)."""
        needed = {"MESSAGE_MODIFY": "ARCHIVE", "MESSAGE_MODIFY_UNDO": "UNDO"}.get(kind)
        if needed is not None and needed not in self._caps:
            raise _mark(Denied("DENIED_CAPABILITY"), False)

    def _authorization(self):
        token = getattr(self._creds, "token", None)
        if not token or not getattr(self._creds, "valid", False):
            raise _mark(WriteAuthError(), False)  # no refresh here: an expired token stops the caller, before anything is sent
        return "Bearer " + token

    def perform(self, method, url, body=None):
        """Policy check -> credentials -> second policy check -> ONE dispatch. Returns (kind, (status, bytes)).

        Everything up to the call of `_dispatch` is BEFORE dispatch: failures there are definite (nothing was sent).
        """
        headers = {"accept": "application/json", "user-agent": USER_AGENT}
        if body is not None:
            headers["content-type"] = "application/json"
        try:
            kind = policy.check_request(method, url, headers, body)  # before anything else; the credential header is never part of this check
        except Denied as exc:
            raise _mark(exc, False)
        self._require_capability(kind)
        if kind in policy.MUTATIONS and not self._allowed:
            raise _mark(AccountNotVerified(), False)
        if self._sent >= policy.MAX_REQUESTS:
            raise _mark(Denied("DENIED_BUDGET"), False)
        headers["authorization"] = self._authorization()
        return kind, self._dispatch(method, url, body, headers)

    def _dispatch(self, method, url, body, headers):
        try:
            kind = policy.check_request(method, url, headers, body, allow_authorization=True)  # the check that guards the wire itself (still pre-dispatch)
        except Denied as exc:
            raise _mark(exc, False)
        self._require_capability(kind)  # also guards a direct call of _dispatch
        mutation = kind in policy.MUTATIONS
        if mutation and not self._allowed:
            raise _mark(AccountNotVerified(), False)  # also guards a direct call of _dispatch
        self._sent += 1
        conn = None
        # ---- from here on dispatch may have begun: creating the connection is NOT assumed to be harmless
        try:
            conn = self._factory()
            conn.request(method, url[len(policy.BASE):], body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(policy.MAX_RESPONSE + 1)
            status = resp.status
            _check_framing(resp, data, status)
        except (TimeoutError, ssl.SSLError, http.client.HTTPException, OSError) as exc:
            code = "TIMEOUT" if isinstance(exc, TimeoutError) else "NETWORK_ERROR"
            raise _mark(UncertainOutcome(code) if mutation else ReadFailure(code), True) from None
        except Exception:  # noqa: BLE001 - anything unexpected after dispatch began is unclear by definition
            raise _mark(UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure(), True) from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - closing must never mask the real outcome
                    pass
        try:
            policy.check_response(status, len(data))
        except Denied as exc:
            if mutation:  # the request was sent: a redirect or oversized answer says nothing about whether the change happened
                raise _mark(UncertainOutcome("AMBIGUOUS_RESULT"), True) from None
            raise _mark(exc, True)
        return status, data


def _interpret(kind, status, data):
    """Map a response to a parsed JSON object or a typed error. For the mutation, anything unclear is UNCERTAIN, never success or rejection.

    Every error raised here follows a complete HTTP answer, so it is marked as possibly dispatched: for a POST, even a well-formed Gmail error
    document does not prove that the mutation had no effect.
    """
    mutation = kind in policy.MUTATIONS
    unclear = _mark(UncertainOutcome("AMBIGUOUS_RESULT") if mutation else ReadFailure(), True)
    if type(status) is not int:
        raise unclear
    if status == 200:
        obj = policy.parse_json(data)
        if obj is None:
            raise unclear
        return obj
    if status >= 500:
        raise _mark(UncertainOutcome("SERVER_ERROR") if mutation else ReadFailure("SERVER_ERROR"), True)
    if status in (400, 401, 403, 404, 429) and _gmail_error(status, data):  # a typed answer only when it is a real Gmail error document
        if status == 401:
            raise _mark(WriteAuthError(), True)
        if status == 403:
            raise _mark(RateLimited() if _reasons(data) & {"rateLimitExceeded", "userRateLimitExceeded"} else WriteAuthError(), True)
        if status == 404:
            exc = MessageNotFound()
            exc.absent_confirmed = _absent(data)
            raise _mark(exc, True)
        if status == 429:
            raise _mark(RateLimited(), True)
        raise _mark(RequestRejected(), True)
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


class RestoreResult:
    """What Gmail's answer to the undo mutation said: the labels after the call. NOT proof that the message was restored or that this tool did it."""
    __slots__ = ("label_ids",)

    def __init__(self, label_ids):
        self.label_ids = label_ids

    def __repr__(self):
        return "<RestoreResult>"


def _labels(value):
    if value is None:
        return ()  # the API omits labelIds when a message has none; valid only because the answer is otherwise complete (checked by callers)
    if not isinstance(value, list) or len(value) > 100 or not all(isinstance(x, str) and 0 < len(x) <= 64 and x.isascii() for x in value):
        raise ReadFailure()
    return tuple(sorted(set(value)))


_PROFILE = policy.BASE + "/gmail/v1/users/me/profile?fields=emailAddress"


class ArchiveAdapter:
    """The only object a future executor receives. Public API: verify_account, message_state, thread_state, observe, archive_message, restore_inbox.

    `archive_message` / `restore_inbox` are refused until `verify_account()` succeeded; a later identity/authorization problem locks them again. Which of the two mutations
    exists at all is decided by the capabilities of the transport the adapter was built on (archive OR undo, never both).
    """
    __slots__ = ("_t", "_expected", "_issuer")

    def __init__(self, transport, expected_account, *, _clock=None):  # `_clock` exists for the fake-only test mailbox; no production factory passes it
        if transport._bound:
            raise ValueError("this transport already belongs to another adapter")  # no cross-account reuse of credentials or verified state
        transport._bound = True
        self._t, self._expected = transport, expected_account
        # one issuer per adapter, bound to the expected account; none when no account is expected (such an adapter can never observe)
        self._issuer = (exec_evidence.new_issuer(expected_account, _clock or _utcnow, seal=_SEAL)
                        if isinstance(expected_account, str) and expected_account.strip() else None)
        self._verified = False

    @property
    def _verified(self):
        return self._t._allowed

    @_verified.setter
    def _verified(self, value):
        self._t._allowed = bool(value)  # the single source of truth lives in the transport that dispatches mutations
        if not value and getattr(self, "_issuer", None) is not None:
            self._issuer.revoke_all()  # losing verification invalidates every unused observation

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
            raise _mark(AccountNotVerified(), False)
        if "ARCHIVE" not in self._t._caps:
            raise _mark(Denied("DENIED_CAPABILITY"), False)
        try:
            url = f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}/modify?fields=id,threadId,labelIds"
        except Denied as exc:
            raise _mark(exc, False)
        try:
            obj = self._call("POST", url, policy.MODIFY_BODY)
            if obj.get("id") != message_id:
                raise UncertainOutcome("AMBIGUOUS_RESULT")
            return ArchiveResult(_labels(obj.get("labelIds")))
        except (Denied, AccountNotVerified, WriteAuthError, RequestRejected, MessageNotFound, RateLimited, UncertainOutcome):
            raise  # definite non-mutations (refused before dispatch, or a validated Gmail error document) and already-uncertain outcomes
        except Exception:  # noqa: BLE001 - any other failure (including an unusable answer) after dispatch may have begun is never a clean "not applied"
            raise _mark(UncertainOutcome("AMBIGUOUS_RESULT"), True) from None

    def restore_inbox(self, message_id):
        """Add INBOX back to exactly one message that this tool archived (a single POST with the one fixed undo body, never retried). Returns RestoreResult or raises a typed error.

        Same error contract as `archive_message`: definite non-mutations (refused before dispatch, a validated Gmail error document) are typed, everything unclear after dispatch
        may have begun is UncertainOutcome. A successful answer is NOT proof of restoration: the caller must make its own independent, execution-bound observation.
        """
        if not self._verified:
            raise _mark(AccountNotVerified(), False)
        if "UNDO" not in self._t._caps:
            raise _mark(Denied("DENIED_CAPABILITY"), False)
        try:
            url = f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}/modify?fields=id,threadId,labelIds"
        except Denied as exc:
            raise _mark(exc, False)
        try:
            obj = self._call("POST", url, policy.UNDO_BODY)
            if obj.get("id") != message_id:
                raise UncertainOutcome("AMBIGUOUS_RESULT")
            return RestoreResult(_labels(obj.get("labelIds")))
        except (Denied, AccountNotVerified, WriteAuthError, RequestRejected, MessageNotFound, RateLimited, UncertainOutcome):
            raise
        except Exception:  # noqa: BLE001 - any other failure after dispatch may have begun is never a clean "not applied"
            raise _mark(UncertainOutcome("AMBIGUOUS_RESULT"), True) from None

    def observe(self, message_id, *, context):
        """One trusted observation of a message's labels, through the existing minimal GET (no new endpoint, no new scope).

        Needs a verified account. Returns a one-time `exec_evidence.TrustedObservation`: present with an explicit labels tuple (an omitted `labelIds`
        in an otherwise complete answer is the explicit empty tuple), or definitively absent for an unambiguous Gmail not-found document. Any
        other answer (malformed, wrong id, other errors) is an error, never an observation. The time is stamped by the injected clock AFTER the
        answer was read. The observation reports a state; it does not show who changed it.
        """
        if not self._verified or self._issuer is None:
            raise _mark(AccountNotVerified(), False)
        if type(context) is not str or not 0 < len(context) <= 128 or not context.isascii():
            raise _mark(ReadFailure(), False)  # an observation is always bound to an execution context; nothing is requested without one
        try:
            url = f"{policy.BASE}/gmail/v1/users/me/messages/{policy.valid_id(message_id)}?format=minimal&fields=id,threadId,labelIds"
        except Denied as exc:
            raise _mark(exc, False)
        try:
            obj = self._get(url)
        except MessageNotFound as exc:
            if not exc.absent_confirmed:
                raise _mark(ReadFailure(), True) from None  # a 404 that is not an unambiguous not-found document is not an observation
            return self._issue(message_id, False, None, context)
        if obj.get("id") != message_id or type(obj.get("threadId")) is not str or not obj["threadId"]:
            raise _mark(ReadFailure(), True)
        return self._issue(message_id, True, _labels(obj.get("labelIds")), context)

    def _issue(self, message_id, present, labels, context):
        if not self._verified:  # verification was lost while the answer was being read
            raise _mark(AccountNotVerified(), True)
        try:
            return self._issuer.issue(message_id, present, labels, context)
        except exec_evidence.ObservationError:
            raise _mark(ReadFailure(), True) from None


def fetch_profile_email(creds, connection_factory=None):
    """One allowed profile read with fresh credentials (used by `auth login-write` to learn which account was authorized)."""
    return ArchiveAdapter(_Transport(creds, connection_factory), None)._profile_email()


def _open_adapter(expected_account, store, client_path, now, connection_factory, capabilities):
    from gmail_intelligence import oauth_write

    blob = store.load()
    if blob is None:
        raise oauth_write.AuthError("no write authorization is stored; run `auth login-write`")
    client = oauth_write.load_write_client_config(client_path)
    creds = oauth_write.blob_to_write_credentials(blob, client)
    if (blob.get("account") or "").strip().lower() != (expected_account or "").strip().lower():
        raise AccountMismatch()
    oauth_write.require_validity(creds, now)
    return ArchiveAdapter(_Transport(creds, connection_factory, capabilities=capabilities), expected_account)


def open_archive_adapter(expected_account, store, client_path, now=None, connection_factory=None):
    """Build the ARCHIVE adapter from the stored write authorization. LOCAL checks only: no refresh, no network, no prompt.

    Needs: a stored record, a matching client file, the exact scope, the same OAuth client, the expected account and at least ten minutes of
    access-token life. The adapter is NOT verified: `verify_account()` (a live profile read, a separately approved step) must succeed
    before `archive_message` is possible. The expected account is compared with the live profile AND was bound to the stored record.
    The transport holds the ARCHIVE capability only: this adapter can never undo.
    """
    return _open_adapter(expected_account, store, client_path, now, connection_factory, ("ARCHIVE",))


def open_undo_adapter(expected_account, store, client_path, now=None, connection_factory=None):
    """Like `open_archive_adapter`, but the transport holds the UNDO capability ONLY (it can restore INBOX on one message and can never archive). Same local checks, same stored
    write authorization, exact scope, client identity, account and at least ten minutes of access-token life; no refresh, no network, no prompt."""
    return _open_adapter(expected_account, store, client_path, now, connection_factory, ("UNDO",))
