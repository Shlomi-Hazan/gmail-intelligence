"""Separate OAuth for the WRITE scope (M4C-B1). The only module that defines the write scope.

Nothing here runs unless the explicit `auth login-write` / `auth revoke-write` commands (or a future approved executor) call it:
no read command, status command or import has any effect. No Keychain access and no network happen at import time.

Isolation rules:
  * a different client file, a different Keychain item (keystore_write) and an exact-scope check; the read-only path never loads these;
  * the stored blob carries a fingerprint of the OAuth client id, so a token issued to another client is refused;
  * token refresh and revocation use a SEPARATE OAuth request wrapper pinned to exactly one Google OAuth URL each; they never go
    through the Gmail request policy, and the Gmail transport never refreshes anything;
  * messages never contain tokens, codes or client secrets.
Deleting the local Keychain item does NOT revoke the remote Google grant; revocation is a separate, explicit network call.

Revocation is project-wide at Google (its documentation says revocation removes all scopes previously granted to the project), so the
write client must belong to a SEPARATE Google Cloud project from the read-only client. That is enforced fail-closed before any operation
that could create or revoke a write grant: both client ids must be in the recognized format, must not be equal nor share a project number,
and the owner's explicit attestation (recorded at `auth setup-write`, bound to fingerprints of both client files) must still match.
A different project number is NECESSARY evidence of a separate project, not proof, and the attestation is the owner's word, not Google's.
The optional `project_id` of the client files is only a consistency check (equal ids contradict "separate"; an absent one is never invented; a malformed one
fails closed); neither equality nor inequality proves who owns or controls a project.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

from gmail_intelligence.oauth import AuthError, load_client_config

WRITE_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
EXPECTED_WRITE_SCOPES = frozenset({WRITE_SCOPE})
TOKEN_URI = "https://oauth2.googleapis.com/token"
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
MIN_REMAINING = timedelta(minutes=10)  # an execution may only start with at least this much access-token life left
LOGIN_PHRASE = "AUTHORIZE GMAIL MODIFY"
REVOKE_PHRASE = "REVOKE GMAIL MODIFY"
REFRESH_PHRASE = "REFRESH GMAIL MODIFY"
BLOB_KIND, BLOB_SCHEMA = "write-authorization", 1

LOGIN_WARNING = (
    f"Requested permission: {WRITE_SCOPE}\n"
    "WARNING: this permission is much broader than archiving. It lets an application read all message content, change labels, move\n"
    "messages to Trash, manage drafts and send mail. This tool restricts itself to archiving one message at a time through its own\n"
    "request allowlist; that is an application policy, NOT a limit enforced by Google. Anyone who obtains this token can do more.\n"
    "Revoke the access when you are done (`auth revoke-write`); deleting the local token alone does not revoke it at Google.")


class IssuedToken:
    """The token material of a grant that Google just issued, kept ONLY so a rejected login can revoke it. Never printed or stored."""
    __slots__ = ("refresh_token", "token")

    def __init__(self, refresh_token=None, token=None):
        self.refresh_token, self.token = refresh_token, token

    def __repr__(self):
        return "<IssuedToken>"


class LoginRejected(AuthError):
    """Authorization completed at Google but this tool refuses the result. `issued` identifies the new grant so the caller can revoke it.

    The message is safe to print; `issued` is not (it holds token material).
    """

    def __init__(self, message, issued):
        super().__init__(message)
        self.issued = issued


_TOKEN_VALUE = r"[A-Za-z0-9._~+/=-]{8,4096}"
_CLIENT_ID = r"([1-9][0-9]{5,19})-[a-z0-9]{8,64}\.apps\.googleusercontent\.com"  # canonical number: no leading zero, so equal numbers compare equal as text
_PROJECT_ID = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"  # Google Cloud project id: 6-30 chars, lower case, digits, hyphens


def _token_or_none(value):
    return value if type(value) is str and re.fullmatch(_TOKEN_VALUE, value, re.ASCII) else None


def _issued_from_mapping(mapping):
    """Validated token handle from an OAuth token mapping. Anything that is not a plain mapping of well-formed strings yields nothing."""
    if not isinstance(mapping, dict):
        return IssuedToken()
    return IssuedToken(_token_or_none(mapping.get("refresh_token")), _token_or_none(mapping.get("access_token")))


def _issued_from_scope_warning(exc, flow):
    """Token handle for the grant behind oauthlib's scope-change Warning.

    The installed oauthlib raises `Warning` (exact type) with the parsed token response on the exception (`token`, plus `old_scope`/`new_scope`)
    BEFORE the session stores it, so `flow.oauth2session.token` is empty then. The exception attribute is used only for that exact shape and
    only after validation; the session token is a validated fallback. Nothing from the exception is ever printed or logged.
    """
    if type(exc) is Warning and hasattr(exc, "old_scope") and hasattr(exc, "new_scope"):
        issued = _issued_from_mapping(getattr(exc, "token", None))
        if issued.refresh_token or issued.token:
            return issued
    return _issued_from_mapping(getattr(getattr(flow, "oauth2session", None), "token", None))


def project_number(client_id):
    """Project-number component of a Google OAuth client id, or None unless the id has exactly the recognized form NUMBER-RANDOM.apps.googleusercontent.com."""
    m = re.fullmatch(_CLIENT_ID, client_id, re.ASCII) if type(client_id) is str else None
    return m.group(1) if m else None


def _fp(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _declared_project_id(config):
    """The optional `installed.project_id` of a client file: None when absent (never invented), the value when well formed, AuthError when supplied but malformed."""
    inst = config["installed"]
    if "project_id" not in inst:
        return None
    value = inst["project_id"]
    if type(value) is not str or re.fullmatch(_PROJECT_ID, value, re.ASCII) is None:
        raise AuthError("a client file declares a malformed project id, so project separation cannot be verified; refusing (fail closed)")
    return value


def check_project_separation(write_config, read_config):
    """Fail closed unless the two clients are recognizably in different projects. Never echoes an id or secret."""
    wid, rid = write_config["installed"]["client_id"], read_config["installed"]["client_id"]
    wn, rn = project_number(wid), project_number(rid)
    if wn is None or rn is None:
        raise AuthError("a client id is not in the recognized Google format, so project separation cannot be verified; refusing (fail closed)")
    wp, rp = _declared_project_id(write_config), _declared_project_id(read_config)  # malformed supplied identity data fails closed
    if wid == rid:
        raise AuthError("the write authorization needs a different OAuth client than the read-only one")
    if wn == rn:
        raise AuthError("the write client belongs to the same Google Cloud project as the read-only client; revocation is project-wide at Google, "
                        "so create the write client in a SEPARATE project")
    if wp is not None and rp is not None and wp == rp:  # both files claim the same project although the client ids encode different numbers
        raise AuthError("both client files declare the same Google Cloud project id; revocation is project-wide at Google, so the write client "
                        "must belong to a SEPARATE project")


def isolation_record(write_config, read_config):
    """What the owner attested at setup, as fingerprints only (no client id, secret or project number is stored)."""
    wp, rp = _declared_project_id(write_config), _declared_project_id(read_config)
    return {"schema": 1, "attested_separate_project": True, "write_client_fp": client_fingerprint(write_config),
            "write_project_fp": _fp(project_number(write_config["installed"]["client_id"])),
            "read_client_fp": client_fingerprint(read_config), "read_project_fp": _fp(project_number(read_config["installed"]["client_id"])),
            "write_project_id_fp": _fp(wp) if wp is not None else None, "read_project_id_fp": _fp(rp) if rp is not None else None}


def write_isolation_record(path, write_config, read_config):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(isolation_record(write_config, read_config), fh, sort_keys=True)
    os.chmod(path, 0o600)


def verify_isolation(write_client_path, read_client_path, setup_path):
    """Run before ANY operation that could create or revoke a write grant (login, revoke, rejected-login cleanup). Local files only.

    Fails closed when the read-only client file is missing or unreadable, an id is unrecognized, the clients are equal or share a project number,
    or the attestation recorded at `auth setup-write` is missing or no longer matches BOTH client files (changed since setup).
    """
    write = load_write_client_config(write_client_path)
    try:
        read = load_client_config(read_client_path)
    except AuthError:
        raise AuthError("the read-only OAuth client file is missing or invalid, so project separation cannot be verified; refusing (fail closed)") from None
    check_project_separation(write, read)
    try:
        with open(setup_path, encoding="utf-8") as fh:
            recorded = json.load(fh)
    except (OSError, ValueError):
        raise AuthError("project separation was never attested; run `auth setup-write --import FILE --confirm-separate-project`") from None
    if recorded != isolation_record(write, read):
        raise AuthError("a client file changed since `auth setup-write`; run it again to re-attest the separate project")


def client_fingerprint(client_config):
    return hashlib.sha256(client_config["installed"]["client_id"].encode("utf-8")).hexdigest()


def load_write_client_config(path):
    """Validate the write client file. The token endpoint must be exactly Google's, so a crafted file cannot redirect a refresh token."""
    data = load_client_config(path)
    if data["installed"]["token_uri"] != TOKEN_URI:
        raise AuthError("OAuth client token endpoint is not Google's; refusing this client file")
    return data


def check_granted_write_scopes(granted):
    """Exactly the write scope and nothing else (extra, missing or broader scopes are refused)."""
    granted = set(granted or [])
    if granted != EXPECTED_WRITE_SCOPES:
        extra, missing = sorted(granted - EXPECTED_WRITE_SCOPES), sorted(EXPECTED_WRITE_SCOPES - granted)
        raise AuthError("unexpected OAuth scopes granted; refusing credentials"
                        + (f" (extra: {', '.join(extra)})" if extra else "") + (f" (missing: {', '.join(missing)})" if missing else ""))


def run_login_write(client_path, flow_factory=None, open_browser=True, timeout_seconds=300):
    """Browser consent flow for the write scope. Returns (credentials, granted_scopes). Stores nothing.

    Only the explicit `auth login-write` command may call this (a static test enforces it). `flow_factory` exists so tests can inject a fake.
    """
    config = load_write_client_config(client_path)
    if flow_factory is None:
        from google_auth_oauthlib.flow import InstalledAppFlow

        def flow_factory(cfg, scopes):  # noqa: E306
            return InstalledAppFlow.from_client_config(cfg, scopes=scopes)  # PKCE on by default
    flow = flow_factory(config, [WRITE_SCOPE])
    try:
        creds = flow.run_local_server(
            host="127.0.0.1", port=0, open_browser=open_browser, timeout_seconds=timeout_seconds,
            access_type="offline", prompt="consent",  # no include_granted_scopes: never accumulate scopes
            authorization_prompt_message="If the browser does not open, visit:\n{url}\n",
            success_message="Authorization received. You can close this tab and return to the terminal.")
    except Warning as warning:  # oauthlib raises this AFTER Google issued the token: recover the handle so the unwanted grant can be revoked
        raise LoginRejected("Google returned different scopes than requested; refusing credentials", _issued_from_scope_warning(warning, flow)) from None
    except Exception as exc:
        code = getattr(exc, "error", None)
        if code == "access_denied":
            raise AuthError("authorization was cancelled or denied in the browser") from None
        if type(exc).__name__ == "WSGITimeoutError":
            raise AuthError("timed out waiting for browser authorization") from None
        raise AuthError(f"authorization failed ({type(exc).__name__}{': ' + str(code) if code else ''})") from None
    token = getattr(getattr(flow, "oauth2session", None), "token", None) or {}
    granted = token.get("scope") or getattr(creds, "granted_scopes", None) or creds.scopes
    if isinstance(granted, str):
        granted = granted.split()
    issued = IssuedToken(_token_or_none(getattr(creds, "refresh_token", None)), _token_or_none(getattr(creds, "token", None)))
    try:
        check_granted_write_scopes(granted)
    except AuthError as exc:
        raise LoginRejected(str(exc), issued) from None
    client_id = getattr(creds, "client_id", None)
    if client_id is not None and client_id != config["installed"]["client_id"]:
        raise LoginRejected("credentials were issued to a different OAuth client; refusing them", issued)
    if not creds.refresh_token:
        raise LoginRejected("Google did not return a refresh token; the write authorization cannot be kept", issued)
    return creds, list(granted)


def write_blob(creds, account, scopes, client_config):
    return {"kind": BLOB_KIND, "schema": BLOB_SCHEMA, "account": account, "scopes": sorted(scopes),
            "client_fp": client_fingerprint(client_config), "token": creds.token, "refresh_token": creds.refresh_token,
            "expiry": creds.expiry.isoformat() if creds.expiry else None}


def check_blob(blob, client_config=None):
    """Structural, scope and (when the client file is given) client-identity checks. Raises AuthError; never echoes blob content."""
    if not isinstance(blob, dict) or blob.get("kind") != BLOB_KIND or blob.get("schema") != BLOB_SCHEMA:
        raise AuthError("stored write authorization is not a valid write-authorization record; run `auth logout-write`")
    check_granted_write_scopes(blob.get("scopes"))
    if client_config is not None and blob.get("client_fp") != client_fingerprint(client_config):
        raise AuthError("stored write authorization belongs to a different OAuth client; run `auth logout-write` and log in again")
    if not blob.get("refresh_token"):
        raise AuthError("stored write authorization has no refresh token; run `auth logout-write` and log in again")


def blob_to_write_credentials(blob, client_config):
    from google.oauth2.credentials import Credentials

    check_blob(blob, client_config)
    inst = client_config["installed"]
    expiry = datetime.fromisoformat(blob["expiry"]) if blob.get("expiry") else None
    if expiry is not None and expiry.tzinfo is not None:
        expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)  # google-auth uses naive UTC
    return Credentials(token=blob.get("token"), refresh_token=blob.get("refresh_token"), expiry=expiry, token_uri=TOKEN_URI,
                       client_id=inst["client_id"], client_secret=inst["client_secret"], scopes=[WRITE_SCOPE])


def remaining_validity(expiry, now=None):
    """Time left on an access token (naive-UTC or aware `expiry`); zero when unknown."""
    if expiry is None:
        return timedelta(0)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return max(expiry - (now or datetime.now(timezone.utc)), timedelta(0))


def require_validity(creds, now=None):
    """Refuse (no refresh, no network) unless the access token has at least MIN_REMAINING left."""
    if not getattr(creds, "token", None) or remaining_validity(getattr(creds, "expiry", None), now) < MIN_REMAINING:
        raise AuthError("the write access token has less than 10 minutes of validity left; renew it explicitly with `auth refresh-write` (or run `auth login-write`)")


class PinnedOAuthRequest:
    """google-auth `Request` look-alike that can send exactly ONE method to exactly ONE URL and never follows redirects.

    This is the only network path used for refresh and revocation. It is deliberately separate from the Gmail request policy.
    """

    def __init__(self, url, delegate=None):
        self._url, self._delegate = url, delegate

    def __call__(self, url, method="GET", body=None, headers=None, timeout=60, **kwargs):
        if url != self._url or str(method).upper() != "POST":
            raise AuthError("blocked an unexpected OAuth request")
        kwargs["allow_redirects"] = False
        return self._delegate(url, method="POST", body=body, headers=headers, timeout=timeout, **kwargs)


def default_oauth_request(url):
    import requests
    from google.auth.transport.requests import Request

    session = requests.Session()
    session.trust_env = False  # ignore proxy environment variables and netrc
    return PinnedOAuthRequest(url, Request(session=session))


def refresh_write_credentials(creds, request=None):
    """EXPLICIT refresh (never called by status or read commands, never by the Gmail transport). Returns True when a refresh happened."""
    from google.auth.exceptions import RefreshError, TransportError

    if request is None:
        request = default_oauth_request(TOKEN_URI)
    elif not isinstance(request, PinnedOAuthRequest):
        request = PinnedOAuthRequest(TOKEN_URI, request)
    try:
        creds.refresh(request)
        check_refresh_result(creds)
    except RefreshError as exc:
        text = str(exc)
        if "invalid_grant" in text or "revoked" in text.lower() or "expired" in text.lower():
            raise AuthError("the stored write authorization is expired or revoked; run `auth login-write` again") from None
        raise AuthError("could not refresh the write authorization; run `auth login-write` again") from None
    except TransportError:
        raise AuthError("network error while refreshing the write authorization") from None
    return True


def check_refresh_result(creds):
    """A refresh must report exactly the write scope and yield a usable token. Fail closed (and store nothing) otherwise.

    The scope list is required, not optional: if Google ever omits it the refresh is refused and this check must be revisited at a
    separately approved live stage. M4C-C must call the refresh explicitly (never from status or read commands).
    """
    granted = getattr(creds, "granted_scopes", None)
    if not granted:
        raise AuthError("the refresh response did not report the granted scopes; refusing it")
    check_granted_write_scopes(granted)
    if not getattr(creds, "token", None) or getattr(creds, "expiry", None) is None or not getattr(creds, "refresh_token", None):
        raise AuthError("the refresh response is incomplete; refusing it")


def refresh_and_store(store, blob, client_config, request=None):
    """Refresh and persist ONLY into the separate write item. Returns the new (credentials, blob).

    The stored record is replaced only after the refresh result passed `check_refresh_result`; on any failure it stays untouched.
    """
    creds = blob_to_write_credentials(blob, client_config)
    refresh_write_credentials(creds, request)
    new = write_blob(creds, blob.get("account"), blob["scopes"], client_config)
    store.save(new)
    return creds, new


def _form_encode(value):
    return "".join(c if (c.isascii() and (c.isalnum() or c in "-._~")) else "%%%02X" % ord(c) for c in value)


def _strict_object(data):
    """JSON object parse for an OAuth error body: bounded, UTF-8, no duplicate keys. None when it is anything else."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > 4096:
        return None

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out
    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def revoke_refresh_token(token, request=None):
    """Revoke ONE token at Google (explicit commands only). Returns "REVOKED" only for an HTTP 200; everything else raises AuthError.

    Google's documentation says a successfully processed revocation answers HTTP 200 and that error conditions answer HTTP 400 "along with an
    error code". It does not document which codes exist, so NO 400 is treated as a confirmation - not even an `invalid_token` body, which only
    suggests the token may already be invalid or revoked (that suggestion is reported, but the local credential is kept). Redirects, other
    statuses, unreadable bodies and transport failures are not confirmations either. Revocation is project-wide at Google (it removes all scopes
    previously granted to the project), which is why a separate project is enforced.
    """
    if not isinstance(token, str) or not token:
        raise AuthError("no token to revoke")
    if request is None:
        request = default_oauth_request(REVOKE_URI)
    elif not isinstance(request, PinnedOAuthRequest):
        request = PinnedOAuthRequest(REVOKE_URI, request)
    try:
        resp = request(REVOKE_URI, method="POST", body=("token=" + _form_encode(token)).encode("ascii"),
                       headers={"content-type": "application/x-www-form-urlencoded"})
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError(f"revocation request failed ({type(exc).__name__}); nothing is confirmed, the local token was kept") from None
    status, data = getattr(resp, "status", None), getattr(resp, "data", b"")
    if type(status) is int and status == 200 and (not data or _strict_object(data) is not None):
        return "REVOKED"
    if type(status) is int and status == 400:
        body = _strict_object(data)
        if body is not None and body.get("error") == "invalid_token":
            raise AuthError("Google answered HTTP 400 with an invalid-token error: the token may already be invalid or revoked, but that is not a documented "
                            "confirmation; the local token was kept (remove it locally with `auth logout-write` if you accept that)")
        raise AuthError("revocation was rejected (HTTP 400); nothing is confirmed, the local token was kept")
    raise AuthError(f"revocation was not confirmed ({'HTTP ' + str(status) if type(status) is int else 'unreadable answer'}); the local token was kept")
