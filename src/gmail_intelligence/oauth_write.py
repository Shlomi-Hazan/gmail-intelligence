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
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from gmail_intelligence.oauth import AuthError, load_client_config

WRITE_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
EXPECTED_WRITE_SCOPES = frozenset({WRITE_SCOPE})
TOKEN_URI = "https://oauth2.googleapis.com/token"
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
MIN_REMAINING = timedelta(minutes=10)  # an execution may only start with at least this much access-token life left
LOGIN_PHRASE = "AUTHORIZE GMAIL MODIFY"
REVOKE_PHRASE = "REVOKE GMAIL MODIFY"
BLOB_KIND, BLOB_SCHEMA = "write-authorization", 1

LOGIN_WARNING = (
    f"Requested permission: {WRITE_SCOPE}\n"
    "WARNING: this permission is much broader than archiving. It lets an application read all message content, change labels, move\n"
    "messages to Trash, manage drafts and send mail. This tool restricts itself to archiving one message at a time through its own\n"
    "request allowlist; that is an application policy, NOT a limit enforced by Google. Anyone who obtains this token can do more.\n"
    "Revoke the access when you are done (`auth revoke-write`); deleting the local token alone does not revoke it at Google.")


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
    except Warning:
        raise AuthError("Google returned different scopes than requested; refusing credentials") from None
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
    check_granted_write_scopes(granted)
    client_id = getattr(creds, "client_id", None)
    if client_id is not None and client_id != config["installed"]["client_id"]:
        raise AuthError("credentials were issued to a different OAuth client; refusing them")
    if not creds.refresh_token:
        raise AuthError("Google did not return a refresh token; revoke the app's access at "
                        "https://myaccount.google.com/permissions and run `auth login-write` again")
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
        raise AuthError("the write access token has less than 10 minutes of validity left; refresh it explicitly or run `auth login-write`")


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
    except RefreshError as exc:
        text = str(exc)
        if "invalid_grant" in text or "revoked" in text.lower() or "expired" in text.lower():
            raise AuthError("the stored write authorization is expired or revoked; run `auth login-write` again") from None
        raise AuthError("could not refresh the write authorization; run `auth login-write` again") from None
    except TransportError:
        raise AuthError("network error while refreshing the write authorization") from None
    return True


def refresh_and_store(store, blob, client_config, request=None):
    """Refresh and persist ONLY into the separate write item. Returns the new (credentials, blob)."""
    creds = blob_to_write_credentials(blob, client_config)
    refresh_write_credentials(creds, request)
    new = write_blob(creds, blob.get("account"), blob["scopes"], client_config)
    store.save(new)
    return creds, new


def _form_encode(value):
    return "".join(c if (c.isascii() and (c.isalnum() or c in "-._~")) else "%%%02X" % ord(c) for c in value)


def revoke_refresh_token(refresh_token, request=None):
    """Revoke ONE refresh token at Google (explicit `auth revoke-write` only). Returns True when revoked or already invalid.

    Only this token's grant is affected. A rejected/unknown token (HTTP 400) counts as already invalid; anything else is an error.
    """
    if not isinstance(refresh_token, str) or not refresh_token:
        raise AuthError("no refresh token to revoke")
    if request is None:
        request = default_oauth_request(REVOKE_URI)
    elif not isinstance(request, PinnedOAuthRequest):
        request = PinnedOAuthRequest(REVOKE_URI, request)
    try:
        resp = request(REVOKE_URI, method="POST", body=("token=" + _form_encode(refresh_token)).encode("ascii"),
                       headers={"content-type": "application/x-www-form-urlencoded"})
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError(f"revocation request failed ({type(exc).__name__})") from None
    status = getattr(resp, "status", None)
    if status == 200:
        return True
    if status == 400:
        return True
    raise AuthError(f"revocation was not confirmed (HTTP {status}); the local token was kept")
