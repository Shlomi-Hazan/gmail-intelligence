"""Desktop OAuth (loopback + PKCE) for the read-only Gmail scope. Never logs or prints secrets."""
import json
from datetime import datetime

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
EXPECTED_SCOPES = frozenset({SCOPE})


class AuthError(Exception):
    """User-facing authentication problem. Messages never contain tokens, codes or secrets."""


def load_client_config(path):
    """Validate a downloaded Desktop-app OAuth client file and return its parsed content."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise AuthError(f"OAuth client file not found: {path} (run `auth setup`)") from None
    except (OSError, ValueError):
        raise AuthError("OAuth client file is unreadable or not valid JSON") from None
    if not isinstance(data, dict) or "installed" not in data:
        kind = "web" if isinstance(data, dict) and "web" in data else "unknown"
        raise AuthError(f"OAuth client must be of type 'Desktop app' (found: {kind})")
    inst = data["installed"]
    missing = [k for k in ("client_id", "client_secret", "auth_uri", "token_uri") if not isinstance(inst, dict) or not inst.get(k)]
    if missing:
        raise AuthError("OAuth client file is missing: " + ", ".join(missing))
    if not str(inst["client_id"]).endswith(".apps.googleusercontent.com"):
        raise AuthError("OAuth client_id does not look like a Google client id")
    return data


def check_granted_scopes(granted):
    """Reject anything other than exactly the read-only scope."""
    granted = set(granted or [])
    if granted != EXPECTED_SCOPES:
        extra = sorted(granted - EXPECTED_SCOPES)
        missing = sorted(EXPECTED_SCOPES - granted)
        raise AuthError("unexpected OAuth scopes granted; refusing credentials"
                        + (f" (extra: {', '.join(extra)})" if extra else "")
                        + (f" (missing: {', '.join(missing)})" if missing else ""))


def run_login(client_path, flow_factory=None, open_browser=True, timeout_seconds=300):
    """Run the browser consent flow. Returns (credentials, granted_scopes). Nothing is stored here."""
    config = load_client_config(client_path)
    if flow_factory is None:
        from google_auth_oauthlib.flow import InstalledAppFlow

        def flow_factory(cfg, scopes):  # noqa: E306
            return InstalledAppFlow.from_client_config(cfg, scopes=scopes)  # PKCE on by default
    flow = flow_factory(config, [SCOPE])
    try:
        creds = flow.run_local_server(
            host="127.0.0.1", port=0, open_browser=open_browser, timeout_seconds=timeout_seconds,
            access_type="offline", prompt="consent",  # no include_granted_scopes: never accumulate scopes
            authorization_prompt_message="If the browser does not open, visit:\n{url}\n",
            success_message="Authorization received. You can close this tab and return to the terminal.",
        )
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
    check_granted_scopes(granted)
    if not creds.refresh_token:
        raise AuthError("Google did not return a refresh token; revoke the app's access at "
                        "https://myaccount.google.com/permissions and log in again")
    return creds, list(granted)


def credentials_to_blob(creds, account, scopes):
    return {
        "account": account,
        "scopes": sorted(scopes),
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }


def blob_to_credentials(blob, client_config):
    """Rebuild credentials from the stored blob. The client secret comes from the client file."""
    from google.oauth2.credentials import Credentials

    check_granted_scopes(blob.get("scopes"))
    inst = client_config["installed"]
    expiry = datetime.fromisoformat(blob["expiry"]) if blob.get("expiry") else None
    return Credentials(
        token=blob.get("token"), refresh_token=blob.get("refresh_token"), expiry=expiry,
        token_uri=inst["token_uri"], client_id=inst["client_id"], client_secret=inst["client_secret"],
        scopes=[SCOPE],
    )


def refresh_credentials(creds, request=None):
    """Refresh the access token if needed. Returns True if a refresh happened."""
    if creds.valid:
        return False
    from google.auth.exceptions import RefreshError, TransportError

    if request is None:
        from google.auth.transport.requests import Request
        request = Request()
    try:
        creds.refresh(request)
    except RefreshError as exc:
        text = str(exc)
        if "invalid_grant" in text or "revoked" in text.lower() or "expired" in text.lower():
            raise AuthError("stored authorization is expired or revoked (Testing-mode tokens expire "
                            "after 7 days); run `auth login` again") from None
        raise AuthError("could not refresh authorization; run `auth login` again") from None
    except TransportError:
        raise AuthError("network error while refreshing authorization; check your connection") from None
    return True
