"""OAuth token storage in the macOS Keychain (via the `keyring` library).

No plaintext fallback: if the macOS Keychain backend is unavailable the store refuses to work.
"""
import json

SERVICE = "gmail-intelligence"
ITEM = "oauth-token:gmail.readonly"


class KeystoreError(Exception):
    """Token storage problem. Messages never contain token material."""


def _default_backend():
    try:
        import keyring
        from keyring.backends import macOS
    except Exception as exc:  # missing dependency or non-macOS platform
        raise KeystoreError(f"Keychain support unavailable ({type(exc).__name__}); "
                            "install dependencies in the project venv (see docs/SETUP-GMAIL.md)") from None
    backend = keyring.get_keyring()
    if not isinstance(backend, macOS.Keyring):
        raise KeystoreError("macOS Keychain backend not active; refusing to store tokens elsewhere "
                            "(no plaintext fallback)")
    return backend


class TokenStore:
    def __init__(self, backend=None):
        self._backend = backend if backend is not None else _default_backend()

    def _call(self, what, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:
            raise KeystoreError(f"Keychain {what} failed ({type(exc).__name__}); "
                                "is the Keychain locked or access denied?") from None

    def save(self, blob):
        self._call("write", self._backend.set_password, SERVICE, ITEM, json.dumps(blob))

    def load(self):
        raw = self._call("read", self._backend.get_password, SERVICE, ITEM)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise KeystoreError("stored token is corrupt; run `auth logout` then `auth login`") from None

    def delete(self):
        """Remove only this application's item. Returns True if something was removed."""
        if self.load() is None:
            return False
        self._call("delete", self._backend.delete_password, SERVICE, ITEM)
        return True
