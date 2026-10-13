"""Keychain storage for the SEPARATE write authorization (M4C-B1). Never reads or writes the read-only token.

A different Keychain service and item than keystore.TokenStore, and no fallback to the read-only item in either direction.
No Keychain access happens at import time; a WriteTokenStore only touches the Keychain when one of its methods is called.
"""
import json

from gmail_intelligence import oauth_write
from gmail_intelligence.keystore import KeystoreError, _default_backend

SERVICE_WRITE = "gmail-intelligence-write"
ITEM_WRITE = "oauth-token:" + oauth_write.WRITE_SCOPE.rsplit("/", 1)[1]


class WriteTokenStore:
    def __init__(self, backend=None):
        self._backend = backend if backend is not None else _default_backend()

    def _call(self, what, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:
            raise KeystoreError(f"Keychain {what} failed ({type(exc).__name__}); is the Keychain locked or access denied?") from None

    def save(self, blob):
        try:
            oauth_write.check_blob(blob)
        except oauth_write.AuthError as exc:
            raise KeystoreError(f"refusing to store an invalid write authorization ({exc})") from None
        self._call("write", self._backend.set_password, SERVICE_WRITE, ITEM_WRITE, json.dumps(blob))

    def load(self):
        raw = self._call("read", self._backend.get_password, SERVICE_WRITE, ITEM_WRITE)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            raise KeystoreError("stored write authorization is corrupt; run `auth logout-write`") from None
        return data

    def delete(self):
        """Remove only the write item, locally. Does NOT revoke the grant at Google. Returns True if something was removed."""
        if self.load() is None:
            return False
        self._call("delete", self._backend.delete_password, SERVICE_WRITE, ITEM_WRITE)
        return True
