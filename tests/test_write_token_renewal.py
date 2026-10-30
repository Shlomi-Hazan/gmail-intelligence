"""M12C.3 / D8 (issue #41): the explicit, owner-controlled renewal of the write access token. Mocked credentials, a fake Keychain and fake OAuth transport only: no Google account, no real
Keychain, no network, no real OAuth login, refresh or revocation."""
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_auth import A_TOK, ACCOUNT, R_TOK, utcnow  # noqa: E402
from test_write_auth import WBase, WCreds, write_client_config  # noqa: E402

from gmail_intelligence import config, gmail_write as gw, oauth, oauth_write  # noqa: E402


class RenewalCommandTests(WBase):
    def stored(self, minutes=1):
        self.write_client_file()
        return self.store_blob(minutes)

    def store_blob(self, minutes):
        blob = oauth_write.write_blob(WCreds(minutes=minutes), ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config())
        self.wstore.save(blob)
        return blob

    def test_an_expired_token_fails_closed_everywhere_and_points_to_the_explicit_renewal(self):
        self.write_client_file()
        self.store_blob(1)                                      # less than the 10 minutes an operation needs
        with mock.patch.object(oauth_write, "refresh_and_store", side_effect=AssertionError("no silent refresh")), \
                mock.patch.object(oauth_write, "refresh_write_credentials", side_effect=AssertionError("no silent refresh")):
            for opener in (gw.open_archive_adapter, gw.open_undo_adapter):
                with self.assertRaises(oauth.AuthError) as ctx:
                    opener(ACCOUNT, self.wstore, config.write_client_secret_path())
                self.assertIn("auth refresh-write", str(ctx.exception))
        creds = WCreds(minutes=1)
        a = gw.ArchiveAdapter(gw._Transport(creds, lambda: self.fail("network"), capabilities=("UNDO",)), ACCOUNT)
        creds.expiry = utcnow() - timedelta(minutes=1)          # expired while the adapter exists: the transport stops before anything is sent
        a._verified = True
        with self.assertRaises(gw.WriteAuthError) as ctx:
            a.restore_inbox("a1")
        self.assertTrue(gw.definitely_not_dispatched(ctx.exception))

    def test_refresh_write_needs_the_typed_phrase_and_changes_nothing_otherwise(self):
        self.stored(1)
        before = dict(self.backend.items)
        with mock.patch.object(oauth_write, "refresh_and_store", side_effect=AssertionError("must not refresh")):
            code, out, err = self.run_cli("auth", "refresh-write", stdin="yes")
        self.assertEqual(code, 1)
        self.assertIn("declined", err)
        self.assertEqual(self.backend.items, before)

    def test_refresh_write_renews_through_the_pinned_oauth_path_and_replaces_only_the_write_item(self):
        self.stored(1)
        self.stored_blob()                                      # a read-only token that must not change
        read_before = {k: v for k, v in self.backend.items.items() if k[0] != "gmail-intelligence-write"}
        old = self.wstore.load()
        fresh = WCreds(minutes=1)
        sent = []
        with mock.patch.object(oauth_write, "blob_to_write_credentials", return_value=fresh), \
                mock.patch.object(oauth_write, "default_oauth_request", lambda url: oauth_write.PinnedOAuthRequest(url, lambda u, **kw: sent.append((u, kw)) or "ok")):
            code, out, err = self.run_cli("auth", "refresh-write", stdin=oauth_write.REFRESH_PHRASE)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("renewed", out)
        self.assertEqual([u for u, _ in sent], [oauth_write.TOKEN_URI])                  # only Google's OAuth token endpoint, never the Gmail API
        self.assertEqual(sent[0][1]["allow_redirects"], False)
        self.assertNotEqual(self.wstore.load()["expiry"], old["expiry"])
        self.assertEqual(self.wstore.load()["scopes"], [oauth_write.WRITE_SCOPE])        # the permission is exactly the same
        self.assertEqual({k: v for k, v in self.backend.items.items() if k[0] != "gmail-intelligence-write"}, read_before)

    def test_a_failed_or_scope_changing_renewal_keeps_the_stored_authorization(self):
        self.stored(1)
        before = dict(self.backend.items)
        for creds in (WCreds(minutes=1, refreshed_scopes=(oauth_write.WRITE_SCOPE, oauth.SCOPE)), WCreds(minutes=1, refreshed_scopes=None),
                      WCreds(minutes=1, raises=__import__("google.auth.exceptions", fromlist=["RefreshError"]).RefreshError("invalid_grant"))):
            with mock.patch.object(oauth_write, "blob_to_write_credentials", return_value=creds), \
                    mock.patch.object(oauth_write, "default_oauth_request", lambda url: oauth_write.PinnedOAuthRequest(url, lambda u, **kw: "ok")):
                code, out, err = self.run_cli("auth", "refresh-write", stdin=oauth_write.REFRESH_PHRASE)
            self.assertEqual(code, 1)
            self.assertIn("was not changed", err)
            self.assertEqual(self.backend.items, before)

    def test_refresh_write_refuses_without_a_stored_authorization_or_attested_isolation(self):
        self.write_client_file()
        with mock.patch.object(oauth_write, "refresh_and_store", side_effect=AssertionError("no refresh")):
            self.assertEqual(self.run_cli("auth", "refresh-write", stdin=oauth_write.REFRESH_PHRASE)[0], 1)   # nothing stored
            self.store_blob(1)
            config.write_setup_path().unlink()                  # the owner's separate-project attestation is gone
            self.assertEqual(self.run_cli("auth", "refresh-write", stdin=oauth_write.REFRESH_PHRASE)[0], 1)   # separation not attested

    def test_status_and_the_undo_path_never_refresh_in_the_background(self):
        self.write_client_file()
        self.store_blob(1)
        with mock.patch.object(oauth_write, "refresh_and_store", side_effect=AssertionError("refresh")), \
                mock.patch.object(oauth_write, "refresh_write_credentials", side_effect=AssertionError("refresh")):
            self.run_cli("auth", "status-write")
            from gmail_intelligence import exec_live_mailbox as live
            with self.assertRaises(live.LiveUndoDisabled):      # disabled: the store is not even read
                live.open_live_undo_mailbox(ACCOUNT, self.wstore, config.write_client_secret_path())

    def test_open_undo_adapter_grants_the_undo_capability_only(self):
        self.write_client_file()
        self.store_blob(60)
        a = gw.open_undo_adapter(ACCOUNT, self.wstore, config.write_client_secret_path())
        self.assertEqual(a._t._caps, frozenset({"UNDO"}))
        self.assertFalse(a._verified)                           # nothing can be modified until the account is verified live
        b = gw.open_archive_adapter(ACCOUNT, self.wstore, config.write_client_secret_path())
        self.assertEqual(b._t._caps, frozenset({"ARCHIVE"}))


if __name__ == "__main__":
    unittest.main()
