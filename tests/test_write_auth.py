"""Offline tests for the SEPARATE write authorization (M4C-B1): OAuth, Keychain item and `auth *-write` commands.

Fake credentials, fake OAuth flow/transport and a fake Keychain only. No Google account, browser, network, real Keychain or real index.
"""
import contextlib
import json
import os
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from google.auth.exceptions import RefreshError, TransportError  # noqa: E402
from test_auth import A_TOK, ACCOUNT, Base, C_SEC, FakeBackend, FakeFlow, R_TOK, SENTINELS, client_config, utcnow  # noqa: E402

from gmail_intelligence import cli, config, gmail_write, keystore, keystore_write, oauth, oauth_write  # noqa: E402

WRITE_CLIENT_ID = "200000000002-writesynth02.apps.googleusercontent.com"
OTHER_CLIENT_ID = "300000000003-othersynth03.apps.googleusercontent.com"
SAME_PROJECT_ID = "100000000001-writesynth02.apps.googleusercontent.com"
ACCOUNT_OTHER = "someone-else@example.invalid"


def read_client_config(**over):
    cfg = client_config()
    cfg["installed"].update(over)
    return cfg


def write_client_config(**over):
    cfg = client_config()
    cfg["installed"]["client_id"] = WRITE_CLIENT_ID
    cfg["installed"].update(over)
    return cfg


class WCreds:
    """Fake write credentials. refresh() is a recorded no-op unless a failure is scripted."""
    def __init__(self, minutes=60, scopes=(oauth_write.WRITE_SCOPE,), refresh=R_TOK, client_id=WRITE_CLIENT_ID, raises=None, refreshed_scopes=(oauth_write.WRITE_SCOPE,)):
        self.token, self.refresh_token, self.client_id = A_TOK, refresh, client_id
        self.expiry, self.scopes, self.raises, self.refreshed, self.requests = utcnow() + timedelta(minutes=minutes), list(scopes), raises, 0, []
        self.granted_scopes, self.refreshed_scopes, self.after_refresh = None, refreshed_scopes, {}

    @property
    def valid(self):
        return bool(self.token) and self.expiry > utcnow()

    def refresh(self, request):
        self.refreshed += 1
        if self.raises:
            raise self.raises
        self.requests.append(request(oauth_write.TOKEN_URI, method="POST", body=b"x"))
        self.token, self.expiry = A_TOK, utcnow() + timedelta(hours=1)
        self.granted_scopes = None if self.refreshed_scopes is None else list(self.refreshed_scopes)
        for k, v in self.after_refresh.items():
            setattr(self, k, v)


class RecordingBackend(FakeBackend):
    def __init__(self, fail=False):
        super().__init__(fail)
        self.touched = []

    def set_password(self, service, user, value):
        self.touched.append((service, user))
        super().set_password(service, user, value)

    def get_password(self, service, user):
        self.touched.append((service, user))
        return super().get_password(service, user)

    def delete_password(self, service, user):
        self.touched.append((service, user))
        super().delete_password(service, user)


class WBase(Base):
    def setUp(self):
        super().setUp()
        self.backend = RecordingBackend()
        self.store = keystore.TokenStore(self.backend)
        self.wstore = keystore_write.WriteTokenStore(self.backend)
        for target in (mock.patch.object(cli, "_store", lambda: self.store), mock.patch.object(cli, "_write_store", lambda: self.wstore)):
            target.start()
            self.addCleanup(target.stop)

    def write_client_file(self, attest=True, **over):
        """Write the write-client file, make sure a read client exists and (by default) record the owner's separate-project attestation."""
        config.ensure_app_dir()
        if not config.client_secret_path().exists():
            self.write_client()
        path = config.write_client_secret_path()
        path.write_text(json.dumps(write_client_config(**over)))
        os.chmod(path, 0o600)
        if attest:
            oauth_write.write_isolation_record(config.write_setup_path(), oauth_write.load_write_client_config(path), oauth.load_client_config(config.client_secret_path()))
        return path

    def write_blob(self, **over):
        blob = oauth_write.write_blob(WCreds(), ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config())
        blob.update(over)
        self.wstore.save(blob) if not over else self.backend.items.__setitem__((keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE), json.dumps(blob))
        return blob


class OAuthWriteTests(WBase):
    def test_scope_is_defined_exactly_and_only_here(self):
        self.assertEqual(oauth_write.WRITE_SCOPE, "https://www.googleapis.com/auth/gmail.modify")
        self.assertEqual(oauth_write.EXPECTED_WRITE_SCOPES, {oauth_write.WRITE_SCOPE})
        self.assertEqual(oauth.SCOPE, "https://www.googleapis.com/auth/gmail.readonly")  # the read-only path is unchanged
        self.assertEqual(oauth.EXPECTED_SCOPES, {oauth.SCOPE})

    def test_exact_scope_check_refuses_extra_missing_and_broader(self):
        oauth_write.check_granted_write_scopes([oauth_write.WRITE_SCOPE])
        for bad in ([], None, [oauth.SCOPE], [oauth_write.WRITE_SCOPE, oauth.SCOPE], [oauth_write.WRITE_SCOPE, "https://mail.google.com/"],
                    [oauth_write.WRITE_SCOPE, "https://www.googleapis.com/auth/gmail.send"], ["https://mail.google.com/"]):
            with self.assertRaisesRegex(oauth.AuthError, "unexpected OAuth scopes", msg=bad):
                oauth_write.check_granted_write_scopes(bad)

    def test_the_read_path_still_refuses_the_write_scope(self):
        with self.assertRaises(oauth.AuthError):
            oauth.check_granted_scopes([oauth_write.WRITE_SCOPE])
        with self.assertRaises(oauth.AuthError):
            oauth.blob_to_credentials({"scopes": [oauth_write.WRITE_SCOPE], "token": A_TOK, "refresh_token": R_TOK}, client_config())

    def test_client_file_validation_pins_googles_token_endpoint(self):
        path = self.write_client_file()
        self.assertEqual(oauth_write.load_write_client_config(path)["installed"]["client_id"], WRITE_CLIENT_ID)
        evil = self.write_client_file(attest=False, token_uri="https://attacker.example.invalid/token")
        with self.assertRaisesRegex(oauth.AuthError, "not Google's"):
            oauth_write.load_write_client_config(evil)
        with self.assertRaises(oauth.AuthError):
            oauth_write.load_write_client_config(self.tmp + "/missing.json")

    def test_login_requests_only_the_write_scope_without_accumulation(self):
        path = self.write_client_file()
        flow, seen = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,)), {}

        def factory(cfg, scopes):
            seen["scopes"] = scopes
            return flow

        creds, granted = oauth_write.run_login_write(path, flow_factory=factory, open_browser=False)
        self.assertEqual((seen["scopes"], granted), ([oauth_write.WRITE_SCOPE], [oauth_write.WRITE_SCOPE]))
        self.assertNotIn("include_granted_scopes", flow.kwargs)
        self.assertEqual((flow.kwargs["host"], flow.kwargs["access_type"], flow.kwargs["prompt"]), ("127.0.0.1", "offline", "consent"))

    def test_real_flow_object_uses_pkce_and_exactly_the_write_scope(self):
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow = InstalledAppFlow.from_client_config(write_client_config(), scopes=[oauth_write.WRITE_SCOPE])
        url, _ = flow.authorization_url(access_type="offline", prompt="consent")  # builds a URL only; nothing is opened or sent
        self.assertIn("code_challenge_method=S256", url)
        self.assertNotIn("include_granted_scopes", url)
        self.assertRegex(url, r"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.modify(&|$)")

    def test_login_refuses_unexpected_scopes_client_mismatch_and_missing_refresh_token(self):
        path = self.write_client_file()
        cases = (("extra scope", FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE, oauth.SCOPE)), "unexpected OAuth scopes"),
                 ("other scope", FakeFlow(creds=WCreds(), scopes=(oauth.SCOPE,)), "unexpected OAuth scopes"),
                 ("other client", FakeFlow(creds=WCreds(client_id="300000000003-othersynth03.apps.googleusercontent.com"), scopes=(oauth_write.WRITE_SCOPE,)), "different OAuth client"),
                 ("no refresh token", FakeFlow(creds=WCreds(refresh=None), scopes=(oauth_write.WRITE_SCOPE,)), "refresh token"),
                 ("scope change warning", FakeFlow(creds=WCreds(), raises=Warning("scope changed")), "different scopes"),
                 ("cancelled", FakeFlow(creds=WCreds(), raises=type("E", (Exception,), {"error": "access_denied"})()), "cancelled"))
        for label, flow, pattern in cases:
            with self.assertRaisesRegex(oauth.AuthError, pattern, msg=label):
                oauth_write.run_login_write(path, flow_factory=lambda c, s, f=flow: f, open_browser=False)

    def test_blob_roundtrip_and_identity_checks(self):
        client = write_client_config()
        blob = oauth_write.write_blob(WCreds(), ACCOUNT, [oauth_write.WRITE_SCOPE], client)
        creds = oauth_write.blob_to_write_credentials(blob, client)
        self.assertEqual((creds.scopes, creds.token_uri, creds.client_id), ([oauth_write.WRITE_SCOPE], oauth_write.TOKEN_URI, WRITE_CLIENT_ID))
        for bad, pattern in ((dict(blob, scopes=[oauth_write.WRITE_SCOPE, oauth.SCOPE]), "unexpected OAuth scopes"), (dict(blob, kind="read"), "valid write-authorization"),
                             (dict(blob, schema=2), "valid write-authorization"), (dict(blob, refresh_token=None), "no refresh token"),
                             (dict(blob, client_fp="0" * 64), "different OAuth client"), ("not a dict", "valid write-authorization")):
            with self.assertRaisesRegex(oauth.AuthError, pattern):
                oauth_write.blob_to_write_credentials(bad, client)
        other = write_client_config(client_id="400000000004-othersynth03.apps.googleusercontent.com")
        with self.assertRaisesRegex(oauth.AuthError, "different OAuth client"):
            oauth_write.blob_to_write_credentials(blob, other)

    def test_ten_minutes_of_validity_are_required_and_nothing_refreshes(self):
        for minutes, ok in ((60, True), (10.5, True), (9, False), (0, False), (-5, False)):
            creds = WCreds(minutes=minutes)
            if ok:
                oauth_write.require_validity(creds)
            else:
                with self.assertRaisesRegex(oauth.AuthError, "10 minutes"):
                    oauth_write.require_validity(creds)
            self.assertEqual(creds.refreshed, 0)
        creds = WCreds()
        creds.expiry = None
        with self.assertRaises(oauth.AuthError):
            oauth_write.require_validity(creds)

    def test_refresh_uses_only_a_pinned_oauth_request_and_stores_only_the_write_item(self):
        client = write_client_config()
        self.stored_blob()  # a read-only token exists and must not change
        read_before = dict(self.backend.items)
        blob = oauth_write.write_blob(WCreds(minutes=1), ACCOUNT, [oauth_write.WRITE_SCOPE], client)
        self.wstore.save(blob)
        sent = []
        delegate = lambda url, **kw: sent.append((url, kw)) or "ok"  # noqa: E731
        fresh = WCreds(minutes=1)
        with mock.patch.object(oauth_write, "blob_to_write_credentials", return_value=fresh):
            creds, new = oauth_write.refresh_and_store(self.wstore, blob, client, request=delegate)
        self.assertEqual(sent[0][0], oauth_write.TOKEN_URI)
        self.assertEqual((sent[0][1]["method"], sent[0][1]["allow_redirects"]), ("POST", False))
        self.assertEqual(self.wstore.load(), new)
        self.assertGreater(oauth_write.remaining_validity(creds.expiry), oauth_write.MIN_REMAINING)
        self.assertEqual({k: v for k, v in self.backend.items.items() if k[0] != keystore_write.SERVICE_WRITE}, read_before)

    def test_a_refresh_result_with_changed_missing_or_unknown_scopes_is_refused_and_stores_nothing(self):
        client = write_client_config()
        blob = oauth_write.write_blob(WCreds(minutes=1), ACCOUNT, [oauth_write.WRITE_SCOPE], client)
        self.wstore.save(blob)
        before = dict(self.backend.items)
        bad = [("broader", dict(refreshed_scopes=(oauth_write.WRITE_SCOPE, oauth.SCOPE))), ("other scope", dict(refreshed_scopes=(oauth.SCOPE,))),
               ("mail scope", dict(refreshed_scopes=("https://mail.google.com/",))), ("extra unknown", dict(refreshed_scopes=(oauth_write.WRITE_SCOPE, "https://example.invalid/x"))),
               ("scopes not reported", dict(refreshed_scopes=None)), ("empty scopes", dict(refreshed_scopes=())),
               ("no token", dict(after_refresh={"token": None})), ("no expiry", dict(after_refresh={"expiry": None})), ("refresh token lost", dict(after_refresh={"refresh_token": None}))]
        for label, kwargs in bad:
            fake = WCreds(minutes=1, **{k: v for k, v in kwargs.items() if k != "after_refresh"})
            fake.after_refresh = kwargs.get("after_refresh", {})
            with mock.patch.object(oauth_write, "blob_to_write_credentials", return_value=fake):
                with self.assertRaises(oauth.AuthError, msg=label) as ctx:
                    oauth_write.refresh_and_store(self.wstore, blob, client, request=lambda *a, **k: "ok")
            for s_ in SENTINELS:
                self.assertNotIn(s_, str(ctx.exception))
            self.assertEqual(self.backend.items, before, label)  # the previously stored credential is untouched
        self.assertEqual(self.wstore.load(), blob)

    def test_status_and_read_commands_never_refresh_the_write_token(self):
        self.write_client_file()
        self.wstore.save(oauth_write.write_blob(WCreds(minutes=1), ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config()))
        with mock.patch.object(oauth_write, "refresh_write_credentials", side_effect=AssertionError("refresh")), \
                mock.patch.object(oauth_write, "refresh_and_store", side_effect=AssertionError("refresh")):
            self.run_cli("auth", "status-write")
            self.run_cli("auth", "status")

    def test_the_pinned_oauth_request_refuses_any_other_url_or_method(self):
        pinned = oauth_write.PinnedOAuthRequest(oauth_write.TOKEN_URI, lambda *a, **k: "sent")
        for url, method in (("https://gmail.googleapis.com/gmail/v1/users/me/profile", "POST"), (oauth_write.REVOKE_URI, "POST"),
                            (oauth_write.TOKEN_URI + "?x=1", "POST"), (oauth_write.TOKEN_URI, "GET"), ("http://oauth2.googleapis.com/token", "POST")):
            with self.assertRaises(oauth.AuthError, msg=(url, method)):
                pinned(url, method=method)
        self.assertEqual(pinned(oauth_write.TOKEN_URI, method="POST"), "sent")

    def test_refresh_failures_are_clear_and_safe(self):
        for exc, pattern in ((RefreshError("invalid_grant: Token has been expired or revoked " + R_TOK), "expired or revoked"),
                             (RefreshError("boom " + R_TOK), "could not refresh"), (TransportError("down " + R_TOK), "network error")):
            with self.assertRaisesRegex(oauth.AuthError, pattern) as ctx:
                oauth_write.refresh_write_credentials(WCreds(raises=exc), request=lambda *a, **k: None)
            for s in SENTINELS:
                self.assertNotIn(s, str(ctx.exception))

    def test_revocation_response_classification(self):
        sent = []

        class Resp:
            def __init__(self, status, data=b""):
                self.status, self.data = status, data

        def request(status, data=b""):
            return lambda url, **kw: sent.append((url, kw)) or Resp(status, data)

        def revoke(status, data=b""):
            return oauth_write.revoke_refresh_token(R_TOK, request=request(status, data))

        self.assertEqual(revoke(200), "REVOKED")
        self.assertEqual(revoke(200, b"{}"), "REVOKED")
        with self.assertRaisesRegex(oauth.AuthError, "not a documented confirmation") as ctx:  # suggestive, but NOT a confirmation: the local token is kept
            revoke(400, b'{"error":"invalid_token","error_description":"Token expired or revoked"}')
        self.assertIn("kept", str(ctx.exception))
        self.assertEqual({u for u, _ in sent}, {oauth_write.REVOKE_URI})
        self.assertEqual(sent[0][1]["body"], b"token=" + R_TOK.encode())
        self.assertFalse(sent[0][1]["allow_redirects"])
        rejected = [(200, b"<html>captive portal</html>"), (200, b"junk"), (200, b"[]"), (400, b'{"error":"invalid_request"}'), (400, b'{"error":"invalid_client"}'),
                    (400, b'{"error":"unauthorized_client"}'), (400, b""), (400, b"junk"), (400, b"[]"), (400, b'["invalid_token"]'), (400, b'{"error":["invalid_token"]}'),
                    (400, b'{"error":"INVALID_TOKEN"}'), (400, b'{"error":"invalid_token","error":"invalid_request"}'), (400, b'{"error":"invalid_token"}' + b" " * 5000),
                    (400, b'{"detail":"invalid_token"}'), (400, "{\"error\":\"invalid_token\"}"), (301, b""), (302, b""), (307, b""), (308, b""), (204, b""), (201, b""),
                    (401, b""), (403, b""), (404, b""), (429, b""), (500, b""), (503, b""), (None, b""), (True, b""), ("200", b""), (200.0, b"")]
        for status, data in rejected:
            with self.assertRaises(oauth.AuthError, msg=(status, data[:30])) as ctx:
                revoke(status, data)
            self.assertIn("kept", str(ctx.exception).lower())  # a local credential is never dropped without confirmation
            self.assertNotIn(R_TOK, str(ctx.exception))

    def test_revocation_transport_failures_and_inputs(self):
        def broken(*a, **k):
            raise OSError("down " + R_TOK)
        with self.assertRaises(oauth.AuthError) as ctx:
            oauth_write.revoke_refresh_token(R_TOK, request=broken)
        self.assertNotIn(R_TOK, str(ctx.exception))
        self.assertIn("kept", str(ctx.exception))
        for bad in ("", None, 5):
            with self.assertRaises(oauth.AuthError):
                oauth_write.revoke_refresh_token(bad)
        pinned = oauth_write.PinnedOAuthRequest(oauth_write.TOKEN_URI, lambda *a, **k: None)  # a request pinned to the wrong URL is refused
        with self.assertRaises(oauth.AuthError):
            oauth_write.revoke_refresh_token(R_TOK, request=pinned)


class KeystoreWriteTests(WBase):
    def test_distinct_service_and_item_and_no_fallback_in_either_direction(self):
        self.assertEqual((keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE), ("gmail-intelligence-write", "oauth-token:gmail.modify"))
        self.assertNotEqual((keystore.SERVICE, keystore.ITEM), (keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE))
        self.stored_blob()  # read item only
        self.assertIsNone(self.wstore.load())  # never falls back to the read-only item
        self.assertEqual({k for k in self.backend.touched}, {(keystore.SERVICE, keystore.ITEM), (keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE)})
        self.backend.items.clear()
        self.write_blob()
        self.assertIsNone(self.store.load())  # and the read-only store never sees the write item

    def test_roundtrip_delete_only_own_item_and_keep_the_read_item(self):
        self.stored_blob()
        self.backend.items[("other-app", "x")] = "keep"
        self.assertFalse(keystore_write.WriteTokenStore(FakeBackend()).delete())
        blob = self.write_blob()
        self.assertEqual(self.wstore.load(), blob)
        self.assertTrue(self.wstore.delete())
        self.assertIsNone(self.wstore.load())
        self.assertIsNotNone(self.store.load())
        self.assertIn(("other-app", "x"), self.backend.items)

    def test_refuses_to_store_an_invalid_record(self):
        good = oauth_write.write_blob(WCreds(), ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config())
        for bad in (dict(good, scopes=[oauth.SCOPE]), dict(good, scopes=[oauth_write.WRITE_SCOPE, oauth.SCOPE]), dict(good, kind="x"),
                    dict(good, refresh_token=""), {"scopes": [oauth.SCOPE], "token": A_TOK, "refresh_token": R_TOK}):
            with self.assertRaises(keystore.KeystoreError):
                self.wstore.save(bad)
        self.assertEqual(self.backend.items, {})

    def test_backend_failure_corruption_and_non_macos_backend(self):
        with self.assertRaises(keystore.KeystoreError) as ctx:
            keystore_write.WriteTokenStore(FakeBackend(fail=True)).load()
        self.assertNotIn(A_TOK, str(ctx.exception))
        self.backend.items[(keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE)] = "{broken"
        with self.assertRaisesRegex(keystore.KeystoreError, "corrupt"):
            self.wstore.load()
        import keyring
        from keyring.backends import fail
        with mock.patch.object(keyring, "get_keyring", return_value=fail.Keyring()):
            with self.assertRaisesRegex(keystore.KeystoreError, "no plaintext fallback"):
                keystore_write.WriteTokenStore()


class WriteCliTests(WBase):
    def test_every_write_command_is_a_subcommand_of_auth_and_login_needs_expect_account(self):
        self.assertEqual(self.run_cli("auth", "login-write")[0], 2)  # --expect-account is mandatory
        self.assertEqual(self.run_cli("auth", "bogus-write")[0], 2)

    def test_setup_write_prints_steps_and_imports_a_validated_separate_client_with_an_attestation(self):
        code, out, _ = self.run_cli("auth", "setup-write")
        self.assertEqual(code, 0)
        self.assertIn("SEPARATE", out)
        self.assertIn(oauth_write.WRITE_SCOPE, out)
        self.assertIn("--confirm-separate-project", out)
        self.write_client()  # the read-only client must exist first
        read_before = config.client_secret_path().read_bytes()
        src = Path(self.tmp) / "dl.json"
        src.write_text(json.dumps(write_client_config()))
        code, _, err = self.run_cli("auth", "setup-write", "--import", str(src))  # no attestation, no import
        self.assertEqual(code, 1)
        self.assertIn("--confirm-separate-project", err)
        self.assertFalse(config.write_client_secret_path().exists())
        code, out, _ = self.run_cli("auth", "setup-write", "--import", str(src), "--confirm-separate-project")
        self.assertEqual(code, 0)
        self.assertEqual(oct(os.stat(config.write_client_secret_path()).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(config.write_setup_path()).st_mode & 0o777), "0o600")
        self.assertEqual(config.client_secret_path().read_bytes(), read_before)  # the read-only client file is untouched
        record = config.write_setup_path().read_text()
        for private in (WRITE_CLIENT_ID, "200000000002", "100000000001", C_SEC):
            self.assertNotIn(private, record + out)  # fingerprints only
        oauth_write.verify_isolation(config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path())

    def test_setup_write_refuses_the_read_client_the_same_project_bad_formats_and_missing_read_client(self):
        self.write_client()
        read_before = config.client_secret_path().read_bytes()
        cases = (("same client", write_client_config(client_id=client_config()["installed"]["client_id"]), "different OAuth client"),
                 ("same project number", write_client_config(client_id=SAME_PROJECT_ID), "same Google Cloud project"),
                 ("short number", write_client_config(client_id="123-abcdefgh.apps.googleusercontent.com"), "recognized Google format"),
                 ("no number", write_client_config(client_id="abcdefghijkl.apps.googleusercontent.com"), "recognized Google format"),
                 ("upper case", write_client_config(client_id="200000000002-WRITESYNTHETIC0000000000000.apps.googleusercontent.com"), "recognized Google format"),
                 ("foreign suffix", write_client_config(client_id="200000000002-writesynth02.apps.example.invalid"), "does not look like a Google client id"),
                 ("evil token endpoint", write_client_config(token_uri="https://attacker.example.invalid/token"), "not Google's"))
        for label, cfg, pattern in cases:
            src = Path(self.tmp) / "x.json"
            src.write_text(json.dumps(cfg))
            code, out, err = self.run_cli("auth", "setup-write", "--import", str(src), "--confirm-separate-project")
            self.assertEqual(code, 1, label)
            self.assertRegex(err, pattern, label)
            for private in ("200000000002", "100000000001", C_SEC, "writesynth", "readsynth"):
                self.assertNotIn(private, out + err, label)  # no client id fragment or secret in an error
            self.assertFalse(config.write_client_secret_path().exists(), label)
            self.assertFalse(config.write_setup_path().exists(), label)
        self.assertEqual(config.client_secret_path().read_bytes(), read_before)

    def test_setup_write_fails_closed_without_a_usable_read_client(self):
        src = Path(self.tmp) / "dl.json"
        src.write_text(json.dumps(write_client_config()))
        for label, prepare in (("missing", lambda: None), ("malformed", lambda: (config.ensure_app_dir(), config.client_secret_path().write_text("{not json"))),
                               ("unrecognized id", lambda: (config.ensure_app_dir(), config.client_secret_path().write_text(json.dumps(client_config()).replace("100000000001-readsynth01", "123-abc"))))):
            prepare()
            code, _, err = self.run_cli("auth", "setup-write", "--import", str(src), "--confirm-separate-project")
            self.assertEqual(code, 1, label)
            self.assertFalse(config.write_client_secret_path().exists(), label)
            self.assertFalse(config.write_setup_path().exists(), label)


    def login(self, creds=None, account=ACCOUNT, stdin=oauth_write.LOGIN_PHRASE, expect=ACCOUNT, **patch):
        self.write_client_file()
        creds = creds or WCreds()
        runner = patch.pop("runner", mock.Mock(return_value=(creds, [oauth_write.WRITE_SCOPE])))
        revoke = patch.pop("revoke", mock.Mock(return_value="REVOKED"))
        with mock.patch.object(oauth_write, "run_login_write", runner), mock.patch.object(gmail_write, "fetch_profile_email", return_value=account), \
                mock.patch.object(oauth_write, "revoke_refresh_token", revoke):
            result = self.run_cli("auth", "login-write", "--expect-account", expect, "--no-browser", stdin=stdin)
        return result, runner, revoke

    def test_login_shows_the_broad_risk_requires_the_typed_phrase_and_stores_only_in_the_write_item(self):
        (code, out, _), runner, revoke = self.login()
        self.assertEqual(code, 0)
        for text in ("much broader than archiving", "send mail", "application policy", "does not revoke", oauth_write.WRITE_SCOPE):
            self.assertIn(text, out.replace("\n", " ") if text == "does not revoke" else out)
        runner.assert_called_once()
        revoke.assert_not_called()
        blob = self.wstore.load()
        self.assertEqual((blob["account"], blob["scopes"], blob["kind"]), (ACCOUNT, [oauth_write.WRITE_SCOPE], oauth_write.BLOB_KIND))
        self.assertEqual({k for k in self.backend.touched} - {(keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE)}, set())  # only the write item
        self.assertIsNone(self.store.load())  # nothing in the read-only item

    def test_login_without_the_exact_phrase_requests_nothing(self):
        for stdin in ("", "y", "yes", "authorize gmail modify", oauth_write.LOGIN_PHRASE + " now"):
            (code, _, err), runner, _ = self.login(stdin=stdin)
            self.assertEqual(code, 1)
            self.assertIn("declined", err)
            runner.assert_not_called()  # no browser, no OAuth flow
        self.assertIsNone(self.wstore.load())

    # ---- failures AFTER Google issued a grant: best-effort revocation, never a false claim, never a stored or revoked unrelated credential
    def fake_flow_login(self, flow, revoke=None, profile=ACCOUNT, expect=ACCOUNT, save_error=None, pre=None):
        """Run the REAL run_login_write with a fake flow through the CLI (so LoginRejected is raised by the real code)."""
        self.write_client_file()
        real = oauth_write.run_login_write
        revoke = revoke or mock.Mock(return_value="REVOKED")
        patches = [mock.patch.object(oauth_write, "run_login_write", lambda path, **k: real(path, flow_factory=lambda c, s: flow, open_browser=False)),
                   mock.patch.object(oauth_write, "revoke_refresh_token", revoke)]
        if isinstance(profile, BaseException):
            patches.append(mock.patch.object(gmail_write, "fetch_profile_email", side_effect=profile))
        else:
            patches.append(mock.patch.object(gmail_write, "fetch_profile_email", return_value=profile))
        if save_error:
            patches.append(mock.patch.object(keystore_write.WriteTokenStore, "save", side_effect=save_error))
        with contextlib.ExitStack() as stack:  # scoped: the base class patches (network block, temporary home) stay untouched
            for p_ in patches:
                stack.enter_context(p_)
            return self.run_cli("auth", "login-write", "--expect-account", expect, "--no-browser", stdin=oauth_write.LOGIN_PHRASE), revoke

    def assert_discarded(self, result, revoke, token, outcome_text="revoked at Google", message=None):
        code, out, err = result
        self.assertEqual(code, 1)
        self.assertIn(outcome_text, err)
        self.assertIn("nothing was stored", err)
        if message:
            self.assertIn(message, err)
        revoke.assert_called_once_with(token)
        self.assertIsNone(self.wstore.load())
        self.assertNotIn(ACCOUNT, out + err)
        self.assertNotIn(ACCOUNT_OTHER, out + err)
        self.assertNotIn("undone", (out + err).lower())  # consent is never claimed undone unless Google confirmed a revocation

    def test_scope_rejection_after_consent_revokes_the_new_grant(self):
        flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE, oauth.SCOPE))
        result, revoke = self.fake_flow_login(flow)
        self.assert_discarded(result, revoke, R_TOK, message="unexpected OAuth scopes")

    def test_a_scope_change_warning_after_consent_still_revokes_the_issued_token(self):
        flow = FakeFlow(creds=WCreds(), raises=Warning("scope changed"))
        flow.oauth2session.token = {"scope": [oauth_write.WRITE_SCOPE, oauth.SCOPE], "refresh_token": R_TOK, "access_token": A_TOK}
        result, revoke = self.fake_flow_login(flow)
        self.assert_discarded(result, revoke, R_TOK, message="different scopes")

    def test_a_foreign_client_or_missing_refresh_token_revokes_what_was_issued(self):
        flow = FakeFlow(creds=WCreds(client_id="300000000003-othersynth03.apps.googleusercontent.com"), scopes=(oauth_write.WRITE_SCOPE,))
        result, revoke = self.fake_flow_login(flow)
        self.assert_discarded(result, revoke, R_TOK, message="different OAuth client")
        self.tearDown_stores()
        flow = FakeFlow(creds=WCreds(refresh=None), scopes=(oauth_write.WRITE_SCOPE,))
        result, revoke = self.fake_flow_login(flow)
        self.assert_discarded(result, revoke, A_TOK, message="refresh token")  # the access token is revoked instead

    def tearDown_stores(self):
        self.backend.items.clear()
        self.backend.touched.clear()

    def test_profile_failure_or_malformed_profile_after_consent_revokes_the_new_grant(self):
        for exc in (gmail_write.UncertainOutcome("NETWORK_ERROR"), gmail_write.ReadFailure(), gmail_write.WriteAuthError(), gmail_write.Denied("DENIED_SIZE")):
            self.tearDown_stores()
            flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,))
            result, revoke = self.fake_flow_login(flow, profile=exc)
            self.assert_discarded(result, revoke, R_TOK, message="could not confirm which account")

    def test_expected_account_mismatch_revokes_the_new_grant_and_reports_honestly(self):
        flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,))
        result, revoke = self.fake_flow_login(flow, profile=ACCOUNT_OTHER)
        self.assert_discarded(result, revoke, R_TOK, message="differs from --expect-account")

    def test_keychain_persistence_failure_revokes_the_new_grant(self):
        flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,))
        result, revoke = self.fake_flow_login(flow, save_error=keystore.KeystoreError("Keychain write failed (RuntimeError)"))
        self.assert_discarded(result, revoke, R_TOK, message="Keychain write failed")

    def test_a_failed_revocation_is_reported_as_failed_and_consent_is_not_claimed_undone(self):
        flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,))
        (code, out, err), revoke = self.fake_flow_login(flow, profile=ACCOUNT_OTHER, revoke=mock.Mock(side_effect=oauth.AuthError("revocation was not confirmed (HTTP 500)")))
        self.assertEqual(code, 1)
        self.assertIn("revocation FAILED", err)
        self.assertIn("Google consent still stands", err)
        self.assertNotIn("was revoked at Google", err)
        self.assertIsNone(self.wstore.load())

    def test_an_existing_credential_is_never_replaced_or_revoked_by_a_new_login(self):
        before = self.write_blob()
        flow = FakeFlow(creds=WCreds(), scopes=(oauth_write.WRITE_SCOPE,))
        (code, out, err), revoke = self.fake_flow_login(flow)  # login refuses before any flow starts
        self.assertEqual(code, 1)
        self.assertIn("already stored", err)
        revoke.assert_not_called()
        self.assertEqual(self.wstore.load(), before)
        self.assertIsNone(flow.kwargs)  # the authorization flow never ran

    def test_a_credential_that_appears_during_login_is_kept_and_nothing_is_revoked_because_the_grant_may_be_shared(self):
        self.write_client_file()
        appeared = {}

        def runner(path, **k):
            appeared["blob"] = self.write_blob()  # another process stored a credential while the browser flow was running
            return WCreds(), [oauth_write.WRITE_SCOPE]
        revoke = mock.Mock(return_value="REVOKED")
        with mock.patch.object(oauth_write, "run_login_write", runner), mock.patch.object(gmail_write, "fetch_profile_email", return_value=ACCOUNT), \
                mock.patch.object(oauth_write, "revoke_refresh_token", revoke):
            code, out, err = self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, stdin=oauth_write.LOGIN_PHRASE)
        self.assertEqual(code, 1)
        self.assertIn("appeared in the Keychain", err)
        self.assertIn("revocation was NOT attempted", err)
        self.assertIn("might share this grant", err)
        revoke.assert_not_called()
        self.assertEqual(self.wstore.load(), appeared["blob"])  # the previously stored credential is untouched

    def test_when_the_keychain_cannot_be_checked_revocation_is_not_attempted(self):
        issued = oauth_write.IssuedToken(R_TOK, A_TOK)
        self.write_client_file()

        class Unreadable:
            def load(self):
                raise keystore.KeystoreError("locked")
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoked")):
            text = cli._discard_new_grant(Unreadable(), issued)
            self.assertIn("revocation was NOT attempted", text)
            self.assertIn("Google consent still stands", text)
            self.assertIn("Google consent may still exist", cli._discard_new_grant(self.wstore, oauth_write.IssuedToken(None, None)))
        self.assertEqual(repr(issued), "<IssuedToken>")  # token material never reaches a repr

    def test_authorization_errors_before_a_grant_exists_attempt_no_revocation(self):
        for exc in (oauth.AuthError("authorization was cancelled or denied in the browser"), oauth.AuthError("timed out waiting for browser authorization")):
            runner = mock.Mock(side_effect=exc)
            (code, _, err), _, revoke = self.login(runner=runner)
            self.assertEqual(code, 1)
            revoke.assert_not_called()
            self.assertIsNone(self.wstore.load())

    def test_login_with_the_wrong_account_stores_nothing_and_revokes_the_unwanted_grant(self):
        (code, _, err), _, revoke = self.login(account=ACCOUNT_OTHER)
        self.assertEqual(code, 1)
        self.assertIn("differs from --expect-account", err)
        self.assertNotIn(ACCOUNT_OTHER, err)
        revoke.assert_called_once_with(R_TOK)
        self.assertIsNone(self.wstore.load())

    def test_login_refuses_when_already_authorized_missing_client_and_storage_failure(self):
        self.write_blob()
        (code, _, err), runner, _ = self.login()
        self.assertEqual(code, 1)
        self.assertIn("already stored", err)
        runner.assert_not_called()
        self.wstore.delete()
        config.write_client_secret_path().unlink()  # no write client file imported yet
        self.assertEqual(self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, stdin=oauth_write.LOGIN_PHRASE)[0], 1)
        with mock.patch.object(cli, "_write_store", side_effect=keystore.KeystoreError("Keychain unavailable")):
            self.write_client_file()
            self.assertEqual(self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, stdin=oauth_write.LOGIN_PHRASE)[0], 1)

    def test_login_flow_errors_are_reported_without_secrets(self):
        runner = mock.Mock(side_effect=oauth.AuthError("authorization was cancelled or denied in the browser"))
        (code, _, err), _, _ = self.login(runner=runner)
        self.assertEqual(code, 1)
        self.assertIn("cancelled", err)
        self.assertIsNone(self.wstore.load())

    def test_status_write_is_local_only_never_refreshes_and_never_logs_in(self):
        code, out, _ = self.run_cli("auth", "status-write")
        self.assertEqual(code, 1)
        self.assertIn("no write authorization stored", out)
        self.write_client_file()
        creds = WCreds(minutes=1)
        blob = oauth_write.write_blob(creds, ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config())
        self.wstore.save(blob)
        with mock.patch.object(oauth_write, "run_login_write", side_effect=AssertionError("login")), \
                mock.patch.object(oauth_write, "refresh_write_credentials", side_effect=AssertionError("refresh")), \
                mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoke")):
            code, out, _ = self.run_cli("auth", "status-write")  # sockets are blocked by the base class: no network either
        self.assertEqual(code, 0)
        self.assertIn("NOT refreshed", out)
        self.assertIn("not verified with Google", out)
        self.assertNotIn(ACCOUNT, out)

    def test_status_write_flags_a_different_client_and_a_wrong_scope(self):
        self.write_client_file(client_id="400000000004-othersynth03.apps.googleusercontent.com")
        self.write_blob()
        code, out, _ = self.run_cli("auth", "status-write")
        self.assertEqual(code, 1)
        self.assertIn("different OAuth client", out)
        self.write_client_file()
        self.write_blob(scopes=[oauth_write.WRITE_SCOPE, oauth.SCOPE])
        self.assertEqual(self.run_cli("auth", "status-write")[0], 1)

    def test_logout_write_removes_only_the_write_item_and_says_it_does_not_revoke(self):
        self.stored_blob()
        self.write_blob()
        self.assertEqual(self.run_cli("auth", "logout-write", stdin="n")[0], 1)
        self.assertIsNotNone(self.wstore.load())
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("must stay local")):
            code, out, _ = self.run_cli("auth", "logout-write", stdin="y")
        self.assertEqual(code, 0)
        self.assertIn("does NOT revoke", out)
        self.assertIsNone(self.wstore.load())
        self.assertIsNotNone(self.store.load())  # read-only authorization untouched
        self.assertEqual(self.run_cli("auth", "logout-write", "--yes")[0], 0)

    def test_the_read_only_logout_does_not_touch_the_write_item(self):
        self.stored_blob()
        self.write_blob()
        self.assertEqual(self.run_cli("auth", "logout", "--yes")[0], 0)
        self.assertIsNone(self.store.load())
        self.assertIsNotNone(self.wstore.load())

    def test_revoke_write_needs_the_phrase_revokes_remotely_then_removes_locally(self):
        self.write_client_file()
        self.stored_blob()
        self.write_blob()
        calls = mock.Mock(return_value="REVOKED")
        with mock.patch.object(oauth_write, "revoke_refresh_token", calls):
            self.assertEqual(self.run_cli("auth", "revoke-write", stdin="revoke")[0], 1)
            calls.assert_not_called()
            self.assertIsNotNone(self.wstore.load())
            code, out, _ = self.run_cli("auth", "revoke-write", stdin=oauth_write.REVOKE_PHRASE)
        self.assertEqual(code, 0)
        calls.assert_called_once_with(R_TOK)
        self.assertIsNone(self.wstore.load())
        self.assertIsNotNone(self.store.load())

    def test_a_failed_revocation_keeps_the_local_token(self):
        self.write_client_file()
        self.write_blob()
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=oauth.AuthError("revocation was not confirmed (HTTP 500); the local token was kept")):
            code, _, err = self.run_cli("auth", "revoke-write", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("kept", err)
        self.assertIsNotNone(self.wstore.load())

    # ---- the REAL installed oauthlib / requests-oauthlib behaviour (fake HTTP session only; no socket is opened)
    def real_flow(self, token_response, relax=False):
        """A genuine google_auth_oauthlib flow whose token endpoint is answered by a fake requests session."""
        import requests
        from google_auth_oauthlib.flow import InstalledAppFlow

        inner = InstalledAppFlow.from_client_config(write_client_config(), scopes=[oauth_write.WRITE_SCOPE])
        inner.redirect_uri = "http://127.0.0.1:1/"
        resp = requests.Response()
        resp.status_code, resp._content = 200, json.dumps(token_response).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url = oauth_write.TOKEN_URI
        resp.request = requests.Request("POST", oauth_write.TOKEN_URI).prepare()
        test = self

        class Flow:
            oauth2session = inner.oauth2session

            def run_local_server(self, **kwargs):
                env = {"OAUTHLIB_RELAX_TOKEN_SCOPE": "1"} if relax else {}
                with mock.patch.dict(os.environ, env), mock.patch.object(requests.Session, "request", return_value=resp):
                    inner.fetch_token(code="synthetic-code")  # the REAL oauthlib parsing, the real Warning
                test.assertEqual(self.oauth2session.token is not None, True)
                return inner.credentials

        return Flow(), inner

    TOKEN = {"access_token": A_TOK, "refresh_token": R_TOK, "token_type": "Bearer", "expires_in": 3600}

    def test_the_real_oauthlib_warning_carries_the_token_and_the_session_stays_empty(self):
        flow, inner = self.real_flow(dict(self.TOKEN, scope=oauth_write.WRITE_SCOPE + " " + oauth.SCOPE))
        with self.assertRaises(Warning) as caught:
            flow.run_local_server()
        self.assertIs(type(caught.exception), Warning)  # documents the installed library's behaviour that the cleanup relies on
        self.assertFalse(dict(inner.oauth2session.token or {}))  # NOT where the credential handle is
        self.assertEqual(caught.exception.token.get("refresh_token"), R_TOK)
        path = self.write_client_file()
        with self.assertRaises(oauth_write.LoginRejected) as ctx:
            oauth_write.run_login_write(path, flow_factory=lambda c, s: flow, open_browser=False)
        self.assertEqual((ctx.exception.issued.refresh_token, ctx.exception.issued.token), (R_TOK, A_TOK))
        for text in (str(ctx.exception), repr(ctx.exception), repr(ctx.exception.issued), str(ctx.exception.__cause__)):
            for secret in (R_TOK, A_TOK):
                self.assertNotIn(secret, text)

    def test_real_warning_through_the_cli_revokes_the_issued_grant_and_prints_nothing_secret(self):
        flow, _ = self.real_flow(dict(self.TOKEN, scope=oauth_write.WRITE_SCOPE + " " + oauth.SCOPE))
        (code, out, err), revoke = self.fake_flow_login(flow)
        self.assert_discarded((code, out, err), revoke, R_TOK, message="different scopes")
        self.assertNotIn("Scope has changed", out + err)  # the Warning text is never shown

    def test_real_scope_rejection_without_a_warning_revokes_too(self):
        flow, _ = self.real_flow(dict(self.TOKEN, scope=oauth_write.WRITE_SCOPE + " " + oauth.SCOPE), relax=True)
        (code, out, err), revoke = self.fake_flow_login(flow)
        self.assert_discarded((code, out, err), revoke, R_TOK, message="unexpected OAuth scopes")

    def test_a_real_response_without_a_refresh_token_revokes_the_access_token(self):
        flow, _ = self.real_flow({"access_token": A_TOK, "token_type": "Bearer", "expires_in": 3600, "scope": oauth_write.WRITE_SCOPE + " " + oauth.SCOPE})
        (code, out, err), revoke = self.fake_flow_login(flow)
        self.assert_discarded((code, out, err), revoke, A_TOK, message="different scopes")

    def test_a_failed_revocation_after_a_real_warning_is_reported_honestly(self):
        flow, _ = self.real_flow(dict(self.TOKEN, scope=oauth_write.WRITE_SCOPE + " " + oauth.SCOPE))
        (code, out, err), revoke = self.fake_flow_login(flow, revoke=mock.Mock(side_effect=oauth.AuthError("revocation was not confirmed (HTTP 500)")))
        self.assertEqual(code, 1)
        self.assertIn("revocation FAILED", err)
        self.assertIn("Google consent still stands", err)
        self.assertNotIn("was revoked at Google", err)
        self.assertIsNone(self.wstore.load())

    def test_untrusted_or_malformed_warning_payloads_are_never_used_as_revocation_credentials(self):
        class Impostor(Warning):  # a subclass is not oauthlib's own Warning
            pass

        def warning(cls=Warning, **attrs):
            w = cls("Scope has changed " + R_TOK)
            for k, v in attrs.items():
                setattr(w, k, v)
            return w
        good = {"refresh_token": R_TOK, "access_token": A_TOK}
        shape = dict(old_scope=[oauth_write.WRITE_SCOPE], new_scope=[oauth.SCOPE])
        cases = (("subclass", warning(Impostor, token=good, **shape)), ("no oauthlib attributes", warning(token=good)), ("token not a mapping", warning(token="x" * 20, **shape)),
                 ("token list", warning(token=[R_TOK], **shape)), ("non-string values", warning(token={"refresh_token": 5, "access_token": ["a"]}, **shape)),
                 ("illegal characters", warning(token=dict(refresh_token="bad token value!", access_token="a b c d e f g h"), **shape)),
                 ("too short", warning(token={"refresh_token": "abc", "access_token": "xy"}, **shape)), ("absent token", warning(**shape)),
                 ("empty token", warning(token={}, **shape)), ("huge", warning(token={"refresh_token": "a" * 5000, "access_token": "b" * 5000}, **shape)))
        path = self.write_client_file()
        for label, exc in cases:
            flow = FakeFlow(creds=WCreds(), raises=exc)
            flow.oauth2session.token = {}
            with self.assertRaises(oauth_write.LoginRejected, msg=label) as ctx:
                oauth_write.run_login_write(path, flow_factory=lambda c, s, f=flow: f, open_browser=False)
            self.assertEqual((ctx.exception.issued.refresh_token, ctx.exception.issued.token), (None, None), label)
        # the session token is only a validated fallback
        flow = FakeFlow(creds=WCreds(), raises=warning(token="junk", **shape))
        flow.oauth2session.token = dict(refresh_token="bad value!", access_token=A_TOK)
        with self.assertRaises(oauth_write.LoginRejected) as ctx:
            oauth_write.run_login_write(path, flow_factory=lambda c, s: flow, open_browser=False)
        self.assertEqual((ctx.exception.issued.refresh_token, ctx.exception.issued.token), (None, A_TOK))
        # and an unusable payload ends in an honest "not attempted"
        flow = FakeFlow(creds=WCreds(), raises=warning(token={}, **shape))
        flow.oauth2session.token = {}
        (code, out, err), revoke = self.fake_flow_login(flow)
        self.assertEqual(code, 1)
        self.assertIn("revocation was NOT attempted", err)
        self.assertIn("Google consent may still exist", err)
        revoke.assert_not_called()

    def test_a_token_equal_to_the_stored_one_is_never_revoked_as_a_new_grant(self):
        blob = self.write_blob()
        self.write_client_file()
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoked")):
            text = cli._discard_new_grant(self.wstore, oauth_write.IssuedToken(blob["refresh_token"], A_TOK))
        self.assertIn("revocation was NOT attempted", text)
        self.assertIsNotNone(self.wstore.load())


class ProjectIsolationTests(WBase):
    """Revocation is project-wide at Google: write/revoke operations fail closed unless the write client is attested to be in a separate project."""
    READ_ID = client_config()["installed"]["client_id"]

    def broken_login_must_not_start(self):
        with mock.patch.object(oauth_write, "run_login_write", side_effect=AssertionError("flow started")), \
                mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoked")):
            code, out, err = self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, stdin=oauth_write.LOGIN_PHRASE)
        self.assertEqual(code, 1)
        self.touched_by_login = list(self.backend.touched)  # captured before the assertions below read the Keychain themselves
        self.assertIsNone(self.wstore.load())
        return out + err

    def test_project_number_parsing_is_strict(self):
        pn = oauth_write.project_number
        self.assertEqual(pn(self.READ_ID), "100000000001")
        self.assertEqual(pn("123456-abcdefgh.apps.googleusercontent.com"), "123456")
        for bad in ("123-abcdefgh.apps.googleusercontent.com", "12345678901234567890123-abcdefgh.apps.googleusercontent.com", "abc-abcdefgh.apps.googleusercontent.com",
                    "100000000001-ABCDEFGH.apps.googleusercontent.com", "100000000001-abc.apps.googleusercontent.com", "100000000001abcdefgh.apps.googleusercontent.com",
                    "100000000001-abcdefgh.apps.googleusercontent.com.evil.invalid", "x100000000001-abcdefgh.apps.googleusercontent.com", " 100000000001-abcdefgh.apps.googleusercontent.com",
                    "100000000001-abcdef\u0661h.apps.googleusercontent.com", "\u0661\u0662\u0663\u0664\u0665\u0666-abcdefgh.apps.googleusercontent.com", "", None, 5, b"100000000001-abcdefgh.apps.googleusercontent.com",
                    "100000000001-abcdefgh.apps.googleusercontent.com\n"):
            self.assertIsNone(pn(bad), repr(bad))

    def test_the_project_number_must_be_canonical(self):
        pn = oauth_write.project_number
        self.assertEqual(pn("100000000001-readsynth01.apps.googleusercontent.com"), "100000000001")
        self.assertEqual(pn("900000-readsynth01.apps.googleusercontent.com"), "900000")
        for bad in ("0100000000001-readsynth01.apps.googleusercontent.com", "000000100000-readsynth01.apps.googleusercontent.com", "0-readsynth01.apps.googleusercontent.com",
                    "0123456-readsynth01.apps.googleusercontent.com", "00-readsynth01.apps.googleusercontent.com"):
            self.assertIsNone(pn(bad), bad)
        read = client_config()
        for variant in ("0100000000001-writesynth02.apps.googleusercontent.com", "00100000000001-writesynth02.apps.googleusercontent.com"):  # same number, non-canonical text
            with self.assertRaisesRegex(oauth.AuthError, "recognized Google format"):
                oauth_write.check_project_separation(write_client_config(client_id=variant), read)
        with self.assertRaisesRegex(oauth.AuthError, "same Google Cloud project"):  # canonical, same project, different client
            oauth_write.check_project_separation(write_client_config(client_id="100000000001-writesynth02.apps.googleusercontent.com"), read)
        oauth_write.check_project_separation(write_client_config(), read)  # different project numbers: accepted as (non-authoritative) evidence

    def test_the_optional_project_id_is_checked_for_consistency_only(self):
        check = oauth_write.check_project_separation
        read_plain, write_plain = client_config(), write_client_config()
        # absent on both or on one side: never invented, nothing to compare
        check(write_plain, read_plain)
        check(write_client_config(project_id="write-project-1"), read_plain)
        check(write_plain, read_client_config(project_id="read-project-1"))
        # present on both and different: accepted (still not proof)
        check(write_client_config(project_id="write-project-1"), read_client_config(project_id="read-project-1"))
        # the same project id although the client ids encode different numbers: an explicit contradiction
        with self.assertRaisesRegex(oauth.AuthError, "same Google Cloud project id") as ctx:
            check(write_client_config(project_id="shared-project-1"), read_client_config(project_id="shared-project-1"))
        self.assertNotIn("shared-project-1", str(ctx.exception))
        # the same number AND different ids is still rejected by the number check
        with self.assertRaisesRegex(oauth.AuthError, "same Google Cloud project"):
            check(write_client_config(client_id=SAME_PROJECT_ID, project_id="write-project-1"), read_client_config(project_id="read-project-1"))
        # supplied but malformed identity data fails closed on either side
        for bad in (5, None, ["a"], {}, True, "", "abc", "A-Project-1", "1-project-name", "project-name-", "project_name_x", "project name x", "p" * 31, "projéct-name-1", "project-name-1\n"):
            for cfg_w, cfg_r in ((write_client_config(project_id=bad), read_plain), (write_plain, read_client_config(project_id=bad))):
                with self.assertRaisesRegex(oauth.AuthError, "malformed project id", msg=repr(bad)):
                    check(cfg_w, cfg_r)

    def test_a_project_id_change_after_setup_invalidates_the_attestation(self):
        w, r, st = config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path()
        self.write_client_file(project_id="write-project-1")
        oauth_write.verify_isolation(w, r, st)
        record = json.loads(st.read_text())
        self.assertNotIn("write-project-1", json.dumps(record))  # fingerprints only
        w.write_text(json.dumps(write_client_config(project_id="other-project-2")))  # same client id, different declared project id
        with self.assertRaisesRegex(oauth.AuthError, "changed since"):
            oauth_write.verify_isolation(w, r, st)
        w.write_text(json.dumps(write_client_config()))  # the field removed
        with self.assertRaisesRegex(oauth.AuthError, "changed since"):
            oauth_write.verify_isolation(w, r, st)
        r.write_text(json.dumps(read_client_config(project_id="write-project-1")))  # the read client now claims the write project
        w.write_text(json.dumps(write_client_config(project_id="write-project-1")))
        with self.assertRaisesRegex(oauth.AuthError, "same Google Cloud project id"):
            oauth_write.verify_isolation(w, r, st)

    def test_setup_write_applies_the_project_id_check_and_never_leaks_it(self):
        self.write_client()
        config.client_secret_path().write_text(json.dumps(read_client_config(project_id="shared-project-1")))
        src = Path(self.tmp) / "dl.json"
        src.write_text(json.dumps(write_client_config(project_id="shared-project-1")))
        code, out, err = self.run_cli("auth", "setup-write", "--import", str(src), "--confirm-separate-project")
        self.assertEqual(code, 1)
        self.assertIn("same Google Cloud project id", err)
        self.assertNotIn("shared-project-1", out + err)
        self.assertFalse(config.write_client_secret_path().exists())
        self.assertFalse(config.write_setup_path().exists())
        src.write_text(json.dumps(write_client_config(project_id="write-project-1")))
        self.assertEqual(self.run_cli("auth", "setup-write", "--import", str(src), "--confirm-separate-project")[0], 0)

    def test_separation_policy_cases(self):
        read = client_config()
        check = oauth_write.check_project_separation
        check(write_client_config(), read)  # different project numbers: passes (necessary evidence, not proof)
        for label, cfg, pattern in (("identical", write_client_config(client_id=self.READ_ID), "different OAuth client"),
                                    ("same number, different client", write_client_config(client_id=SAME_PROJECT_ID), "same Google Cloud project"),
                                    ("unrecognized write id", write_client_config(client_id="123-abc.apps.googleusercontent.com"), "recognized Google format")):
            with self.assertRaisesRegex(oauth.AuthError, pattern, msg=label) as ctx:
                check(cfg, read)
            self.assertNotIn("100000000001", str(ctx.exception))
        with self.assertRaisesRegex(oauth.AuthError, "recognized Google format"):
            check(write_client_config(), read_client_config(client_id="123-abc.apps.googleusercontent.com"))

    def test_verification_fails_closed_for_every_missing_malformed_or_changed_input(self):
        w, r, st = config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path()
        self.write_client_file()
        oauth_write.verify_isolation(w, r, st)  # baseline: attested and consistent
        original_read, original_write, original_record = r.read_bytes(), w.read_bytes(), st.read_bytes()

        def restore():
            r.write_bytes(original_read)
            w.write_bytes(original_write)
            st.write_bytes(original_record)

        mutations = (
            ("read client missing", lambda: r.unlink(), "read-only OAuth client file"),
            ("read client malformed", lambda: r.write_text("{not json"), "read-only OAuth client file"),
            ("read client unrecognized id", lambda: r.write_text(json.dumps(read_client_config(client_id="123-abc.apps.googleusercontent.com"))), "recognized Google format"),
            ("read client replaced", lambda: r.write_text(json.dumps(read_client_config(client_id="500000000005-replsynth05.apps.googleusercontent.com"))), "changed since"),
            ("read client now in the write project", lambda: r.write_text(json.dumps(read_client_config(client_id="200000000002-movedsynth07.apps.googleusercontent.com"))), "same Google Cloud project"),
            ("write client missing", lambda: w.unlink(), "not found"),
            ("write client malformed", lambda: w.write_text("[]"), "Desktop app"),
            ("write client swapped after setup", lambda: w.write_text(json.dumps(write_client_config(client_id="600000000006-swapsynth06.apps.googleusercontent.com"))), "changed since"),
            ("write client moved to the read project", lambda: w.write_text(json.dumps(write_client_config(client_id=SAME_PROJECT_ID))), "same Google Cloud project"),
            ("write token endpoint changed", lambda: w.write_text(json.dumps(write_client_config(token_uri="https://attacker.example.invalid/token"))), "not Google's"),
            ("attestation missing", lambda: st.unlink(), "never attested"),
            ("attestation corrupt", lambda: st.write_text("{broken"), "never attested"),
            ("attestation empty object", lambda: st.write_text("{}"), "changed since"),
            ("attestation flag false", lambda: st.write_text(json.dumps(dict(json.loads(original_record), attested_separate_project=False))), "changed since"),
            ("attestation for other fingerprints", lambda: st.write_text(json.dumps(dict(json.loads(original_record), write_client_fp="0" * 64))), "changed since"),
        )
        for label, mutate, pattern in mutations:
            restore()
            mutate()
            with self.assertRaisesRegex(oauth.AuthError, pattern, msg=label) as ctx:
                oauth_write.verify_isolation(w, r, st)
            for private in ("100000000001", "200000000002", C_SEC, "synth0", "synth"):
                self.assertNotIn(private, str(ctx.exception), label)
        restore()
        w.write_text(json.dumps(write_client_config(client_secret="ROTATED-SYNTH")))  # the attestation binds client IDENTITY: a rotated secret is not a new client
        oauth_write.verify_isolation(w, r, st)
        restore()
        oauth_write.verify_isolation(w, r, st)

    def test_login_fails_closed_before_any_flow_when_isolation_is_not_verified(self):
        self.write_client_file()
        for label, mutate in (("no read client", lambda: config.client_secret_path().unlink()),
                              ("changed write client", lambda: config.write_client_secret_path().write_text(json.dumps(write_client_config(client_id=OTHER_CLIENT_ID)))),
                              ("no attestation", lambda: config.write_setup_path().unlink())):
            self.write_client_file()
            mutate()
            self.backend.touched.clear()
            text = self.broken_login_must_not_start()
            self.assertNotIn("100000000001", text)
            self.assertNotIn(("gmail-intelligence-write", "oauth-token:gmail.modify"), self.touched_by_login, label)  # the write item is not even read

    def test_attestation_missing_blocks_login_but_a_valid_setup_does_not(self):
        self.write_client_file(attest=False)
        self.broken_login_must_not_start()
        self.write_client_file()
        with mock.patch.object(oauth_write, "run_login_write", return_value=(WCreds(), [oauth_write.WRITE_SCOPE])), \
                mock.patch.object(gmail_write, "fetch_profile_email", return_value=ACCOUNT):
            code, _, _ = self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, "--no-browser", stdin=oauth_write.LOGIN_PHRASE)
        self.assertEqual(code, 0)
        self.assertIsNotNone(self.wstore.load())

    def test_revoke_write_and_cleanup_refuse_to_revoke_without_verified_separation(self):
        blob = self.write_blob()
        self.write_client_file()
        config.write_setup_path().unlink()  # separation can no longer be verified
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoked")):
            code, _, err = self.run_cli("auth", "revoke-write", "--yes")
            self.assertEqual(code, 1)
            self.assertIn("never attested", err)
            self.assertEqual(self.wstore.load(), blob)  # the local token stays
            text = cli._discard_new_grant(self.wstore, oauth_write.IssuedToken(R_TOK, A_TOK))
        self.assertIn("revocation was NOT attempted", text)
        self.assertIn("could affect the read-only authorization", text)
        self.assertIn("Google consent may still exist", text)

    def test_status_write_reports_the_attestation_and_a_failure(self):
        self.write_client_file()
        self.write_blob()
        code, out, _ = self.run_cli("auth", "status-write")
        self.assertEqual(code, 0)
        self.assertIn("attestation", out)
        config.write_client_secret_path().write_text(json.dumps(write_client_config(client_id=SAME_PROJECT_ID)))
        code, out, _ = self.run_cli("auth", "status-write")
        self.assertEqual(code, 1)
        self.assertIn("project separation", out)
        self.assertNotIn("100000000001", out)

    def test_logout_write_needs_no_isolation_because_it_never_contacts_google(self):
        self.write_blob()
        with mock.patch.object(oauth_write, "revoke_refresh_token", side_effect=AssertionError("revoked")):
            self.assertEqual(self.run_cli("auth", "logout-write", "--yes")[0], 0)
        self.assertIsNone(self.wstore.load())

    def test_the_read_only_client_and_token_are_never_modified_by_any_write_operation(self):
        self.write_client_file()
        self.stored_blob()
        read_file, read_items = config.client_secret_path().read_bytes(), {k: v for k, v in self.backend.items.items() if k[0] == keystore.SERVICE}
        for argv in (("auth", "status-write"), ("auth", "setup-write"), ("auth", "logout-write", "--yes")):
            self.run_cli(*argv)
        with mock.patch.object(oauth_write, "run_login_write", side_effect=oauth.AuthError("denied")):
            self.run_cli("auth", "login-write", "--expect-account", ACCOUNT, stdin=oauth_write.LOGIN_PHRASE)
        self.assertEqual(config.client_secret_path().read_bytes(), read_file)
        self.assertEqual({k: v for k, v in self.backend.items.items() if k[0] == keystore.SERVICE}, read_items)


class NoCrossoverTests(WBase):
    """Ordinary commands must never touch the write item, the write client file or an authorization flow."""

    def test_read_commands_never_access_the_write_keychain_item_or_start_any_flow(self):
        self.write_client()
        self.stored_blob()
        self.write_blob()
        self.backend.touched.clear()
        bombs = [mock.patch.object(oauth_write, n, side_effect=AssertionError(n)) for n in
                 ("run_login_write", "refresh_write_credentials", "revoke_refresh_token", "blob_to_write_credentials")]
        bombs += [mock.patch.object(cli, "_write_store", side_effect=AssertionError("write store")),
                  mock.patch.object(keystore_write.WriteTokenStore, "__init__", side_effect=AssertionError("write store"))]
        for b in bombs:
            b.start()
            self.addCleanup(b.stop)
        from test_auth import FakeReader

        from gmail_intelligence import gmail
        with mock.patch.object(gmail, "build_reader", return_value=FakeReader()):
            for argv in (("version",), ("doctor",), ("auth", "setup"), ("auth", "status"), ("gmail", "check"), ("auth", "logout", "--yes")):
                self.run_cli(*argv)
        self.assertNotIn(keystore_write.SERVICE_WRITE, {s for s, _ in self.backend.touched})
        self.assertIsNotNone(self.wstore._backend.items.get((keystore_write.SERVICE_WRITE, keystore_write.ITEM_WRITE)))

    def test_the_write_client_file_is_a_different_path_and_never_the_read_client(self):
        self.assertNotEqual(config.write_client_secret_path(), config.client_secret_path())
        self.assertEqual(config.write_client_secret_path().name, "client_secret_write.json")


if __name__ == "__main__":
    unittest.main()
