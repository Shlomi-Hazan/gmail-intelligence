"""Offline tests for OAuth, Keychain storage, the read-only Gmail adapter and the auth/gmail CLI.

No Google account, network, real credentials or real Keychain is used: all values are synthetic and
Google/Keychain interactions are replaced by small in-memory fakes. Requires the project venv
(`pip install -e .`) so the Google libraries can be imported.
"""
import contextlib
import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import httplib2  # noqa: E402
from google.auth.exceptions import RefreshError, TransportError  # noqa: E402
from google.oauth2.credentials import Credentials  # noqa: E402
from googleapiclient.errors import HttpError  # noqa: E402

from gmail_intelligence import cli, config, gmail, keystore, oauth  # noqa: E402

# Synthetic sentinels (short on purpose; none resembles a real credential).
A_TOK, R_TOK, C_SEC = "SYNTH-ACCESS-1", "SYNTH-REFRESH-1", "SYNTH-CLIENT-S1"
SENTINELS = (A_TOK, R_TOK, C_SEC, "SYNTH-CODE-1")
ACCOUNT = "tester@example.invalid"
SECRET_KEY = "client_" + "secret"


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)  # google-auth uses naive UTC


def client_config(kind="installed"):
    return {kind: {"client_id": "100000000001-readsynth01.apps.googleusercontent.com", SECRET_KEY: C_SEC,
                   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                   "token_uri": "https://oauth2.googleapis.com/token"}}


class FakeBackend:
    def __init__(self, fail=False):
        self.items, self.fail = {}, fail

    def set_password(self, service, user, value):
        if self.fail:
            raise RuntimeError("keychain locked " + value)  # message must never leak
        self.items[(service, user)] = value

    def get_password(self, service, user):
        if self.fail:
            raise RuntimeError("keychain locked")
        return self.items.get((service, user))

    def delete_password(self, service, user):
        if self.fail:
            raise RuntimeError("keychain locked")
        del self.items[(service, user)]


class FakeCreds:
    def __init__(self, scopes=(oauth.SCOPE,), refresh=R_TOK):
        self.token, self.refresh_token = A_TOK, refresh
        self.expiry, self.scopes = utcnow() + timedelta(hours=1), list(scopes)
        self.valid = True


class FakeFlow:
    def __init__(self, creds=None, scopes=(oauth.SCOPE,), raises=None):
        self.creds, self.raises, self.kwargs = creds or FakeCreds(), raises, None
        self.oauth2session = mock.Mock(token={"scope": list(scopes)})

    def run_local_server(self, **kwargs):
        self.kwargs = kwargs
        if self.raises:
            raise self.raises
        return self.creds


class FakeReader:
    def __init__(self, email=ACCOUNT):
        self.email = email

    def get_profile(self):
        return {"emailAddress": self.email, "messagesTotal": 12, "threadsTotal": 7, "historyId": "99"}

    def list_labels(self):
        return [{"id": "INBOX", "type": "system"}, {"id": "Label_1", "type": "user"}]


def http_error(status, body=b"{}"):
    return HttpError(httplib2.Response({"status": status}), body)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gi-auth-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        env = mock.patch.dict(os.environ, {config.HOME_ENV: self.tmp + "/home"})
        env.start()
        self.addCleanup(env.stop)
        self.backend = FakeBackend()
        self.store = keystore.TokenStore(self.backend)
        patch = mock.patch.object(cli, "_store", lambda: self.store)
        patch.start()
        self.addCleanup(patch.stop)
        # Any real network use during these tests is a failure.
        net = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used"))
        net.start()
        self.addCleanup(net.stop)

    def write_client(self, kind="installed"):
        config.ensure_app_dir()
        path = config.client_secret_path()
        path.write_text(json.dumps(client_config(kind)))
        os.chmod(path, 0o600)
        return path

    def stored_blob(self, **over):
        blob = {"account": ACCOUNT, "scopes": [oauth.SCOPE], "token": A_TOK, "refresh_token": R_TOK,
                "expiry": (utcnow() + timedelta(hours=1)).isoformat()}
        blob.update(over)
        self.store.save(blob)
        return blob

    def run_cli(self, *argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("builtins.input", return_value=stdin):
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        text = out.getvalue() + err.getvalue()
        for s in SENTINELS:
            self.assertNotIn(s, text, "secret leaked to output")
        return code, out.getvalue(), err.getvalue()


class OAuthTests(Base):
    def test_scope_is_exactly_readonly(self):
        self.assertEqual(oauth.SCOPE, "https://www.googleapis.com/auth/gmail.readonly")
        self.assertEqual(oauth.EXPECTED_SCOPES, {oauth.SCOPE})

    def test_rejects_broader_or_missing_scopes(self):
        oauth.check_granted_scopes([oauth.SCOPE])
        for bad in ([oauth.SCOPE, "https://www.googleapis.com/auth/gmail.modify"],
                    ["https://mail.google.com/"], [], None):
            with self.assertRaises(oauth.AuthError):
                oauth.check_granted_scopes(bad)

    def test_client_config_validation(self):
        good = self.write_client()
        self.assertIn("installed", oauth.load_client_config(good))
        web = Path(self.tmp) / "web.json"
        web.write_text(json.dumps(client_config("web")))
        with self.assertRaisesRegex(oauth.AuthError, "Desktop app"):
            oauth.load_client_config(web)
        bad = Path(self.tmp) / "bad.json"
        bad.write_text("{not json")
        for path in (bad, Path(self.tmp) / "missing.json"):
            with self.assertRaises(oauth.AuthError):
                oauth.load_client_config(path)
        cfg = client_config()
        cfg["installed"]["client_id"] = "nope"
        bad.write_text(json.dumps(cfg))
        with self.assertRaises(oauth.AuthError):
            oauth.load_client_config(bad)
        del cfg["installed"][SECRET_KEY]
        bad.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(oauth.AuthError, "missing"):
            oauth.load_client_config(bad)

    def test_login_success_requests_only_readonly_scope_without_accumulation(self):
        path = self.write_client()
        flow = FakeFlow()
        seen = {}

        def factory(cfg, scopes):
            seen["scopes"] = scopes
            return flow

        creds, granted = oauth.run_login(path, flow_factory=factory, open_browser=False)
        self.assertEqual(seen["scopes"], [oauth.SCOPE])
        self.assertEqual(granted, [oauth.SCOPE])
        self.assertEqual(flow.kwargs["host"], "127.0.0.1")
        self.assertNotIn("include_granted_scopes", flow.kwargs)
        self.assertEqual(flow.kwargs["access_type"], "offline")

    def test_real_flow_uses_pkce_and_exact_scope(self):
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow = InstalledAppFlow.from_client_config(client_config(), scopes=[oauth.SCOPE])
        url, _ = flow.authorization_url(access_type="offline", prompt="consent")
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("code_challenge=", url)
        self.assertNotIn("include_granted_scopes", url)
        self.assertRegex(url, r"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly(&|$)")

    def test_login_rejects_unexpected_broader_grant(self):
        path = self.write_client()
        flow = FakeFlow(scopes=(oauth.SCOPE, "https://www.googleapis.com/auth/gmail.modify"))
        with self.assertRaisesRegex(oauth.AuthError, "unexpected OAuth scopes"):
            oauth.run_login(path, flow_factory=lambda c, s: flow, open_browser=False)

    def test_login_rejects_scope_change_warning(self):
        path = self.write_client()
        flow = FakeFlow(raises=Warning("Scope has changed"))
        with self.assertRaisesRegex(oauth.AuthError, "different scopes"):
            oauth.run_login(path, flow_factory=lambda c, s: flow, open_browser=False)

    def test_login_cancellation(self):
        path = self.write_client()
        exc = Exception("denied")
        exc.error = "access_denied"
        with self.assertRaisesRegex(oauth.AuthError, "cancelled or denied"):
            oauth.run_login(path, flow_factory=lambda c, s: FakeFlow(raises=exc), open_browser=False)

    def test_login_without_refresh_token_is_rejected(self):
        path = self.write_client()
        flow = FakeFlow(creds=FakeCreds(refresh=None))
        with self.assertRaisesRegex(oauth.AuthError, "refresh token"):
            oauth.run_login(path, flow_factory=lambda c, s: flow, open_browser=False)

    def _creds(self, expired=True):
        exp = utcnow() + (timedelta(minutes=-5) if expired else timedelta(hours=1))
        blob = {"scopes": [oauth.SCOPE], "token": A_TOK, "refresh_token": R_TOK, "expiry": exp.isoformat()}
        return oauth.blob_to_credentials(blob, client_config())

    def test_blob_roundtrip_and_scope_check(self):
        creds = self._creds(expired=False)
        blob = oauth.credentials_to_blob(creds, ACCOUNT, [oauth.SCOPE])
        self.assertNotIn(C_SEC, json.dumps(blob))  # client secret is never stored in the token blob
        with self.assertRaises(oauth.AuthError):
            oauth.blob_to_credentials(dict(blob, scopes=[oauth.SCOPE, "https://mail.google.com/"]), client_config())

    def test_refresh_success_and_not_needed(self):
        fresh = self._creds(expired=False)
        self.assertFalse(oauth.refresh_credentials(fresh, request=object()))
        stale = self._creds(expired=True)

        def fake_refresh(self_, request):
            self_.token, self_.expiry = "SYNTH-ACCESS-2", utcnow() + timedelta(hours=1)

        with mock.patch.object(Credentials, "refresh", fake_refresh):
            self.assertTrue(oauth.refresh_credentials(stale, request=object()))
        self.assertTrue(stale.valid)

    def test_refresh_failures_are_clear_and_safe(self):
        for err, pattern in ((RefreshError("invalid_grant: Token has been expired or revoked."), "expired or revoked"),
                             (RefreshError("weird"), "could not refresh"),
                             (TransportError("offline"), "network error")):
            with mock.patch.object(Credentials, "refresh", side_effect=err):
                with self.assertRaisesRegex(oauth.AuthError, pattern):
                    oauth.refresh_credentials(self._creds(), request=object())


class KeystoreTests(Base):
    def test_roundtrip_missing_and_delete_only_own_item(self):
        self.assertIsNone(self.store.load())
        self.assertFalse(self.store.delete())
        self.backend.items[("other-app", "other")] = "keep"
        self.store.save({"a": 1})
        self.assertEqual(self.store.load(), {"a": 1})
        self.assertTrue(self.store.delete())
        self.assertIsNone(self.store.load())
        self.assertEqual(self.backend.items, {("other-app", "other"): "keep"})

    def test_backend_failures_wrapped_without_leaking(self):
        store = keystore.TokenStore(FakeBackend(fail=True))
        with self.assertRaises(keystore.KeystoreError) as ctx:
            store.save({"token": A_TOK})
        self.assertNotIn(A_TOK, str(ctx.exception))
        with self.assertRaises(keystore.KeystoreError):
            store.load()

    def test_corrupt_item(self):
        self.backend.items[(keystore.SERVICE, keystore.ITEM)] = "{broken"
        with self.assertRaisesRegex(keystore.KeystoreError, "corrupt"):
            self.store.load()

    def test_default_backend_refuses_non_macos_keychain(self):
        import keyring
        from keyring.backends import fail

        with mock.patch.object(keyring, "get_keyring", return_value=fail.Keyring()):
            with self.assertRaisesRegex(keystore.KeystoreError, "no plaintext fallback"):
                keystore.TokenStore()


class GmailAdapterTests(Base):
    def service_returning(self, data=None, error=None):
        req = mock.Mock()
        if error:
            req.execute.side_effect = error
        else:
            req.execute.return_value = data
        svc = mock.MagicMock()
        svc.users.return_value.getProfile.return_value = req
        svc.users.return_value.labels.return_value.list.return_value = req
        return svc, req

    def test_profile_and_labels(self):
        svc, req = self.service_returning({"emailAddress": ACCOUNT, "messagesTotal": 3, "threadsTotal": 2,
                                           "historyId": "5", "extra": "dropped",
                                           "labels": [{"id": "INBOX", "name": "Private Name", "type": "system"}]})
        reader = gmail.GmailReader(svc)
        self.assertEqual(reader.get_profile()["emailAddress"], ACCOUNT)
        self.assertNotIn("extra", reader.get_profile())
        self.assertEqual(reader.list_labels(), [{"id": "INBOX", "type": "system"}])  # names are not exposed
        req.execute.assert_called_with(num_retries=3)

    def test_error_translation(self):
        cases = ((401, b"{}", gmail.GmailAuthError), (403, b'{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}',
                                                        gmail.GmailRateLimitError),
                 (429, b"{}", gmail.GmailRateLimitError), (403, b"{}", gmail.GmailAuthError),
                 (500, b"{}", gmail.GmailApiError))
        for status, body, exc_type in cases:
            svc, _ = self.service_returning(error=http_error(status, body))
            with self.assertRaises(exc_type) as ctx:
                gmail.GmailReader(svc).get_profile()
            self.assertIs(type(ctx.exception), exc_type)

    def test_network_error(self):
        svc, _ = self.service_returning(error=OSError("down"))
        with self.assertRaisesRegex(gmail.GmailApiError, "network"):
            gmail.GmailReader(svc).get_profile()

    def test_only_read_methods_are_exposed(self):
        public = {n for n in dir(gmail.GmailReader) if not n.startswith("_") and callable(getattr(gmail.GmailReader, n))}
        self.assertEqual(public, {"get_profile", "list_labels", "list_label_details", "list_message_ids",
                                  "get_message_metadata"})
        for banned in ("send", "modify", "batchModify", "trash", "delete", "insert", "import_", "drafts"):
            self.assertFalse(hasattr(gmail.GmailReader, banned), banned)

    def test_source_has_no_write_or_content_api_calls_and_no_broader_scopes(self):
        text = (SRC / "gmail_intelligence" / "gmail.py").read_text()
        self.assertIsNone(re.search(r"\.(send|modify|batchModify|trash|untrash|delete|batchDelete|insert|import_|"
                                    r"drafts|settings|attachments|threads|history)\(", text))
        # the only message calls allowed are read-only list/get
        self.assertEqual(set(re.findall(r"\.messages\(\)\.(\w+)\(", text)), {"list", "get"})
        self.assertEqual(set(re.findall(r"\.labels\(\)\.(\w+)\(", text)), {"list"})
        for path in (SRC / "gmail_intelligence").glob("*.py"):
            src = path.read_text()
            for scope in ("gmail.modify", "gmail.send", "gmail.settings", "mail.google.com", "gmail.compose"):
                if scope == "gmail.modify" and path.name == "oauth_write.py":
                    continue  # M4C-B1: the single module that defines the write scope (see test_write_boundary)
                self.assertNotIn(scope, src, f"{path.name} mentions {scope}")


class CliTests(Base):
    def test_status_without_anything(self):
        code, out, _ = self.run_cli("auth", "status")
        self.assertEqual(code, 1)
        self.assertIn("none stored", out)
        self.assertIn("not verified with Google", out)

    def test_status_ready_is_local_only(self):
        self.write_client()
        self.stored_blob()
        code, out, _ = self.run_cli("auth", "status")  # socket.connect is patched to fail
        self.assertEqual(code, 0)
        self.assertIn(ACCOUNT, out)

    def test_status_flags_wrong_scope_and_storage_failure(self):
        self.write_client()
        self.stored_blob(scopes=[oauth.SCOPE, "https://mail.google.com/"])
        self.assertEqual(self.run_cli("auth", "status")[0], 1)
        self.store = keystore.TokenStore(FakeBackend(fail=True))
        code, out, _ = self.run_cli("auth", "status")
        self.assertEqual(code, 1)
        self.assertIn("token storage", out)

    def test_setup_import_validates_and_restricts_permissions(self):
        src = Path(self.tmp) / "dl.json"
        src.write_text(json.dumps(client_config()))
        code, out, _ = self.run_cli("auth", "setup", "--import", str(src))
        self.assertEqual(code, 0, out)
        self.assertEqual(stat.S_IMODE(os.stat(config.client_secret_path()).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(config.app_dir()).st_mode), 0o700)
        src.write_text(json.dumps(client_config("web")))
        self.assertEqual(self.run_cli("auth", "setup", "--import", str(src))[0], 1)
        code, out, _ = self.run_cli("auth", "setup")
        self.assertEqual(code, 0)
        self.assertIn(oauth.SCOPE, out)

    def _login(self, *argv, creds=None, stdin="y", error=None, email=ACCOUNT):
        self.write_client()
        patches = [mock.patch.object(oauth, "run_login", side_effect=error) if error else
                   mock.patch.object(oauth, "run_login", return_value=(creds or FakeCreds(), [oauth.SCOPE])),
                   mock.patch.object(gmail, "build_reader", return_value=FakeReader(email))]
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return self.run_cli("auth", "login", *argv, stdin=stdin)

    def test_login_confirms_and_stores(self):
        code, out, _ = self._login()
        self.assertEqual(code, 0, out)
        self.assertIn(ACCOUNT, out)
        self.assertEqual(self.store.load()["scopes"], [oauth.SCOPE])
        self.assertEqual(self.store.load()["account"], ACCOUNT)

    def test_login_declined_stores_nothing(self):
        self.assertEqual(self._login(stdin="n")[0], 1)
        self.assertIsNone(self.store.load())

    def test_login_expect_account_mismatch_and_match(self):
        self.assertEqual(self._login("--expect-account", "other@example.invalid")[0], 1)
        self.assertIsNone(self.store.load())
        self.assertEqual(self._login("--expect-account", ACCOUNT.upper(), stdin="n")[0], 0)
        self.assertIsNotNone(self.store.load())

    def test_login_failure_and_missing_client(self):
        code, _, err = self._login(error=oauth.AuthError("authorization was cancelled or denied in the browser"))
        self.assertEqual(code, 1)
        self.assertIn("cancelled", err)
        os.remove(config.client_secret_path())
        self.assertEqual(self.run_cli("auth", "login")[0], 1)

    def test_login_keychain_failure(self):
        self.store = keystore.TokenStore(FakeBackend(fail=True))
        code, _, err = self._login()
        self.assertEqual(code, 1)
        self.assertIn("Keychain", err)

    def test_logout_confirmation_and_scope(self):
        self.backend.items[("other-app", "x")] = "keep"
        self.stored_blob()
        self.assertEqual(self.run_cli("auth", "logout", stdin="n")[0], 1)
        self.assertIsNotNone(self.store.load())
        code, out, _ = self.run_cli("auth", "logout", stdin="y")
        self.assertEqual(code, 0)
        self.assertIn("does not revoke", out)
        self.assertIsNone(self.store.load())
        self.assertEqual(self.backend.items, {("other-app", "x"): "keep"})
        self.assertEqual(self.run_cli("auth", "logout", "--yes")[0], 0)  # nothing left: still success

    def _check(self, **blob_over):
        self.write_client()
        self.stored_blob(**blob_over)
        with mock.patch.object(gmail, "build_reader", return_value=FakeReader()):
            return self.run_cli("gmail", "check")

    def test_check_success_prints_only_counts(self):
        code, out, _ = self._check()
        self.assertEqual(code, 0, out)
        self.assertIn("messages: 12", out)
        self.assertIn("labels: 2", out)

    def test_check_requires_login(self):
        self.write_client()
        self.assertEqual(self.run_cli("gmail", "check")[0], 1)

    def test_check_refreshes_and_persists_new_token(self):
        def fake_refresh(self_, request):
            self_.token, self_.expiry = "SYNTH-ACCESS-2", utcnow() + timedelta(hours=1)

        stale = (utcnow() - timedelta(minutes=5)).isoformat()
        with mock.patch.object(Credentials, "refresh", fake_refresh):
            code, _, _ = self._check(expiry=stale)
        self.assertEqual(code, 0)
        self.assertEqual(self.store.load()["token"], "SYNTH-ACCESS-2")

    def test_check_refresh_failure_and_api_failures(self):
        stale = (utcnow() - timedelta(minutes=5)).isoformat()
        with mock.patch.object(Credentials, "refresh", side_effect=RefreshError("invalid_grant")):
            code, _, err = self._check(expiry=stale)
        self.assertEqual(code, 1)
        self.assertIn("auth login", err)
        self.write_client()
        self.stored_blob()
        for exc in (gmail.GmailAuthError("rejected"), gmail.GmailRateLimitError("slow down")):
            reader = mock.Mock(get_profile=mock.Mock(side_effect=exc))
            with mock.patch.object(gmail, "build_reader", return_value=reader):
                self.assertEqual(self.run_cli("gmail", "check")[0], 1)

    def test_check_account_mismatch(self):
        self.write_client()
        self.stored_blob(account="someone-else@example.invalid")
        with mock.patch.object(gmail, "build_reader", return_value=FakeReader()):
            code, _, err = self.run_cli("gmail", "check")
        self.assertEqual(code, 1)
        self.assertIn("differs", err)

    def test_invalid_subcommands_exit_2(self):
        for argv in (("auth",), ("auth", "nope"), ("gmail",), ("gmail", "send")):
            self.assertEqual(self.run_cli(*argv)[0], 2, argv)


if __name__ == "__main__":
    unittest.main()
