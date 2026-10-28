"""M6B: the local read-only dashboard server (issue #18). Real HTTP requests to a loopback server on a synthetic index; no Gmail, no Keychain, no external network."""
import ast
import hashlib
import http.client
import json
import socket
import sys
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, M5Base, label, mail  # noqa: E402
from test_analytics import fixture_messages  # noqa: E402

from gmail_intelligence import analytics, dashboard_server as ds, index as idx  # noqa: E402

_REAL_CONNECT = socket.socket.connect  # captured before any test guard replaces it
TOKEN = "t0ken-for-tests-only-0123456789abcdefghij"
EVIL = "http://evil.example"


def _loopback_only(sock, address):
    if isinstance(address, tuple) and address[0] in ("127.0.0.1", "localhost"):
        return _REAL_CONNECT(sock, address)
    raise AssertionError("network used")


class ServerBase(M5Base):
    def setUp(self):
        super().setUp()
        self.fixture([label("Label_1", "PrivateLabelName")], fixture_messages())
        self.start()

    def start(self, **kw):
        # the socket guard of the base class blocks outgoing connects; the test client talks to 127.0.0.1 only, so allow exactly that
        guard = mock.patch.object(socket.socket, "connect", _loopback_only)
        guard.start()
        self.addCleanup(guard.stop)
        self.server = ds.DashboardServer(self.index.path, ACCT, TOKEN, **kw)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def get(self, path, headers=None, method="GET", host=True, token=True, body=None):
        h = {} if headers is None else dict(headers)
        if host is True:
            h.setdefault("Host", f"127.0.0.1:{self.server.port}")
        elif host:
            h["Host"] = host
        if token is True:
            h.setdefault("Authorization", "Bearer " + TOKEN)
        elif token:
            h["Authorization"] = token
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items():
                conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            r = conn.getresponse()
            data = r.read()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        finally:
            conn.close()

    def api(self, route, **kw):
        status, headers, data = self.get("/api/v1/" + route, **kw)
        return status, headers, (json.loads(data) if data and headers.get("content-type", "").startswith("application/json") else data)


class BindingTests(ServerBase):
    def test_binds_to_loopback_only_on_a_free_port(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertGreater(self.server.port, 0)
        self.assertEqual(self.server.socket.getsockname()[0], "127.0.0.1")

    def test_there_is_no_host_option(self):
        import inspect
        self.assertNotIn("host", inspect.signature(ds.DashboardServer.__init__).parameters)
        self.assertNotIn("host", inspect.signature(ds.serve).parameters)
        from gmail_intelligence import cli
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["dashboard", "serve", "--host", "0.0.0.0"])

    def test_port_is_validated(self):
        for bad in (-1, 70000, "80", True):
            with self.assertRaises(ValueError):
                ds.DashboardServer(self.index.path, ACCT, TOKEN, port=bad)

    def test_the_url_carries_the_token_only_in_the_fragment(self):
        url = self.server.url()
        self.assertTrue(url.startswith(f"http://127.0.0.1:{self.server.port}/#t="))
        self.assertEqual(self.server.url(False), f"http://127.0.0.1:{self.server.port}/")


class AuthTests(ServerBase):
    def test_a_valid_token_is_accepted(self):
        status, _, body = self.api("overview")
        self.assertEqual((status, body["section"]), (200, "overview"))
        self.assertEqual(body["data"]["messages"], 28)

    def test_missing_wrong_and_malformed_tokens_are_refused(self):
        for token in (False, "Bearer wrong", "Bearer ", "Bearer", "Basic " + TOKEN, TOKEN, "Bearer " + TOKEN + "x", "bearer\t" + TOKEN):
            status, headers, body = self.api("overview", token=token)
            self.assertEqual(status, 401, token)
            self.assertEqual(body["error"]["code"], "UNAUTHORIZED")
            self.assertEqual(headers["www-authenticate"], "Bearer")
            self.assertNotIn(TOKEN, json.dumps(body))

    def test_the_token_is_compared_in_constant_time(self):
        src = (ROOT / "src" / "gmail_intelligence" / "dashboard_server.py").read_text()
        self.assertIn("hmac.compare_digest", src)

    def test_a_query_string_token_does_not_authenticate(self):
        status, _, _ = self.api("overview?token=" + TOKEN, token=False)
        self.assertEqual(status, 401)

    def test_static_files_need_no_token_but_contain_no_data(self):
        status, _, body = self.get("/", token=False)
        self.assertEqual(status, 200)
        self.assertNotIn(b"messages", body.lower().replace(b"<!doctype", b""))


class HostAndOriginTests(ServerBase):
    def test_host_must_match_exactly(self):
        port = self.server.port
        self.assertEqual(self.get("/api/v1/meta", host=f"localhost:{port}")[0], 200)
        for host in ("evil.example", f"evil.example:{port}", "127.0.0.1", "localhost", f"127.0.0.1:{port + 1}", f"127.0.0.1:{port}.evil.example", f"[::1]:{port}", f"0.0.0.0:{port}", ""):
            status, _, body = self.api("meta", host=host or None) if host else self.api("meta", host=False)
            self.assertIn(status, (421, 400), host)
        status, _, _ = self.get("/", host=f"evil.example:{port}", token=False)
        self.assertEqual(status, 421)  # the page itself is refused too, so a rebound name never loads the UI

    def test_dns_rebinding_with_a_valid_token_is_still_refused(self):
        status, _, body = self.api("overview", host=f"attacker.example:{self.server.port}")
        self.assertEqual(status, 421)
        self.assertNotIn("data", body)

    def test_duplicate_host_headers_are_refused(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=5)
        conn.putrequest("GET", "/api/v1/meta", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.server.port}")
        conn.putheader("Host", "evil.example")
        conn.putheader("Authorization", "Bearer " + TOKEN)
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 421)
        conn.close()

    def test_foreign_origins_are_refused_even_with_the_token(self):
        for origin in (EVIL, "null", "http://127.0.0.1", f"https://127.0.0.1:{self.server.port}", f"http://127.0.0.1:{self.server.port + 1}", f"http://127.0.0.1:{self.server.port}.evil.example"):
            status, _, _ = self.api("overview", headers={"Origin": origin})
            self.assertEqual(status, 403, origin)

    def test_the_servers_own_origin_and_a_missing_origin_are_allowed(self):
        own = f"http://127.0.0.1:{self.server.port}"
        self.assertEqual(self.api("meta", headers={"Origin": own})[0], 200)
        self.assertEqual(self.api("meta")[0], 200)  # ordinary same-origin GETs may omit Origin; the token is the gate

    def test_fetch_metadata(self):
        for site in ("cross-site", "same-site"):
            self.assertEqual(self.api("meta", headers={"Sec-Fetch-Site": site})[0], 403, site)
        self.assertEqual(self.api("meta", headers={"Sec-Fetch-Site": "same-origin"})[0], 200)
        self.assertEqual(self.api("meta", headers={"Sec-Fetch-Site": "none"})[0], 403)  # typing an API URL is not an app request
        self.assertEqual(self.api("meta", headers={"Sec-Fetch-Mode": "navigate"})[0], 403)
        self.assertEqual(self.get("/", headers={"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}, token=False)[0], 200)  # the first page load is a navigation
        self.assertEqual(self.get("/", headers={"Sec-Fetch-Site": "cross-site"}, token=False)[0], 403)

    def test_a_foreign_page_cannot_read_a_protected_response(self):
        # simulate every request a script on another site could make: no CORS header is ever sent, a preflight is refused, and the token cannot be guessed
        for kw in (dict(headers={"Origin": EVIL, "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"}, token=False),
                   dict(headers={"Origin": EVIL, "Sec-Fetch-Site": "cross-site"}), dict(headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"}, token=False)):
            status, headers, data = self.get("/api/v1/senders?kind=address", **kw)
            self.assertIn(status, (401, 403))
            self.assertFalse([h for h in headers if h.startswith("access-control-")])
            self.assertNotIn(b"example.test", data)
        status, headers, _ = self.get("/api/v1/overview", method="OPTIONS", headers={"Origin": EVIL, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}, token=False)
        self.assertEqual(status, 405)
        self.assertFalse([h for h in headers if h.startswith("access-control-")])

    def test_no_response_ever_carries_cors_headers(self):
        for path in ("/", "/api/v1/meta", "/api/v1/nope", "/missing.js"):
            for kw in ({}, {"headers": {"Origin": f"http://127.0.0.1:{self.server.port}"}}):
                _, headers, _ = self.get(path, **kw)
                self.assertFalse([h for h in headers if h.startswith("access-control-")], path)


class MethodAndRequestTests(ServerBase):
    def test_mutating_and_other_methods_are_refused(self):
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "FOO"):
            for path in ("/api/v1/overview", "/", "/api/v1/cleanup/history"):
                status, headers, body = self.get(path, method=method)
                self.assertEqual(status, 405, (method, path))
                self.assertEqual(headers.get("allow"), "GET, HEAD")
        self.assertEqual(self.get("/api/v1/overview", method="POST", body=b'{"x":1}')[0], 405)

    def test_head_matches_get_without_a_body(self):
        g = self.get("/api/v1/overview")
        h = self.get("/api/v1/overview", method="HEAD")
        self.assertEqual((h[0], h[1]["content-length"], h[2]), (200, g[1]["content-length"], b""))
        self.assertEqual(self.get("/api/v1/overview", method="HEAD", token=False)[0], 401)

    def test_requests_with_a_body_are_refused(self):
        status, _, _ = self.get("/api/v1/overview", body=b"abc")
        self.assertEqual(status, 400)

    def test_queries_are_validated(self):
        self.assertEqual(self.api("senders?kind=address&limit=3")[2]["data"]["limit"], 3)
        for q in ("senders?kind=evil", "senders?limit=0", "senders?limit=101", "senders?limit=-1", "senders?limit=a", "senders?x=1", "senders?kind=domain&kind=address", "overview?x=1",
                  "categories?by=year", "senders?%00=1", "volume?limit=1", "senders?limit=5;DROP"):
            self.assertEqual(self.api(q)[0], 400, q)
        self.assertEqual(self.api("categories?by=month")[2]["data"]["by_month"][0]["period"], "2026-01")

    def test_unknown_routes_and_oddly_formed_paths(self):
        self.assertEqual(self.api("nope")[0], 404)
        self.assertEqual(self.api("")[0], 404)
        for path in ("/api/v1/../index.html", "/api/v1/%2e%2e/index.html", "//etc/passwd", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/static/../../server.py", "/api\\v1\\meta",
                     "http://evil.example/", "/index.html%00.js", "/./index.html", "/a//b"):
            status, _, data = self.get(path, token=True)
            self.assertIn(status, (400, 404, 421), path)
            self.assertNotIn(b"root:", data)


class StaticTests(ServerBase):
    def test_only_allowlisted_files_are_served(self):
        self.assertEqual(self.get("/", token=False)[0], 200)
        self.assertEqual(self.get("/index.html", token=False)[0], 200)
        for path in ("/dashboard_server.py", "/../dashboard_server.py", "/.env", "/index.html?x=1", "/index.sqlite3", "/js/", "/js"):
            self.assertEqual(self.get(path, token=False)[0] in (200,), False, path)

    def test_load_static_skips_symlinks_dotfiles_and_other_types(self):
        root = self.tmp / "static"
        (root / "js").mkdir(parents=True)
        (root / "index.html").write_text("<p>x</p>")
        (root / "js" / "a.js").write_text("1")
        (root / "notes.txt").write_text("no")
        (root / ".secret.js").write_text("no")
        outside = self.tmp / "outside.js"
        outside.write_text("secret")
        (root / "link.js").symlink_to(outside)
        (root / "dirlink").symlink_to(self.tmp)
        got = ds.load_static(root)
        self.assertEqual(sorted(got), ["/index.html", "/js/a.js"])

    def test_headers_on_every_response(self):
        for path, kw in (("/", dict(token=False)), ("/api/v1/overview", {}), ("/api/v1/nope", {}), ("/api/v1/overview", dict(token=False))):
            _, h, _ = self.get(path, **kw)
            self.assertIn("default-src 'none'", h["content-security-policy"])
            self.assertIn("script-src 'self'", h["content-security-policy"])
            self.assertNotIn("unsafe", h["content-security-policy"])
            self.assertNotIn("http", h["content-security-policy"].replace("http://", ""))
            self.assertEqual((h["x-content-type-options"], h["referrer-policy"], h["cache-control"], h["x-frame-options"]), ("nosniff", "no-referrer", "no-store", "DENY"))
            self.assertEqual(h["cross-origin-resource-policy"], "same-origin")
            self.assertNotIn("set-cookie", h)
        self.assertNotIn("python", self.get("/", token=False)[1].get("server", "").lower())


class ApiContractTests(ServerBase):
    def test_every_route_returns_the_envelope(self):
        for route in ds.ROUTES:
            status, h, body = self.api(route)
            self.assertEqual(status, 200, route)
            self.assertTrue(h["content-type"].startswith("application/json"))
            if route == "meta":
                self.assertEqual((body["read_only"], body["schema"], body["languages"]), (True, 7, ["en", "he"]))
                self.assertNotIn(ACCT, json.dumps(body))
            else:
                self.assertEqual(set(body), {"section", "data", "basis", "explain", "as_of", "index"}, route)

    def test_responses_match_the_library(self):
        ro = idx.ReadOnlyIndex(self.index.path)
        try:
            lib = analytics.Analytics(ro, ACCT, now=datetime.now(timezone.utc)).volume()
        finally:
            ro.close()
        api = self.api("volume")[2]
        self.assertEqual(api["data"], lib["data"])

    def test_the_account_and_private_names_never_appear(self):
        dump = "".join(json.dumps(self.api(r)[2]) for r in ds.ROUTES)
        self.assertNotIn(ACCT, dump)
        self.assertNotIn("PrivateLabelName", dump)
        self.assertNotIn("deals@promo", self.api("senders?kind=address")[2]["data"]["items"][0]["display"])

    def test_reveal_flags_are_server_side_choices(self):
        self.stop()
        self.start(reveal_senders=True, reveal_names=True)
        self.assertEqual(self.api("senders?kind=address")[2]["data"]["items"][0]["display"], "deals@promo.example.test")
        self.assertEqual(self.api("meta")[2]["reveal"], {"senders": True, "names": True})
        self.assertEqual(self.api("senders?kind=address&reveal=1")[0], 400)  # a client cannot ask for more than the launcher allowed

    def test_each_request_sees_the_current_database(self):
        before = self.api("overview")[2]["data"]["messages"]
        self.fixture([], [mail(5000, ["INBOX"], sender="late@new.example.test")])
        self.assertEqual(self.api("overview")[2]["data"]["messages"], before + 1)


class ReadOnlyAndFailureTests(ServerBase):
    def digest(self):
        return hashlib.sha256(Path(self.index.path).read_bytes()).hexdigest()

    def test_serving_every_route_does_not_change_the_database(self):
        before = self.digest()
        for route in ds.ROUTES:
            self.api(route)
        for _ in range(3):
            self.get("/api/v1/senders?kind=address&limit=5")
        self.assertEqual(self.digest(), before)

    def test_a_missing_or_old_index_gives_a_safe_503(self):
        self.server.db_path = str(self.tmp / "gone.sqlite3")
        status, _, body = self.api("overview")
        self.assertEqual((status, body["error"]["code"]), (503, "INDEX_UNAVAILABLE"))
        self.assertNotIn(str(self.tmp), json.dumps(body))
        old = self.tmp / "old.sqlite3"
        import sqlite3
        c = sqlite3.connect(old)
        c.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + idx.SCHEMA_V4 + idx.SCHEMA_V5 + "PRAGMA user_version = 5;COMMIT;")
        c.close()
        raw = old.read_bytes()
        self.server.db_path = str(old)
        self.assertEqual(self.api("overview")[0], 503)
        self.assertEqual(old.read_bytes(), raw)  # never migrated
        self.assertEqual(list(old.parent.glob("old.sqlite3.*")), [])

    def test_unexpected_errors_do_not_leak(self):
        with mock.patch.object(analytics.Analytics, "overview", side_effect=RuntimeError("secret detail /Users/x/path")):
            status, _, data = self.get("/api/v1/overview")
        self.assertEqual(status, 500)
        self.assertNotIn(b"secret", data)
        self.assertNotIn(b"/Users", data)

    def test_tokens_are_never_logged(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        self.server.verbose = True
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.api("overview")
            self.get("/api/v1/overview?x=" + TOKEN, token=False)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        self.assertNotIn("?", out.getvalue())

    def test_the_server_module_imports_no_gmail_or_credential_code(self):
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "exec_live_mailbox", "cleanup_exec", "cleanup_executor",
                     "cleanup_undo", "cleanup_canary", "cleanup_live", "cleanup_plans", "label_plans", "requests", "ssl", "keyring", "googleapiclient"}
        mods = set()
        for n in ast.walk(ast.parse((ROOT / "src" / "gmail_intelligence" / "dashboard_server.py").read_text())):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
        self.assertEqual(mods & forbidden, set())

    def test_no_handler_writes_to_the_database(self):
        src = (ROOT / "src" / "gmail_intelligence" / "dashboard_server.py").read_text()
        for word in ("INSERT", "UPDATE ", "DELETE", "DROP", "CREATE TABLE", "executescript", ".commit(", "audit.append"):
            self.assertNotIn(word, src)
        import re
        self.assertIsNone(re.search(r"(?<!ReadOnly)Index\(", src))  # only the read-only view is ever constructed
        self.assertIn("ReadOnlyIndex", src)


class AccountTests(M5Base):
    def test_account_detection_uses_only_the_index(self):
        self.fixture([label("Label_1", "A")], [mail(1, ["INBOX"])])
        self.assertEqual(ds.detect_account(self.index.path), ACCT)
        self.assertEqual(ds.detect_account(self.index.path, ACCT.upper()), ACCT)
        with self.assertRaises(ValueError):
            ds.detect_account(self.index.path, "other@example.invalid")
        self.fixture([], [mail(2, ["INBOX"])], account="second@example.invalid")
        with self.assertRaises(ValueError) as cm:
            ds.detect_account(self.index.path)
        self.assertIn("--account", str(cm.exception))

    def test_cli_refuses_without_touching_keychain_or_gmail(self):
        code, out, err = self.run_cli("dashboard", "serve", "--port", "80")
        self.assertEqual(code, 1)
        self.assertNotIn("Keychain", err)
        with mock.patch.object(ds, "serve", return_value=0) as served:
            self.fixture([label("Label_1", "A")], [mail(1, ["INBOX"])])
            code, _, _ = self.run_cli("dashboard", "serve")
        self.assertEqual(code, 0)
        self.assertEqual(served.call_args.args[1], ACCT)
        self.assertFalse(served.call_args.kwargs["reveal_senders"])


class SyntheticDemoTests(unittest.TestCase):
    """The synthetic demo index (invented domains, hostile strings) served end to end."""

    def setUp(self):
        import tempfile
        import dashboard_fixture as fx
        self.fx = fx
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "index.sqlite3"
        index = fx.build(self.path, messages=150)
        fx.add_history(index)
        index.close()

    def serve(self, **kw):
        guard = mock.patch.object(socket.socket, "connect", _loopback_only)
        guard.start()
        self.addCleanup(guard.stop)
        server = ds.DashboardServer(str(self.path), self.fx.ACCOUNT, TOKEN, **kw)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(5)))
        return server

    def fetch(self, server, route):
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        conn.request("GET", "/api/v1/" + route, headers={"Host": f"127.0.0.1:{server.port}", "Authorization": "Bearer " + TOKEN})
        r = conn.getresponse()
        body = r.read().decode("utf-8")
        conn.close()
        return r.status, body

    def test_every_route_works_on_the_demo_index_and_nothing_hostile_survives(self):
        server = self.serve(reveal_senders=True, reveal_names=True)
        dump = ""
        for route in ds.ROUTES:
            status, body = self.fetch(server, route + ("?kind=address&limit=50" if route == "senders" else ""))
            self.assertEqual(status, 200, route)
            dump += body
        for ch in ("\u202e", "\u2066", "\u200f", "\x00", "\x07"):
            self.assertNotIn(ch, dump.replace("\\u202e", ""))
        self.assertIn("evil.example.test", dump)  # the hostile sender is present, as inert text
        self.assertNotIn(self.fx.ACCOUNT, dump)

    def test_the_hostile_sender_and_label_are_masked_by_default(self):
        server = self.serve()
        _, senders = self.fetch(server, "senders?kind=address&limit=50")
        _, org = self.fetch(server, "organization")
        self.assertNotIn("onerror", senders)
        self.assertNotIn("<script>", org)
        self.assertNotIn("<img", senders)
        for item in json.loads(senders)["data"]["items"]:
            self.assertTrue(item["masked"] and item["key"] is None)


if __name__ == "__main__":
    unittest.main()
