"""M6 final security pass: adversarial, synthetic, real local HTTP. Complements test_dashboard_server.py (which covers the baseline rules)."""
import hashlib
import http.client
import io
import json
import socket
import sqlite3
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, M5Base, label, mail  # noqa: E402
from test_analytics import fixture_messages  # noqa: E402
from test_dashboard_server import TOKEN, ServerBase, _loopback_only  # noqa: E402

from gmail_intelligence import analytics, dashboard_server as ds, index as idx  # noqa: E402
from leak_support import isolate_known_leaks  # noqa: E402


def raw(server, data, read=65536):
    """Send raw bytes to the server and return the response text (status line and headers) - for requests http.client would refuse to build."""
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect(("127.0.0.1", server.port))
        s.sendall(data)
        chunks = b""
        while True:
            part = s.recv(read)
            if not part:
                break
            chunks += part
            if b"\r\n\r\n" in chunks and len(chunks) > 200:
                break
        return chunks.decode("latin-1")
    except (ConnectionResetError, socket.timeout):
        return ""
    finally:
        s.close()


def status_of(text):
    return int(text.split(" ", 2)[1]) if text.startswith("HTTP/") else 0


class AdversarialRequestTests(ServerBase):
    def req(self, line, headers=(), body=b""):
        host = f"Host: 127.0.0.1:{self.server.port}\r\n"
        extra = "".join(h + "\r\n" for h in headers)
        return raw(self.server, (line + "\r\n" + host + extra + "\r\n").encode("latin-1") + body)

    def auth(self):
        return f"Authorization: Bearer {TOKEN}"

    def test_oversized_request_line_and_headers_are_refused(self):
        self.assertIn(status_of(self.req("GET /" + "a" * 70000 + " HTTP/1.1")), (414, 400, 0))
        self.assertIn(status_of(self.req("GET /api/v1/meta HTTP/1.1", [self.auth()] + [f"X-{i}: v" for i in range(200)])), (431, 400, 0))
        self.assertIn(status_of(self.req("GET /api/v1/meta HTTP/1.1", [self.auth(), "X-Big: " + "b" * 70000])), (431, 400, 0))

    def test_ambiguous_framing_is_refused(self):
        for headers in (["Content-Length: 5", "Transfer-Encoding: chunked"], ["Transfer-Encoding: chunked"], ["Content-Length: 3"]):
            text = self.req("GET /api/v1/overview HTTP/1.1", [self.auth()] + headers, b"abc")
            self.assertEqual(status_of(text), 400, headers)

    def test_other_request_line_shapes(self):
        for line, ok in (("GET http://evil.example/api/v1/meta HTTP/1.1", (400,)), ("GET //evil.example/api/v1/meta HTTP/1.1", (400, 404)), ("GET api/v1/meta HTTP/1.1", (400,)),
                         ("GET /api/v1/meta%00 HTTP/1.1", (400, 404)), ("GET /api/v1/\xff\xfe HTTP/1.1", (400, 404)), ("GET /api/v1/meta\\..\\x HTTP/1.1", (400,)),
                         ("GET * HTTP/1.1", (400,)), ("GET /api/v1/meta HTTP/9.9", (505, 400)), ("GET /api/v1/meta", (200, 400, 421, 0))):
            text = self.req(line, [self.auth()])
            self.assertIn(status_of(text), ok + (0,), line)

    def test_http10_without_host_is_refused(self):
        text = raw(self.server, b"GET /api/v1/meta HTTP/1.0\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\n\r\n")
        self.assertEqual(status_of(text), 421)

    def test_authorization_edge_cases(self):
        for header in ("Authorization: Bearer  " + TOKEN, "Authorization: BEARER " + TOKEN, "Authorization: bearer " + TOKEN):
            self.assertEqual(status_of(self.req("GET /api/v1/meta HTTP/1.1", [header])), 200, header)
        for header in ("Authorization: Bearer\t" + TOKEN, "Authorization: Bearer " + TOKEN[:-1], "Authorization: Bearer " + TOKEN + "é", "Authorization: Token " + TOKEN, "Authorization: Bearer", "Authorization:"):
            self.assertEqual(status_of(self.req("GET /api/v1/meta HTTP/1.1", [header])), 401, header)
        two = self.req("GET /api/v1/meta HTTP/1.1", ["Authorization: Bearer wrong", self.auth()])
        self.assertIn(status_of(two), (200, 401))  # one of the two is a valid token; the server must pick deterministically, never crash

    def test_unauthenticated_requests_cannot_enumerate_routes_or_probe_parameters(self):
        for path in ("/api/v1/overview", "/api/v1/nope", "/api/v1/senders?kind=bogus", "/api/v1/../../etc/passwd", "/api/v1/"):
            text = self.req(f"GET {path} HTTP/1.1")
            self.assertIn(status_of(text), (401, 400), path)  # never 404/200: nothing reveals whether a route or parameter exists
        for method in ("GET", "HEAD"):
            self.assertEqual(status_of(self.req(f"{method} /api/v1/overview HTTP/1.1")), 401)

    def test_pipelined_requests_after_an_error_are_not_served(self):
        host = f"Host: 127.0.0.1:{self.server.port}\r\n"
        first = f"GET /api/v1/overview HTTP/1.1\r\n{host}\r\n"  # 401 closes the connection
        second = f"GET /api/v1/meta HTTP/1.1\r\n{host}Authorization: Bearer {TOKEN}\r\n\r\n"
        text = raw(self.server, (first + second).encode())
        self.assertEqual(text.count("HTTP/1.1 "), 1)
        self.assertNotIn('"api_version"', text)

    def test_slow_clients_cannot_block_others(self):
        stalled = []
        for _ in range(8):
            s = socket.socket()
            s.connect(("127.0.0.1", self.server.port))
            s.sendall(b"GET /api/v1/meta HTTP/1.1\r\nHost: 127.0.0.1")  # never finished
            stalled.append(s)
        try:
            self.assertEqual(self.api("meta")[0], 200)
        finally:
            for s in stalled:
                s.close()

    def test_non_ascii_and_control_characters_in_headers(self):
        for header in ("Host: 127.0.0.1:%d\x00" % self.server.port, "Origin: http://127.0.0.1:%d\x07" % self.server.port, "Authorization: Bearer " + TOKEN + "\x0b"):
            text = raw(self.server, f"GET /api/v1/meta HTTP/1.1\r\nHost: 127.0.0.1:{self.server.port}\r\n{header}\r\nAuthorization: Bearer {TOKEN}\r\n\r\n".encode("latin-1"))
            self.assertIn(status_of(text), (200, 400, 403, 421, 401, 0))

    def test_ascii_digit_queries_only(self):
        from urllib.parse import quote
        for value in (chr(0x663), chr(0xb2), chr(0xff15), "5 ", "+5", "5.0", "0x5", "-1", chr(0x661) + chr(0x660)):
            self.assertEqual(self.api("senders?limit=" + quote(value))[0], 400, repr(value))
        self.assertEqual(self.api("senders?limit=5")[0], 200)


class TokenLifecycleTests(M5Base):
    def test_every_launch_has_a_fresh_unguessable_token_that_is_printed_once(self):
        self.fixture([label("Label_1", "x")], fixture_messages())
        seen = []
        for _ in range(3):
            out = io.StringIO()
            with mock.patch.object(ds.DashboardServer, "serve_forever", side_effect=KeyboardInterrupt), redirect_stdout(out), redirect_stderr(io.StringIO()):
                ds.serve(self.index.path, ACCT, port=0)
            tokens = [t for t in out.getvalue().replace("#t=", " ").split() if len(t) >= 40 and t.replace("-", "").replace("_", "").isalnum()]
            self.assertEqual(len(tokens), 1)
            seen.append(tokens[0])
        self.assertEqual(len(set(seen)), 3)
        self.assertTrue(all(len(t) >= 43 for t in seen))  # 256 bits
        self.assertNotIn("http://127.0.0.1:0", out.getvalue())

    def test_the_old_token_stops_working_with_the_server_and_a_new_server_rejects_it(self):
        self.fixture([label("Label_1", "x")], fixture_messages())
        guard = mock.patch.object(socket.socket, "connect", _loopback_only)
        guard.start()
        self.addCleanup(guard.stop)
        first = ds.DashboardServer(self.index.path, ACCT, "token-one-" + "a" * 30)
        t1 = threading.Thread(target=first.serve_forever, daemon=True)
        t1.start()
        second = ds.DashboardServer(self.index.path, ACCT, "token-two-" + "b" * 30)
        t2 = threading.Thread(target=second.serve_forever, daemon=True)
        t2.start()
        self.addCleanup(lambda: [(s.shutdown(), s.server_close()) for s in (first, second)])
        def call(server, token):
            c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            c.request("GET", "/api/v1/meta", headers={"Host": f"127.0.0.1:{server.port}", "Authorization": "Bearer " + token})
            r = c.getresponse()
            r.read()
            c.close()
            return r.status
        self.assertEqual(call(first, "token-one-" + "a" * 30), 200)
        self.assertEqual(call(second, "token-one-" + "a" * 30), 401)  # a token from another launch never works
        self.assertEqual(call(second, "token-two-" + "b" * 30), 200)

    def test_the_token_never_appears_in_any_response_or_log(self):
        self.fixture([label("Label_1", "x")], fixture_messages())
        guard = mock.patch.object(socket.socket, "connect", _loopback_only)
        guard.start()
        self.addCleanup(guard.stop)
        server = ds.DashboardServer(self.index.path, ACCT, TOKEN, verbose=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))
        out, err = io.StringIO(), io.StringIO()
        blob = ""
        with redirect_stdout(out), redirect_stderr(err):
            for path in ("/", "/index.html", "/api/v1/meta", "/api/v1/overview", "/api/v1/senders?kind=address", "/api/v1/nope", "/missing"):
                c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
                c.request("GET", path, headers={"Host": f"127.0.0.1:{server.port}", "Authorization": "Bearer " + TOKEN, "Referer": f"http://127.0.0.1:{server.port}/#t={TOKEN}"})
                r = c.getresponse()
                blob += str(r.getheaders()) + r.read().decode("utf-8", "replace")
                c.close()
        self.assertNotIn(TOKEN, blob + out.getvalue() + err.getvalue())


class ConcurrencyAndIsolationTests(ServerBase):
    def digest(self):
        return hashlib.sha256(Path(self.index.path).read_bytes()).hexdigest()

    def test_many_concurrent_requests_agree_and_change_nothing(self):
        before = self.digest()
        routes = list(ds.ROUTES) + ["senders?kind=address&limit=5", "categories?by=month", "cleanup/history?recent=5"]
        results, errors = {}, []

        def worker(i):
            try:
                for route in routes:
                    status, _, body = self.api(route)
                    results.setdefault(route, []).append((status, json.dumps(body, sort_keys=True)))
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual(errors, [])
        for route, answers in results.items():
            self.assertEqual({a[0] for a in answers}, {200}, route)
            if route != "meta":
                self.assertEqual(len({a[1] for a in answers}), 1, route)  # identical for every concurrent caller
        self.assertEqual(self.digest(), before)

    def test_reads_survive_a_concurrent_writer_and_see_only_committed_data(self):
        writer_done = threading.Event()

        def write():
            writer = idx.Index(self.index.path)  # a SQLite connection belongs to one thread
            try:
                scan = writer.recent_scans(ACCT, 1)[0]["id"]
                for k in range(20):
                    writer.save_batch(ACCT, scan, [mail(7000 + k, ["INBOX"], sender="w@writer.example.test")])
            finally:
                writer.close()
                writer_done.set()
        t = threading.Thread(target=write)
        t.start()
        statuses = set()
        for _ in range(25):  # a bounded number of reads while the writer works (an unbounded loop would exhaust local TCP ports)
            statuses.add(self.api("overview")[0])
            if writer_done.is_set():
                break
        t.join()
        self.assertTrue(statuses <= {200, 503}, statuses)  # a busy database yields a clean 503, never a crash or a partial answer
        self.assertEqual(self.api("overview")[2]["data"]["messages"], 28 + 20)

    @isolate_known_leaks

    def test_a_locked_database_gives_a_safe_503(self):
        other = sqlite3.connect(self.index.path, timeout=0)
        other.execute("BEGIN EXCLUSIVE")  # a writer holding the database exclusively (for example a scan committing)
        try:
            status, _, body = self.api("overview")
        finally:
            other.rollback()
            other.close()
        self.assertEqual((status, body["error"]["code"]), (503, "INDEX_UNAVAILABLE"))
        self.assertNotIn(str(self.index.path), json.dumps(body))
        self.assertEqual(self.api("overview")[0], 200)  # and it recovers by itself once the lock is gone

    def test_the_cache_never_mixes_privacy_modes_or_parameters(self):
        masked = self.api("senders?kind=address&limit=3")[2]
        again = self.api("senders?kind=address&limit=3")[2]
        self.assertEqual(masked, again)
        self.assertNotIn("deals@promo.example.test", json.dumps(masked))
        other_limit = self.api("senders?kind=address&limit=1")[2]
        self.assertEqual(len(other_limit["data"]["items"]), 1)
        self.stop()
        self.start(reveal_senders=True)
        revealed = self.api("senders?kind=address&limit=3")[2]
        self.assertIn("deals@promo.example.test", json.dumps(revealed))
        self.stop()
        self.start()  # a fresh server (fresh cache) is masked again: nothing carries over between servers
        self.assertNotIn("deals@promo.example.test", json.dumps(self.api("senders?kind=address&limit=3")[2]))

    def test_the_cache_is_invalidated_when_the_database_changes_and_is_bounded(self):
        a = self.api("overview")[2]["data"]["messages"]
        self.fixture([], [mail(8000, ["INBOX"], sender="n@new.example.test")])
        self.assertEqual(self.api("overview")[2]["data"]["messages"], a + 1)
        for limit in range(1, 101):
            self.api(f"senders?kind=domain&limit={limit}")
        self.assertLessEqual(len(self.server._cache), 64)

    def test_private_data_is_not_in_error_bodies_headers_or_cache_keys_visible_to_clients(self):
        for path in ("/api/v1/nope", "/api/v1/senders?limit=x", "/missing"):
            status, headers, data = self.get(path)
            text = str(headers) + data.decode("utf-8", "replace")
            for secret in (ACCT, "deals@promo", str(self.index.path), TOKEN):
                self.assertNotIn(secret, text, path)


class HostileInputRenderingTests(ServerBase):
    def test_bidi_and_control_input_never_reaches_a_response_unsanitized(self):
        nasty = "evil‮⁦‏\x07\x1b[31m@bidi.example.test"
        self.fixture([label("Label_9", "name‮⁧\x00end")], [mail(9100 + i, ["INBOX"], sender=nasty) for i in range(4)])
        self.stop()
        self.start(reveal_senders=True, reveal_names=True)
        dump = "".join(json.dumps(self.api(r)[2], ensure_ascii=False) for r in ("senders?kind=address&limit=100", "senders?kind=domain&limit=100", "subscriptions", "organization"))
        for ch in ("‮", "⁦", "⁧", "‏", "\x07", "\x1b", "\x00"):
            self.assertNotIn(ch, dump)
        self.assertIn("bidi.example.test", dump)


class PrivilegeBoundaryTests(unittest.TestCase):
    def test_no_module_the_server_imports_can_reach_gmail_credentials_or_writes(self):
        import importlib
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); import gmail_intelligence.dashboard_server as m; " % str(ROOT / "src") +
                "bad=[n for n in sys.modules if n.split('.')[0] in ('google','googleapiclient','keyring','requests','httplib2') or n.startswith('gmail_intelligence.') and n.split('.')[1] in "
                "('gmail','oauth','oauth_write','keystore','keystore_write','gmail_write','gmail_write_policy','exec_live_mailbox','cleanup_exec','cleanup_executor','cleanup_undo','cleanup_canary','cleanup_live','scanner','cleanup_plans','label_plans')]; "
                "print(bad)")
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]")
        self.assertIsNotNone(importlib)

    def test_the_server_exposes_no_write_capable_handler_or_route(self):
        handler_methods = {n for n in dir(ds.Handler) if n.startswith("do_")}
        self.assertEqual(handler_methods, {"do_GET", "do_HEAD"})
        self.assertTrue(all(r in ds.ROUTES for r in ("meta", "overview")))
        src = (ROOT / "src" / "gmail_intelligence" / "dashboard_server.py").read_text()
        for word in ("do_POST", "do_PUT", "do_DELETE", "do_PATCH", "rfile.read", "cursor.execute(\"INSERT", "executescript"):
            self.assertNotIn(word, src)


if __name__ == "__main__":
    unittest.main()
