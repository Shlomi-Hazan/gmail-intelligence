"""M8A-3: the Action Center on the local dashboard (issue #53): the `attention` route, its parity with `mailbox attention`, authentication, privacy, error states,
cursor behaviour, translations and the read-only guarantees. Real HTTP requests to a loopback server on a synthetic index; no Gmail, no Keychain, no external network."""
import ast
import hashlib
import json
import os
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_dashboard_server as TDS  # noqa: E402
from m5_support import ACCT, M5Base, label, mail  # noqa: E402
from test_analytics import fixture_messages  # noqa: E402

from gmail_intelligence import attention, dashboard_server as ds, index as idx  # noqa: E402

STATIC = ROOT / "src" / "gmail_intelligence" / "dashboard" / "static"
MARK = "leakmarker-5521"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def catalogs():
    return json.loads((STATIC / "i18n/en.json").read_text(encoding="utf-8")), json.loads((STATIC / "i18n/he.json").read_text(encoding="utf-8"))


class AttentionBase(TDS.ServerBase):
    def setUp(self):
        super(TDS.ServerBase, self).setUp()  # M5Base only: the server is started below, with a fixed clock
        self.fixture([label("Label_1", "PrivateLabelName")], fixture_messages())
        scan = self.index.recent_scans(ACCT, 1)[0]["id"]
        rows = [mail(9000 + k, ["INBOX", "STARRED"], sender=f"{MARK}{k}@vip{k % 3}.example.test", days=3 + k, thread=f"thr{9000 + k}", unread=(k % 2 == 0)) for k in range(30)]
        self.index.save_batch(ACCT, scan, rows)
        self.index.conn.commit()
        self.start(clock=lambda: NOW)

    def digest(self):
        return hashlib.sha256(Path(self.index.path).read_bytes()).hexdigest()

    def pages(self, query="limit=7&sender_limit=0"):
        out, cursor = [], None
        while True:
            status, _, body = self.api("attention?" + query + (f"&cursor={cursor}" if cursor else ""))
            self.assertEqual(status, 200, body)
            out.append(body)
            cursor = body["next_cursor"]
            if not cursor:
                return out


class ParityTests(AttentionBase):
    PARAMS = (("limit=25", {}), ("limit=10&sort=date&signal=starred&sender_limit=0", {"limit": 10, "sort": "date", "signals": ("starred",), "sender_limit": 0}),
              ("limit=5&sort=oldest&tier=medium&collapse=0&low=1", {"limit": 5, "sort": "oldest", "min_tier": "medium", "collapse": False, "include_low_score": True}))

    def library(self, **kw):
        ro = idx.ReadOnlyIndex(self.index.path)
        try:
            kw.setdefault("limit", 25)
            return json.loads(json.dumps(attention.compute(ro, ACCT, now=NOW, **kw)))
        finally:
            ro.close()

    def test_the_route_returns_exactly_what_the_library_returns(self):
        for query, kw in self.PARAMS:
            status, headers, body = self.api("attention?" + query)
            self.assertEqual(status, 200, query)
            self.assertTrue(headers["content-type"].startswith("application/json"))
            self.assertEqual(body, self.library(**kw), query)

    def test_the_route_and_the_command_line_agree(self):
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = NOW
        with mock.patch.object(attention, "datetime", fake), mock.patch.object(attention.config if hasattr(attention, "config") else ds.config, "index_path", return_value=Path(self.index.path)):
            for query, kw in self.PARAMS:
                argv = ["mailbox", "attention", "--account", ACCT, "--json", "--limit", str(kw.get("limit", 25)), "--sort", kw.get("sort", "priority"),
                        "--sender-limit", str(kw.get("sender_limit", 3))]
                for s in kw.get("signals", ()):
                    argv += ["--signal", s]
                if "min_tier" in kw:
                    argv += ["--min-tier", kw["min_tier"]]
                if kw.get("collapse") is False:
                    argv.append("--no-collapse")
                if kw.get("include_low_score"):
                    argv.append("--include-low-score")
                code, out, err = self.run_cli(*argv)
                self.assertEqual((code, err), (0, ""), argv)
                self.assertEqual(json.loads(out), self.api("attention?" + query)[2], query)

    def test_the_pages_together_are_the_whole_list(self):
        full = self.api("attention?limit=100&sender_limit=0")[2]["items"]
        items = [i for p in self.pages() for i in p["items"]]
        self.assertEqual(items, full)
        self.assertEqual([i["rank"] for i in items], list(range(1, len(items) + 1)))
        self.assertGreater(len(full), 25)

    def test_the_second_identical_request_is_served_equal_and_a_change_is_seen(self):
        first = self.api("attention?limit=5")[2]
        self.assertEqual(first, self.api("attention?limit=5")[2])
        scan = self.index.recent_scans(ACCT, 1)[0]["id"]
        self.index.save_batch(ACCT, scan, [mail(9900, ["INBOX", "STARRED"], sender="late@new.example.test", days=1)])
        self.assertNotEqual(first["snapshot"], self.api("attention?limit=5")[2]["snapshot"])


class AccessTests(AttentionBase):
    def test_no_token_and_a_wrong_token_are_refused(self):
        self.assertEqual(self.api("attention", token=False)[0], 401)
        self.assertEqual(self.get("/api/v1/attention", headers={"Authorization": "Bearer wrong"}, token=False)[0], 401)

    def test_only_get_and_head_work(self):
        self.assertEqual(self.get("/api/v1/attention", method="POST", body=b"{}")[0], 405)
        self.assertEqual(self.get("/api/v1/attention", method="HEAD")[0], 200)
        self.assertEqual(self.get("/api/v1/attention/extra")[0], 404)

    def test_every_parameter_is_validated_against_a_closed_set(self):
        good = self.api("attention?limit=3")[2]["next_cursor"]
        bad = ["limit=0", "limit=101", "limit=x", "limit=-1", "limit=1&limit=2", "sort=bogus", "signal=bogus", "tier=bogus", "sender_limit=11", "collapse=2", "low=yes",
               "unknown=1", "cursor=garbage", "cursor=" + "a" * 300, "cursor=" + good + "0", "cursor=" + good.upper(), "cursor=", "limit=%00", "sort=%0d%0a",
               "cursor=a1.20261021." + "0" * 64 + ".1.zz"]
        for query in bad:
            status, _, body = self.api("attention?" + query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": {"code": "BAD_REQUEST", "message": "the request is not valid"}}, query)

    def test_the_response_headers_are_the_dashboards_usual_ones(self):
        status, headers, _ = self.api("attention")
        self.assertEqual((headers["cache-control"], headers["x-content-type-options"], headers["referrer-policy"]), ("no-store", "nosniff", "no-referrer"))
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertNotIn("access-control-allow-origin", headers)


class ErrorStateTests(AttentionBase):
    def failure(self, query, status, code):
        got, _, body = self.api("attention?" + query)
        self.assertEqual(got, status, body)
        self.assertEqual(set(body), {"error"})
        self.assertEqual(body["error"]["code"], code)
        self.assertTrue(body["error"]["message"])
        self.assertNotIn(MARK, json.dumps(body))
        self.assertNotIn(ACCT, json.dumps(body))
        self.assertNotIn("items", body)  # never a partial result
        return body

    def test_a_changed_list_is_refused_with_no_items(self):
        cursor = self.api("attention?limit=5")[2]["next_cursor"]
        scan = self.index.recent_scans(ACCT, 1)[0]["id"]
        self.index.save_batch(ACCT, scan, [mail(9901, ["INBOX", "STARRED"], sender="late@new.example.test", days=1)])
        self.failure(f"limit=5&cursor={cursor}", 409, "SNAPSHOT_CHANGED")

    def test_other_parameters_with_an_old_cursor_are_also_a_changed_list(self):
        cursor = self.api("attention?limit=5")[2]["next_cursor"]
        self.failure(f"limit=5&sort=date&cursor={cursor}", 409, "SNAPSHOT_CHANGED")

    def test_a_tampered_position_is_an_invalid_cursor(self):
        cursor = self.api("attention?limit=5")[2]["next_cursor"]
        day, snap, n, key = cursor.split(".")[1:]
        self.failure(f"limit=5&cursor=a1.{day}.{snap}.{int(n) + 1}.{key}", 400, "CURSOR_INVALID")

    def test_a_list_too_large_to_compute_completely_is_refused(self):
        with mock.patch.object(attention, "RETAINED_THREAD_BUDGET", 3):
            self.failure("limit=5", 422, "RESULT_INCOMPLETE")

    def test_an_index_that_keeps_changing_is_refused(self):
        counter = iter(range(1000))
        with mock.patch.object(attention, "_data_version", lambda index: next(counter)):
            self.failure("limit=5", 503, "INDEX_CHANGED_DURING_READ")

    def test_an_unexpected_failure_is_the_generic_error_whatever_its_text(self):
        for exc in (RuntimeError(MARK), KeyError(MARK), ValueError("from the index: " + MARK), UnicodeDecodeError("utf-8", b"\xff", 0, 1, MARK)):
            with self.subTest(type(exc).__name__), mock.patch.object(attention, "_run", side_effect=exc):
                got, _, body = self.api("attention?limit=5")
                self.assertEqual((got, body), (500, {"error": {"code": "INTERNAL", "message": "an internal error occurred"}}))

    def test_a_missing_or_old_index_is_the_dashboards_usual_unavailable_error(self):
        os.remove(self.index.path)
        got, _, body = self.api("attention?limit=5")
        self.assertEqual((got, body["error"]["code"]), (503, "INDEX_UNAVAILABLE"))


class PrivacyAndReadOnlyTests(AttentionBase):
    def text(self, query="limit=100&sender_limit=0"):
        status, _, body = self.api("attention?" + query)
        self.assertEqual(status, 200)
        return json.dumps(body)

    def test_senders_are_masked_by_default_and_nothing_identifying_is_in_the_response(self):
        out = self.text()
        for needle in (MARK, ACCT, "9000", "thr9000", "http", "mail.google", "PrivateLabelName"):
            self.assertNotIn(needle, out, needle)
        body = json.loads(out)
        self.assertTrue(all(i["sender"]["masked"] for i in body["items"]))
        self.assertTrue(all(i["link"] == {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"} for i in body["items"]))
        self.assertTrue(all(MARK not in (i["sender"]["display"] or "") for i in body["items"]))

    def test_addresses_are_shown_only_when_the_server_was_started_to_reveal_them(self):
        self.stop()
        self.start(clock=lambda: NOW, reveal_senders=True)
        out = self.text()
        self.assertIn(MARK, out)
        for needle in (ACCT, "thr9000", "mail.google"):
            self.assertNotIn(needle, out)

    def test_a_request_never_writes_anything(self):
        before, names = self.digest(), sorted(os.listdir(Path(self.index.path).parent))
        for query in ("limit=25", "sort=date&signal=unread", "tier=high&low=1", "limit=7&collapse=0"):
            self.api("attention?" + query)
        self.pages()
        with mock.patch.object(attention, "RETAINED_THREAD_BUDGET", 3):
            self.api("attention")
        self.assertEqual(self.digest(), before)
        self.assertEqual(sorted(os.listdir(Path(self.index.path).parent)), names)

    def test_the_route_table_is_closed_and_the_server_imports_no_write_or_gmail_module(self):
        spec = ds.ROUTES["attention"][1]
        self.assertEqual(set(spec), {"limit", "sort", "signal", "tier", "sender_limit", "collapse", "low", "cursor"})
        self.assertEqual(set(spec["sort"]), {"priority", "date", "oldest"})
        src = (ROOT / "src" / "gmail_intelligence" / "dashboard_server.py").read_text(encoding="utf-8")
        for word in ("do_POST", "executescript", "rfile.read", "mail.google", "http://", "https://"):
            self.assertNotIn(word, src.replace("http://127.0.0.1", "").replace('"http://" + h', ""))


class FrontendTests(unittest.TestCase):
    JS = (STATIC / "js" / "attention.js").read_text(encoding="utf-8")

    def test_the_screen_is_registered_with_a_label_and_an_icon(self):
        en, he = catalogs()
        views = (STATIC / "js" / "views.js").read_text(encoding="utf-8")
        self.assertIn('{ id: "attention", icon: "attention", render: attentionScreen }', views)
        self.assertIn("attention:", (STATIC / "js" / "icons.js").read_text(encoding="utf-8"))
        for key in ("nav.attention", "nav.attention.short"):
            self.assertIn(key, en)
            self.assertIn(key, he)

    def test_the_script_is_text_only_link_free_and_action_free(self):
        for pattern in (r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", r"https?://", r"mail\.google", r"\bhref\b", r"window\.open|location\.", r"method:\s*[\"'](?!GET)"):
            self.assertIsNone(re.search(pattern, self.JS), pattern)
        self.assertIn("untrusted(who", self.JS)
        self.assertNotIn("POST", self.JS)

    def test_every_translation_key_the_screen_uses_exists_in_both_languages(self):
        en, he = catalogs()
        literal = set(re.findall(r"\bt\(\"([\w.]+)\"", self.JS)) | set(re.findall(r"(?:select|checkbox)\(\"([\w.]+)\"", self.JS)) | {k + ".other" for k in re.findall(r"\btn\(\"([\w.]+)\"", self.JS)}
        self.assertGreater(len(literal), 20)
        self.assertEqual(sorted(k for k in literal if k not in en or k not in he), [])
        for prefix, values in (("att.sort", ("priority", "date", "oldest")), ("att.signal", ("all", "starred", "important", "unread", "rule")), ("att.mintier", ("any", "low", "medium", "high"))):
            for v in values:
                self.assertIn(f"{prefix}.{v}", en)
                self.assertIn(f"{prefix}.{v}", he)

    def test_the_server_vocabularies_are_all_translated_in_both_languages(self):
        en, he = catalogs()
        tree = ast.parse((ROOT / "src" / "gmail_intelligence" / "attention.py").read_text(encoding="utf-8"))
        flags, warns = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                if node.func.attr == "add" and isinstance(node.func.value, ast.Name) and node.func.value.id == "flags":
                    flags.add(node.args[0].value)
                if node.func.attr == "append" and isinstance(node.func.value, ast.Name) and node.func.value.id == "warnings":
                    warns.add(node.args[0].value)
        penalties = {"PENALTY_" + name for name, _ in attention.DEFAULT_WEIGHTS.penalty}
        want = {"att.tier": {name for name, _ in attention.DEFAULT_WEIGHTS.tiers} | {"MINIMAL"}, "att.evidence": set(attention.EVIDENCE), "att.flag": flags, "att.warn": warns,
                "att.sig": {"STARRED", "USER_RULE", "GMAIL_IMPORTANT", "UNREAD", "PERSONAL_SENDER"} | penalties}
        self.assertTrue(flags and warns)
        for prefix, values in want.items():
            for v in values:
                self.assertIn(f"{prefix}.{v}", en, f"{prefix}.{v}")
                self.assertIn(f"{prefix}.{v}", he, f"{prefix}.{v}")
        self.assertIn("type.UNRECOGNISED", en)
        for failure in attention.ERRORS:
            self.assertIn(failure, self.JS)  # the screen has a state for every closed failure of the engine

    def test_hebrew_text_is_hebrew_and_english_text_is_not(self):
        en, he = catalogs()
        for key in (k for k in en if k.startswith(("att.", "nav.attention")) and re.search("[A-Za-z]", re.sub(r"\{\w+\}", "", en[k]))):  # a text with no words ("#{n}") is the same in both
            self.assertTrue(re.search("[֐-׿]", he[key]), key)
            self.assertFalse(re.search("[֐-׿]", en[key]), key)

    def test_the_layout_uses_logical_properties_only(self):
        css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
        block = css[css.index("/* Action Center (M8A-3) */"):]
        for physical in ("margin-left", "margin-right", "padding-left", "padding-right", "text-align: left", "text-align: right", "float:", "border-left", "border-right"):
            self.assertNotIn(physical, block)


if __name__ == "__main__":
    unittest.main()
