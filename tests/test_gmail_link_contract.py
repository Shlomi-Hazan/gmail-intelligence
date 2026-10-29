"""M8A-2: the inert Gmail link contract (issue #52). Pure synthetic tests: no Gmail, no Google, no network, no account of anyone.

In production the contract answers CONTRACT_UNVERIFIED for every input and yields no URL. The gates are exercised by overriding `CONTRACT_STATUS` inside a test only; nothing in the
CLI, the dashboard API or the dashboard UI uses the module, and none of them has a link flag, an href or a link button.
"""
import ast
import contextlib
import inspect
import io
import itertools
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from gmail_intelligence import gmail_link_contract as lc  # noqa: E402

ACCOUNT = "owner@example.test"
THREAD = "18c4f2a9b3d07e61"
UNVERIFIED = {"status": "UNAVAILABLE", "reason": "CONTRACT_UNVERIFIED"}


def verified():
    """Only a test may do this: the contract is VERIFIED for the duration of the block."""
    return mock.patch.object(lc, "CONTRACT_STATUS", "VERIFIED")


def link(**kw):
    kw.setdefault("index_account", ACCOUNT)
    kw.setdefault("confirmed_account", ACCOUNT)
    kw.setdefault("thread_id", THREAD)
    kw.setdefault("requested", True)
    return lc.build_link(**kw)


GARBAGE = (None, "", " ", 0, 1, -1, 1.5, True, False, b"abc", b"", [], [1], {}, {"a": 1}, (), object(), "A" * 5000, "\x00", "\n", "a@b.c/u/0", "%2F", "ünï@çödé.test",
           "<script>alert(1)</script>", "javascript:alert(1)", "../../etc/passwd", "u/0", THREAD, ACCOUNT)


class ProductionFailClosedTests(unittest.TestCase):
    def test_the_shipped_status_is_unverified(self):
        self.assertEqual(lc.CONTRACT_STATUS, "UNVERIFIED")

    def test_every_input_category_gets_the_same_fixed_answer_and_no_url(self):
        for index_account, confirmed, thread, requested, excluded, deleted in itertools.product(GARBAGE[:12] + (ACCOUNT, "x@y.z"), GARBAGE[:12] + (ACCOUNT,), GARBAGE[:12] + (THREAD,),
                                                                                                  (True, False, None, "yes"), (True, False, None), (True, False)):
            got = lc.build_link(index_account, confirmed, thread, requested=requested, excluded=excluded, deleted=deleted)
            self.assertEqual(got, UNVERIFIED)

    def test_a_fully_valid_request_is_still_unavailable_and_has_no_url(self):
        got = link()
        self.assertEqual(got, UNVERIFIED)
        self.assertEqual(set(got), {"status", "reason"})
        self.assertNotIn("href", got)
        self.assertNotRegex(json.dumps(got), r"https?:|google|mail/|#all")

    def test_hostile_inputs_neither_raise_nor_leak(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for value in GARBAGE:
                got = lc.build_link(value, value, value, requested=True, excluded=value, deleted=value)
                self.assertEqual(got, UNVERIFIED)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_any_status_other_than_exactly_verified_is_unverified(self):
        for status in ("UNVERIFIED", "unverified", "verified", "Verified", "", None, True, 1, "VERIFIED ", b"VERIFIED", "VERIFIED\n"):
            with mock.patch.object(lc, "CONTRACT_STATUS", status):
                self.assertEqual(link(), UNVERIFIED, repr(status))

    def test_the_answer_is_a_fresh_object_that_cannot_alter_later_answers(self):
        first = link()
        first["reason"] = "TAMPERED"
        first["href"] = "https://evil.example/"
        self.assertEqual(link(), UNVERIFIED)


class GateTests(unittest.TestCase):
    """The gates an enabled contract would apply; reachable only by overriding the constant in a test."""

    def reason(self, **kw):
        with verified():
            got = link(**kw)
        self.assertEqual(got["status"], "UNAVAILABLE", got)
        self.assertEqual(set(got), {"status", "reason"})
        self.assertIn(got["reason"], lc.REASONS)
        return got["reason"]

    def test_a_link_must_be_requested(self):
        for value in (False, None, 0, 1, "yes", "True"):
            self.assertEqual(self.reason(requested=value), "LINKS_DISABLED", value)

    def test_excluded_or_deleted_messages_never_get_a_link(self):
        for kw in ({"excluded": True}, {"deleted": True}, {"excluded": True, "deleted": True}, {"excluded": None}, {"deleted": 1}, {"excluded": "no"}):
            self.assertEqual(self.reason(**kw), "LINKS_DISABLED", kw)
        self.assertEqual(self.reason(excluded=True, thread_id="NOT HEX"), "LINKS_DISABLED")  # decided before anything else about the message is looked at

    def test_the_account_must_be_confirmed_and_equal_exactly(self):
        for confirmed in (None, "", "other@example.test", "OWNER@example.test", ACCOUNT + " ", " " + ACCOUNT, ACCOUNT.upper(), 5, b"owner@example.test", ["owner@example.test"]):
            self.assertEqual(self.reason(confirmed_account=confirmed), "ACCOUNT_NOT_CONFIRMED", repr(confirmed))
        for index_account in (None, "", 5, b"owner@example.test"):
            self.assertEqual(self.reason(index_account=index_account, confirmed_account=ACCOUNT), "ACCOUNT_NOT_CONFIRMED", repr(index_account))

    def test_an_unsafe_account_string_is_refused_even_when_confirmed(self):
        unsafe = ["a/b@example.test", "a@exa/mple.test", "a@example.test/u/0", "a?x=1@example.test", "a@example.test?x=1", "a#b@example.test", "a@example.test#all", "a%2fb@example.test",
                  "a@example%2e.test", "a\\b@example.test", "a b@example.test", " a@example.test", "a@example.test ", "a\t@example.test", "a\n@example.test", "a\x00@example.test",
                  "a'b@example.test", 'a"b@example.test', "<a>@example.test", "a@exa mple.test", "a@@example.test", "a@example", "@example.test", "a@", "a", "a@.example.test",
                  "a@example..test", "a..b@example.test", ".a@example.test", "a.@example.test", "a@-example.test", "a@example-.test", "a@exa_mple.test", "Aa@example.test",
                  "a@Example.test", "ünï@example.test", "a@çödé.test", "a@example.test‮", "a@example.test​", "x" * 250 + "@example.test", "a:b@example.test", "a;b@example.test",
                  "a,b@example.test", "a(b)@example.test", "javascript:alert(1)@example.test"]
        for account in unsafe:
            self.assertEqual(self.reason(index_account=account, confirmed_account=account), "ACCOUNT_FORMAT_UNSAFE", repr(account))

    def test_a_missing_or_invalid_thread_id_is_refused(self):
        for thread in (None, ""):
            self.assertEqual(self.reason(thread_id=thread), "THREAD_ID_MISSING", repr(thread))
        invalid = ["ABC123", "18C4F2A9", "g1", "xyz", "12 34", " 1234", "1234 ", "12\n34", "1234\n", "../1234", "12/34", "12?34", "12#34", "12%34", "0x1f", "-1", "1.5", "١٢", "ａｂｃ",
                   "a" * 33, "<b>", "'; DROP", 12345, 1.5, True, b"abc123", ["abc"], ("abc",), {"a": "b"}]
        for thread in invalid:
            self.assertEqual(self.reason(thread_id=thread), "THREAD_ID_INVALID", repr(thread))

    def test_the_first_failing_gate_decides_in_a_fixed_order(self):
        self.assertEqual(self.reason(requested=False, excluded=True, confirmed_account="x", thread_id=None), "LINKS_DISABLED")
        self.assertEqual(self.reason(excluded=True, confirmed_account="x", thread_id=None), "LINKS_DISABLED")
        self.assertEqual(self.reason(confirmed_account="x@y.z", index_account="not an account", thread_id=None), "ACCOUNT_NOT_CONFIRMED")
        self.assertEqual(self.reason(index_account="bad account", confirmed_account="bad account", thread_id=None), "ACCOUNT_FORMAT_UNSAFE")
        self.assertEqual(self.reason(thread_id=None), "THREAD_ID_MISSING")
        self.assertEqual(self.reason(thread_id="ZZ"), "THREAD_ID_INVALID")

    def test_the_reason_vocabulary_is_closed_and_every_code_has_a_producer(self):
        produced = {"CONTRACT_UNVERIFIED": link()["reason"], "LINKS_NOT_IMPLEMENTED": lc.NOT_IMPLEMENTED["reason"], "LINKS_DISABLED": self.reason(requested=False),
                    "ACCOUNT_NOT_CONFIRMED": self.reason(confirmed_account=None), "ACCOUNT_FORMAT_UNSAFE": self.reason(index_account="a b", confirmed_account="a b"),
                    "THREAD_ID_MISSING": self.reason(thread_id=None), "THREAD_ID_INVALID": self.reason(thread_id="XYZ")}
        self.assertEqual(set(produced), set(lc.REASONS))
        self.assertTrue(all(code == reason for code, reason in produced.items()))
        self.assertEqual(len(set(lc.REASONS)), len(lc.REASONS))
        for reason in lc.REASONS:
            self.assertRegex(reason, r"^[A-Z_]+$")  # nothing but a fixed code can ever be returned

    def test_a_refusal_never_echoes_the_input(self):
        marker = "marker-secret-4417"
        with verified():
            for kw in ({"confirmed_account": marker}, {"index_account": marker, "confirmed_account": marker}, {"thread_id": marker}, {"thread_id": marker.upper()},
                       {"index_account": marker + "@example.test/u/0", "confirmed_account": marker + "@example.test/u/0"}):
                self.assertNotIn(marker, json.dumps(link(**kw)))


class EnabledOutputTests(unittest.TestCase):
    def test_the_only_link_is_the_fixed_template_filled_with_two_validated_values(self):
        with verified():
            got = link()
        self.assertEqual(got, {"status": "AVAILABLE", "reason": None, "href": f"https://mail.google.com/mail/u/{ACCOUNT}/#all/{THREAD}"})
        self.assertEqual(set(got), {"status", "reason", "href"})
        self.assertEqual(lc.HOST, "mail.google.com")
        self.assertEqual(lc.TEMPLATE, "https://mail.google.com/mail/u/{account}/#all/{thread}")

    def test_the_link_never_uses_a_positional_account_index(self):
        with verified():
            accounts = [ACCOUNT, "a.b+c-d_e@sub.example.test", "x1@googlemail.test"]
            hrefs = [link(index_account=a, confirmed_account=a, thread_id=t)["href"] for a in accounts for t in ("1", THREAD, "f" * 32)]
        for href in hrefs:
            self.assertIsNone(re.search(r"/u/\d", href), href)
            self.assertNotIn("authuser", href)
            self.assertRegex(href, r"^https://mail\.google\.com/mail/u/[a-z0-9._+@-]+/#all/[0-9a-f]{1,32}$")
            self.assertEqual(href.count("/u/"), 1)
        self.assertNotIn("/u/0", Path(lc.__file__).read_text(encoding="utf-8"))

    def test_the_template_has_exactly_two_slots_and_they_are_the_validated_values(self):
        self.assertEqual(sorted(re.findall(r"\{(\w+)\}", lc.TEMPLATE)), ["account", "thread"])

    def test_a_valid_thread_of_any_allowed_length_is_accepted(self):
        with verified():
            for n in (1, 2, 16, 31, 32):
                self.assertEqual(link(thread_id="a" * n)["status"], "AVAILABLE", n)
            self.assertEqual(link(thread_id="a" * 33)["reason"], "THREAD_ID_INVALID")

    def test_sender_controlled_text_has_no_way_in(self):
        parameters = list(inspect.signature(lc.build_link).parameters)
        self.assertEqual(parameters, ["index_account", "confirmed_account", "thread_id", "requested", "excluded", "deleted"])
        self.assertFalse([p for p in parameters if "sender" in p or "subject" in p or "name" in p or "label" in p or "domain" in p])
        with verified():
            self.assertNotIn("evil.example.test", link()["href"])

    def test_the_function_is_pure(self):
        before = (lc.CONTRACT_STATUS, lc.HOST, lc.TEMPLATE, lc.REASONS, dict(lc.NOT_IMPLEMENTED))
        with verified():
            [link() for _ in range(3)]
        self.assertEqual((lc.CONTRACT_STATUS, lc.HOST, lc.TEMPLATE, lc.REASONS, dict(lc.NOT_IMPLEMENTED)), before)


class DisconnectionTests(unittest.TestCase):
    def test_the_module_imports_only_re_and_nothing_of_the_project(self):
        tree = ast.parse(Path(lc.__file__).read_text(encoding="utf-8"))
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertEqual(imported, {"re"})
        code = "import sys; sys.path.insert(0, %r); import gmail_intelligence.gmail_link_contract; print(sorted(m for m in sys.modules if m.startswith('gmail_intelligence')))" % str(SRC)
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, "['gmail_intelligence', 'gmail_intelligence.gmail_link_contract']")

    def test_nothing_in_the_product_uses_the_contract(self):
        offenders = []
        for path in (ROOT / "src").rglob("*"):
            if path.is_file() and path.suffix in (".py", ".js", ".json", ".css", ".html") and path.name != "gmail_link_contract.py":
                text = path.read_text(encoding="utf-8")
                if re.search(r"link_contract|build_link", text):
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])
        for path in (ROOT / "scripts").rglob("*.py"):
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"link_contract|build_link")

    def test_no_interface_has_a_link_flag_an_href_or_a_link_button(self):
        cli_src = (SRC / "gmail_intelligence" / "cli.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"--(gmail-)?links?\b|--link-account|--accept-unverified|--open-in-gmail", cli_src))
        static = SRC / "gmail_intelligence" / "dashboard" / "static"
        for path in (static / "js").rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\bhref\b.*(mail\.google|gmail)", path.name)
            self.assertNotIn("mail.google", text, path.name)
        server = (SRC / "gmail_intelligence" / "dashboard_server.py").read_text(encoding="utf-8")
        self.assertNotIn("mail.google", server)

    def test_the_engine_and_the_interfaces_still_say_not_implemented(self):
        self.assertEqual(lc.NOT_IMPLEMENTED, {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"})
        source = (SRC / "gmail_intelligence" / "attention.py").read_text(encoding="utf-8")
        self.assertIn('"link": {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"}', source)
        self.assertNotIn("link_contract", source)

    def test_the_documentation_marks_every_gmail_url_behaviour_as_not_verified(self):
        doc = (ROOT / "docs" / "GMAIL-LINK-CONTRACT.md").read_text(encoding="utf-8")
        for needle in ("INERT", "UNVERIFIED", "NOT VERIFIED", "separate owner authorization", "CONTRACT_UNVERIFIED", "/u/0/"):
            self.assertIn(needle, doc, needle)
        for reason in lc.REASONS:
            self.assertIn(reason, doc, reason)
        self.assertGreaterEqual(doc.count("NOT VERIFIED"), 7)
        self.assertNotRegex(doc, r"(?i)\bis verified\b|\bwas verified\b|\bverified live\b")


if __name__ == "__main__":
    unittest.main()
