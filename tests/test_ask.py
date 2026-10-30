"""M11A: deterministic metadata question answering (issue #31): intents, parameters, unsupported/ambiguous/insufficient replies, source and freshness, masking, read-only, no network.
Synthetic data only: no Gmail, no Keychain, no model."""
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

from m5_support import ACCT, M5Base, mail  # noqa: E402
from test_cleanup import NOW as NOW_MS  # noqa: E402

from gmail_intelligence import ask, cli  # noqa: E402

NOW = datetime.fromtimestamp(NOW_MS / 1000, timezone.utc)
MARK = "leakmarker-9913"
PROMO = ["INBOX", "CATEGORY_PROMOTIONS"]


class Base(M5Base):
    def setUp(self):
        super().setUp()
        rows = []
        for i in range(1, 13):
            rows.append(mail(i, PROMO, sender=f"{MARK}@promo.example.test", days=i * 9, unread=i % 3 != 0))
        for i in range(13, 19):
            rows.append(mail(i, ["INBOX"], sender="noreply@news.example.test", days=(i - 12) * 20, unread=False))
        for i in range(19, 22):
            rows.append(mail(i, ["INBOX", "CATEGORY_PERSONAL"], sender="friend@friends.example.test", days=i, unread=True))
        self.fixture([], rows)
        self.db = Path(self.index.path)

    def ask(self, q, **kw):
        return ask.answer(self.index, ACCT, q, now=NOW, **kw)


class IntentTests(Base):
    def test_every_supported_intent_answers_with_source_period_and_freshness(self):
        for q, intent in (("How many messages do I have?", "TOTAL_MESSAGES"), ("How many messages per month in the last 6 months?", "MESSAGES_OVER_TIME"),
                          ("Which senders email me most?", "TOP_SENDERS"), ("How many unread messages do I have?", "UNREAD"),
                          ("What categories of mail do I get?", "CATEGORIES"), ("How many subscriptions should I review?", "SUBSCRIPTIONS")):
            r = self.ask(q)
            self.assertEqual((r["status"], r["intent"], r["read_only"]), ("ANSWERED", intent, True), q)
            self.assertEqual(set(r["source"]), {"index", "function", "aggregate"})
            self.assertTrue(r["reference_period"] and r["freshness"]["snapshot_not_live"], q)
            self.assertEqual(set(r["freshness"]), {"as_of", "age_days", "index_state", "health", "issues", "snapshot_not_live"})

    def test_figures_match_the_underlying_reports(self):
        self.assertEqual(self.ask("How many messages do I have?")["observations"][0], {"fact": "messages_indexed", "value": 21})
        r = self.ask("top 2 sender domains")
        self.assertEqual([(o["sender"], o["messages"]) for o in r["observations"]], [("promo.example.test", 12), ("news.example.test", 6)])
        self.assertEqual(r["parameters"], {"by": "domain", "top": 2})
        v = self.ask("messages per month, last 3 months")
        self.assertEqual(v["parameters"], {"months": 3})
        self.assertLessEqual(len(v["observations"]), 3)
        u = self.ask("How many unread messages do I have?")
        self.assertEqual(u["observations"][0]["value"], 8 + 3)

    def test_observations_and_heuristic_conclusions_are_kept_apart(self):
        c = self.ask("what categories of mail do I get")
        self.assertTrue(c["heuristics"] and "inference" in c["summary"])
        s = self.ask("how many subscriptions should I review")
        self.assertIn("heuristic", s["summary"])
        self.assertEqual({h["conclusion"] for h in s["heuristics"]}, {"worth_reviewing_by_hand", "ruled_out_by_protection_or_dormancy", "not_enough_evidence", "weak"})
        self.assertTrue(all("fact" in o for o in s["observations"]))
        u = self.ask("what is the unread trend over the last 12 months")
        self.assertTrue(all(h["conclusion"] == "unread_direction" for h in u["heuristics"]))


class RefusalTests(Base):
    def test_unsupported_ambiguous_and_out_of_range_get_fixed_replies(self):
        for q in ("What does my boss's email say?", "delete all newsletters", "hello", "'; DROP TABLE messages; --", "SELECT * FROM messages", "unsubscribe from everything", "mark all unread messages as read"):
            r = self.ask(q)
            self.assertEqual((r["status"], r["summary"]), ("UNSUPPORTED", ask.FIXED["UNSUPPORTED"]), q)
        self.assertEqual(self.ask("which senders have the most unread")["status"], "AMBIGUOUS")
        for q in ("last 0 months", "messages per month in the last 999 months", "top 99 senders"):
            r = self.ask(q)
            self.assertEqual((r["status"], r["summary"]), ("UNSUPPORTED", ask.FIXED["PARAMETER"]), q)

    def test_the_question_is_never_echoed_or_executed(self):
        q = f"which senders email me most {MARK} <script>alert(1)</script> {{{{7*7}}}} __import__('os')"
        res = self.ask(q)
        text = ask.as_json({k: v for k, v in res.items() if k not in ("freshness", "reference_time")})  # the timestamps are real clock values and may contain "49" by chance
        for bad in (MARK, "<script>", "49", "__import__"):
            self.assertNotIn(bad, text)
        for bad in ("", "  ", "x" * 301, None, 5):
            with self.assertRaises(ask.ParameterError):
                self.ask(bad)


class InsufficientEvidenceTests(M5Base):
    def ask(self, q):
        return ask.answer(self.index, ACCT, q, now=NOW)

    def test_an_empty_index_is_insufficient_evidence(self):
        r = self.ask("which senders email me most")
        self.assertEqual((r["status"], r["summary"], r["observations"]), ("INSUFFICIENT_EVIDENCE", ask.FIXED["EMPTY_INDEX"], []))

    def test_missing_classification_is_insufficient_evidence(self):
        self.fixture([], [mail(i, ["INBOX"], sender="a@b.example.test", days=i) for i in range(1, 5)], classify=False)
        r = self.ask("what categories do I get")
        self.assertEqual((r["status"], r["summary"]), ("INSUFFICIENT_EVIDENCE", ask.FIXED["NO_CLASSIFICATION"]))


class PrivacyAndStabilityTests(Base):
    def test_addresses_are_masked_unless_revealed_and_nothing_else_leaks(self):
        masked = ask.as_json(self.ask("top sender addresses"))
        self.assertNotIn(MARK, masked)
        self.assertIn("(addresses masked)", self.ask("top sender addresses")["summary"])
        self.assertIn(MARK, ask.as_json(self.ask("top sender addresses", reveal_senders=True)))
        for q in ("top sender addresses", "how many messages", "unread trend", "subscriptions", "categories"):
            out = ask.as_json(self.ask(q)) + ask.render_text(self.ask(q))
            self.assertNotRegex(out, r"https?://|mailto:|\bm[0-9]+\b|mail\.google")

    def test_results_are_stable(self):
        for q in ("which senders email me most", "unread trend over the last 12 months", "what categories do I get"):
            self.assertEqual(ask.as_json(self.ask(q)), ask.as_json(self.ask(q)))


class CommandAndSafetyTests(Base):
    def run_cmd(self, *argv):
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = NOW
        with mock.patch.object(ask, "datetime", fake):
            return self.run_cli("mailbox", "ask", "--account", ACCT, *argv)

    def test_text_and_json_output(self):
        code, out, err = self.run_cmd("--json", "Which senders email me most?")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), json.loads(ask.as_json(self.ask("Which senders email me most?"))))
        code, text, err = self.run_cmd("Which senders email me most?")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("source:", text)
        self.assertIn("freshness:", text)

    def test_read_only_no_network_and_fixed_errors(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        names = sorted(os.listdir(self.db.parent))
        for q in ("how many messages", "unread trend", "delete everything"):
            self.assertEqual(self.run_cmd(q)[::2], (0, ""))
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(self.db.parent)), names)
        self.assertEqual(self.run_cmd("x" * 301), (1, "", "error: the question must be 1 to 300 characters\n"))
        with mock.patch.object(ask, "answer", side_effect=ValueError("stored: " + MARK)):
            self.assertEqual(self.run_cmd("how many messages"), (1, "", "error: " + cli._REPORT_UNEXPECTED + "\n"))

    def test_the_module_cannot_reach_the_network_run_code_or_write(self):
        src = (ROOT / "src" / "gmail_intelligence" / "ask.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bimport (socket|urllib|http|smtplib|requests|subprocess|webbrowser|os|sqlite3)\b|https?://|mailto:|\b(eval|exec|compile)\(|_q\(|INSERT|UPDATE |DELETE |CREATE |SELECT ", src))
        self.assertEqual(set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.M)), {"json", "re", "datetime", "gmail_intelligence"})


if __name__ == "__main__":
    unittest.main()
