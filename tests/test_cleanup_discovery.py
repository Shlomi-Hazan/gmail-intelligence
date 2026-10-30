"""M12A: cleanup discovery (issue #59): grouping, counts, volume estimates, reasons, preservation of the M4A protections, conservative handling of uncertain mail, determinism, edge cases,
privacy, read-only operation and no network. Synthetic data only: no Gmail, no Keychain, no personal index."""
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

from m5_support import ACCT, M5Base  # noqa: E402
from test_cleanup import NOW as NOW_MS, msg  # noqa: E402

from gmail_intelligence import cleanup_candidates as cc, cleanup_discovery as disc, cleanup_protect, cli  # noqa: E402

NOW = datetime.fromtimestamp(NOW_MS / 1000, timezone.utc)
PROMO = ("INBOX", "CATEGORY_PROMOTIONS")
MARK = "leakmarker-3318"


def bulk(start, count, domain, labels=PROMO, days=200, size=1000, local=None):
    out = []
    for k in range(count):
        m = msg(start + k, days=days, sender=f"{local or MARK + str(k % 2)}@{domain}", labels=labels)
        m["size"] = size
        out.append(m)
    return out


class Base(M5Base):
    """big (8, one unsized) and mid (6) are eligible; tiny (2) is below the group size; the rest must never be reported as eligible."""

    def setUp(self):
        super().setUp()
        rows = bulk(1, 8, "big.example.test", size=2000) + bulk(20, 6, "mid.example.test", days=120, size=500) + bulk(40, 2, "tiny.example.test")
        rows[3]["size"] = None                                                                   # an unsized eligible message
        rows += bulk(60, 3, "starred.example.test", labels=PROMO + ("STARRED",))                  # hard protection
        rows += bulk(70, 4, "unread.example.test", labels=PROMO + ("UNREAD",))                   # review: unread
        rows += bulk(80, 2, "important.example.test", labels=PROMO + ("IMPORTANT",))             # review: important + attention signal
        rows += bulk(90, 3, "recent.example.test", days=10)                                      # not applicable: too recent
        rows += bulk(100, 2, "archived.example.test", labels=("CATEGORY_PROMOTIONS",))           # not applicable: not in inbox
        rows += bulk(110, 3, "sent.example.test", labels=PROMO + ("SENT",))                      # hard protection
        self.seed(rows)
        self.db = Path(self.index.path)

    def report(self, **kw):
        kw.setdefault("now", NOW)
        return disc.compute(self.index, ACCT, **kw)

    def decisions(self):
        return {d.message_id: d for d in cc.evaluate_all(self.index, ACCT, now_ms=NOW_MS).decisions}


class GroupingTests(Base):
    def test_groups_counts_volume_and_reasons(self):
        r = self.report()
        self.assertEqual([(g["rank"], g["domain"], g["messages"], g["bytes"], g["unknown_size"]) for g in r["groups"]],
                         [(1, "big.example.test", 8, 7 * 2000, 1), (2, "mid.example.test", 6, 3000, 0)])
        big = r["groups"][0]
        self.assertEqual((big["threads"], big["oldest_days"], big["newest_days"]), (8, 200, 200))
        self.assertEqual(big["evidence"][0]["type"], "PROMOTIONAL")
        self.assertIn("OLDER_THAN_90D", big["why"])
        self.assertEqual(r["below_min_group"], {"groups": 1, "messages": 2, "bytes": 2000})
        self.assertIn("SOME_SIZES_UNKNOWN", r["warnings"])
        self.assertTrue(r["read_only"] and r["mutations"] == 0)

    def test_totals_separate_eligible_uncertain_protected_and_not_applicable(self):
        t = self.report()["totals"]
        self.assertEqual(t["indexed"], 8 + 6 + 2 + 3 + 4 + 2 + 3 + 2 + 3)
        self.assertEqual(t["eligible"]["messages"], 16)
        self.assertEqual((t["uncertain"]["messages"], t["protected"]["messages"], t["not_applicable"]["messages"], t["unsafe_data"]["messages"]), (6, 6, 5, 0))
        self.assertEqual(sum(t[k]["messages"] for k in ("eligible", "uncertain", "protected", "unsafe_data", "not_applicable")), t["indexed"])  # every message in exactly one bucket

    def test_min_group_size_and_limit(self):
        self.assertEqual([g["domain"] for g in self.report(min_group=7)["groups"]], ["big.example.test"])
        self.assertEqual(len(self.report(min_group=1)["groups"]), 3)
        r = self.report(limit=1, min_group=1)
        self.assertEqual((len(r["groups"]), r["groups_shown"], r["groups_total"]), (1, 1, 3))
        self.assertIn("NO_GROUP_REACHES_MIN_SIZE", self.report(min_group=100)["warnings"])

    def test_the_age_threshold_can_only_be_stricter(self):
        self.assertEqual([g["domain"] for g in self.report(min_age_days=150)["groups"]], ["big.example.test"])
        with self.assertRaises(disc.ParameterError):
            self.report(min_age_days=30)


class SafetyTests(Base):
    def test_no_group_member_is_ever_outside_the_m4a_eligible_set(self):
        res = self.report(min_group=1)
        eligible = {d for d in self.decisions().values() if d.outcome == cc.ELIGIBLE}
        self.assertEqual(res["totals"]["eligible"]["messages"], len(eligible))
        self.assertEqual(sum(g["messages"] for g in res["groups"]), len(eligible))
        self.assertEqual({g["domain"] for g in res["groups"]}, {d.sender.rpartition("@")[2] for d in eligible})

    def test_protections_are_preserved_and_reported_as_protected(self):
        res = self.report(min_group=1)
        self.assertTrue({"starred.example.test", "sent.example.test", "unread.example.test", "important.example.test", "recent.example.test"}.isdisjoint({g["domain"] for g in res["groups"]}))
        self.assertEqual({r["code"]: r["messages"] for r in res["protected_reasons"]}, {"STARRED": 3, "SENT": 3})
        unc = {r["code"]: r["messages"] for r in res["uncertain_reasons"]}
        self.assertEqual((unc["UNREAD"], unc["IMPORTANT_LABEL"], unc["ATTENTION_SIGNAL"]), (4, 2, 2))  # attention = conservative protection

    def test_a_user_protection_rule_removes_a_group_and_changes_the_fingerprint(self):
        before = self.report()
        cleanup_protect.add(self.index, ACCT, domain="big.example.test", note="synthetic")
        after = self.report()
        self.assertEqual([g["domain"] for g in after["groups"]], ["mid.example.test"])
        self.assertEqual(after["protection"]["active_user_rules"], 1)
        self.assertNotEqual(after["protection"]["fingerprint"], before["protection"]["fingerprint"])
        self.assertEqual({r["code"]: r["messages"] for r in after["protected_reasons"]}["USER_PROTECTED"], 8)

    def test_a_mixed_thread_keeps_a_message_out_of_every_group(self):
        extra = [msg(200, thread="shared", sender="a@thread.example.test", labels=PROMO), msg(201, thread="shared", sender="b@thread.example.test", labels=PROMO + ("STARRED",))]
        self.seed(extra)
        res = self.report(min_group=1)
        self.assertNotIn("thread.example.test", {g["domain"] for g in res["groups"]})
        self.assertGreaterEqual({r["code"]: r["messages"] for r in res["uncertain_reasons"]}["MIXED_THREAD"], 1)

    def test_the_wording_never_claims_certainty(self):
        text = disc.render_text(self.report())
        self.assertIn("possibilities to review, not statements that any mail is unnecessary", text)
        self.assertIn("planning, approval and any execution are separate", text)
        self.assertNotRegex(text.lower(), r"safe to delete|definitely|certainly|junk|will be (deleted|archived)|unnecessary mail")
        self.assertEqual(self.report()["explain"][0], "CANDIDATES_NOT_CERTAINTY")


class SubscriptionContextTests(Base):
    def test_m9a_context_is_inferred_and_never_changes_a_group(self):
        r = self.report()
        ctx = r["groups"][0]["subscription_review"]
        self.assertEqual((ctx["basis"], ctx["unsubscribe"]), ("INFERRED", "NOT_CHECKED"))
        base = [(g["domain"], g["messages"], g["bytes"]) for g in r["groups"]]
        with mock.patch.object(disc.subscriptions, "compute", side_effect=disc.subscriptions.ParameterError("x")):
            self.assertEqual([(g["domain"], g["messages"], g["bytes"]) for g in self.report()["groups"]], base)


class DeterminismAndEdgeTests(Base):
    def test_results_are_stable(self):
        self.assertEqual(disc.as_json(self.report(min_group=1)), disc.as_json(self.report(min_group=1)))
        keys = [(-g["messages"], -g["bytes"], g["domain"]) for g in self.report(min_group=1)["groups"]]
        self.assertEqual(keys, sorted(keys))

    def test_parameters_are_validated_with_fixed_text(self):
        for kw in ({"limit": 0}, {"limit": 101}, {"limit": True}, {"min_group": 0}, {"min_group": 1001}, {"min_age_days": True}, {"min_age_days": 99999}):
            with self.assertRaises(disc.ParameterError):
                self.report(**kw)


class EmptyAndPartialTests(M5Base):
    def test_an_empty_index_is_an_honest_empty_report(self):
        r = disc.compute(self.index, ACCT, now=NOW)
        self.assertEqual((r["groups"], r["totals"]["indexed"], r["totals"]["eligible"]["messages"]), ([], 0, 0))
        self.assertIn("INDEX_EMPTY", r["warnings"])
        self.assertIn("Nothing to show", disc.render_text(r))

    def test_a_partial_index_recommends_nothing(self):
        self.fixture([], bulk(1, 10, "big.example.test"), complete=False)
        r = disc.compute(self.index, ACCT, now=NOW, min_group=1)
        self.assertEqual((r["groups"], r["totals"]["eligible"]["messages"]), ([], 0))
        self.assertIn("INDEX_PARTIAL", r["warnings"])

    def test_incomplete_metadata_is_unsafe_data_not_a_candidate(self):
        rows = bulk(1, 6, "big.example.test")
        rows[0]["internal_ms"] = None
        rows[1]["sender"] = ""
        self.fixture([], rows)
        r = disc.compute(self.index, ACCT, now=NOW, min_group=1)
        self.assertEqual(r["totals"]["unsafe_data"]["messages"], 2)
        self.assertEqual(r["groups"][0]["messages"], 4)
        self.assertEqual({x["code"] for x in r["unsafe_data_reasons"]}, {"MISSING_DATE", "MISSING_SENDER"})


class CommandAndSafetyTests(Base):
    def run_cmd(self, *argv):
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = NOW
        with mock.patch.object(disc, "datetime", fake):
            return self.run_cli("cleanup", "discover", "--account", ACCT, *argv)

    def test_json_and_text_agree_and_match_the_library(self):
        code, out, err = self.run_cmd("--json", "--min-group-size", "1")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), json.loads(disc.as_json(self.report(min_group=1))))
        code, text, err = self.run_cmd()
        self.assertEqual((code, err), (0, ""))
        self.assertIn("big.example.test", text)

    def test_the_command_writes_nothing_contacts_nobody_and_prints_no_identifier(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        names = sorted(os.listdir(self.db.parent))
        for argv in ((), ("--json",), ("--min-group-size", "1", "--json"), ("--min-age-days", "180")):
            code, out, err = self.run_cmd(*argv)  # run_cli forbids Gmail and the Keychain; the test base forbids the network
            self.assertEqual((code, err), (0, ""), argv)
            self.assertNotIn(MARK, out)
            self.assertNotRegex(out, r"https?://|mailto:|@|\bm[0-9]+\b|\bt[0-9]+\b")
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(self.db.parent)), names)

    def test_bad_parameters_and_internal_errors_have_fixed_messages(self):
        for argv, text in ((("--limit", "0"), "--limit must be between 1 and 100"), (("--min-group-size", "0"), "--min-group-size must be between 1 and 1000"),
                           (("--min-age-days", "30"), "--min-age-days must be between 90 and 3650 (you may only be stricter than the default)")):
            self.assertEqual(self.run_cmd(*argv), (1, "", f"error: {text}\n"))
        with mock.patch.object(disc, "compute", side_effect=ValueError("stored: " + MARK)):
            self.assertEqual(self.run_cmd("--json"), (1, "", "error: " + cli._REPORT_UNEXPECTED + "\n"))

    def test_the_module_adds_no_policy_and_cannot_write_or_reach_a_network(self):
        src = (ROOT / "src" / "gmail_intelligence" / "cleanup_discovery.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bimport (socket|urllib|http|smtplib|requests|subprocess|webbrowser|sqlite3|os)\b|https?://|mailto:|INSERT|UPDATE |DELETE |CREATE |_open_reader|gmail_write|cleanup_exec|cleanup_plans", src))
        self.assertEqual(set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.M)), {"json", "collections", "datetime", "gmail_intelligence"})
        self.assertIn("cc.evaluate_all", src)


if __name__ == "__main__":
    unittest.main()
