"""M9A: subscription intelligence from metadata (issue #27): grouping, counts, frequency and unread signals, deterministic and explained recommendations, edge cases, privacy, read-only
operation and no network. Synthetic data only: no Gmail, no Keychain, no sender is ever contacted."""
import contextlib
import hashlib
import io
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
from test_cleanup import DAY, NOW as NOW_MS  # noqa: E402

from gmail_intelligence import cli, subscriptions as sub  # noqa: E402

NOW = datetime.fromtimestamp(NOW_MS / 1000, timezone.utc)
MARK = "leakmarker-7752"
PROMO = ["INBOX", "CATEGORY_PROMOTIONS"]


class Base(M5Base):
    """promo: strong; news: moderate; read: weak (all read); starred / friends / dormant: ruled out; sparse and short: not enough evidence."""

    def setUp(self):
        super().setUp()
        rows, n = [], [0]

        def add(domain, count, labels, days, unread_every=None, local=None, unread_all=False, starred_first=False):
            for k in range(count):
                n[0] += 1
                lab = list(labels) + (["STARRED"] if starred_first and k == 0 else [])
                rows.append(mail(n[0], lab, sender=f"{local or MARK + str(k % 3)}@{domain}", days=days[k % len(days)] if isinstance(days, (list, tuple)) else days,
                                 unread=unread_all or (unread_every is not None and k % unread_every != 0)))
        add("promo.example.test", 12, PROMO, [5, 15, 30, 40, 50, 60, 70, 80, 90, 100, 110, 115], unread_every=12)     # 11 of 12 unread, oldest 115 days, still arriving
        add("news.example.test", 8, ["INBOX"], [3, 10, 20, 30, 40, 50, 55, 60], local="noreply", unread_every=3)      # automated sender; 5 of 8 unread (0.625)
        add("read.example.test", 10, PROMO, [5, 15, 25, 35, 45, 55, 65, 75, 85, 95])                                  # promotions but never unread
        add("starred.example.test", 10, PROMO, [5, 15, 25, 35, 45, 55, 65, 75, 85, 95], unread_all=True, starred_first=True)
        add("friends.example.test", 10, ["INBOX", "CATEGORY_PERSONAL"], [5, 15, 25, 35, 45, 55, 65, 75, 85, 95], unread_all=True)
        add("dormant.example.test", 8, PROMO, [300, 320, 340, 360, 380, 400, 420, 440], unread_all=True)
        add("sparse.example.test", 3, PROMO, [10, 20, 30], unread_all=True)
        add("short.example.test", 6, PROMO, [1, 2, 3, 4, 5, 6], unread_all=True)
        self.fixture([], rows)
        self.db = Path(self.index.path)

    def run_report(self, **kw):
        kw.setdefault("limit", 100)
        kw.setdefault("now", NOW)
        return sub.compute(self.index, ACCT, **kw)

    def by_group(self, res):
        return {i["group"]["display"]: i for i in res["items"]}


class GroupingAndSignalTests(Base):
    def test_groups_counts_and_the_evidence_levels(self):
        res = self.run_report(show_all=True)
        g = self.by_group(res)
        self.assertEqual({k: (v["messages"], v["estimate"]) for k, v in g.items()}, {
            "promo.example.test": (12, "STRONGER_EVIDENCE"), "news.example.test": (8, "STRONGER_EVIDENCE"), "read.example.test": (10, "WEAK_EVIDENCE"),
            "starred.example.test": (10, "NOT_RECOMMENDED"), "friends.example.test": (10, "NOT_RECOMMENDED"), "dormant.example.test": (8, "NOT_RECOMMENDED"),
            "sparse.example.test": (3, "NOT_ENOUGH_EVIDENCE"), "short.example.test": (6, "NOT_ENOUGH_EVIDENCE")})
        self.assertEqual(res["totals"], {"groups": 8, "candidates": 2, "not_recommended": 3, "not_enough_evidence": 2, "weak": 1, "shown": 8, "indexed": 67})
        self.assertEqual([i["group"]["display"] for i in self.run_report()["items"]], ["promo.example.test", "news.example.test"])  # only the reviewable groups by default

    def test_volume_unread_frequency_and_trend_are_calculated_from_the_index(self):
        promo = self.by_group(self.run_report())["promo.example.test"]
        sig = {s["code"]: s for s in promo["signals"]}
        self.assertEqual(sig["UNREAD_RATIO"]["detail"], {"unread": 11, "messages": 12, "ratio": 0.92})
        self.assertEqual(sig["OLDEST_UNREAD"]["detail"], {"days": 115})
        span = (115 - 5)
        self.assertEqual(sig["FREQUENCY"]["detail"], {"per_30_days": round(12 / span * 30, 2), "span_days": span})
        self.assertEqual(sig["TREND"]["detail"], {"last_90_days": 9, "previous_90_days": 3})
        self.assertEqual((promo["first_seen"] < promo["last_seen"], promo["points"]), (True, 5))
        self.assertEqual([s["code"] for s in promo["signals"] if s["basis"] == "INFERRED"], ["DOMINANT_TYPE", "BULK_TYPE"])

    def test_address_grouping_masks_senders_unless_revealed(self):
        res = self.run_report(by="address", show_all=True)
        self.assertTrue(all(i["group"]["masked"] for i in res["items"]))
        self.assertNotIn(MARK, json.dumps(res))
        shown = json.dumps(self.run_report(by="address", show_all=True, reveal_senders=True))
        self.assertIn(MARK, shown)
        self.assertEqual({k for k in self.by_group(self.run_report(by="address", show_all=True, reveal_senders=True)) if "noreply" in k}, {"noreply@news.example.test"})

    def test_a_protection_rules_a_group_out_and_says_why(self):
        g = self.by_group(self.run_report(show_all=True))
        self.assertEqual([b["code"] for b in g["starred.example.test"]["blockers"]], ["STARRED_MESSAGE"])
        self.assertEqual([b["code"] for b in g["friends.example.test"]["blockers"]], ["PERSONAL_MAIL_PRESENT"])
        self.assertEqual([b["code"] for b in g["dormant.example.test"]["blockers"]], ["DORMANT"])
        self.assertEqual([b["code"] for b in g["sparse.example.test"]["blockers"]], ["INSUFFICIENT_HISTORY"])
        self.assertEqual({i["recommendation"] for k, i in g.items() if i["estimate"] in ("NOT_RECOMMENDED", "NOT_ENOUGH_EVIDENCE", "WEAK_EVIDENCE")}, {"NONE"})

    def test_reading_what_arrives_is_engagement_even_when_it_is_regular(self):
        read = self.by_group(self.run_report(show_all=True))["read.example.test"]
        self.assertEqual((read["estimate"], read["recommendation"]), ("WEAK_EVIDENCE", "NONE"))
        self.assertGreaterEqual(read["points"], 2)  # regular and still arriving, yet not recommended

    def test_min_messages_changes_what_is_assessed(self):
        low = self.by_group(self.run_report(min_messages=3, show_all=True))
        self.assertEqual(low["sparse.example.test"]["messages"], 3)
        self.assertNotIn("INSUFFICIENT_HISTORY", [b["code"] for b in low["sparse.example.test"]["blockers"]])


class ExplanationTests(Base):
    def test_every_recommendation_is_explained_with_observed_and_inferred_evidence(self):
        res = self.run_report()
        self.assertTrue(res["items"])
        for it in res["items"]:
            bases = {s["basis"] for s in it["signals"]}
            self.assertEqual(bases, {"OBSERVED", "INFERRED"}, it["group"])
            self.assertEqual(it["recommendation"], "REVIEW_MANUALLY")
            self.assertEqual(it["unsubscribe"], {"status": "NOT_CHECKED", "reason": "NO_HEADERS_INDEXED"})
            self.assertTrue({"VOLUME", "UNREAD_RATIO", "BULK_TYPE"} <= {s["code"] for s in it["signals"]})
        self.assertEqual(set(res["explain"]), {"POSSIBLE_NOT_CERTAIN", "METADATA_ONLY", "HEURISTIC_THRESHOLDS", "NO_UNSUBSCRIBE_DATA", "NOTHING_IS_SENT_OR_VISITED", "REVIEW_BY_HAND"})
        self.assertIn("min_span_days", res["thresholds"])

    def test_the_wording_is_conservative(self):
        text = sub.render_text(self.run_report())
        self.assertIn("possibilities", text)
        self.assertIn("not statements that a sender is a subscription", text)
        self.assertIn("NOT CHECKED", text)
        self.assertIn("look for an unsubscribe option", text)
        self.assertNotRegex(text.lower(), r"definitely|certainly|you should unsubscribe|unsubscribe now")
        for it in self.run_report()["items"]:
            self.assertNotIn("href", json.dumps(it))


class DeterminismAndEdgeTests(Base):
    def test_identical_runs_and_orders_give_identical_output(self):
        a, b = sub.as_json(self.run_report(show_all=True)), sub.as_json(self.run_report(show_all=True))
        self.assertEqual(a, b)
        code = ("import sys; sys.path[:0] = [%r, %r]\nfrom test_subscriptions import *\nimport unittest\n" % (str(ROOT / "src"), str(ROOT / "tests")))
        self.assertEqual(sub.as_json(self.run_report(by="address", show_all=True)), sub.as_json(self.run_report(by="address", show_all=True)))
        self.assertNotIn("PYTHONHASHSEED", code)

    def test_the_ranking_is_total_and_stable(self):
        items = self.run_report(show_all=True)["items"]
        keys = [(-i["points"], -i["unread"], -i["messages"], i["group"]["display"]) for i in items]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([i["rank"] for i in items], list(range(1, len(items) + 1)))

    def test_parameters_are_validated_with_fixed_text(self):
        for kw in ({"by": "x"}, {"limit": 0}, {"limit": 101}, {"limit": True}, {"min_messages": 1}, {"min_messages": 1001}):
            with self.assertRaises(sub.ParameterError) as cm:
                self.run_report(**kw)
            self.assertNotIn("101", str(cm.exception).replace("between 1 and 100", ""))


class EmptyAndSparseTests(M5Base):
    def test_an_empty_index_gives_an_honest_empty_report(self):
        res = sub.compute(self.index, ACCT, now=NOW)
        self.assertEqual((res["items"], res["totals"]["groups"], res["totals"]["indexed"]), ([], 0, 0))
        self.assertIn("INDEX_EMPTY", res["warnings"])
        self.assertIn("Nothing to show", sub.render_text(res))

    def test_undated_senderless_and_odd_messages_do_not_break_the_report(self):
        rows = [mail(i, PROMO, sender=f"x@odd.example.test", days=10 + i, unread=True) for i in range(1, 8)]
        for r in rows[:2]:
            r["internal_ms"] = None
        rows.append(mail(90, PROMO, sender=None))
        rows[-1]["sender"] = None
        rows.append(mail(91, PROMO, sender="no-at-sign"))
        self.fixture([], rows)
        res = sub.compute(self.index, ACCT, now=NOW, show_all=True)
        self.assertEqual({i["group"]["display"] for i in res["items"]}, {"odd.example.test"})
        self.assertEqual(res["items"][0]["messages"], 7)
        self.assertEqual(res["items"][0]["unread"], 7)  # undated unread messages still count as unread

    def test_unclassified_mail_is_never_called_bulk(self):
        rows = [mail(i, ["INBOX"], sender="x@plain.example.test", days=5 * i, unread=True) for i in range(1, 12)]
        self.fixture([], rows, classify=False)
        res = sub.compute(self.index, ACCT, now=NOW, show_all=True)
        item = res["items"][0]
        self.assertEqual((item["estimate"], item["blockers"][0]["code"]), ("NOT_ENOUGH_EVIDENCE", "NO_BULK_TYPE_EVIDENCE"))
        self.assertIn("UNCLASSIFIED", res["warnings"])


class CommandAndSafetyTests(Base):
    def run_cmd(self, *argv):
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = NOW
        with mock.patch.object(sub, "datetime", fake):
            return self.run_cli("mailbox", "subscriptions", "--account", ACCT, *argv)

    def test_json_and_text_agree_and_match_the_library(self):
        code, out, err = self.run_cmd("--json", "--all")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), json.loads(sub.as_json(self.run_report(show_all=True, limit=20))))
        code, text, err = self.run_cmd("--all")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("promo.example.test", text)

    def test_the_command_writes_nothing_contacts_nobody_and_prints_no_identifier(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        names = sorted(os.listdir(self.db.parent))
        for argv in ((), ("--json",), ("--by", "address", "--all", "--json"), ("--by", "address", "--reveal-senders")):
            code, out, err = self.run_cmd(*argv)  # run_cli forbids Gmail and the Keychain; the test base forbids the network
            self.assertEqual((code, err), (0, ""), argv)
            self.assertNotRegex(out, r"https?://|mailto:|\bm[0-9]+\b")
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(self.db.parent)), names)

    def test_addresses_are_masked_in_the_output_unless_revealed(self):
        masked = self.run_cmd("--by", "address", "--all", "--json")[1]
        self.assertNotIn(MARK, masked)
        self.assertIn(MARK, self.run_cmd("--by", "address", "--all", "--json", "--reveal-senders")[1])

    def test_bad_parameters_and_internal_errors_have_fixed_messages(self):
        for argv, text in ((("--limit", "0"), "--limit must be between 1 and 100"), (("--min-messages", "1"), "--min-messages must be between 2 and 1000")):
            code, out, err = self.run_cmd(*argv)
            self.assertEqual((code, out, err), (1, "", f"error: {text}\n"))
        with mock.patch.object(sub, "compute", side_effect=ValueError("stored: " + MARK)):
            code, out, err = self.run_cmd("--json")
        self.assertEqual((code, out, err), (1, "", "error: " + cli._REPORT_UNEXPECTED + "\n"))

    def test_the_module_has_no_way_to_reach_the_network_or_a_sender(self):
        src = (ROOT / "src" / "gmail_intelligence" / "subscriptions.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bimport (socket|urllib|http|smtplib|requests|subprocess|webbrowser)|https?://|mailto:|INSERT|UPDATE |DELETE |CREATE ", src))
        self.assertNotIn("_open_reader", src)
        imports = set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.M))
        self.assertEqual(imports, {"json", "datetime", "gmail_intelligence"})


if __name__ == "__main__":
    unittest.main()
