"""M6A: aggregate analytics (issue #17). Synthetic fixtures only; no Gmail, no network, nothing is ever written."""
import ast
import hashlib
import json
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, OTHER, M5Base, label, mail  # noqa: E402
from test_cleanup import NOW  # noqa: E402

from gmail_intelligence import analytics as an, analytics_report, classifier, cleanup_audit, cleanup_candidates as cc, cleanup_plans as cp, index as idx  # noqa: E402
from gmail_intelligence import label_plans as lp  # noqa: E402

PROMO = ("INBOX", "CATEGORY_PROMOTIONS")


def ms(y, m, d):
    return int(datetime(y, m, d, 12, tzinfo=timezone.utc).timestamp() * 1000)


def when(i, y, m, d, sender, labels=("INBOX",), unread=False):
    r = mail(i, labels, sender=sender)
    r["internal_ms"] = ms(y, m, d)
    if unread:
        r["label_ids"] = list(labels) + ["UNREAD"]
    return r


def fixture_messages():
    out, n = [], 0

    def add(count, *a, **k):
        nonlocal n
        for _ in range(count):
            n += 1
            out.append(when(n, *a, **k))
    add(6, 2026, 1, 15, "deals@promo.example.test", PROMO)
    add(4, 2026, 2, 10, "deals@promo.example.test", PROMO, unread=True)
    add(5, 2026, 1, 20, "weekly@news.example.test")
    add(3, 2026, 4, 5, "weekly@news.example.test", unread=True)
    add(6, 2026, 4, 9, "noreply@alerts.example.test")
    add(4, 2026, 2, 3, "friend@mail.example.test")
    return out


class AnalyticsBase(M5Base):
    def setUp(self):
        super().setUp()
        classifier.add_rule(self.index, ACCT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, domain="news.example.test")
        classifier.add_rule(self.index, ACCT, kind="type", value="EDUCATIONAL", confidence="HIGH", priority=0, domain="news.example.test")
        self.fixture([label("Label_1", "Private Label")], fixture_messages())
        self.fixture([label("Label_9", "OtherOnly")], [when(1, 2026, 3, 3, "x@other.example.test")], account=OTHER)
        self.now = datetime.now(timezone.utc)

    def a(self, **kw):
        return an.Analytics(self.index, ACCT, now=self.now, **kw)


class SectionTests(AnalyticsBase):
    def test_overview_arithmetic(self):
        e = self.a().overview()
        d = e["data"]
        self.assertEqual((d["messages"], d["unread"], d["in_inbox"]), (28, 7, 28))
        self.assertEqual(d["unread_share_pct"], 25.0)
        self.assertEqual((d["oldest"], d["newest"]), ("2026-01-15", "2026-04-09"))
        self.assertEqual(d["user_labels"], 1)
        self.assertEqual(d["classified"], 28)
        self.assertEqual((e["basis"], e["section"]), ("OBSERVED", "overview"))
        self.assertIn("SNAPSHOT_NOT_LIVE", e["explain"])

    def test_volume_fills_gaps_and_sums_to_the_index(self):
        d = self.a().volume()["data"]
        self.assertEqual([p["period"] for p in d["points"]], ["2026-01", "2026-02", "2026-03", "2026-04"])
        self.assertEqual([p["messages"] for p in d["points"]], [11, 8, 0, 9])
        self.assertEqual(sum(p["messages"] for p in d["points"]), 28)
        self.assertEqual(sum(p["unread"] for p in d["points"]), 7)
        self.assertEqual(d["peak"], "2026-01")
        self.assertEqual([p["in_progress"] for p in d["points"]].count(True), 0)  # the scan month is not inside the fixture range

    def test_categories_count_every_message_once(self):
        e = self.a().categories()
        d = e["data"]
        by = {t["type"]: t["messages"] for t in d["types"]}
        self.assertEqual(sum(by.values()), 28)
        self.assertEqual((by["PROMOTIONAL"], by["NEWSLETTER"], by["AUTOMATED_NOTIFICATION"]), (10, 8, 6))
        self.assertEqual(d["classified"] + d["unclassified"], d["indexed"])
        self.assertEqual(d["multi_type_messages"], 8)  # NEWSLETTER + EDUCATIONAL are compatible; counted once, under the first in taxonomy order
        self.assertEqual(by.get("EDUCATIONAL", 0), 0)
        self.assertEqual(e["basis"], "INFERRED")
        shares = sum(t["share_of_indexed_pct"] for t in d["types"])
        self.assertAlmostEqual(shares, 100.0, delta=0.3)

    def test_categories_by_month_add_up(self):
        d = self.a().categories(by="month")["data"]
        self.assertEqual(sum(sum(m["counts"].values()) for m in d["by_month"]), 28)
        feb = next(m for m in d["by_month"] if m["period"] == "2026-02")
        self.assertEqual(feb["counts"]["PROMOTIONAL"], 4)
        with self.assertRaises(ValueError):
            self.a().categories(by="year")

    def test_senders_domains_are_shown_addresses_masked(self):
        d = self.a().senders()["data"]
        self.assertEqual([i["display"] for i in d["items"]][:3], ["promo.example.test", "news.example.test", "alerts.example.test"])
        self.assertEqual(d["items"][0]["messages"], 10)
        addr = self.a().senders(kind="address")["data"]
        self.assertEqual(addr["items"][0]["display"], "d•••@promo.example.test")
        self.assertTrue(addr["items"][0]["masked"] and addr["items"][0]["key"] is None)
        self.assertNotIn("deals@promo.example.test", json.dumps(addr))
        shown = self.a(reveal_senders=True).senders(kind="address")["data"]
        self.assertEqual(shown["items"][0]["display"], "deals@promo.example.test")
        self.assertEqual(shown["covered_messages"], sum(i["messages"] for i in shown["items"]))

    def test_sender_ties_are_broken_by_key(self):
        d = self.a().senders(kind="address", limit=100)["data"]["items"]
        keys = [(-i["messages"], i["display"]) for i in d]
        self.assertEqual(keys, sorted(keys))
        for bad in ({"kind": "x"}, {"limit": 0}, {"limit": 101}, {"limit": "5"}):
            with self.assertRaises(ValueError):
                self.a().senders(**bad)

    def test_subscriptions(self):
        d = self.a().subscriptions()["data"]
        by = {t["type"]: t for t in d["types"]}
        self.assertEqual(by["NEWSLETTER"]["messages"], 8)
        self.assertEqual(by["NEWSLETTER"]["top_domains"][0], {"domain": "news.example.test", "messages": 8, "unread": 3, "last_seen": "2026-04-05"})
        self.assertEqual(sum(p["messages"] for p in by["PROMOTIONAL"]["monthly"]), 10)
        self.assertEqual(len(by["AUTOMATED_NOTIFICATION"]["monthly"]), 4)  # the same period axis for every type

    def test_untrusted_sender_text_is_cleaned(self):
        evil = "bad\u202e\x07@evil.example.test"
        self.fixture([], [when(900, 2026, 1, 1, evil)], complete=True)
        text = json.dumps(self.a(reveal_senders=True).senders(kind="address", limit=100), ensure_ascii=False)
        for ch in ("\u202e", "\x07"):
            self.assertNotIn(ch, text)
        self.assertEqual(an.clean("a\u2066b\u200fc\n d"), "a b c d")
        self.assertEqual(len(an.clean("x" * 500)), 120)
        self.assertEqual(an.mask_address("nobody"), "•••")


class FreshnessTests(AnalyticsBase):
    def test_a_fresh_complete_snapshot(self):
        f = self.a().freshness()["data"]
        self.assertEqual((f["state"], f["health"], f["issues"]), ("complete", "OK", []))
        self.assertEqual(f["classification"], {"indexed": 28, "current": 28, "stale": 0, "unclassified": 0})

    def test_stale_data_is_reported_honestly(self):
        a = an.Analytics(self.index, ACCT, now=self.now + timedelta(days=an.STALE_DAYS + 3))
        f = a.freshness()
        self.assertIn("STALE", f["data"]["issues"])
        self.assertTrue(f["index"]["stale"])
        self.assertGreaterEqual(f["data"]["age_days"], an.STALE_DAYS + 3)
        self.assertEqual(a.overview()["data"]["health"], "STALE")

    def test_partial_and_empty_indexes(self):
        self.fixture([], [when(1, 2026, 1, 1, "a@one.example.test")], complete=False, account="partial@example.invalid")
        a = an.Analytics(self.index, "partial@example.invalid", now=self.now)
        self.assertEqual(a.freshness()["data"]["health"], "PARTIAL")
        e = an.Analytics(self.index, "nobody@example.invalid", now=self.now)
        self.assertEqual(e.freshness()["data"]["health"], "EMPTY")
        self.assertEqual(e.overview()["data"]["messages"], 0)
        self.assertEqual(e.volume()["data"]["points"], [])
        self.assertEqual(e.categories()["data"]["types"][-1]["type"], an.UNCLASSIFIED)
        self.assertEqual(e.senders()["data"]["items"], [])

    def test_a_rule_change_makes_classification_stale(self):
        classifier.add_rule(self.index, ACCT, kind="type", value="SOCIAL", confidence="HIGH", priority=0, domain="mail.example.test")
        f = self.a().freshness()["data"]
        self.assertIn("CLASSIFICATION_STALE", f["issues"])
        self.assertEqual(f["classification"]["current"], 0)
        cats = self.a().categories()["data"]
        self.assertEqual(cats["unclassified"], 28)  # stale results are never counted as current
        self.assertEqual(cats["classified"], 0)


class DeterminismAndIsolationTests(AnalyticsBase):
    def test_same_input_same_output_and_json_safe(self):
        first = {s: self.a().section(s) for s in an.SECTIONS}
        second = {s: self.a().section(s) for s in an.SECTIONS}
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        for env in first.values():
            self.assertEqual(set(env), {"section", "data", "basis", "explain", "as_of", "index"})
            self.assertIn(env["basis"], ("OBSERVED", "INFERRED", "MIXED"))
            self.assertTrue(env["explain"])
            for code in env["explain"]:
                self.assertRegex(code, r"^[A-Z0-9_]+$")

    def test_accounts_are_isolated(self):
        other = an.Analytics(self.index, OTHER, now=self.now)
        text = json.dumps({s: other.section(s) for s in an.SECTIONS})
        for private in ("promo.example.test", "news.example.test", "alerts.example.test", "Private Label"):
            self.assertNotIn(private, text)
        self.assertEqual(other.overview()["data"]["messages"], 1)
        self.assertEqual(self.a().overview()["data"]["messages"], 28)

    def test_unknown_section(self):
        with self.assertRaises(ValueError):
            self.a().section("secrets")


class CleanupTests(AnalyticsBase):
    def test_summary_matches_the_candidate_engine(self):
        now_ms = int(self.now.timestamp() * 1000)
        direct = cc.evaluate_all(self.index, ACCT, now_ms=now_ms).summary
        d = self.a().cleanup_summary()["data"]
        self.assertEqual(d["total"], direct["total"])
        self.assertEqual(sum(d["outcomes"].values()), d["total"])
        self.assertEqual(d["outcomes"][cc.ELIGIBLE], direct["outcomes"][cc.ELIGIBLE])
        self.assertTrue(d["recommendations_only"])

    def test_protected_messages_stay_out_of_the_recommendations(self):
        self.fixture([], [when(950, 2025, 1, 1, "deals@promo.example.test", PROMO + ("STARRED",))])
        d = self.a().cleanup_summary()["data"]
        direct = cc.evaluate_all(self.index, ACCT, now_ms=int(self.now.timestamp() * 1000))
        starred = next(x for x in direct.decisions if x.message_id == "m950")
        self.assertNotEqual(starred.outcome, cc.ELIGIBLE)
        self.assertIn(cc.EXCLUDED, d["outcomes"])

    def test_history_reflects_the_audit_ledger(self):
        empty = self.a().cleanup_history()["data"]
        self.assertEqual((empty["plans"], empty["audit"]["events"], empty["audit"]["chain_ok"]), ([], 0, True))
        t = datetime.fromtimestamp(NOW / 1000, timezone.utc)
        ids = [r["id"] for r in fixture_messages()[:0]] or ["m1", "m2"]
        # create a plan on messages that are eligible at the fixture's reference time
        res = cc.evaluate_all(self.index, ACCT, now_ms=NOW)
        eligible = [d.message_id for d in res.decisions if d.outcome == cc.ELIGIBLE][:2]
        self.assertTrue(eligible)
        plan = cp.create_plan(self.index, ACCT, eligible, now=t)
        cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=t + timedelta(minutes=1))
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=t + timedelta(minutes=2))
        h = self.a().cleanup_history()["data"]
        self.assertEqual(h["plan_states"], {"APPROVED": 1})
        self.assertEqual(h["approvals"], {"VALID": 1})
        self.assertEqual(h["executions"], [])
        self.assertEqual(h["audit"]["by_type"], {"PLAN_APPROVED": 1, "PLAN_CREATED": 1, "PLAN_REVIEWED": 1})
        self.assertTrue(h["audit"]["chain_ok"])
        dump = json.dumps(h)
        for mid in eligible:
            self.assertNotIn(f'"{mid}"', dump)  # no message ids anywhere
        self.assertEqual(h["items_applied"], 0)
        # tampering with the ledger is surfaced
        self.index.conn.execute("DROP TRIGGER cleanup_audit_no_update")
        self.index.conn.execute("UPDATE cleanup_audit SET meta='{}' WHERE event_type='PLAN_CREATED'")
        self.index.conn.commit()
        bad = self.a().cleanup_history()["data"]["audit"]
        self.assertFalse(bad["chain_ok"])
        self.assertIsNotNone(bad["first_bad_seq"])


class OrganizationTests(AnalyticsBase):
    def test_organization_summarizes_m5_without_names(self):
        self.fixture([label("Label_1", "Receipts"), label("Label_2", "receipts"), label("Label_3", "SecretIdle")], [when(960, 2026, 1, 1, "z@z.example.test")])
        d = self.a().organization()["data"]
        self.assertGreaterEqual(d["hygiene"]["findings"], 1)
        self.assertIn("NEAR_DUPLICATE", d["hygiene"]["by_code"])
        self.assertTrue(d["read_only"])
        dump = json.dumps(d)
        self.assertNotIn("Receipts", dump)
        self.assertNotIn("SecretIdle", dump)
        shown = self.a(reveal_names=True).organization()["data"]
        self.assertIn("Receipts", json.dumps(shown))

    def test_label_plans_are_counted_not_executed(self):
        lp.create_plan(self.index, ACCT, [("CREATE", "Archive")], now=datetime.fromtimestamp(NOW / 1000, timezone.utc))
        d = self.a().organization()["data"]
        self.assertEqual(d["label_plans"], {"DRAFT": 1})


class ReadOnlyTests(AnalyticsBase):
    def digest(self):
        return hashlib.sha256(Path(self.index.path).read_bytes()).hexdigest()

    def test_every_section_leaves_the_file_byte_identical(self):
        before = self.digest()
        ro = idx.ReadOnlyIndex(self.index.path)
        a = an.Analytics(ro, ACCT, now=self.now)
        for s in an.SECTIONS:
            a.section(s)
        ro.close()
        self.assertEqual(self.digest(), before)

    def test_writes_fail_inside_sqlite(self):
        ro = idx.ReadOnlyIndex(self.index.path)
        for fn in (lambda: ro.save_labels(ACCT, [label("Label_5", "x")]), lambda: ro.conn.execute("DELETE FROM messages"), lambda: ro.conn.execute("CREATE TABLE t (a)"),
                   lambda: ro.conn.execute("PRAGMA user_version = 99")):
            with self.assertRaises(sqlite3.OperationalError):
                fn()
        self.assertEqual(ro.conn.execute("SELECT COUNT(*) FROM messages WHERE account=?", (ACCT,)).fetchone()[0], 28)
        ro.close()

    def test_old_schema_is_refused_and_never_migrated(self):
        path = self.tmp / "v5" / "index.sqlite3"
        path.parent.mkdir(mode=0o700)
        c = sqlite3.connect(path)
        c.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + idx.SCHEMA_V4 + idx.SCHEMA_V5 + "PRAGMA user_version = 5;COMMIT;")
        c.close()
        raw = path.read_bytes()
        with self.assertRaises(idx.IndexProblem) as cm:
            idx.ReadOnlyIndex(path)
        self.assertIn("schema version 5", str(cm.exception))
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(list(path.parent.glob("*backup*")), [])

    def test_missing_corrupt_and_future_files(self):
        with self.assertRaises(idx.IndexProblem):
            idx.ReadOnlyIndex(self.tmp / "nope.sqlite3")
        bad = self.tmp / "bad.sqlite3"
        bad.write_bytes(b"not a database" * 50)
        with self.assertRaises(idx.IndexProblem):
            idx.ReadOnlyIndex(bad)
        self.assertFalse((self.tmp / "nope.sqlite3").exists())  # nothing is created

    def test_analytics_modules_import_nothing_live(self):
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "exec_live_mailbox", "cleanup_exec",
                     "cleanup_executor", "cleanup_undo", "cleanup_canary", "cleanup_live", "http", "urllib", "socket", "ssl", "requests", "subprocess"}
        for name in ("analytics", "analytics_report"):
            mods = set()
            for n in ast.walk(ast.parse((ROOT / "src" / "gmail_intelligence" / f"{name}.py").read_text())):
                if isinstance(n, ast.Import):
                    mods |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom):
                    mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
            self.assertEqual(mods & forbidden, set(), name)


class CliTests(AnalyticsBase):
    def test_json_output_and_masking(self):
        code, out, err = self.run_cli("mailbox", "insights", "senders", "--kind", "address", "--json", "--account", ACCT)
        self.assertEqual((code, err), (0, ""))
        env = json.loads(out)
        self.assertEqual(env["section"], "senders")
        self.assertNotIn("deals@promo", out)
        code, out, _ = self.run_cli("mailbox", "insights", "senders", "--kind", "address", "--reveal-senders", "--json", "--account", ACCT)
        self.assertIn("deals@promo.example.test", out)

    def test_every_section_renders_as_text_and_json(self):
        for s in an.SECTIONS:
            code, out, err = self.run_cli("mailbox", "insights", s, "--account", ACCT)
            self.assertEqual((code, err), (0, ""), s)
            self.assertIn("LOCAL ONLY", out)
            self.assertIn("explains:", out)
            code, out, _ = self.run_cli("mailbox", "insights", s, "--json", "--account", ACCT)
            self.assertEqual(json.loads(out)["section"], s)
        code, out, _ = self.run_cli("mailbox", "insights", "all", "--json", "--account", ACCT)
        self.assertEqual(sorted(json.loads(out)), sorted(an.SECTIONS))

    def test_the_account_never_appears_and_nothing_live_is_used(self):
        code, out, err = self.run_cli("mailbox", "insights", "all", "--account", ACCT)
        self.assertEqual(code, 0)
        self.assertNotIn(ACCT, out + err)

    def test_organization_hides_names_by_default(self):
        _, out, _ = self.run_cli("mailbox", "insights", "organization", "--json", "--account", ACCT)
        self.assertNotIn("Private Label", out)

    def test_help(self):
        code, out, _ = self.run_cli("mailbox", "insights", "--help")
        self.assertEqual(code, 0)
        self.assertIn("--reveal-senders", out)


if __name__ == "__main__":
    unittest.main()
