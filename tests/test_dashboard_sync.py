"""M7C: aggregate sync information in the read-only dashboard freshness section (additive, cheap, no deep checks, no new routes). Synthetic data only."""
import json
import re
import sqlite3
import unittest
from datetime import timedelta
from pathlib import Path

import test_dashboard_server as TDS
from test_analytics import fixture_messages

import m7_support
from sync_support import ACCOUNT, SRC, SyncCase, idx, sync_lease
from gmail_intelligence import analytics, dashboard_server as ds, sync_health

STATIC = SRC / "gmail_intelligence" / "dashboard" / "static"
LABELS = ("OK", "MISSING", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE", "FULL_SCAN_UNFINISHED", "STALE", "INCONSISTENT")


def catalogs():
    return json.loads((STATIC / "i18n/en.json").read_text(encoding="utf-8")), json.loads((STATIC / "i18n/he.json").read_text(encoding="utf-8"))


class FreshnessSyncTests(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)

    def fresh(self, now=None):
        self.index.conn.commit()
        ro = idx.ReadOnlyIndex(self.db)
        try:
            return analytics.Analytics(ro, ACCOUNT, now=now or self.clock.now).freshness()
        finally:
            ro.close()

    def test_a_healthy_index_reports_ok_and_changes_none_of_the_existing_fields(self):
        env = self.fresh()
        s = env["data"]["sync"]
        self.assertEqual((s["state"], s["healthy"], s["checkpoint"], s["status"], s["codes"]), ("OK", True, "present", "OK", []))
        self.assertEqual(s["maintenance_command"], "mailbox maintenance")
        self.assertIsNotNone(s["last_completed_sync_at"])
        old = {"state", "why", "as_of", "age_days", "stale_after_days", "last_full_scan", "scans_recorded", "classification", "issues", "health"}
        self.assertTrue(old <= set(env["data"]))
        self.assertEqual(set(env), {"section", "data", "basis", "explain", "as_of", "index"})
        self.assertEqual(set(env["index"]), {"state", "age_days", "stale", "health"})             # the envelope's index block is exactly what it was
        self.assertIn("SYNC_FROM_LOCAL_RECORDS", env["explain"])

    def test_sync_problems_do_not_leak_into_the_existing_issues_or_health(self):
        before = self.fresh()["data"]
        self.sql_state("UPDATE sync_state SET status='NEEDS_RECONCILE'")
        env = self.fresh()
        self.assertEqual((env["data"]["issues"], env["data"]["health"]), (before["issues"], before["health"]))
        self.assertEqual(env["data"]["sync"]["state"], "NEEDS_RECONCILE")

    def sql_state(self, sql):
        with self.index.conn:
            self.index.conn.execute(sql)

    def test_every_state_is_reported(self):
        cases = {}
        self.sql_state("DELETE FROM sync_state")
        cases["MISSING"] = self.fresh()["data"]["sync"]
        self.baseline()
        self.clock.advance(60)
        self.sql_state("UPDATE sync_state SET status='INTERRUPTED'")
        cases["INTERRUPTED"] = self.fresh()["data"]["sync"]
        self.sql_state("UPDATE sync_state SET status='NEEDS_RECONCILE', reason='HISTORY_EXPIRED'")
        cases["NEEDS_RECONCILE"] = self.fresh()["data"]["sync"]
        self.baseline()
        self.clock.advance(60)
        self.sql_state("INSERT INTO scans (account, mode, status, started_at) VALUES ('%s', 'full', 'interrupted', '2026-10-20T13:00:00Z')" % ACCOUNT)
        self.sql_state("UPDATE sync_state SET status='INTERRUPTED', reason='FULL_SCAN_INTERRUPTED'")
        cases["FULL_SCAN_UNFINISHED"] = self.fresh()["data"]["sync"]
        self.sql_state("DELETE FROM scans WHERE status='interrupted'")
        self.sql_state("UPDATE sync_state SET status='OK', reason=NULL, basis_scan_id=basis_scan_id-1")
        cases["INCONSISTENT"] = self.fresh()["data"]["sync"]
        self.sql_state("UPDATE sync_state SET basis_scan_id=basis_scan_id+1")
        cases["STALE"] = self.fresh(now=self.clock.now + timedelta(hours=30))["data"]["sync"]
        lease = sync_lease.acquire(self.index, ACCOUNT, "INCREMENTAL", clock=self.clock)
        cases["IN_PROGRESS"] = self.fresh()["data"]["sync"]
        lease.finish("interrupted", "INTERRUPTED", "API_ERROR")
        for label, s in cases.items():
            self.assertEqual(s["state"], label)
            self.assertFalse(s["healthy"], label)
        self.assertEqual(cases["MISSING"]["checkpoint"], "missing")
        self.assertEqual(cases["NEEDS_RECONCILE"]["reason"], "HISTORY_EXPIRED")
        self.assertIsNone(cases["MISSING"]["age_hours"])
        self.assertEqual(set(cases) | {"OK"}, set(LABELS))

    def test_stored_text_is_never_echoed(self):
        self.sql_state("UPDATE sync_state SET reason='S3cretAlphaNumeric99'")
        self.sql_state("UPDATE sync_run SET finished_at='john.smith@company.example'")
        out = json.dumps(self.fresh(), sort_keys=True)
        self.assertNotIn("S3cretAlphaNumeric99", out)
        self.assertNotIn("john.smith", out)
        self.assertEqual(self.fresh()["data"]["sync"]["reason"], "UNRECOGNISED")

    def test_loading_freshness_runs_no_deep_or_integrity_check_and_no_write(self):
        self.index.conn.commit()
        ro = idx.ReadOnlyIndex(self.db)
        statements = []
        ro.conn.set_trace_callback(statements.append)
        analytics.Analytics(ro, ACCOUNT, now=self.clock.now).freshness()
        ro.close()
        self.assertTrue(statements)
        for stmt in statements:
            self.assertNotRegex(stmt, r"(?i)integrity_check|quick_check|foreign_key_check|\b(INSERT|UPDATE|DELETE|CREATE|DROP)\b")

    def test_the_dashboard_code_does_not_reach_the_maintenance_module(self):
        for name in ("dashboard_server.py", "analytics.py"):
            text = (SRC / "gmail_intelligence" / name).read_text()
            self.assertNotRegex(text, r"(?m)^\s*(from|import)\b[^\n]*\bmaintenance\b", name)
            self.assertNotIn("integrity_check", text)

    def test_the_vocabulary_is_translated_in_both_languages(self):
        en, he = catalogs()
        for label in LABELS:
            self.assertIn(f"sync.{label}", en)
            self.assertIn(f"sync.{label}", he)
            if label != "OK":
                self.assertIn(f"fresh.sync.{label}", en, label)
                self.assertIn(f"fresh.sync.{label}", he, label)
        for key in ("explain.SYNC_FROM_LOCAL_RECORDS", "fresh.sync.hint", "dt.sync", "dt.sync.checkpoint", "dt.sync.last", "dt.sync.hours", "dt.sync.never", "dt.sync.note", "dt.sync.note.label", "dt.maint", "dt.maint.hint"):
            self.assertIn(key, en)
            self.assertIn(key, he)
        self.assertTrue(re.search(r"[֐-׿]", he["fresh.sync.MISSING"]))
        self.assertIn("mailbox maintenance", en["fresh.sync.hint"])
        self.assertIn("mailbox maintenance", he["fresh.sync.hint"])

    def test_scan_and_sync_freshness_stay_separate_and_both_languages_explain_it(self):
        env = self.fresh(now=self.clock.now + timedelta(hours=30))  # 30 h: past the 24 h sync threshold, far inside the 7-day scan threshold
        self.assertEqual(env["data"]["sync"]["state"], "STALE")
        self.assertFalse(env["data"]["sync"]["healthy"])
        self.assertNotIn("STALE", env["data"]["state"].upper().split("_"))  # the scan-based state is untouched by the sync threshold
        self.assertFalse([i for i in env["data"]["issues"] if "SYNC" in i.upper()])  # sync freshness never leaks into the scan health issues
        self.assertEqual((analytics.STALE_DAYS, sync_health.SYNC_MAX_AGE), (7, timedelta(hours=24)))  # neither threshold moved
        en, he = catalogs()
        for lang, cat in (("en", en), ("he", he)):
            note = cat["dt.sync.note"]
            self.assertTrue(cat["dt.sync.note.label"], lang)
            self.assertIn("7", note, lang)
            self.assertIn("24", note, lang)
        self.assertTrue(re.search(r"[֐-׿]", he["dt.sync.note"]))
        self.assertFalse(re.search(r"[֐-׿]", en["dt.sync.note"]))
        self.assertIn('t("dt.sync.note")', (STATIC / "js/views.js").read_text(encoding="utf-8"))

    def test_the_screens_use_only_text_nodes_and_local_assets(self):
        views, comps = (STATIC / "js/views.js").read_text(encoding="utf-8"), (STATIC / "js/components.js").read_text(encoding="utf-8")
        self.assertIn('code("fresh.sync", sync.state)', comps)
        self.assertIn('t("dt.sync")', views)
        self.assertIn("gmail-intelligence mailbox maintenance", views)
        for src in (views, comps):
            self.assertNotRegex(src, r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function")
            self.assertNotRegex(src, r"https?://")


class ServerSyncTests(TDS.ServerBase):
    def test_the_freshness_route_carries_the_sync_block_and_no_route_was_added(self):
        status, headers, body = self.api("freshness")
        self.assertEqual(status, 200)
        self.assertEqual((body["data"]["sync"]["state"], body["data"]["sync"]["checkpoint"]), ("OK", "present"))
        self.index.conn.execute("DELETE FROM sync_state")
        self.index.conn.commit()
        body = self.api("freshness")[2]
        self.assertEqual((body["data"]["sync"]["state"], body["data"]["sync"]["checkpoint"]), ("MISSING", "missing"))
        self.assertEqual(set(ds.ROUTES), {"meta", "freshness", "overview", "volume", "categories", "senders", "subscriptions", "cleanup/summary", "cleanup/history", "organization",
                                          "attention"})  # M7C added no route; the only later addition is the M8A-3 attention route
        self.assertFalse(any("maint" in r or "sync" in r for r in ds.ROUTES))

    def test_security_rules_are_unchanged_for_the_freshness_route(self):
        self.assertEqual(self.get("/api/v1/freshness", token=False)[0], 401)
        self.assertNotEqual(self.get("/api/v1/freshness", host="evil.example")[0], 200)                       # DNS-rebinding style Host
        self.assertNotEqual(self.get("/api/v1/freshness", headers={"Origin": TDS.EVIL})[0], 200)
        status, headers, body = self.get("/api/v1/freshness")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers.get("content-security-policy", "") + "default-src 'none'")
        self.assertNotIn("access-control-allow-origin", headers)                                                # still no CORS
        dump = json.dumps(self.api("freshness")[2])
        self.assertNotIn(TDS.ACCT, dump)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            self.assertNotEqual(self.get("/api/v1/freshness", method=method)[0], 200)


if __name__ == "__main__":
    unittest.main()
