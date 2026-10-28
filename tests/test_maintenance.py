"""M7C: `mailbox maintenance` - local, user-triggered, READ-ONLY integrity checks and advisory report. Synthetic databases and backups in temp directories only.

Every finding is checked for code, severity, certainty and a manual recommendation; the report is checked to change nothing (hashes, mtimes, directory listing,
the SQL it runs), to contact no Gmail, and never to echo stored text.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import test_cleanup_exec as TCE
from test_cleanup import ACCT, msg
from test_cleanup_plans import T0

from sync_support import ACCOUNT, HERE, SRC, SyncCase, config, fast_limiter, file_digest, idx, scanner, sync_health, sync_lease
import m7_support
from fake_history import FakeHistoryMailbox, standard_mailbox
from gmail_intelligence import cleanup_plans as cp, cli, maintenance, sync

SEVERITIES = {"INFO": 3, "WARN": 2, "ERROR": 1, "CRITICAL": 0}
LEAK = "S3cretPersonalValue99"


class Crash(BaseException):
    pass


def downgrade_to_v6(path):
    c = sqlite3.connect(path)
    for t in ("sync_state", "sync_run", "message_tombstone"):
        c.execute(f"DROP TABLE {t}")
    c.execute("PRAGMA user_version = 6")
    c.commit()
    c.close()


def tree_state(directory):
    """(name, size, mtime_ns, mode, sha256) of every entry: any change by the report would show here."""
    out = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        st = os.lstat(p)
        digest = None
        if os.path.isfile(p) and not os.path.islink(p):
            with open(p, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
        out.append((name, st.st_size, st.st_mtime_ns, st.st_mode, digest))
    return out


class Case(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)

    def run_m(self, deep=False, account=ACCOUNT, now=None):
        self.index.conn.commit()
        return maintenance.run(self.db, account, deep=deep, now=now or self.clock.now)

    def by_code(self, rep):
        return {f["code"]: f for f in rep["findings"]}

    def assertFinding(self, rep, code, severity, certainty, count=None):
        f = self.by_code(rep).get(code)
        self.assertIsNotNone(f, f"{code} not reported; got {sorted(self.by_code(rep))}")
        self.assertEqual((f["severity"], f["certainty"]), (severity, certainty), code)
        self.assertTrue(f["explanation"] and f["recommendation"] and f["category"] in "ABCDE", code)
        if count is not None:
            self.assertEqual(f.get("count"), count, code)
        return f

    def assertNoFinding(self, rep, code):
        self.assertNotIn(code, self.by_code(rep))

    def sql(self, *statements):
        with self.index.conn:
            for s in statements:
                self.index.conn.execute(*s) if isinstance(s, tuple) else self.index.conn.execute(s)


class HealthyTests(Case):
    def test_a_valid_synced_index_has_no_problems_and_keeps_the_four_properties_apart(self):
        self.mailbox.add("n1")
        self.sync()
        for deep in (False, True):
            rep = self.run_m(deep=deep)
            self.assertEqual((rep["mode"], rep["read_only"], rep["gmail_contacted"]), ("deep" if deep else "quick", True, False))
            p = rep["properties"]
            self.assertEqual((p["local_database"]["status"], p["local_database"]["schema_version"]), ("HEALTHY", 7))
            self.assertEqual((p["mailbox_index_freshness"]["status"], p["mailbox_index_freshness"]["codes"]), ("FRESH", []))
            self.assertEqual((p["backups"]["status"], p["m4_plan_operations"]["status"], p["audit_chain"]["status"]), ("NONE_FOUND", "ALLOWED_BY_INDEX_FRESHNESS", "NO_EVENTS"))
            self.assertEqual(rep["overall"], "INFO")
            self.assertEqual(sorted(self.by_code(rep)), ["HISTORY_RETENTION_UNCERTAIN", "NO_BACKUPS_FOUND"])
            self.assertIn("Gmail itself was not contacted or verified", " ".join(rep["limits"]))
            self.assertIn("not proof", " ".join(rep["limits"]))

    def test_findings_are_complete_sorted_and_the_text_distinguishes_the_properties(self):
        text = maintenance.render_text(self.run_m())
        for needle in ("local database:", "mailbox index fresh:", "backups:", "cleanup plan operations:", "audit chain:", "Gmail is not verified", "Suggested (manual):", "Limits:"):
            self.assertIn(needle, text)
        rep = self.run_m()
        order = [(SEVERITIES[f["severity"]], f["code"]) for f in rep["findings"]]
        self.assertEqual(order, sorted(order))


class SqliteIntegrityTests(Case):
    def test_missing_unreadable_and_garbage_files(self):
        self.index.close()
        os.remove(self.db)
        self.assertFinding(maintenance.run(self.db, ACCOUNT, now=self.clock.now), "INDEX_MISSING", "WARN", "OBSERVED")
        Path(self.db).write_bytes(b"this is not a sqlite database at all" * 200)
        rep = maintenance.run(self.db, ACCOUNT, now=self.clock.now)
        self.assertFinding(rep, "INDEX_UNREADABLE_OR_CORRUPT", "CRITICAL", "OBSERVED")
        self.assertEqual((rep["overall"], rep["properties"]["local_database"]["status"]), ("CRITICAL", "PROBLEMS_DETECTED"))
        self.assertEqual(rep["properties"]["mailbox_index_freshness"]["status"], "UNKNOWN")      # nothing is claimed about what could not be read
        os.chmod(self.db, 0o000)
        self.addCleanup(lambda: os.path.exists(self.db) and os.chmod(self.db, 0o600))
        self.assertFinding(maintenance.run(self.db, ACCOUNT, now=self.clock.now), "INDEX_NOT_READABLE", "ERROR", "OBSERVED")
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")

    def zero_version_file(self, data_tables=True):
        self.index.close()
        os.remove(self.db)
        c = sqlite3.connect(self.db)
        if data_tables:
            c.execute("CREATE TABLE notes (x TEXT)")
            c.execute("INSERT INTO notes VALUES ('S3cretPersonalValue99')")
        c.commit()
        c.close()
        os.chmod(self.db, 0o600)
        with contextlib.closing(sqlite3.connect(self.db)) as probe:
            self.assertEqual(probe.execute("PRAGMA user_version").fetchone()[0], 0)

    def test_a_valid_sqlite_file_with_schema_version_zero_is_not_called_healthy(self):
        for with_tables in (True, False):
            self.zero_version_file(with_tables)
            before = tree_state(self.tmp)
            for deep in (False, True):
                rep = maintenance.run(self.db, ACCOUNT, deep=deep, now=self.clock.now)
                db = rep["properties"]["local_database"]
                self.assertEqual((db["sqlite_integrity"], db["application_schema"], db["status"], db["schema_version"]), ("OK", "UNRECOGNISED", "UNSUPPORTED_SCHEMA", 0))
                self.assertNotEqual(db["status"], "HEALTHY")
                f = self.assertFinding(rep, "INDEX_SCHEMA_UNRECOGNISED", "WARN", "OBSERVED")
                self.assertIn("changed nothing", f["recommendation"])
                for code in ("SQLITE_INTEGRITY_FAILED", "INDEX_UNREADABLE_OR_CORRUPT", "INDEX_SCHEMA_OLD"):
                    self.assertNoFinding(rep, code)                       # structure is fine; only the application schema is unrecognised
                self.assertFalse([c for c in self.by_code(rep) if c.startswith(("ORPHAN", "INVALID_SCAN", "TOMBSTONE", "CHECKPOINT", "SYNC_", "AUDIT"))])   # row-level M7 checks skipped
                self.assertEqual(rep["properties"]["mailbox_index_freshness"]["status"], "UNKNOWN")
                text = maintenance.render_text(rep)
                self.assertIn("UNSUPPORTED_SCHEMA", text)
                self.assertIn("SQLite integrity OK", text)
                blob = text + json.dumps(rep)
                for needle in ("S3cretPersonalValue99", "notes", self.db, str(self.tmp)):
                    self.assertNotIn(needle, blob)
            self.assertEqual(before, tree_state(self.tmp))                # not migrated, not touched
            c = sqlite3.connect(self.db)
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 0)
            c.close()
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")


    def test_integrity_and_schema_are_separate_conclusions_for_every_schema_state(self):
        expect = {7: ("OK", "SUPPORTED", "HEALTHY")}
        rep = self.run_m()
        db = rep["properties"]["local_database"]
        self.assertEqual((db["sqlite_integrity"], db["application_schema"], db["status"]), expect[7])
        self.index.close()
        downgrade_to_v6(self.db)
        db = maintenance.run(self.db, ACCOUNT, now=self.clock.now)["properties"]["local_database"]
        self.assertEqual((db["sqlite_integrity"], db["application_schema"], db["status"]), ("OK", "OLDER", "UNSUPPORTED_SCHEMA"))
        c = sqlite3.connect(self.db)
        c.execute("PRAGMA user_version = 9")
        c.commit()
        c.close()
        db = maintenance.run(self.db, ACCOUNT, now=self.clock.now)["properties"]["local_database"]
        self.assertEqual((db["sqlite_integrity"], db["application_schema"], db["status"]), ("OK", "NEWER", "UNSUPPORTED_SCHEMA"))
        Path(self.db).write_bytes(b"garbage" * 500)
        db = maintenance.run(self.db, ACCOUNT, now=self.clock.now)["properties"]["local_database"]
        self.assertEqual((db["sqlite_integrity"], db["application_schema"], db["status"]), ("FAILED", "NOT_VERIFIED", "PROBLEMS_DETECTED"))
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")

    def test_the_cli_reports_schema_zero_without_touching_the_file(self):
        env = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.tmp / "zero-home")})
        env.start()
        self.addCleanup(env.stop)
        os.makedirs(config.app_dir(), exist_ok=True)
        c = sqlite3.connect(config.index_path())
        c.execute("CREATE TABLE t (x)")
        c.commit()
        c.close()
        os.chmod(config.index_path(), 0o600)
        store = mock.Mock()
        store.load.return_value = {"account": ACCOUNT}
        before = tree_state(config.app_dir())
        out = io.StringIO()
        with mock.patch.object(cli, "_store", return_value=store), mock.patch.object(cli, "_open_reader", side_effect=AssertionError("no Gmail")), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["mailbox", "maintenance", "--json"]), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["properties"]["local_database"]["status"], "UNSUPPORTED_SCHEMA")
        self.assertEqual(before, tree_state(config.app_dir()))


    def test_a_damaged_page_is_detected_by_the_deep_check_without_revealing_values(self):
        self.sql(("UPDATE messages SET sender=?", (f"{LEAK}@private.example.test",)))
        self.index.conn.execute("PRAGMA wal_checkpoint")
        self.index.close()
        raw = bytearray(Path(self.db).read_bytes())
        pages = len(raw) // 4096
        for page in range(2, pages):                                   # damage every data page after the schema page
            raw[page * 4096 + 100: page * 4096 + 140] = b"\xff" * 40
        Path(self.db).write_bytes(bytes(raw))
        rep = maintenance.run(self.db, ACCOUNT, deep=True, now=self.clock.now)
        self.assertEqual(rep["overall"], "CRITICAL")
        self.assertTrue({"SQLITE_INTEGRITY_FAILED", "INDEX_UNREADABLE_OR_CORRUPT"} & set(self.by_code(rep)))
        blob = maintenance.render_text(rep) + json.dumps(rep)
        for needle in (LEAK, "private.example", self.db, str(self.tmp)):
            self.assertNotIn(needle, blob)
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")

    def corrupt_index_entry(self, path):
        """Change one byte of one key INSIDE the messages_sender index page so the index no longer matches its table (the b-tree itself stays well formed)."""
        c = sqlite3.connect(path)
        root = c.execute("SELECT rootpage FROM sqlite_master WHERE name='messages_sender'").fetchone()[0]
        size = c.execute("PRAGMA page_size").fetchone()[0]
        c.close()
        raw = bytearray(Path(path).read_bytes())
        start = (root - 1) * size
        at = raw[start:start + size].find(b"m005@sender.example.test")
        self.assertGreater(at, 0)
        raw[start + at + 23] = ord("u")
        Path(path).write_bytes(bytes(raw))

    def test_the_deep_check_finds_what_the_quick_check_misses(self):
        self.index.close()
        self.corrupt_index_entry(self.db)
        quick = maintenance.run(self.db, ACCOUNT, deep=False, now=self.clock.now)
        self.assertNotIn("SQLITE_INTEGRITY_FAILED", self.by_code(quick))                  # quick_check does not compare indexes with their tables
        self.assertEqual(quick["properties"]["local_database"]["status"], "HEALTHY")
        deep = maintenance.run(self.db, ACCOUNT, deep=True, now=self.clock.now)
        f = self.assertFinding(deep, "SQLITE_INTEGRITY_FAILED", "CRITICAL", "OBSERVED", count=1)
        self.assertEqual(deep["properties"]["local_database"]["status"], "PROBLEMS_DETECTED")
        self.assertNotIn("messages_sender", json.dumps(deep) + maintenance.render_text(deep))   # SQLite's own message (it names the index and a row) is never shown
        self.assertIn("No repair was attempted", f["recommendation"])
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")

    def test_the_same_holds_for_a_backup(self):
        path = f"{self.db}.pre-m7-backup-20261020T110000Z"
        src, dest = sqlite3.connect(self.db), sqlite3.connect(path)
        src.backup(dest)
        dest.close()
        src.close()
        downgrade_to_v6(path)
        os.chmod(path, 0o600)
        self.corrupt_index_entry(path)
        self.assertNoFinding(self.run_m(deep=False), "BACKUP_CORRUPT")
        self.assertFinding(self.run_m(deep=True), "BACKUP_CORRUPT", "ERROR", "OBSERVED", count=1)

    def test_foreign_key_violations_are_reported_by_table_only(self):
        self.index.conn.execute("PRAGMA foreign_keys = OFF")                  # the writer connection normally refuses this; a damaged file would not
        self.sql("DROP TRIGGER cleanup_item_only_in_draft",
                 ("INSERT INTO cleanup_item VALUES (?,?,?,?,?)", (ACCOUNT, "plan-ghost", "m1", "t1", "0" * 64)))
        rep = self.run_m()
        f = self.assertFinding(rep, "FOREIGN_KEY_VIOLATIONS", "ERROR", "OBSERVED", count=1)
        self.assertEqual(f["detail"], {"cleanup_item": 1})
        self.assertEqual(rep["properties"]["local_database"]["status"], "PROBLEMS_DETECTED")
        self.assertNotIn("plan-ghost", json.dumps(rep))

    def test_an_older_or_newer_schema_skips_row_checks_and_says_how_to_upgrade(self):
        self.index.close()
        downgrade_to_v6(self.db)
        rep = maintenance.run(self.db, ACCOUNT, now=self.clock.now)
        f = self.assertFinding(rep, "INDEX_SCHEMA_OLD", "WARN", "OBSERVED")
        self.assertIn("index upgrade", f["recommendation"])
        self.assertNotIn("ORPHAN_MESSAGE_LABELS", self.by_code(rep))
        c = sqlite3.connect(self.db)
        c.execute("PRAGMA user_version = 9")
        c.commit()
        c.close()
        self.assertFinding(maintenance.run(self.db, ACCOUNT, now=self.clock.now), "INDEX_SCHEMA_NEWER", "ERROR", "OBSERVED")
        self.index = idx.Index.__new__(idx.Index)
        self.index.conn = sqlite3.connect(":memory:")

    def test_open_permissions_on_the_index_are_flagged_not_changed(self):
        os.chmod(self.db, 0o644)
        rep = self.run_m()
        self.assertFinding(rep, "INDEX_PERMISSIONS_TOO_OPEN", "WARN", "OBSERVED")
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o644)

    def test_a_journal_file_means_the_index_is_not_opened_at_all(self):
        Path(self.db + "-journal").write_bytes(b"x" * 64)
        before = tree_state(self.tmp)
        rep = self.run_m()
        self.assertFinding(rep, "INDEX_AUX_FILES_PRESENT", "WARN", "UNKNOWN")
        self.assertEqual(rep["properties"]["local_database"]["status"], "NOT_VERIFIED")
        self.assertEqual(rep["properties"]["mailbox_index_freshness"]["status"], "UNKNOWN")
        self.assertEqual(before, tree_state(self.tmp))


class RowConsistencyTests(Case):
    def test_orphans_are_errors(self):
        self.sql(("INSERT INTO message_labels VALUES (?,?,?)", (ACCOUNT, "ghost-1", "INBOX")),
                 ("INSERT INTO message_labels VALUES (?,?,?)", (ACCOUNT, "ghost-2", "INBOX")),
                 ("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)", (ACCOUNT, "ghost-1", "type", "PROMOTIONAL", "HIGH", "rule", "r", "x", "h", 1, "2026-01-01")))
        rep = self.run_m()
        self.assertFinding(rep, "ORPHAN_MESSAGE_LABELS", "ERROR", "OBSERVED", count=2)
        self.assertFinding(rep, "ORPHAN_CLASSIFICATIONS", "ERROR", "OBSERVED", count=1)
        self.assertNotIn("ghost-1", json.dumps(rep))

    def test_unknown_label_references_are_only_a_possibility(self):
        self.sql(("UPDATE message_labels SET label_id='Label_gone' WHERE message_id='m001' AND label_id='INBOX'",))
        f = self.assertFinding(self.run_m(), "LABEL_REFERENCES_UNKNOWN_LABEL", "WARN", "INFERRED", count=1)
        self.assertIn("Possible", f["explanation"])

    def test_invalid_scan_references_positive_negative_and_zero(self):
        self.sql(("UPDATE messages SET scan_id=9999 WHERE id='m001'",), ("UPDATE messages SET scan_id=-9999 WHERE id='m002'",), ("UPDATE messages SET scan_id=0 WHERE id='m003'",))
        rep = self.run_m()
        self.assertFinding(rep, "INVALID_SCAN_REFERENCE_POSITIVE", "ERROR", "OBSERVED", count=1)
        self.assertFinding(rep, "INVALID_SCAN_REFERENCE_NEGATIVE", "ERROR", "OBSERVED", count=1)
        self.assertFinding(rep, "INVALID_SCAN_REFERENCE_ZERO", "ERROR", "OBSERVED", count=1)

    def test_valid_negative_stamps_from_real_sync_runs_are_not_flagged(self):
        self.mailbox.labels_change("m001", add=("STARRED",))
        self.sync()
        self.assertEqual(self.index._q("SELECT scan_id FROM messages WHERE id='m001'")[0][0] < 0, True)
        rep = self.run_m()
        for code in ("INVALID_SCAN_REFERENCE_POSITIVE", "INVALID_SCAN_REFERENCE_NEGATIVE", "CLASSIFICATION_REFERENCES_MISSING_SCAN"):
            self.assertNoFinding(rep, code)

    def test_classification_that_points_at_a_missing_scan(self):
        self.sql(("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)", (ACCOUNT, "m001", "type", "PROMOTIONAL", "HIGH", "rule", "r", "x", "h", 4242, "2026-01-01")))
        self.assertFinding(self.run_m(), "CLASSIFICATION_REFERENCES_MISSING_SCAN", "WARN", "OBSERVED", count=1)

    def test_tombstone_and_message_contradiction_is_a_possibility_not_a_verdict(self):
        self.sql(("INSERT INTO message_tombstone VALUES (?,?,?,?,?)", (ACCOUNT, "m001", "2026-10-20T12:00:00Z", "HISTORY_DELETED", None)),
                 ("INSERT INTO message_tombstone VALUES (?,?,?,?,?)", (ACCOUNT, "x-gone", "2026-10-20T12:00:00Z", "FULL_RECONCILE", 4242)))
        rep = self.run_m()
        f = self.assertFinding(rep, "TOMBSTONE_MESSAGE_CONTRADICTION", "WARN", "OBSERVED", count=1)
        self.assertIn("possible false deletion", f["explanation"])
        self.assertIn("scan --all", f["recommendation"])
        self.assertFinding(rep, "TOMBSTONE_RUN_MISSING", "WARN", "OBSERVED", count=1)

    def test_checkpoint_lineage_problems(self):
        self.sql("UPDATE sync_state SET basis_scan_id=777")
        rep = self.run_m()
        self.assertFinding(rep, "CHECKPOINT_BASELINE_MISSING", "ERROR", "OBSERVED")
        self.assertFinding(rep, "SYNC_STATE_INCONSISTENT", "ERROR", "OBSERVED")
        self.sql(("UPDATE sync_state SET basis_scan_id=?", (self.index._q("SELECT MAX(id) FROM scans")[0][0],)), "UPDATE scans SET mode='limited'")
        self.assertFinding(self.run_m(), "CHECKPOINT_BASELINE_NOT_COMPLETED_FULL", "ERROR", "OBSERVED")

    def test_a_run_that_points_at_a_missing_scan(self):
        self.sql("UPDATE sync_run SET scan_id=5555")
        self.assertFinding(self.run_m(), "SYNC_RUN_SCAN_MISSING", "WARN", "OBSERVED")

    def test_an_account_without_data_is_reported_as_such(self):
        self.assertFinding(self.run_m(account="nobody@example.test"), "NO_DATA_FOR_ACCOUNT", "INFO", "OBSERVED")

    def test_no_account_means_file_level_checks_only(self):
        rep = maintenance.run(self.db, None, now=self.clock.now)
        self.assertFinding(rep, "ACCOUNT_UNKNOWN", "INFO", "OBSERVED")
        self.assertEqual(rep["properties"]["local_database"]["status"], "HEALTHY")

    def test_accounts_are_isolated_for_row_level_checks_but_file_level_ones_apply_to_all(self):
        other = "second.owner@example.test"
        self.index.conn.execute("PRAGMA foreign_keys = OFF")
        self.sql(("INSERT INTO message_labels VALUES (?,?,?)", (other, "ghost", "INBOX")), "DROP TRIGGER cleanup_item_only_in_draft",
                 ("INSERT INTO cleanup_item VALUES (?,?,?,?,?)", (other, "plan-ghost", "m1", "t1", "0" * 64)))
        mine, theirs = self.run_m(), self.run_m(account=other)
        self.assertNoFinding(mine, "ORPHAN_MESSAGE_LABELS")
        self.assertFinding(theirs, "ORPHAN_MESSAGE_LABELS", "ERROR", "OBSERVED", count=1)
        self.assertFinding(mine, "FOREIGN_KEY_VIOLATIONS", "ERROR", "OBSERVED")       # the foreign-key check is a property of the FILE
        self.assertFinding(theirs, "FOREIGN_KEY_VIOLATIONS", "ERROR", "OBSERVED")


class ScanAndSyncTests(Case):
    def test_no_baseline_scan(self):
        other = idx.Index(str(self.tmp / "empty.sqlite3"))
        other.close()
        with contextlib.closing(sqlite3.connect(str(self.tmp / "empty.sqlite3"))) as c, c:
            c.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'limited', 'completed', '2026-10-20T10:00:00Z')", (ACCOUNT,))
        rep = maintenance.run(str(self.tmp / "empty.sqlite3"), ACCOUNT, now=self.clock.now)
        f = self.assertFinding(rep, "NO_BASELINE_SCAN", "WARN", "OBSERVED")
        self.assertIn("scan --all", f["recommendation"])
        self.assertEqual(rep["properties"]["m4_plan_operations"]["status"], "BLOCKED_BY_INDEX_FRESHNESS")

    def test_full_scans_without_a_checkpoint(self):
        self.sql("DELETE FROM sync_state")
        self.assertFinding(self.run_m(), "CHECKPOINT_MISSING", "WARN", "OBSERVED")

    def test_unfinished_and_failed_scans(self):
        self.sql("INSERT INTO scans (account, mode, status, started_at, failed) VALUES ('%s', 'full', 'incomplete', '2026-10-20T13:00:00Z', 3)" % ACCOUNT)
        rep = self.run_m()
        self.assertFinding(rep, "FULL_SCAN_UNFINISHED", "WARN", "OBSERVED")
        self.assertFinding(rep, "SCAN_FAILED_REFRESHES", "WARN", "OBSERVED", count=1)

    def test_failed_and_interrupted_sync_runs(self):
        self.mailbox.add("n1")
        self.mailbox.faults["get_message_metadata"] = [__import__("gmail_intelligence.gmail", fromlist=["x"]).GmailApiError("bad", 400)]
        with self.assertRaises(sync_lease.SyncError):
            self.sync()
        rep = self.run_m()
        self.assertFinding(rep, "SYNC_INTERRUPTED", "WARN", "OBSERVED")
        self.assertFinding(rep, "LATEST_RUN_NOT_COMPLETED", "WARN", "OBSERVED")
        self.assertFinding(rep, "SYNC_RUN_FAILED_REFRESHES", "WARN", "OBSERVED", count=1)

    def test_an_active_lease_is_information_and_an_expired_one_proves_nothing(self):
        self.mailbox.add("n1")
        with self.assertRaises(Crash):
            self.sync(hook=lambda p: (_ for _ in ()).throw(Crash()) if p == "collected" else None)
        sync_lease.release(self.index)
        rep = self.run_m()
        self.assertFinding(rep, "SYNC_RUN_ACTIVE", "INFO", "OBSERVED", count=1)
        self.assertNoFinding(rep, "SYNC_LEASE_EXPIRED")
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)
        rep = self.run_m()
        f = self.assertFinding(rep, "SYNC_LEASE_EXPIRED", "WARN", "INFERRED", count=1)
        self.assertIn("does not prove the process stopped", f["explanation"])
        self.assertNotIn("dead", json.dumps(rep).lower())
        self.assertNoFinding(rep, "SYNC_RUN_ACTIVE")

    def test_stale_and_possibly_expired_checkpoints(self):
        self.clock.advance(25 * 3600)
        rep = self.run_m()
        self.assertFinding(rep, "CHECKPOINT_STALE", "WARN", "OBSERVED")
        self.assertNoFinding(rep, "CHECKPOINT_MAY_EXPIRE")
        self.clock.advance(5 * 24 * 3600)
        f = self.assertFinding(self.run_m(), "CHECKPOINT_MAY_EXPIRE", "WARN", "INFERRED")
        self.assertIn("possibility, not a fact", f["explanation"])
        self.clock.advance(3 * 24 * 3600)
        f = self.assertFinding(self.run_m(), "CHECKPOINT_LIKELY_EXPIRED", "ERROR", "INFERRED")
        self.assertIn("Not verified", f["explanation"])

    def test_needs_reconcile_and_inconsistency(self):
        self.sql("UPDATE sync_state SET status='NEEDS_RECONCILE', reason='HISTORY_EXPIRED'")
        rep = self.run_m()
        self.assertFinding(rep, "SYNC_NEEDS_RECONCILE", "WARN", "OBSERVED")
        self.assertEqual(rep["properties"]["mailbox_index_freshness"]["status"], "NOT_FRESH")
        self.sql("UPDATE sync_state SET status='IN_PROGRESS'")
        self.assertFinding(self.run_m(), "SYNC_STATE_INCONSISTENT", "ERROR", "OBSERVED")

    def test_history_retention_is_always_uncertain(self):
        f = self.assertFinding(self.run_m(), "HISTORY_RETENTION_UNCERTAIN", "INFO", "UNKNOWN")
        self.assertIn("does not guarantee", f["explanation"])


class BackupTests(Case):
    def make_backup(self, tag="pre-m7", stamp="20261020T110000Z", version=6, mode=0o600, suffix=""):
        path = f"{self.db}.{tag}-backup-{stamp}{suffix}"
        src = sqlite3.connect(self.db)
        dest = sqlite3.connect(path)
        src.backup(dest)
        dest.close()
        src.close()
        if version == 6:
            downgrade_to_v6(path)
        os.chmod(path, mode)
        return path

    def test_an_unknown_version_tag_is_never_verified_never_counted_and_never_opened(self):
        path = self.make_backup(tag="pre-m99")                         # a perfectly valid SQLite file, but this tool does not know that tag
        real, opened = sqlite3.connect, []
        before = tree_state(self.tmp)
        for deep in (False, True):
            with mock.patch.object(maintenance.sqlite3, "connect", lambda target, *a, **k: (opened.append(target), real(target, *a, **k))[1]):
                rep = self.run_m(deep=deep)
            b = rep["properties"]["backups"]
            item = b["items"][0]
            self.assertEqual((item["status"], item["schema_version"], item["expected_schema_version"]), ("UNSUPPORTED_TAG", None, None))
            self.assertEqual((b["found"], b["verified"], b["status"]), (1, 0, "NOT_FULLY_VERIFIED"))
            self.assertNotEqual(b["status"], "ALL_VERIFIED")
            self.assertNoFinding(rep, "BACKUPS_VERIFIED")
            f = self.assertFinding(rep, "BACKUP_UNSUPPORTED_TAG", "WARN", "UNKNOWN", count=1)
            self.assertIn("NOT verified", f["explanation"])
            for code in ("BACKUP_CORRUPT", "BACKUP_INVALID", "BACKUP_SCHEMA_VERSION_MISMATCH"):
                self.assertNoFinding(rep, code)                          # an unfamiliar tag is not evidence of damage
            blob = maintenance.render_text(rep) + json.dumps(rep)
            self.assertNotIn("pre-m99", blob)
            self.assertIn("UNSUPPORTED_TAG", blob)
        self.assertFalse([t for t in opened if "pre-m99" in str(t)])      # it was not even opened
        self.assertEqual(before, tree_state(self.tmp))

    def test_an_unknown_tag_beside_a_valid_backup_keeps_the_aggregate_honest(self):
        self.make_backup(stamp="20261020T110000Z")
        self.make_backup(tag="pre-m99", stamp="20261020T110001Z")
        corrupt = self.make_backup(tag="pre-m100", stamp="20261020T110002Z")
        Path(corrupt).write_bytes(b"not a database" * 100)             # even garbage under an unknown tag is not opened, so it is not called corrupt
        os.chmod(corrupt, 0o600)
        rep = self.run_m(deep=True)
        b = rep["properties"]["backups"]
        self.assertEqual((b["found"], b["verified"], b["status"]), (3, 1, "NOT_FULLY_VERIFIED"))
        self.assertFinding(rep, "BACKUPS_VERIFIED", "INFO", "OBSERVED", count=1)
        self.assertFinding(rep, "BACKUP_UNSUPPORTED_TAG", "WARN", "UNKNOWN", count=2)
        self.assertNoFinding(rep, "BACKUP_INVALID")
        self.assertEqual(sorted(i["status"] for i in b["items"]), ["UNSUPPORTED_TAG", "UNSUPPORTED_TAG", "VERIFIED"])

    def test_a_recognised_valid_backup_is_unchanged_by_this_rule(self):
        self.make_backup()
        rep = self.run_m(deep=True)
        self.assertEqual(rep["properties"]["backups"]["status"], "ALL_VERIFIED")
        self.assertNoFinding(rep, "BACKUP_UNSUPPORTED_TAG")

    def test_absence_is_information_not_corruption(self):
        rep = self.run_m()
        f = self.assertFinding(rep, "NO_BACKUPS_FOUND", "INFO", "OBSERVED")
        self.assertIn("not a fault", f["explanation"])
        self.assertEqual(rep["properties"]["backups"]["status"], "NONE_FOUND")
        for code in ("BACKUP_CORRUPT", "BACKUP_INVALID", "BACKUP_UNREADABLE"):
            self.assertNoFinding(rep, code)

    def test_a_valid_backup_is_verified_quick_and_deep(self):
        self.make_backup()
        for deep in (False, True):
            rep = self.run_m(deep=deep)
            self.assertFinding(rep, "BACKUPS_VERIFIED", "INFO", "OBSERVED", count=1)
            b = rep["properties"]["backups"]
            self.assertEqual((b["status"], b["found"], b["verified"]), ("ALL_VERIFIED", 1, 1))
            self.assertEqual((b["items"][0]["tag"], b["items"][0]["schema_version"], b["items"][0]["expected_schema_version"], b["items"][0]["status"]), ("pre-m7", 6, 6, "VERIFIED"))
            self.assertIsNotNone(b["items"][0]["age_hours"])
            self.assertEqual(rep["overall"], "INFO")

    def test_wrong_permissions_wrong_schema_corruption_and_garbage(self):
        self.make_backup(stamp="20261020T110001Z", mode=0o644)
        self.make_backup(tag="pre-m5", stamp="20261020T110002Z", version=7)                      # a pre-m5 backup must be v5, this is v7
        corrupt = self.make_backup(stamp="20261020T110003Z")
        raw = bytearray(Path(corrupt).read_bytes())
        for page in range(2, len(raw) // 4096):
            raw[page * 4096 + 100: page * 4096 + 140] = b"\xff" * 40
        Path(corrupt).write_bytes(bytes(raw))
        garbage = f"{self.db}.pre-m7-backup-20261020T110004Z"
        Path(garbage).write_bytes(b"not a database" * 100)
        os.chmod(garbage, 0o600)
        rep = self.run_m(deep=True)
        self.assertFinding(rep, "BACKUP_PERMISSIONS_TOO_OPEN", "WARN", "OBSERVED", count=1)
        self.assertFinding(rep, "BACKUP_SCHEMA_VERSION_MISMATCH", "ERROR", "OBSERVED", count=1)
        self.assertTrue({"BACKUP_CORRUPT", "BACKUP_INVALID"} & set(self.by_code(rep)))
        self.assertFinding(rep, "BACKUP_INVALID", "ERROR", "OBSERVED")
        self.assertEqual(rep["properties"]["backups"]["status"], "PROBLEMS_DETECTED")

    def test_an_unreadable_backup_is_not_verified_rather_than_declared_corrupt(self):
        path = self.make_backup()
        os.chmod(path, 0o000)
        self.addCleanup(lambda: os.path.exists(path) and os.chmod(path, 0o600))
        rep = self.run_m()
        f = self.assertFinding(rep, "BACKUP_UNREADABLE", "WARN", "UNKNOWN", count=1)
        self.assertIn("not verified", f["explanation"])
        self.assertNoFinding(rep, "BACKUP_CORRUPT")
        self.assertNoFinding(rep, "BACKUP_INVALID")

    def test_aux_files_or_links_mean_the_backup_is_not_opened_and_nothing_is_touched(self):
        path = self.make_backup()
        Path(path + "-journal").write_bytes(b"x" * 32)
        link = f"{self.db}.pre-m4c-backup-20261020T110005Z"
        os.symlink(path, link)
        before = tree_state(self.tmp)
        rep = self.run_m(deep=True)
        self.assertFinding(rep, "BACKUP_NOT_VERIFIED_AUX_FILES", "WARN", "UNKNOWN", count=1)
        self.assertFinding(rep, "BACKUP_NOT_REGULAR_FILE", "WARN", "OBSERVED", count=1)
        self.assertEqual(before, tree_state(self.tmp))

    def test_backups_are_never_created_changed_or_deleted_and_never_named(self):
        a = self.make_backup(stamp="20261020T110006Z")
        b = self.make_backup(stamp="20261020T110007Z", mode=0o644)
        before = tree_state(self.tmp)
        rep = self.run_m(deep=True)
        self.assertEqual(before, tree_state(self.tmp))                                           # same bytes, mtimes, modes and directory listing
        blob = maintenance.render_text(rep) + json.dumps(rep)
        for needle in ("20261020T11", os.path.basename(self.db), str(self.tmp), "sqlite3."):
            self.assertNotIn(needle, blob)
        self.assertEqual(os.stat(b).st_mode & 0o777, 0o644)                                       # the open permissions were reported, not fixed

    def test_a_backup_is_a_separate_property_from_a_healthy_database(self):
        self.make_backup(mode=0o644)
        rep = self.run_m()
        p = rep["properties"]
        self.assertEqual(p["local_database"]["status"], "HEALTHY")
        self.assertEqual(p["backups"]["status"], "NOT_FULLY_VERIFIED")
        self.assertEqual(p["mailbox_index_freshness"]["status"], "FRESH")


class AuditAndExecutionTests(TCE.ExecBase):
    def setUp(self):
        super().setUp()
        m7_support.seed_healthy_sync(self.index, ACCT, at=T0)       # the fixture's clock is in 2027: give the checkpoint a matching age

    def run_m(self, deep=False):
        return maintenance.run(self.index.path, ACCT, deep=deep, now=self.t)

    def by_code(self, rep):
        return {f["code"]: f for f in rep["findings"]}

    def test_a_continuous_chain_and_its_documented_limit(self):
        self.approved_plan()
        rep = self.run_m()
        a = rep["properties"]["audit_chain"]
        self.assertEqual(a["status"], "CONTINUOUS")
        self.assertGreaterEqual(a["events"], 3)
        f = self.by_code(rep)["AUDIT_TAIL_NOT_VERIFIABLE"]
        self.assertEqual((f["severity"], f["certainty"]), ("INFO", "UNKNOWN"))
        self.assertIn("external checkpoint", f["explanation"])
        self.assertNotIn("AUDIT_CHAIN_BROKEN", self.by_code(rep))

    def test_a_broken_chain_is_critical_and_never_repaired(self):
        self.approved_plan()
        with self.index.conn:
            self.index.conn.execute("DROP TRIGGER cleanup_audit_no_update")
            self.index.conn.execute("UPDATE cleanup_audit SET at='2000-01-01T00:00:00.000000Z' WHERE seq=(SELECT MIN(seq) FROM cleanup_audit)")
        rows_before = [tuple(r) for r in self.index.conn.execute("SELECT * FROM cleanup_audit ORDER BY seq")]
        rep = self.run_m()
        f = self.by_code(rep)["AUDIT_CHAIN_BROKEN"]
        self.assertEqual((f["severity"], f["certainty"]), ("CRITICAL", "OBSERVED"))
        self.assertIn("restoring a verified backup after review", f["recommendation"])
        self.assertEqual(rep["properties"]["audit_chain"]["status"], "BROKEN")
        self.assertEqual(rep["overall"], "CRITICAL")
        self.assertEqual(rows_before, [tuple(r) for r in self.index.conn.execute("SELECT * FROM cleanup_audit ORDER BY seq")])

    def test_deleting_the_newest_entries_is_NOT_detected(self):
        """The documented limit: a hash chain cannot show that its tail was cut off."""
        self.approved_plan()
        with self.index.conn:
            self.index.conn.execute("DROP TRIGGER cleanup_audit_no_delete")
            self.index.conn.execute("DELETE FROM cleanup_audit WHERE seq=(SELECT MAX(seq) FROM cleanup_audit)")
        rep = self.run_m()
        self.assertEqual(rep["properties"]["audit_chain"]["status"], "CONTINUOUS")
        self.assertIn("AUDIT_TAIL_NOT_VERIFIABLE", self.by_code(rep))

    def test_open_and_reconciliation_required_executions(self):
        plan = self.approved_plan()
        ex = self.reserve(plan)
        rep = self.run_m()
        f = self.by_code(rep)["EXECUTION_OPEN"]
        self.assertEqual((f["severity"], f["certainty"], f["count"]), ("WARN", "OBSERVED", 1))
        self.assertIn("Finish or abort it deliberately; this command never does", f["recommendation"])
        with self.index.conn:
            for t in [r[0] for r in self.index.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'cleanup_exec%'")]:
                self.index.conn.execute(f"DROP TRIGGER {t}")
            self.index.conn.execute("UPDATE cleanup_execution SET state='RECONCILIATION_REQUIRED'")
        rep = self.run_m()
        f = self.by_code(rep)["EXECUTION_RECONCILIATION_REQUIRED"]
        self.assertEqual((f["severity"], f["certainty"]), ("WARN", "OBSERVED"))
        self.assertIn("cleanup exec show", f["recommendation"])
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_execution SET state='EXECUTED'")
        self.assertIn("EXECUTION_STATE_INCONSISTENT", self.by_code(self.run_m()))               # finished, yet items still pending

    def test_consumed_approval_without_an_execution(self):
        plan = self.approved_plan()
        with self.index.conn:
            self.index.conn.execute("DROP TRIGGER cleanup_approval_forward_only")
            self.index.conn.execute("UPDATE cleanup_approval SET status='CONSUMED'")
        f = self.by_code(self.run_m())["APPROVAL_CONSUMED_WITHOUT_EXECUTION"]
        self.assertEqual((f["severity"], f["certainty"]), ("ERROR", "OBSERVED"))

    def test_expected_history_is_not_misclassified_as_corruption(self):
        """Immutable plan items whose message has since left the index are normal history: INFO, never ERROR."""
        plan = self.approved_plan()
        with self.index.conn:
            self.index.conn.execute("DELETE FROM message_labels WHERE message_id=?", (self.ids[0],))
            self.index.conn.execute("DELETE FROM message_class WHERE message_id=?", (self.ids[0],))
            self.index.conn.execute("DELETE FROM messages WHERE id=?", (self.ids[0],))
            self.index.conn.execute("INSERT INTO message_tombstone VALUES (?,?,?,?,?)", (ACCT, self.ids[0], "2027-01-15T07:00:00Z", "HISTORY_DELETED", None))
        rep = self.run_m()
        f = self.by_code(rep)["PLAN_ITEMS_REFERENCE_REMOVED_MESSAGES"]
        self.assertEqual((f["severity"], f["certainty"], f["count"], f["detail"]), ("INFO", "OBSERVED", 1, {"with_deletion_record": 1, "without_deletion_record": 0}))
        self.assertIn("EXPECTED", f["explanation"])
        self.assertIn("not corruption", f["explanation"])
        for code in ("ORPHAN_MESSAGE_LABELS", "ORPHAN_CLASSIFICATIONS", "FOREIGN_KEY_VIOLATIONS", "TOMBSTONE_MESSAGE_CONTRADICTION"):
            self.assertNotIn(code, self.by_code(rep))
        self.assertNotIn(rep["overall"], ("ERROR", "CRITICAL"))
        self.assertEqual(rep["properties"]["local_database"]["status"], "HEALTHY")

    def test_plans_past_expiry_are_counted_but_not_expired(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:2], now=self.tick())
        events = self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0]
        rep = maintenance.run(self.index.path, ACCT, now=self.t + timedelta(hours=60))
        self.assertEqual(self.by_code(rep)["PLANS_PAST_EXPIRY_NOT_RECORDED"]["count"], 1)
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "DRAFT")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0], events)

    def test_plan_operations_are_a_separate_property(self):
        self.approved_plan()
        rep = self.run_m()
        self.assertEqual(rep["properties"]["m4_plan_operations"]["status"], "ALLOWED_BY_INDEX_FRESHNESS")
        self.assertIn("not the safety of any single plan", rep["properties"]["m4_plan_operations"]["note"])
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='INTERRUPTED'")
        self.assertEqual(self.run_m()["properties"]["m4_plan_operations"]["status"], "BLOCKED_BY_INDEX_FRESHNESS")


class ReadOnlyAndPrivacyTests(Case):
    ALLOWED_PRAGMAS = {"query_only", "user_version", "quick_check", "integrity_check", "foreign_key_check"}

    def prepare(self):
        self.mailbox.add("n1")
        self.mailbox.delete("m001")
        self.sync()
        TestBackups = BackupTests
        path = f"{self.db}.pre-m7-backup-20261020T110000Z"
        src = sqlite3.connect(self.db)
        dest = sqlite3.connect(path)
        src.backup(dest)
        dest.close()
        src.close()
        downgrade_to_v6(path)
        os.chmod(path, 0o644)
        self.index.conn.commit()

    def test_nothing_changes_not_a_byte_a_timestamp_a_mode_or_a_file(self):
        self.prepare()
        before = tree_state(self.tmp)
        for deep in (False, True, False):
            maintenance.run(self.db, ACCOUNT, deep=deep, now=self.clock.now)
        self.assertEqual(before, tree_state(self.tmp))
        self.assertEqual(os.listdir(self.tmp).count("index.sqlite3-journal"), 0)

    def test_only_read_only_connections_and_only_read_statements(self):
        self.prepare()
        real, seen, statements = sqlite3.connect, [], []

        def spy(target, *a, **kw):
            seen.append((target, kw))
            conn = real(target, *a, **kw)
            conn.set_trace_callback(statements.append)
            return conn
        with mock.patch.object(maintenance.sqlite3, "connect", spy):
            maintenance.run(self.db, ACCOUNT, deep=True, now=self.clock.now)
        self.assertTrue(seen)
        for target, kw in seen:
            self.assertTrue(kw.get("uri"), target)
            self.assertIn("mode=ro", target)
        self.assertTrue(any("immutable=1" in t for t, _ in seen))                                    # backups are opened immutable
        self.assertFalse(any("immutable" in t for t, _ in seen[:1]))                                  # the live index is not (a writer may be active)
        for stmt in statements:
            head = stmt.strip().split(None, 1)[0].upper()
            self.assertIn(head, ("SELECT", "PRAGMA"), stmt)
            if head == "PRAGMA":
                self.assertIn(re.match(r"PRAGMA\s+(\w+)", stmt.strip(), re.I).group(1).lower(), self.ALLOWED_PRAGMAS, stmt)

    def test_the_writable_index_class_is_never_used_and_no_repair_or_gmail_function_is_reached(self):
        self.prepare()
        bomb = mock.Mock(side_effect=AssertionError("must not be called by a read-only report"))
        with mock.patch.object(idx.Index, "__init__", bomb), mock.patch.object(idx, "SCHEMA_VERSION", 7), mock.patch.object(sync, "run_sync", bomb), \
                mock.patch.object(scanner, "run_scan", bomb), mock.patch.object(sync_lease, "acquire", bomb), mock.patch.object(cp, "expire_due", bomb), \
                mock.patch.object(cp, "_txn", bomb), mock.patch.object(cp, "_reject", bomb), mock.patch.object(shutil, "copy2", bomb), mock.patch.object(shutil, "move", bomb), \
                mock.patch.object(os, "remove", bomb), mock.patch.object(os, "unlink", bomb), mock.patch.object(os, "rename", bomb), mock.patch.object(os, "chmod", bomb), \
                mock.patch.object(os, "fchmod", bomb):
            rep = maintenance.run(self.db, ACCOUNT, deep=True, now=self.clock.now)
        self.assertEqual(rep["section"], "maintenance")
        bomb.assert_not_called()

    def test_the_module_has_no_write_gmail_or_repair_vocabulary(self):
        text = (SRC / "gmail_intelligence" / "maintenance.py").read_text()
        for banned in ("googleapiclient", "oauth", "keystore", "urllib", "socket", "subprocess", "import requests", "shutil", "os.remove", "os.unlink", "os.rename", "os.chmod",
                       "INSERT ", "UPDATE ", "DELETE ", "VACUUM", "REINDEX", "ALTER ", "DROP ", "CREATE ", "executescript", "Index(", "allow_upgrade", "run_sync", "run_scan"):
            self.assertNotIn(banned, text.replace("`", ""), banned)

    def test_adversarial_stored_strings_never_reach_any_output(self):
        evil = ("owner@leak.test", LEAK, "Private Label Name", "/Users/someone/secret", "‮RLO", "<script>alert(1)</script>", "'; DROP TABLE messages;--")
        self.sql(("UPDATE sync_run SET error=?", (evil[1],)), ("UPDATE sync_state SET reason=?", (evil[1],)), ("UPDATE messages SET sender=?, thread_id=?", (evil[0], evil[2])),
                 ("UPDATE labels SET name=?", (evil[2],)), ("INSERT INTO message_labels VALUES (?,?,?)", (ACCOUNT, evil[3], evil[4])),
                 ("INSERT INTO message_tombstone VALUES (?,?,?,?,?)", (ACCOUNT, evil[5], evil[6], "HISTORY_DELETED", None)))
        rep = self.run_m(deep=True)
        blob = maintenance.render_text(rep) + json.dumps(rep, sort_keys=True)
        for value in evil:
            self.assertNotIn(value, blob)
        self.assertTrue(set(blob.replace("\n", " ")) <= set(chr(c) for c in range(32, 127)) | set("—"))

    def test_the_path_is_never_printed_even_when_it_contains_private_words(self):
        private_dir = self.tmp / "John-Smith-secret-folder"
        private_dir.mkdir()
        target = private_dir / "index.sqlite3"
        shutil.copy(self.db, target)
        rep = maintenance.run(str(target), ACCOUNT, deep=True, now=self.clock.now)
        blob = maintenance.render_text(rep) + json.dumps(rep)
        for needle in ("John-Smith", "secret-folder", str(self.tmp), "index.sqlite3"):
            self.assertNotIn(needle, blob)


class CliTests(Case):
    def setUp(self):
        super().setUp()
        self.index.close()
        self.env = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.tmp / "home")})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.makedirs(config.app_dir(), exist_ok=True)
        shutil.copy(self.db, config.index_path())
        os.chmod(config.index_path(), 0o600)
        self.index = idx.Index(self.db)
        store = mock.Mock()
        store.load.return_value = {"account": ACCOUNT}
        patch = mock.patch.object(cli, "_store", return_value=store)
        patch.start()
        self.addCleanup(patch.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        bomb = mock.Mock(side_effect=AssertionError("Gmail must not be touched"))
        with mock.patch.object(cli, "_open_reader", bomb), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_text_json_and_deep_modes(self):
        before = tree_state(config.app_dir())
        code, text, err = self.run_cli(["mailbox", "maintenance"])
        self.assertEqual(code, 0)
        self.assertIn("Maintenance report (quick checks", text)
        code, raw, err = self.run_cli(["mailbox", "maintenance", "--deep", "--json"])
        data = json.loads(raw)
        self.assertEqual((code, data["mode"], data["read_only"], data["gmail_contacted"]), (0, "deep", True, False))
        self.assertEqual(before, tree_state(config.app_dir()))
        for blob in (text, raw):
            self.assertNotIn(ACCOUNT, blob)
            self.assertNotIn(str(config.app_dir()), blob)


    def test_it_runs_on_a_corrupt_or_old_or_missing_index_without_a_traceback(self):
        Path(config.index_path()).write_bytes(b"garbage" * 500)
        code, text, err = self.run_cli(["mailbox", "maintenance"])
        self.assertEqual(code, 0)
        self.assertIn("INDEX_UNREADABLE_OR_CORRUPT", text)
        self.assertNotIn("Traceback", err)
        os.remove(config.index_path())
        code, text, err = self.run_cli(["mailbox", "maintenance", "--json"])
        self.assertIn("INDEX_MISSING", text)

    def test_without_a_known_account_only_file_checks_run(self):
        store = mock.Mock()
        store.load.return_value = None
        with mock.patch.object(cli, "_store", return_value=store):
            code, text, err = self.run_cli(["mailbox", "maintenance"])
        self.assertEqual(code, 0)
        self.assertIn("ACCOUNT_UNKNOWN", text)

    def test_the_command_is_registered_and_offers_no_repair_option(self):
        parser = cli.build_parser()
        sub = next(a for a in parser._subparsers._group_actions[0].choices["mailbox"]._subparsers._group_actions[0].choices["maintenance"]._actions)
        options = {s for a in parser._subparsers._group_actions[0].choices["mailbox"]._subparsers._group_actions[0].choices["maintenance"]._actions for s in a.option_strings}
        self.assertEqual(options, {"-h", "--help", "--account", "--deep", "--json"})
        for banned in ("repair", "fix", "delete", "rescan", "migrate", "restore", "schedule"):
            self.assertFalse(any(banned in o for o in options))


class DeterminismTests(unittest.TestCase):
    def test_the_report_is_identical_under_different_hash_seeds(self):
        digests = set()
        for seed in ("0", "1", "42", "1234"):
            proc = subprocess.run([sys.executable, "-I", str(HERE / "maint_digest.py")], capture_output=True, text=True, timeout=120,
                                  env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")})
            self.assertEqual(proc.returncode, 0, proc.stderr)
            digests.add(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(len(digests), 1)


class VocabularyTests(unittest.TestCase):
    def test_every_finding_has_static_text_and_a_valid_category(self):
        for code, (category, explanation, recommendation) in maintenance.TEXT.items():
            self.assertIn(category, "ABCDE", code)
            self.assertTrue(explanation.endswith(".") and recommendation, code)
            self.assertNotRegex(explanation + recommendation, r"\{|\}|%s", code)

    def test_inferred_findings_use_cautious_language(self):
        for code in ("LABEL_REFERENCES_UNKNOWN_LABEL", "CHECKPOINT_MAY_EXPIRE", "CHECKPOINT_LIKELY_EXPIRED", "SYNC_LEASE_EXPIRED", "TOMBSTONE_MESSAGE_CONTRADICTION"):
            text = maintenance.TEXT[code][1].lower()
            self.assertTrue(any(w in text for w in ("possible", "possibility", "may ", "not verified", "does not prove")), code)


if __name__ == "__main__":
    unittest.main()
