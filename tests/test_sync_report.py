"""M7B: `mailbox changes` - a read-only, privacy-safe report of what synchronization changed. Fake Gmail and synthetic databases only."""
import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest
from unittest import mock

from sync_support import ACCOUNT, HERE, SRC, SyncCase, config, file_digest, idx, standard_mailbox, sync_lease, table_digest, fast_limiter
from fake_history import FakeHistoryMailbox
from gmail_intelligence import cli, gmail, scanner, sync_report

ALL_TABLES = ("messages", "message_labels", "labels", "scans", "message_class", "sync_state", "sync_run", "message_tombstone", "cleanup_audit", "cleanup_plan",
              "cleanup_approval", "cleanup_execution")


class Crash(BaseException):
    pass


class ReportCase(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)

    def report(self, runs=5, account=ACCOUNT):
        ro = idx.ReadOnlyIndex(self.db)
        try:
            return sync_report.changes_report(ro, account, runs=runs, now=self.clock.now)
        finally:
            ro.close()

    def last(self, rep=None):
        return (rep or self.report())["runs"][0]


class CountersTests(ReportCase):
    def test_the_baseline_full_scan_is_reported_from_its_scan_row(self):
        rep = self.report()
        run = rep["runs"][0]
        self.assertEqual((run["kind"], run["status"], run["phase"]), ("FULL", "completed", "COMPLETED"))
        self.assertEqual((run["ids_listed"], run["messages_fetched_or_refreshed"], run["removed_by_reconciliation"], run["failed_refreshes"]), (self.N, self.N, 0, 0))
        self.assertEqual((rep["checkpoint"]["status"], rep["healthy"]), ("OK", True))
        self.assertIsNotNone(rep["last_completed_full_scan"])
        self.assertIsNone(rep["last_completed_incremental_sync"])

    def test_a_new_message_counts_as_new_or_changed_and_never_claims_a_split(self):
        self.mailbox.add("n1")
        self.sync()
        run = self.last()
        self.assertEqual((run["new_or_changed"], run["unchanged"], run["deleted"], run["failed_refreshes"]), (1, 0, 0, 0))
        self.assertIsNone(run["new_only"])                                # the stored counters do not separate new from changed: reported as unavailable
        self.assertIsNone(run["changed_only"])
        self.assertIn("new vs changed: not recorded", sync_report.changes_text(self.report()))

    def test_updated_metadata_and_label_changes(self):
        self.mailbox.labels_change("m001", add=("STARRED",))
        self.mailbox.labels_change("m002", remove=("INBOX",))
        self.mailbox.msgs["m003"]["sender"] = "renamed@sender.example.test"
        self.mailbox._event("labels", "m003")
        self.sync()
        run = self.last()
        self.assertEqual((run["new_or_changed"], run["unchanged"], run["deleted"], run["messages_affected"]), (3, 0, 0, 3))

    def test_permanent_deletion_versus_a_move_to_trash(self):
        self.mailbox.labels_change("m004", add=("TRASH",), remove=("INBOX",))
        self.sync()
        run = self.last()
        self.assertEqual((run["new_or_changed"], run["deleted"], run["tombstone_rows_for_run"]), (1, 0, {}))      # trash is a label change, not a deletion
        self.clock.advance(60)
        self.mailbox.delete("m004")
        self.sync()
        run = self.last()
        self.assertEqual((run["deleted"], run["tombstone_rows_for_run"], run["counters_consistent_with_tombstones"]), (1, {"HISTORY_DELETED": 1}, True))
        self.assertEqual(self.report()["deletions_recorded_in_total"], {"HISTORY_DELETED": 1})

    def test_a_message_gone_before_it_was_ever_indexed_is_not_a_deletion(self):
        self.mailbox.add("tmp")
        self.mailbox.delete("tmp")
        self.sync()
        run = self.last()
        self.assertEqual((run["deleted"], run["never_indexed_and_gone"], run["new_or_changed"]), (0, 1, 0))

    def test_reconciliation_removals_come_from_the_scan_and_the_tombstones(self):
        self.mailbox.delete("m002")
        self.mailbox.delete("m003")
        self.scan_all()
        run = self.last()
        self.assertEqual((run["kind"], run["removed_by_reconciliation"], run["removal_tombstones"], run["counters_consistent_with_tombstones"]), ("FULL", 2, 2, True))
        self.assertEqual(self.report()["deletions_recorded_in_total"], {"FULL_RECONCILE": 2})

    def test_a_no_op_sync(self):
        self.mailbox.hid += 3
        self.sync()
        run = self.last()
        self.assertEqual((run["status"], run["messages_affected"], run["new_or_changed"], run["unchanged"], run["deleted"]), ("completed", 0, 0, 0, 0))
        self.assertIsNotNone(self.report()["last_completed_incremental_sync"])

    def test_an_unchanged_but_affected_message_counts_as_unchanged(self):
        self.mailbox.labels_change("m001", add=("STARRED",))
        self.mailbox.labels_change("m001", remove=("STARRED",))
        self.sync()
        run = self.last()
        self.assertEqual((run["new_or_changed"], run["unchanged"]), (0, 1))


class PartialRunTests(ReportCase):
    def test_replay_after_an_interruption_shows_a_partial_run_then_a_completed_one_and_warns_about_overlap(self):
        for i in range(6):
            self.mailbox.add(f"x{i}")
        with self.assertRaises(Crash):
            self.sync(chunk=2, hook=lambda p: (_ for _ in ()).throw(Crash()) if p == "chunk:1" else None)
        sync_lease.release(self.index)
        run = self.last()
        self.assertEqual((run["status"], run["phase"], run["new_or_changed"]), ("running", "PARTIAL_RUNNING_LEASE_ACTIVE", 2))
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)
        self.assertEqual(self.last()["phase"], "PARTIAL_ABANDONED_LEASE_EXPIRED")             # judged from the stored lease, not guessed
        self.sync(chunk=2)
        first_attempt, replay = self.report()["runs"][1], self.report()["runs"][0]
        self.assertEqual((first_attempt["status"], first_attempt["phase"], first_attempt["new_or_changed"]), ("interrupted", "PARTIAL_INTERRUPTED", 2))
        self.assertEqual((replay["phase"], replay["new_or_changed"], replay["unchanged"]), ("COMPLETED", 4, 2))   # the 2 already applied are found unchanged on replay
        self.assertEqual((first_attempt["messages_affected"], replay["messages_affected"]), (6, 6))
        self.assertGreater(first_attempt["messages_affected"] + replay["messages_affected"], 6)             # ... the same 6 messages are "affected" in both runs ...
        text = sync_report.changes_text(self.report())
        self.assertIn("PARTIAL", text)
        self.assertIn("must not be added together", text)                                      # ... and the report says so
        self.assertEqual(self.report()["checkpoint"]["status"], "OK")

    def test_a_failed_refresh_is_reported_with_the_run_marked_partial(self):
        self.mailbox.add("n1")
        self.mailbox.faults["get_message_metadata"] = [gmail.GmailApiError("bad", 400)]
        with self.assertRaises(sync_lease.SyncError):
            self.sync()
        run = self.last()
        self.assertEqual((run["status"], run["phase"], run["failed_refreshes"]), ("failed", "PARTIAL_FAILED", 1))
        rep = self.report()
        self.assertEqual((rep["checkpoint"]["status"], rep["healthy"]), ("INTERRUPTED", False))
        self.assertIn("SYNC_INTERRUPTED", rep["health_codes"])

    def test_an_incomplete_full_scan_is_partial_and_removes_nothing(self):
        self.mailbox.delete("m001")
        self.mailbox.profile_total = 900
        row = self.scan_all()
        self.assertEqual(row["status"], "incomplete")
        run = self.last()
        self.assertEqual((run["status"], run["phase"], run["scan_status"], run["removed_by_reconciliation"], run["removal_tombstones"]), ("needs_reconcile", "PARTIAL_NEEDS_RECONCILE", "incomplete", 0, 0))
        self.assertEqual(self.report()["checkpoint"]["status"], "NEEDS_RECONCILE")
        self.assertIsNone(run["counters_consistent_with_tombstones"])

    def test_a_needs_reconcile_after_expired_history_is_reported_without_inventing_counts(self):
        self.mailbox.expired_before = 10 ** 9
        with self.assertRaises(sync_lease.SyncError):
            self.sync()
        run = self.last()
        self.assertEqual((run["phase"], run["messages_affected"], run["new_or_changed"], run["note"]), ("PARTIAL_NEEDS_RECONCILE", 0, 0, "HISTORY_EXPIRED"))
        self.assertEqual(self.report()["checkpoint"]["reason"], "HISTORY_EXPIRED")


class ScopeAndSafetyTests(ReportCase):
    def test_other_accounts_never_appear(self):
        other = "second.owner@example.test"
        mb = FakeHistoryMailbox(other)
        mb.add("o1")
        scanner.run_scan(mb, self.index, other, mode="full", limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=3)
        mb.delete("o1")
        scanner.run_scan(mb, self.index, other, mode="full", limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=3)
        mine, theirs = self.report(), self.report(account=other)
        self.assertEqual(len(mine["runs"]), 1)
        self.assertEqual(mine["deletions_recorded_in_total"], {})
        self.assertEqual(theirs["deletions_recorded_in_total"], {"FULL_RECONCILE": 1})
        self.assertEqual({r["run"] for r in mine["runs"]} & {r["run"] for r in theirs["runs"]}, set())

    def test_the_report_changes_nothing_and_runs_on_a_database_that_cannot_be_written(self):
        self.mailbox.delete("m001")
        self.sync()
        before = table_digest(self.index, ALL_TABLES)
        digest, mtime = file_digest(self.db), os.stat(self.db).st_mtime_ns
        for _ in range(2):
            ro = idx.ReadOnlyIndex(self.db)                              # mode=ro + query_only: a hidden write would raise
            sync_report.changes_report(ro, ACCOUNT, now=self.clock.now)
            sync_report.changes_text(sync_report.changes_report(ro, ACCOUNT, now=self.clock.now))
            ro.close()
        self.assertEqual((before, digest, mtime), (table_digest(self.index, ALL_TABLES), file_digest(self.db), os.stat(self.db).st_mtime_ns))

    def test_output_is_aggregate_and_privacy_safe(self):
        self.mailbox.add("private-id-777", sender="secret.sender@private.example.test")
        self.mailbox.labels.append({"id": "Label_9", "name": "Private Label Name", "type": "user"})
        self.mailbox.delete("m001")
        self.sync()
        rep = self.report()
        text, raw = sync_report.changes_text(rep), json.dumps(rep, sort_keys=True)
        for blob in (text, raw):
            for needle in ("private-id-777", "secret.sender", "private.example", "Private Label Name", ACCOUNT, "m001", self.db, str(self.tmp), "sha256"):
                self.assertNotIn(needle, blob)
            self.assertIsNone(re.search(r"[0-9a-f]{32,}", blob))        # no token, hash or id-like blob
        self.assertTrue(set(raw) <= set(chr(c) for c in range(32, 127)))

    def test_note_text_from_the_run_is_sanitised(self):
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_run SET error=? WHERE id=(SELECT MAX(id) FROM sync_run)", ("bad\x1b[31m‮ owner@leak.test",))
        note = self.last()["note"]
        self.assertNotIn("\x1b", note)
        self.assertNotIn("‮", note)


class CliTests(ReportCase):
    def setUp(self):
        super().setUp()
        self.index.close()
        self.env = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.tmp / "home")})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.makedirs(config.app_dir(), exist_ok=True)
        import shutil
        shutil.copy(self.db, config.index_path())
        self.path = config.index_path()
        self.index = idx.Index(self.db)
        store = mock.Mock()
        store.load.return_value = {"account": ACCOUNT}
        patch = mock.patch.object(cli, "_store", return_value=store)
        patch.start()
        self.addCleanup(patch.stop)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail must not be touched")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_text_and_json_without_touching_gmail_or_the_file(self):
        before = file_digest(self.path)
        code, text, err = self.run_cli(["mailbox", "changes"])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Sync changes", text)
        code, raw, err = self.run_cli(["mailbox", "changes", "--json", "--runs", "3"])
        data = json.loads(raw)
        self.assertEqual((code, data["read_only"], data["gmail_contacted"]), (0, True, False))
        self.assertEqual(before, file_digest(self.path))
        for blob in (text, raw):
            self.assertNotIn(ACCOUNT, blob)
            self.assertNotIn(str(self.path), blob)

    def test_bad_arguments_and_an_old_index_are_refused_without_changes(self):
        self.assertEqual(self.run_cli(["mailbox", "changes", "--runs", "0"])[0], 1)
        import sqlite3
        c = sqlite3.connect(self.path)
        for t in ("sync_state", "sync_run", "message_tombstone"):
            c.execute(f"DROP TABLE {t}")
        c.execute("PRAGMA user_version = 6")
        c.commit()
        c.close()
        before = file_digest(self.path)
        code, out, err = self.run_cli(["mailbox", "changes"])
        self.assertEqual(code, 1)
        self.assertIn("index upgrade", err)
        self.assertEqual(before, file_digest(self.path))


class DeterminismTests(unittest.TestCase):
    def test_the_report_is_identical_under_different_hash_seeds(self):
        import tempfile
        ops = json.dumps([["add", "n1", ["INBOX"]], ["labels", "m001", ["STARRED"], []], ["delete", "m002"], ["add", "n2", ["INBOX", "UNREAD"]]])
        digests = set()
        for seed in ("0", "1", "42", "1234"):
            with tempfile.TemporaryDirectory() as tmp:
                db = os.path.join(tmp, "i.sqlite3")
                idx.Index(db).close()
                proc = subprocess.run([sys.executable, "-I", str(HERE / "sync_worker.py"), "--db", db, "--mode", "e2e-report", "--script", ops, "--n", "12"], capture_output=True,
                                      text=True, timeout=120, env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                digests.add(json.loads(proc.stdout.strip().splitlines()[-1])["ok"]["digest"])
        self.assertEqual(len(digests), 1)


if __name__ == "__main__":
    unittest.main()
