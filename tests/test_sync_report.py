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


SECRETS = ("ZXCV1234QWERTY5678UIOPasdf", "john.smith@company.example", "Private Label Name", "/Users/someone/Library/index.sqlite3", "m18c0ffee00001234",
           "token abc123SECRETxyz", "ya29a0AfH6SMBxTOKEN", "SenderNameJaneDoe", "S3cretAlphaNumeric99")


class StoredTextPrivacyTests(ReportCase):
    """P1: sync_run.error / sync_state.reason / scan columns are stored free text. The report must never echo them: only a strict allow-list of known diagnostic codes
    (and numbers parsed from two fixed shapes) is shown; everything else becomes a generic 'unrecognised' marker - including secrets made only of letters and digits."""

    def poison(self, value):
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_run SET error=? WHERE id=(SELECT MAX(id) FROM sync_run)", (value,))

    def all_output(self):
        rep = self.report()
        ro = idx.ReadOnlyIndex(self.db)
        try:
            from gmail_intelligence import cli as cli_mod
            status = cli_mod.sync_status_text(ro, ACCOUNT)
        finally:
            ro.close()
        return sync_report.changes_text(rep) + "\n" + json.dumps(rep, sort_keys=True) + "\n" + status

    def test_secret_bearing_error_strings_never_reach_text_json_or_status(self):
        for secret in SECRETS:
            for shape in ("{s}", "API error (HTTP 503) {s}", "{s} 12 messages could not be refreshed", "LEASE_EXPIRED {s}", "{s}\nLEASE_EXPIRED", "x" + "{s}" + "y"):
                with self.subTest(secret=secret, shape=shape):
                    self.poison(shape.format(s=secret))
                    out = self.all_output()
                    self.assertNotIn(secret, out)
                    self.assertEqual(self.last()["note"], "UNRECOGNISED")
                    self.assertIn("not shown", sync_report.changes_text(self.report()))

    def test_secret_bearing_state_reason_and_scan_columns_are_not_echoed_either(self):
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET reason=?", ("S3cretAlphaNumeric99",))
            self.index.conn.execute("UPDATE scans SET status=?, mode=?", ("ZXCV1234QWERTY5678UIOPasdf", "SenderNameJaneDoe"))
            self.index.conn.execute("UPDATE sync_run SET started_at=?, finished_at=?", ("john.smith@company.example", "ya29a0AfH6SMBxTOKEN"))
        out = self.all_output()
        for secret in SECRETS:
            self.assertNotIn(secret, out)
        rep = self.report()
        self.assertEqual(rep["checkpoint"]["reason"], "UNRECOGNISED")

    def test_known_diagnostics_stay_meaningful(self):
        cases = {"LEASE_EXPIRED": ("LEASE_EXPIRED", None), "HISTORY_EXPIRED": ("HISTORY_EXPIRED", None), "COUNT_MISMATCH": ("COUNT_MISMATCH", None),
                 "API error (HTTP 503)": ("API_ERROR_HTTP", {"http_status": 503}), "12 messages could not be refreshed": ("MESSAGE_FAILURES", {"count": 12, "stage": "refreshed"}),
                 "3 messages could not be indexed": ("MESSAGE_FAILURES", {"count": 3, "stage": "indexed"}), "authorization failed": ("AUTH_FAILED", None),
                 "interrupted by user": ("INTERRUPTED_BY_USER", None), "rate limit": ("RATE_LIMIT", None)}
        for raw, (code, detail) in cases.items():
            with self.subTest(raw=raw):
                self.poison(raw)
                run = self.last()
                self.assertEqual((run["note"], run["note_detail"]), (code, detail))
                self.assertTrue(run["note_text"])
        self.poison(None)
        self.assertEqual((self.last()["note"], self.last()["note_text"]), (None, None))

    def test_oversized_or_non_text_notes_are_unrecognised(self):
        for raw in ("A" * 5000, "API error (HTTP 99999)", "99999999999999 messages could not be refreshed", b"bytes"):
            with self.subTest(raw=str(raw)[:20]):
                self.poison(raw)
                self.assertEqual(self.last()["note"], "UNRECOGNISED")

    def test_the_cli_commands_do_not_leak_either(self):
        self.poison("S3cretAlphaNumeric99")
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET reason=?", ("ZXCV1234QWERTY5678UIOPasdf",))
        self.index.close()
        env = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.tmp / "h2")})
        env.start()
        self.addCleanup(env.stop)
        os.makedirs(config.app_dir(), exist_ok=True)
        import shutil
        shutil.copy(self.db, config.index_path())
        store = mock.Mock()
        store.load.return_value = {"account": ACCOUNT}
        with mock.patch.object(cli, "_store", return_value=store):
            for argv in (["mailbox", "changes"], ["mailbox", "changes", "--json"], ["mailbox", "sync", "--status"]):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    cli.main(argv)
                for secret in ("S3cretAlphaNumeric99", "ZXCV1234QWERTY5678UIOPasdf"):
                    self.assertNotIn(secret, out.getvalue(), argv)
        self.index = idx.Index(self.db)


class CounterSemanticsTests(ReportCase):
    """P2: history pages / records / affected are COLLECTED (recorded once, before any message is applied); refreshed / unchanged / deleted / vanished / failed are
    APPLIED (recorded with each chunk). A partial run must not present collected numbers as applied changes."""

    def crash_at(self, point, **kw):
        def hook(p):
            if p == point:
                raise Crash()
        with self.assertRaises(Crash):
            self.sync(hook=hook, **kw)
        sync_lease.release(self.index)

    def test_an_interruption_after_collection_and_before_the_first_chunk(self):
        for i in range(6):
            self.mailbox.add(f"x{i}")
        self.mailbox.delete("m001")
        self.crash_at("collected", chunk=2)
        run = self.last()
        self.assertEqual((run["phase"], run["history_collection_recorded"]), ("PARTIAL_RUNNING_LEASE_ACTIVE", True))
        self.assertGreaterEqual(run["history_pages"], 1)
        self.assertEqual((run["messages_affected"], run["history_records"]), (7, 7))              # collected ...
        self.assertEqual((run["new_or_changed"], run["unchanged"], run["deleted"], run["never_indexed_and_gone"], run["failed_refreshes"]), (0, 0, 0, 0, 0))   # ... nothing applied
        self.assertEqual(run["messages_not_yet_applied"], 7)
        self.assertFalse(run["checkpoint_advanced_by_this_run"])
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages WHERE id LIKE 'x%'")[0][0], 0)           # and indeed no message row was touched
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM message_tombstone")[0][0], 0)
        text = sync_report.changes_text(self.report())
        self.assertIn("Collected before any message was applied", text)
        self.assertIn("pages", text)
        self.assertIn("Applied durably", text)
        self.assertIn("new or changed 0", text)
        self.assertIn("Not yet applied: 7", text)
        self.assertIn("the next run will replay them", text)
        self.assertIn("did not move", text)
        self.assertNotIn("only what was durably applied", text)                                    # the old, wrong blanket statement is gone

    def test_an_interruption_after_some_chunks_splits_applied_from_remaining(self):
        for i in range(6):
            self.mailbox.add(f"x{i}")
        self.crash_at("chunk:1", chunk=2)
        run = self.last()
        self.assertEqual((run["messages_affected"], run["new_or_changed"], run["messages_not_yet_applied"]), (6, 2, 4))
        self.assertIn("Not yet applied: 4", sync_report.changes_text(self.report()))

    def test_a_run_that_stopped_before_collection_finished_records_no_collection(self):
        self.mailbox.add("x1")
        self.mailbox.faults["list_history"] = [Crash()]
        with self.assertRaises(Crash):
            self.sync()
        sync_lease.release(self.index)
        run = self.last()
        self.assertEqual((run["history_collection_recorded"], run["history_pages"], run["messages_affected"]), (False, 0, 0))
        self.assertIsNone(run["messages_not_yet_applied"])                                          # unknown, not zero
        text = sync_report.changes_text(self.report())
        self.assertIn("History collection: not recorded", text)
        self.assertIn("0 here means not recorded", text)

    def test_a_completed_run_has_nothing_left_and_the_checkpoint_moved(self):
        self.mailbox.add("x1")
        self.sync()
        run = self.last()
        self.assertEqual((run["phase"], run["messages_not_yet_applied"], run["checkpoint_advanced_by_this_run"], run["history_collection_recorded"]), ("COMPLETED", None, True, True))
        self.assertEqual(run["new_or_changed"] + run["unchanged"] + run["deleted"] + run["never_indexed_and_gone"] + run["failed_refreshes"], run["messages_affected"])
        text = sync_report.changes_text(self.report())
        self.assertNotIn("Not yet applied", text)
        self.assertIn("checkpoint advanced", text)

    def test_a_partial_full_scan_reports_progress_counters_not_applied_changes(self):
        self.at_call("list_message_ids", 2, lambda: (_ for _ in ()).throw(Crash()))
        with self.assertRaises(Crash):
            self.scan_all()
        sync_lease.release(self.index)
        run = self.last()
        self.assertEqual((run["kind"], run["checkpoint_advanced_by_this_run"], run["removed_by_reconciliation"]), ("FULL", False, 0))
        text = sync_report.changes_text(self.report())
        self.assertIn("progress so far", text)
        self.assertIn("removed nothing", text)
        self.assertIn("no checkpoint", text)

    def test_the_overlap_warning_still_holds(self):
        text = sync_report.changes_text(self.report())
        self.assertIn("must not be added together", text)
