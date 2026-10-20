"""M7A: sync_health, the full-scan interlock (F1), reconciliation and prune safety (F2), and D144 (LS1)."""
import argparse
import ast
import contextlib
import io
import os
import unittest
from datetime import timedelta
from unittest import mock

from sync_support import ACCOUNT, HERE, SRC, SyncCase, config, fast_limiter, file_digest, idx, scanner, standard_mailbox, sync_health, sync_lease, table_digest
from fake_history import FakeHistoryMailbox
from gmail_intelligence import cli, gmail


class Crash(BaseException):
    pass


class HealthRuleTests(SyncCase):
    def test_no_checkpoint_is_unhealthy(self):
        self.assertEqual(self.health(), ["SYNC_CHECKPOINT_MISSING"])

    def test_a_completed_baseline_is_healthy_and_the_age_rules_work(self):
        self.baseline()
        self.assertEqual(self.health(), [])
        self.clock.advance(23 * 3600)
        self.assertEqual(self.health(), [])
        self.clock.advance(2 * 3600)
        self.assertEqual(self.health(), ["SYNC_STALE"])
        self.clock.advance(-48 * 3600)                                  # recorded time far in the future
        self.assertEqual(self.health(), ["SYNC_STATE_INCONSISTENT"])

    def test_each_status_flag_is_unhealthy(self):
        self.baseline()
        for status, expected in (("INTERRUPTED", "SYNC_INTERRUPTED"), ("NEEDS_RECONCILE", "SYNC_NEEDS_RECONCILE")):
            with self.index.conn:
                self.index.conn.execute("UPDATE sync_state SET status=?", (status,))
            self.assertEqual(self.health(), [expected])

    def test_basis_must_be_the_newest_completed_full_scan(self):
        self.baseline()
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET basis_scan_id=basis_scan_id-1")
        self.assertEqual(self.health(), ["SYNC_STATE_INCONSISTENT"])

    def test_a_running_run_beside_an_ok_flag_is_inconsistent_and_in_progress(self):
        self.baseline()
        lease = sync_lease.acquire(self.index, ACCOUNT, "INCREMENTAL", clock=self.clock)
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='OK'")
        self.assertEqual(self.health(), ["SYNC_IN_PROGRESS", "SYNC_STATE_INCONSISTENT"])
        lease.finish("interrupted", "INTERRUPTED", "API_ERROR")

    def test_an_unfinished_scan_newer_than_the_basis_is_unhealthy_even_with_an_ok_flag(self):
        self.baseline()
        with self.index.conn:
            self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'limited', 'interrupted', '2026-10-20T12:00:00Z')", (ACCOUNT,))
        self.assertEqual(self.state()["status"], "OK")
        self.assertEqual(self.health(), ["SYNC_FULL_SCAN_INCOMPLETE"])

    def test_an_unfinished_scan_older_than_the_basis_is_ignored(self):
        with self.index.conn:
            self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'failed', '2026-10-20T11:00:00Z')", (ACCOUNT,))
        self.baseline()
        self.assertEqual(self.health(), [])

    def test_the_module_is_read_only_and_independent_of_the_m4_modules(self):
        text = (SRC / "gmail_intelligence" / "sync_health.py").read_text()
        for node in ast.walk(ast.parse(text)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) else [])
            for name in names:
                self.assertNotRegex(name or "", r"cleanup|index|gmail|oauth|scanner|sync")
        self.assertNotRegex(text, r"\b(INSERT|UPDATE|DELETE)\b")
        self.baseline()
        before = table_digest(self.index, ("sync_state", "sync_run", "scans", "messages"))
        self.health()
        self.assertEqual(before, table_digest(self.index, ("sync_state", "sync_run", "scans", "messages")))


class FullScanInterlockTests(SyncCase):
    """F1: SYNC.md 8.3, row by row."""

    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)
        self.h0 = self.state()["history_id"]

    def test_active_baseline_without_an_earlier_checkpoint(self):
        fresh = idx.Index(str(self.tmp / "other.sqlite3"))
        self.addCleanup(fresh.close)
        seen = []
        mb = standard_mailbox(self.N)
        mb.hooks[("list_message_ids", 2)] = lambda: seen.append(sync_health.problems(fresh, ACCOUNT, self.clock.now))
        scanner.run_scan(mb, fresh, ACCOUNT, mode="full", limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=3)
        self.assertEqual(seen, [["SYNC_CHECKPOINT_MISSING", "SYNC_FULL_SCAN_INCOMPLETE"]])
        self.assertEqual(sync_health.problems(fresh, ACCOUNT, self.clock.now), [])

    def test_active_full_scan_beside_a_healthy_checkpoint_is_unhealthy_while_it_runs(self):
        seen = []
        self.at_call("list_message_ids", 2, lambda: seen.append((self.health(), self.state()["status"])))
        self.scan_all()
        self.assertEqual(seen, [(["SYNC_FULL_SCAN_INCOMPLETE", "SYNC_IN_PROGRESS"], "IN_PROGRESS")])
        self.assertEqual((self.state()["status"], self.health()), ("OK", []))

    def test_interrupted_full_scan_never_restores_the_earlier_ok(self):
        self.at_call("list_message_ids", 2, lambda: self.mailbox.faults.__setitem__("list_message_ids", [gmail.GmailApiError("x", 500)] * scanner.MAX_ATTEMPTS))
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan_all()
        st = self.state()
        self.assertEqual((st["status"], st["reason"], st["history_id"]), ("INTERRUPTED", "FULL_SCAN_INTERRUPTED", self.h0))
        self.assertEqual(self.health(), ["SYNC_FULL_SCAN_INCOMPLETE", "SYNC_INTERRUPTED"])
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_FULL_SCAN_UNFINISHED")

    def test_a_failed_reconciliation_leaves_needs_reconcile_and_prunes_nothing(self):
        self.mailbox.delete("m003")
        self.mailbox.faults["get_message_metadata"] = [gmail.GmailApiError("bad", 400)]          # one permanent per-message failure
        row = self.scan_all()
        self.assertEqual(row["status"], "incomplete")
        st = self.state()
        self.assertEqual((st["status"], st["reason"], st["history_id"]), ("NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE", self.h0))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages WHERE id='m003'")[0][0], 1)  # nothing pruned
        self.assertEqual(self.tombstones(), {})
        self.assertIn("SYNC_NEEDS_RECONCILE", self.health())

    def test_an_authorization_failure_is_a_failed_reconciliation(self):
        self.mailbox.faults["get_message_metadata"] = [gmail.GmailAuthError("no", 401)]
        with self.assertRaises(gmail.GmailAuthError):
            self.scan_all()
        self.assertEqual((self.state()["status"], self.state()["reason"]), ("NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE"))

    def test_a_successful_reconciliation_restores_health_with_a_new_checkpoint_and_tombstones(self):
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='NEEDS_RECONCILE', reason='HISTORY_EXPIRED'")
        self.mailbox.delete("m003")
        self.mailbox.add("fresh")
        row = self.scan_all()
        self.assertEqual((row["status"], row["pruned"]), ("completed", 1))
        st = self.state()
        self.assertEqual((st["status"], st["reason"], st["history_id"], st["basis_scan_id"], st["source"]),
                         ("OK", None, str(self.h0 and self.runs()[-1]["first_history_id"]), row["id"], "PROFILE_BEFORE_FULL_LIST"))
        self.assertEqual(self.tombstones(), {"m003": "FULL_RECONCILE"})
        self.assertEqual(self.health(), [])

    def test_healthy_checkpoint_plus_a_later_incomplete_scan_is_unhealthy_in_every_form(self):
        for status in ("running", "interrupted", "failed", "incomplete"):
            with self.subTest(scan=status):
                with self.index.conn:
                    self.index.conn.execute("DELETE FROM scans WHERE status<>'completed'")
                    self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', ?, '2026-10-20T12:30:00Z')", (ACCOUNT, status))
                self.assertIn("SYNC_FULL_SCAN_INCOMPLETE", self.health())

    def test_mutation_the_derived_guard_is_what_catches_a_wrong_flag(self):
        with self.index.conn:
            self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'interrupted', '2026-10-20T12:30:00Z')", (ACCOUNT,))
        with mock.patch.object(sync_health, "unfinished_full_scan", return_value=False):
            self.assertEqual(self.health(), [])                              # the flag alone says healthy ...
        self.assertEqual(self.health(), ["SYNC_FULL_SCAN_INCOMPLETE"])       # ... the real derivation does not


class ReconciliationTests(SyncCase):
    """F2: completeness, safe pruning and the count check."""
    N = 120

    def test_a_count_mismatch_prunes_nothing_and_sets_no_checkpoint(self):
        self.mailbox.profile_total = 400
        row = self.scan_all()
        self.assertEqual((row["status"], row["error"], row["pruned"]), ("incomplete", "COUNT_MISMATCH", 0))
        self.assertIsNone(self.state())

    def test_a_reviewed_count_mismatch_can_be_accepted_explicitly(self):
        self.mailbox.profile_total = 400
        row = self.scan_all(accept_count_mismatch=True)
        self.assertEqual(row["status"], "completed")
        self.assertEqual(self.state()["status"], "OK")

    def test_a_missing_estimate_cannot_confirm_the_listing(self):
        self.mailbox.profile_total = -1
        self.assertEqual(self.scan_all()["error"], "COUNT_MISMATCH")

    def test_a_small_difference_within_tolerance_passes(self):
        self.mailbox.profile_total = 120 + 40
        self.assertEqual(self.scan_all()["status"], "completed")

    def test_a_silently_truncated_listing_is_caught_before_pruning(self):
        self.baseline()
        orig = self.mailbox.list_message_ids
        self.mailbox.list_message_ids = lambda token=None, max_results=500: (lambda ids, nxt: (ids, None if token is not None or True else nxt))(*orig(token, max_results))
        self.mailbox.msgs.update({})                      # the mailbox still holds all 120 messages; the listing stops after one page
        self.mailbox.profile_total = 120
        row = self.scan_all(page_size=40)
        self.assertEqual((row["status"], row["error"], row["pruned"]), ("incomplete", "COUNT_MISMATCH", 0))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages")[0][0], 120)
        self.assertEqual(self.tombstones(), {})

    def test_a_large_prune_needs_an_explicit_second_confirmation(self):
        self.baseline()
        for i in range(40):                                # 33% of the indexed messages disappear
            self.mailbox.delete(f"m{i:03d}")
        row = self.scan_all()
        self.assertEqual((row["status"], row["error"], row["pruned"]), ("incomplete", "LARGE_PRUNE", 0))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages")[0][0], 120)
        self.assertEqual(self.state()["status"], "NEEDS_RECONCILE")
        self.clock.advance(60)
        row = self.scan_all(allow_large_prune=True)
        self.assertEqual((row["status"], row["pruned"]), ("completed", 40))
        self.assertEqual(len(self.tombstones()), 40)
        self.assertEqual(set(self.tombstones().values()), {"FULL_RECONCILE"})
        self.assertEqual((self.state()["status"], self.health()), ("OK", []))

    def test_a_prune_under_twenty_percent_is_allowed_with_tombstones(self):
        self.baseline()
        for i in range(10):
            self.mailbox.delete(f"m{i:03d}")
        self.clock.advance(60)
        self.assertEqual(self.scan_all()["pruned"], 10)
        self.assertEqual(len(self.tombstones()), 10)

    def test_limited_scans_never_prune(self):
        row = scanner.run_scan(self.mailbox, self.index, ACCOUNT, mode="limited", limit=10, limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=5)
        self.assertEqual(row["pruned"], 0)
        self.assertEqual(self.tombstones(), {})


class LimitedScanRefusalTests(SyncCase):
    """LS1 / D144: refused whenever ANY sync_state row exists, locally, before any Gmail request."""

    def setUp(self):
        super().setUp()
        self.baseline()

    def test_refused_in_every_status_by_the_lease_layer(self):
        for status in ("OK", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE"):
            with self.subTest(status=status):
                with self.index.conn:
                    self.index.conn.execute("UPDATE sync_state SET status=?", (status,))
                calls = len(self.mailbox.calls)
                with self.assertRaises(sync_lease.SyncError) as ctx:
                    scanner.run_scan(self.mailbox, self.index, ACCOUNT, mode="limited", limit=3, limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock)
                self.assertEqual(ctx.exception.code, "SYNC_LIMITED_REFUSED")
                self.assertEqual(len(self.mailbox.calls), calls)

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail must not be touched")):
            code = cli.cmd_mailbox_scan(args)
        return code, out.getvalue(), err.getvalue()

    def test_the_cli_refuses_before_opening_any_reader_and_changes_no_byte(self):
        self.index.close()
        before = file_digest(self.db)
        ns = argparse.Namespace(all=False, limit=5, resume=False, max_units_per_minute=4500, accept_count_mismatch=False, allow_large_prune=False, account=ACCOUNT)
        with mock.patch.object(config, "index_path", return_value=__import__("pathlib").Path(self.db)):
            for status in ("OK", "NEEDS_RECONCILE"):
                c = idx.Index(self.db)
                with c.conn:
                    c.conn.execute("UPDATE sync_state SET status=?", (status,))
                c.close()
                before = file_digest(self.db)
                code, out, err = self.run_cli(ns)
                self.assertEqual(code, 1)
                self.assertIn("SYNC_LIMITED_REFUSED", err)
                self.assertEqual(before, file_digest(self.db))
        self.index = idx.Index(self.db)

    def test_a_limited_resume_is_refused_the_same_way(self):
        self.index.close()
        c = idx.Index(self.db)
        with c.conn:
            c.conn.execute("INSERT INTO scans (account, mode, limit_n, status, started_at) VALUES (?, 'limited', 3, 'interrupted', '2026-10-20T13:00:00Z')", (ACCOUNT,))
        c.close()
        ns = argparse.Namespace(all=False, limit=None, resume=True, max_units_per_minute=4500, accept_count_mismatch=False, allow_large_prune=False, account=ACCOUNT)
        before = file_digest(self.db)
        with mock.patch.object(config, "index_path", return_value=__import__("pathlib").Path(self.db)):
            code, out, err = self.run_cli(ns)
        self.assertEqual((code, before == file_digest(self.db)), (1, True))
        self.assertIn("SYNC_LIMITED_REFUSED", err)
        self.index = idx.Index(self.db)

    def test_before_the_first_checkpoint_a_limited_scan_works_and_sets_none(self):
        other = idx.Index(str(self.tmp / "fresh.sqlite3"))
        self.addCleanup(other.close)
        row = scanner.run_scan(standard_mailbox(10), other, ACCOUNT, mode="limited", limit=4, limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=2)
        self.assertEqual(row["status"], "completed")
        self.assertIsNone(sync_health.state_row(other, ACCOUNT))


if __name__ == "__main__":
    unittest.main()
