"""M7A: single-writer lease, fencing, heartbeat, takeover and crash recovery (L1-L6, RC1-RC6). Includes REAL separate processes (kill -9, stalls, races)."""
import json
import re
import sqlite3
import unittest
from datetime import timedelta
from unittest import mock

from sync_support import (ACCOUNT, M4_TABLES, SyncCase, WorkerMixin, fast_limiter, file_digest, idx, scanner, standard_mailbox, sync_health, sync_lease,
                          table_digest)
from fake_history import FakeHistoryMailbox
from gmail_intelligence import gmail

SCRIPT = [["add", "n1", ["INBOX"]], ["add", "n2", ["INBOX", "UNREAD"]], ["labels", "m001", ["STARRED"], []], ["delete", "m002"], ["labels", "m004", ["Label_1"], []],
          ["add", "n3", ["INBOX"]], ["labels", "m005", ["IMPORTANT"], []]]


class Crash(BaseException):
    pass


class LeaseUnitTests(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)
        self.other = idx.Index(self.db)       # a second, independent connection = a second process
        self.addCleanup(self.other.close)

    def acquire(self, index=None, kind="INCREMENTAL"):
        return sync_lease.acquire(index or self.index, ACCOUNT, kind, clock=self.clock)

    def test_l1_the_lease_has_a_random_256_bit_token_and_a_five_minute_term(self):
        a = self.acquire()
        row = self.runs()[-1]
        self.assertRegex(row["lease_token"], r"^[0-9a-f]{64}$")
        self.assertEqual(sync_lease.LEASE_TTL, timedelta(minutes=5))
        self.assertEqual((row["status"], row["kind"]), ("running", "INCREMENTAL"))
        t = lambda s: sync_lease.sync_health.parse(s)  # noqa: E731
        self.assertEqual(t(row["lease_expires_at"]) - t(row["heartbeat_at"]), timedelta(minutes=5))
        a.finish("interrupted", "INTERRUPTED", "API_ERROR")
        sync_lease.release(self.index)
        b = self.acquire()
        self.assertNotEqual(b.token, a.token)
        b.finish("interrupted", "INTERRUPTED", "API_ERROR")

    def test_l1_the_database_itself_refuses_a_second_running_row(self):
        self.acquire()
        with self.assertRaises(sqlite3.IntegrityError), self.index.conn:
            self.index.conn.execute("INSERT INTO sync_run (account,kind,status,started_at,lease_token,lease_expires_at,heartbeat_at) VALUES (?,?,?,?,?,?,?)",
                                    (ACCOUNT, "INCREMENTAL", "running", "2026-10-20T12:00:00Z", "a" * 64, "2026-10-20T12:05:00Z", "2026-10-20T12:00:00Z"))

    def test_an_active_lease_is_never_taken_over(self):
        self.acquire()
        self.clock.advance(299)
        for kind in ("INCREMENTAL", "FULL"):
            with self.assertRaises(sync_lease.SyncError) as ctx:
                self.acquire(self.other, kind)
            self.assertEqual(ctx.exception.code, "SYNC_BUSY")
        self.assertEqual(self.runs()[-1]["status"], "running")

    def test_an_expired_lease_is_taken_over_by_compare_and_swap_and_the_state_is_interrupted_then_in_progress(self):
        a = self.acquire()
        self.clock.advance(301)
        b = self.acquire(self.other)
        old, new = self.runs()[-2:]
        self.assertEqual((old["status"], old["error"], new["status"]), ("interrupted", "LEASE_EXPIRED", "running"))
        self.assertEqual(self.state()["status"], "IN_PROGRESS")
        self.assertEqual(self.state()["history_id"], "112")                     # the checkpoint is exactly as last committed
        self.assertNotEqual(a.token, b.token)

    def test_a_clock_that_moved_backwards_cannot_prove_abandonment(self):
        self.acquire()
        with self.index.conn:                                                   # an expired lease whose heartbeat lies in the future
            self.index.conn.execute("UPDATE sync_run SET lease_expires_at='2026-10-20T11:00:00Z', heartbeat_at='2026-10-20T13:00:00Z' WHERE status='running'")
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.acquire(self.other)
        self.assertEqual(ctx.exception.code, "SYNC_CLOCK_UNCERTAIN")
        self.assertEqual(self.runs()[-1]["status"], "running")

    def test_l3_a_superseded_holder_cannot_write_anything(self):
        a = self.acquire()
        self.clock.advance(301)
        self.acquire(self.other)
        before = table_digest(self.index, ("messages", "message_labels", "labels", "scans", "sync_state", "sync_run", "message_tombstone"))
        for fn in (lambda: self.index.save_labels(ACCOUNT, [{"id": "X", "name": "x", "type": "user"}]),
                   lambda: a.heartbeat(),
                   lambda: self.index.save_batch(ACCOUNT, 1, [{"id": "z", "thread_id": "t", "internal_ms": 1, "size": 1, "sender": "a@b.test", "label_ids": []}]),
                   lambda: self.index.set_listed(1, 99)):
            with self.assertRaises(sync_lease.LeaseLost):
                fn()
        self.assertEqual(before, table_digest(self.index, ("messages", "message_labels", "labels", "scans", "sync_state", "sync_run", "message_tombstone")))
        a.finish("completed", "OK")                                             # a superseded run's clean-up writes nothing either
        self.assertEqual(before, table_digest(self.index, ("messages", "message_labels", "labels", "scans", "sync_state", "sync_run", "message_tombstone")))

    def test_heartbeat_renews_the_lease_without_touching_the_checkpoint_and_never_revives_a_lost_one(self):
        a = self.acquire()
        state_before = dict(self.state())
        self.clock.advance(200)
        a.heartbeat()
        run = self.runs()[-1]
        self.assertEqual(sync_health.parse(run["lease_expires_at"]), self.clock.now + sync_lease.LEASE_TTL)
        self.assertEqual({k: v for k, v in self.state().items() if k != "status"}, {k: v for k, v in state_before.items() if k != "status"})
        self.clock.advance(400)
        self.acquire(self.other)                                               # lost: the heartbeat must not bring it back
        with self.assertRaises(sync_lease.LeaseLost):
            a.heartbeat()
        self.assertEqual(self.runs()[-2]["status"], "interrupted")

    def test_heartbeat_continues_during_a_long_backoff_sleep(self):
        a = self.acquire()
        started = sync_health.parse(self.runs()[-1]["heartbeat_at"])
        a.sleep(250, self.clock.sleep)                                         # cut into 30 s slices; beats between them
        self.assertGreater(sync_health.parse(self.runs()[-1]["heartbeat_at"]), started + timedelta(seconds=100))
        self.assertTrue(all(s <= sync_lease.SLEEP_SLICE for s in self.clock.slept))

    def test_heartbeat_continues_through_long_pagination_without_any_commit(self):
        for i in range(30):
            self.mailbox.add(f"x{i}")
        calls = {"n": 0}
        busy = []

        def tick():                                                            # every history page takes 100 s of "work"
            calls["n"] += 1
            self.clock.advance(100)
            if calls["n"] == 8:                                                # 800 s after the start: far beyond one lease term
                with self.assertRaises(sync_lease.SyncError) as ctx:
                    self.acquire(self.other)
                busy.append(ctx.exception.code)
        for k in range(1, 12):
            self.at_call("list_history", k, tick)
        self.sync(page_size=3)
        self.assertEqual(busy, ["SYNC_BUSY"])
        self.assertMatchesOracle()

    def test_a_lease_lost_mid_run_stops_without_further_commits(self):
        for i in range(12):
            self.mailbox.add(f"x{i}")
        state = {}

        def takeover(point):
            if point == "chunk:1":
                self.clock.advance(301)
                state["b"] = self.acquire(self.other)
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync(chunk=3, hook=takeover)
        self.assertEqual(ctx.exception.code, "SYNC_LEASE_LOST")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages WHERE id LIKE 'x%'")[0][0], 3)      # only the first committed chunk
        self.assertEqual(self.state()["history_id"], "112")

    def test_l6_an_active_cleanup_execution_blocks_every_kind_of_writer(self):
        with mock.patch.object(sync_lease, "active_execution", return_value=True):
            for kind in ("INCREMENTAL", "FULL", "LIMITED"):
                with self.assertRaises(sync_lease.SyncError) as ctx:
                    self.acquire(kind=kind)
                self.assertIn(ctx.exception.code, ("SYNC_EXECUTION_ACTIVE", "SYNC_LIMITED_REFUSED"))
        self.assertEqual([r["status"] for r in self.runs()], ["completed"])

    def test_l6_purge_is_refused_while_a_lease_is_active_and_only_then(self):
        a = self.acquire()
        with self.assertRaises(idx.IndexProblem):
            self.other.purge(ACCOUNT)
        self.assertGreater(self.index._q("SELECT COUNT(*) FROM messages")[0][0], 0)
        a.finish("interrupted", "INTERRUPTED", "API_ERROR")
        sync_lease.release(self.index)
        self.other.purge(ACCOUNT)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages")[0][0], 0)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM sync_state")[0][0], 0)


class RecoveryUnitTests(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)
        self.h0 = self.state()["history_id"]

    def crash_full_scan(self):
        """A FULL scan whose process dies mid-listing (BaseException skips every clean-up, like a kill)."""
        self.at_call("list_message_ids", 2, lambda: (_ for _ in ()).throw(Crash()))
        with self.assertRaises(Crash):
            self.scan_all()
        sync_lease.release(self.index)
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)

    def test_rc1_a_dead_incremental_run_is_replayed_from_the_committed_checkpoint(self):
        for i in range(8):
            self.mailbox.add(f"x{i}")
        with self.assertRaises(Crash):
            self.sync(chunk=3, hook=lambda p: (_ for _ in ()).throw(Crash()) if p == "chunk:2" else None)
        sync_lease.release(self.index)
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("IN_PROGRESS", self.h0))
        self.clock.advance(100)
        with self.assertRaises(sync_lease.SyncError) as busy:                  # before the lease expires nobody may take over
            self.sync()
        self.assertEqual(busy.exception.code, "SYNC_BUSY")
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds())
        self.sync(chunk=3)
        self.assertMatchesOracle()
        runs = self.runs()
        self.assertEqual([(r["kind"], r["status"], r["start_history_id"]) for r in runs[-2:]], [("INCREMENTAL", "interrupted", self.h0), ("INCREMENTAL", "completed", self.h0)])
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("OK", str(self.mailbox.hid)))

    def test_rc2_a_dead_full_scan_is_never_bypassed_by_incremental_sync(self):
        self.crash_full_scan()
        calls = len(self.mailbox.calls)
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_FULL_SCAN_UNFINISHED")
        self.assertEqual(len(self.mailbox.calls), calls)                       # no Gmail request at all
        self.assertEqual((self.state()["status"], self.state()["reason"], self.state()["history_id"]), ("INTERRUPTED", "FULL_SCAN_INTERRUPTED", self.h0))
        self.assertIn("SYNC_FULL_SCAN_INCOMPLETE", self.health())
        # resuming reuses the ORIGINAL baseline of the dead scan and only its completion restores OK
        original = self.runs()[-1]["first_history_id"]
        self.mailbox.add("later")
        row = self.scan_all(resume=True)
        self.assertEqual(row["status"], "completed")
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("OK", original))
        self.clock.advance(60)
        self.sync()                                                             # now incremental sync is admitted and sees the change
        self.assertMatchesOracle()

    def test_rc3_a_corrupted_status_flag_cannot_hide_an_unfinished_full_scan(self):
        self.crash_full_scan()
        with self.assertRaises(sync_lease.SyncError):
            self.sync()                                                         # reaps the dead run
        for status, reason in (("OK", None), ("INTERRUPTED", "LEASE_EXPIRED")):
            with self.index.conn:
                self.index.conn.execute("UPDATE sync_state SET status=?, reason=? WHERE account=?", (status, reason, ACCOUNT))
            with self.assertRaises(sync_lease.SyncError) as ctx:
                self.sync()
            self.assertEqual(ctx.exception.code, "SYNC_FULL_SCAN_UNFINISHED")
            self.assertIn("SYNC_FULL_SCAN_INCOMPLETE", self.health())

    def test_rc5_a_refused_requester_still_commits_the_reap_and_repeating_is_idempotent(self):
        self.crash_full_scan()
        before_hist = self.state()["history_id"]
        for _ in range(2):
            with self.assertRaises(sync_lease.SyncError):
                self.sync()
        dead = [r for r in self.runs() if r["kind"] == "FULL"][-1]
        self.assertEqual((dead["status"], dead["error"]), ("interrupted", "LEASE_EXPIRED"))
        self.assertEqual(self.index._q("SELECT status FROM scans ORDER BY id DESC LIMIT 1")[0][0], "interrupted")
        self.assertNotEqual(self.state()["status"], "OK")
        self.assertEqual(self.state()["history_id"], before_hist)

    def test_rc6_an_in_progress_flag_without_a_run_is_inconsistent_and_only_a_full_scan_repairs_it(self):
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='IN_PROGRESS' WHERE account=?", (ACCOUNT,))
        self.assertEqual(self.health(), ["SYNC_IN_PROGRESS", "SYNC_STATE_INCONSISTENT"])
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_STATE_INCONSISTENT")
        self.assertEqual(self.scan_all()["status"], "completed")
        self.assertEqual((self.state()["status"], self.health()), ("OK", []))

    def test_rc6_a_legacy_running_scan_row_is_reaped_and_counts_as_unfinished(self):
        with self.index.conn:
            self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'running', '2026-01-01T00:00:00Z')", (ACCOUNT,))
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_FULL_SCAN_UNFINISHED")
        self.assertEqual(self.index._q("SELECT status FROM scans ORDER BY id DESC LIMIT 1")[0][0], "interrupted")


class ProcessTests(SyncCase, WorkerMixin):
    """REAL processes: kill -9, forced stalls, races. The parent builds the baseline; workers rebuild the same deterministic fake mailbox."""

    def setUp(self):
        super().setUp()
        self.baseline()
        self.h0 = self.state()["history_id"]
        self.expected = standard_mailbox(self.N)
        self.expected.script(SCRIPT)
        self.index.close()                                                     # the workers own the database now
        self.index = idx.Index(self.db, create=False)

    def refresh(self):
        self.index.close()
        self.index = idx.Index(self.db, create=False)
        self.addCleanup(lambda: self.index.close())

    def test_l1_two_processes_started_together_exactly_one_holds_the_lease(self):
        first, paused, release = self.worker("sync", SCRIPT, pause_at="acquired")
        self.wait_for(paused)
        second = self.worker("sync", SCRIPT, wait=True)
        code, out = self.finish(second)
        self.assertEqual((code, out), (3, {"error": "SYNC_BUSY"}))
        release.write_text("go")
        code, out = self.finish(first)
        self.assertEqual(code, 0, out)
        self.refresh()
        self.assertEqual(self.state()["status"], "OK")
        self.assertMatchesOracle(self.expected)

    def test_l2_eight_racing_processes_leave_exactly_one_holder(self):
        procs = [self.worker("sync", SCRIPT, pause_at="acquired") for _ in range(8)]
        import time
        end = time.time() + 40
        while time.time() < end and sum(1 for _, paused, _ in procs if paused.exists()) < 1:
            time.sleep(0.05)
        time.sleep(1.5)                                                         # let every loser fail its acquire
        holders = [p for p in procs if p[1].exists()]
        self.assertEqual(len(holders), 1)
        self.refresh()
        self.assertEqual(len([r for r in self.runs() if r["status"] == "running"]), 1)
        holders[0][2].write_text("go")
        results = [self.finish(p[0]) for p in procs]
        self.assertEqual(sorted(code for code, _ in results), [0] + [3] * 7)
        self.assertTrue(all(out == {"error": "SYNC_BUSY"} for code, out in results if code == 3))
        self.refresh()
        self.assertMatchesOracle(self.expected)

    def test_l2_kill_9_then_takeover_and_recovery(self):
        proc, paused, _ = self.worker("sync", SCRIPT, pause_at="chunk:1", chunk=2)
        self.wait_for(paused)
        proc.kill()                                                             # SIGKILL: no clean-up of any kind
        proc.wait()
        self.refresh()
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("IN_PROGRESS", self.h0))
        self.assertIn("SYNC_IN_PROGRESS", self.health())
        code, out = self.finish(self.worker("sync", SCRIPT, wait=True))        # right away: the lease is still active
        self.assertEqual((code, out), (3, {"error": "SYNC_BUSY"}))
        code, out = self.finish(self.worker("sync", SCRIPT, offset=400, wait=True, chunk=2))   # 400 s later by its clock: expired, taken over
        self.assertEqual(code, 0, out)
        self.refresh()
        self.assertMatchesOracle(self.expected)
        runs = self.runs()
        self.assertEqual([(r["status"], r["error"]) for r in runs[-2:]], [("interrupted", "LEASE_EXPIRED"), ("completed", None)])
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("OK", str(self.expected.hid)))

    def test_l3_a_suspended_former_holder_cannot_commit_after_takeover(self):
        proc, paused, release = self.worker("sync", SCRIPT, pause_at="chunk:1", chunk=2)   # stalled holder (as if the machine slept)
        self.wait_for(paused)
        code, out = self.finish(self.worker("sync", SCRIPT, offset=400, wait=True, chunk=2))
        self.assertEqual(code, 0, out)
        self.refresh()
        after_takeover = table_digest(self.index, ("messages", "message_labels", "labels", "scans", "sync_state", "message_tombstone", "sync_run"))
        release.write_text("go")                                                # the old process wakes up and tries to continue
        code, out = self.finish(proc)
        self.assertEqual((code, out), (3, {"error": "SYNC_LEASE_LOST"}))
        self.refresh()
        self.assertEqual(after_takeover, table_digest(self.index, ("messages", "message_labels", "labels", "scans", "sync_state", "message_tombstone", "sync_run")))
        self.assertMatchesOracle(self.expected)

    def test_l4_two_takeover_attempts_on_the_same_expired_lease_have_one_winner(self):
        proc, paused, _ = self.worker("sync", SCRIPT, pause_at="chunk:1", chunk=2)
        self.wait_for(paused)
        proc.kill()
        proc.wait()
        racers = [self.worker("sync", SCRIPT, offset=400, pause_at="acquired", chunk=2) for _ in range(2)]
        import time
        time.sleep(2.5)
        holders = [r for r in racers if r[1].exists()]
        self.assertEqual(len(holders), 1)
        holders[0][2].write_text("go")
        results = sorted(self.finish(r[0])[0] for r in racers)
        self.assertEqual(results, [0, 3])
        self.refresh()
        self.assertEqual([r["status"] for r in self.runs()[-2:]], ["interrupted", "completed"])
        self.assertMatchesOracle(self.expected)

    def test_rc2_a_killed_full_scan_blocks_incremental_sync_across_processes(self):
        proc, paused, _ = self.worker("scan-all", pause_at="page2")
        self.wait_for(paused)
        proc.kill()
        proc.wait()
        code, out = self.finish(self.worker("sync", SCRIPT, offset=400, wait=True))
        self.assertEqual((code, out), (3, {"error": "SYNC_FULL_SCAN_UNFINISHED"}))
        self.refresh()
        self.assertEqual((self.state()["status"], self.state()["reason"], self.state()["history_id"]), ("INTERRUPTED", "FULL_SCAN_INTERRUPTED", self.h0))
        code, out = self.finish(self.worker("scan-resume", offset=800, wait=True))
        self.assertEqual((code, out["ok"]["status"]), (0, "completed"))
        self.refresh()
        self.assertEqual(self.state()["status"], "OK")
        code, out = self.finish(self.worker("sync", SCRIPT, offset=900, wait=True))
        self.assertEqual(code, 0, out)

    def test_l5_a_limited_scan_and_a_sync_cannot_run_together(self):
        proc, paused, release = self.worker("sync", SCRIPT, pause_at="acquired")
        self.wait_for(paused)
        code, out = self.finish(self.worker("scan-all", wait=True))
        self.assertEqual((code, out), (3, {"error": "SYNC_BUSY"}))
        release.write_text("go")
        self.assertEqual(self.finish(proc)[0], 0)


if __name__ == "__main__":
    unittest.main()
