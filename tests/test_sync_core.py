"""M7A: baseline capture, replay-based incremental sync and failure handling (S1-S5, C1-C8). Fake Gmail and temporary synthetic databases only."""
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from sync_support import ACCOUNT, HERE, SRC, SyncCase, WorkerMixin, M4_TABLES, standard_mailbox, sync, sync_health, sync_lease, table_digest
from fake_history import FakeHistoryMailbox
from gmail_intelligence import gmail, scanner


class Crash(BaseException):
    """Simulated process death: bypasses every `except Exception` clean-up, like a kill."""


class BaselineTests(SyncCase):
    def test_s1_history_id_is_read_before_listing_and_stored_with_the_scan(self):
        h_before = self.mailbox.hid
        # a change that happens WHILE the listing runs must not move the baseline
        self.mailbox.hooks[("list_message_ids", 2)] = lambda: self.mailbox.add("m-late")
        row = self.baseline()
        self.assertEqual(self.mailbox.calls[0], "get_profile")
        self.assertLess(self.mailbox.calls.index("get_profile"), self.mailbox.calls.index("list_message_ids"))
        st = self.state()
        self.assertEqual((st["status"], st["source"], st["basis_scan_id"], st["history_id"]), ("OK", "PROFILE_BEFORE_FULL_LIST", row["id"], str(h_before)))
        run = self.runs()[0]
        self.assertEqual((run["kind"], run["status"], run["scan_id"], run["first_history_id"]), ("FULL", "completed", row["id"], str(h_before)))
        self.assertEqual(self.health(), [])

    def test_s1_resumed_scan_keeps_the_original_baseline(self):
        h_before = self.mailbox.hid
        self.mailbox.hooks[("list_message_ids", 2)] = lambda: self.mailbox.faults.__setitem__(
            "list_message_ids", [gmail.GmailApiError("down", 500) for _ in range(scanner.MAX_ATTEMPTS)])
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan_all()
        self.assertIsNone(self.state())                      # an interrupted scan establishes nothing
        self.assertEqual(self.runs()[0]["status"], "interrupted")
        self.mailbox.add("m-after")                          # the mailbox moves on before the resume
        row = self.scan_all(resume=True)
        self.assertEqual(row["status"], "completed")
        self.assertEqual(self.state()["history_id"], str(h_before))   # NOT the newer id
        self.assertEqual([r["first_history_id"] for r in self.runs()], [str(h_before)] * 2)

    def test_s1_limited_scan_never_establishes_a_checkpoint(self):
        row = scanner.run_scan(self.mailbox, self.index, ACCOUNT, mode="limited", limit=4, limiter=__import__("sync_support").fast_limiter(),
                               sleep=self.clock.sleep, clock=self.clock, page_size=2)
        self.assertEqual(row["status"], "completed")
        self.assertIsNone(self.state())
        self.assertIn("SYNC_CHECKPOINT_MISSING", self.health())

    def test_s1_a_scan_from_before_v7_establishes_no_checkpoint(self):
        self.mailbox.hooks[("list_message_ids", 2)] = lambda: self.mailbox.faults.__setitem__(
            "list_message_ids", [gmail.GmailApiError("down", 500) for _ in range(scanner.MAX_ATTEMPTS)])
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan_all()
        with self.index.conn:
            self.index.conn.execute("DELETE FROM sync_run")      # what a v6-era scan looks like: no run row, no baseline
        row = self.scan_all(resume=True)
        self.assertEqual(row["status"], "completed")
        self.assertIsNone(self.state())

    def test_full_scan_completion_is_one_transaction_nothing_partial_on_a_crash_inside_it(self):
        self.baseline()
        self.mailbox.delete("m001")
        before = table_digest(self.index, ("messages", "message_tombstone", "sync_state", "scans"))
        real = self.index._prune_unseen

        def boom(*a, **k):
            real(*a, **k)
            raise Crash()
        with mock.patch.object(self.index, "_prune_unseen", boom), self.assertRaises(Crash):
            self.scan_all()
        # prune + tombstone + scan completion + checkpoint were rolled back together (the new scan row itself is an in-flight 'running' row)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM message_tombstone")[0][0], 0)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM messages WHERE id='m001'")[0][0], 1)
        self.assertNotEqual(before, table_digest(self.index, ("scans",)))


class IncrementalTests(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)

    def test_s2_empty_history_advances_to_the_response_id_when_present(self):
        self.mailbox.hid += 5                                # events outside our filter: nothing listed, but the mailbox id moved
        out = self.sync()
        self.assertEqual((out["affected"], out["refreshed"], out["tombstoned"]), (0, 0, 0))
        st = self.state()
        self.assertEqual((st["status"], st["history_id"], st["source"]), ("OK", str(self.mailbox.hid), "HISTORY_RESPONSE"))

    def test_s2_empty_history_without_a_response_id_keeps_the_checkpoint(self):
        before = self.state()["history_id"]
        orig = self.mailbox.list_history
        self.mailbox.list_history = lambda *a, **k: dict(orig(*a, **k), history_id=None)
        self.sync()
        self.assertEqual((self.state()["history_id"], self.state()["status"]), (before, "OK"))
        self.assertEqual(self.runs()[-1]["error"], "NO_HISTORY_ID")

    def test_s2_one_and_many_new_messages_match_the_oracle(self):
        self.mailbox.add("n001", ("INBOX", "UNREAD"))
        out = self.sync()
        self.assertEqual(out["refreshed"], 1)
        self.assertMatchesOracle()
        run_id = self.runs()[-1]["id"]
        self.assertEqual(self.index._q("SELECT scan_id FROM messages WHERE id='n001'")[0][0], -run_id)   # negative scan_id for changed/new rows
        for i in range(25):
            self.mailbox.add(f"x{i:03d}")
        self.clock.advance(60)
        self.sync(page_size=4, chunk=7)
        self.assertMatchesOracle()

    def test_s2_a_message_added_during_the_run_is_picked_up_by_the_next_run(self):
        self.mailbox.add("n001")
        self.at_call("get_message_metadata", 1, lambda: self.mailbox.add("late-1"))
        self.sync()
        self.assertNotIn("late-1", self.index_rows())          # beyond the conservative upper bound: replayed next time, never lost
        self.clock.advance(60)
        self.sync()
        self.assertMatchesOracle()

    def test_s3_label_changes_unread_starred_important_and_multiple_changes(self):
        self.mailbox.labels_change("m001", add=("STARRED", "IMPORTANT"))
        self.mailbox.labels_change("m001", remove=("STARRED",))
        self.mailbox.labels_change("m000", remove=("UNREAD",))          # unread -> read
        self.mailbox.labels_change("m002", add=("UNREAD", "Label_1"))
        self.mailbox.labels_change("m003", add=("TRASH",), remove=("INBOX",))   # trash is a label event, not a deletion
        out = self.sync()
        self.assertEqual(out["tombstoned"], 0)
        self.assertMatchesOracle()
        self.assertEqual(self.index._q("SELECT unread FROM messages WHERE id='m000'")[0][0], 0)

    def test_s3_label_definitions_are_refreshed_every_run(self):
        self.mailbox.labels.append({"id": "Label_9", "name": "Another Private Name", "type": "user"})
        self.sync()
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM labels WHERE id='Label_9'")[0][0], 1)

    def test_unchanged_messages_are_true_no_ops(self):
        self.mailbox.labels_change("m001", add=("STARRED",))
        self.mailbox.labels_change("m001", remove=("STARRED",))          # net effect: nothing
        old_scan = self.index._q("SELECT scan_id FROM messages WHERE id='m001'")[0][0]
        out = self.sync()
        self.assertEqual((out["refreshed"], out["unchanged"]), (0, 1))
        self.assertEqual(self.index._q("SELECT scan_id FROM messages WHERE id='m001'")[0][0], old_scan)   # untouched, still the positive scan id
        self.assertGreater(old_scan, 0)

    def test_s4_permanent_deletion_writes_a_tombstone_and_removes_dependent_rows(self):
        with self.index.conn:
            self.index.conn.execute("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)", (ACCOUNT, "m004", "type", "PROMOTIONAL", "HIGH", "rule", "r", "x", "h", 1, "2026-01-01"))
        self.mailbox.delete("m004")
        out = self.sync()
        self.assertEqual(out["tombstoned"], 1)
        self.assertEqual(self.tombstones(), {"m004": "HISTORY_DELETED"})
        for table, col in (("messages", "id"), ("message_labels", "message_id"), ("message_class", "message_id")):
            self.assertEqual(self.index._q(f"SELECT COUNT(*) FROM {table} WHERE {col}='m004'")[0][0], 0)
        self.assertMatchesOracle()

    def test_s4_added_then_deleted_in_one_range_leaves_no_tombstone(self):
        self.mailbox.add("tmp-1")
        self.mailbox.delete("tmp-1")
        out = self.sync()
        self.assertEqual((out["vanished"], out["tombstoned"]), (1, 0))
        self.assertEqual(self.tombstones(), {})

    def test_s4_a_message_gone_on_refresh_without_a_delete_event_is_tombstoned(self):
        self.mailbox.labels_change("m005", add=("STARRED",))
        del self.mailbox.msgs["m005"]                        # vanished without a history event we can see
        self.sync()
        self.assertEqual(self.tombstones(), {"m005": "NOT_FOUND_ON_REFRESH"})

    def test_s5_shuffled_and_duplicated_events_give_the_same_result(self):
        ops = [["add", "n1", ["INBOX"]], ["labels", "m001", ["STARRED"], []], ["delete", "m002"], ["labels", "m001", [], ["STARRED"]],
               ["add", "n2", ["INBOX", "UNREAD"]], ["labels", "m006", ["Label_1"], []]]
        plain = standard_mailbox(self.N)
        plain.script([])
        results = []
        for shuffle, dup, ps in ((False, False, 100), (True, False, 2), (True, True, 3)):
            import sync_support as sp
            case_index = sp.idx.Index(str(self.tmp / f"x-{shuffle}-{dup}.sqlite3"))
            self.addCleanup(case_index.close)
            mb = standard_mailbox(self.N)
            sp.scanner.run_scan(mb, case_index, ACCOUNT, mode="full", limiter=sp.fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=3)
            mb.script(ops)
            mb.shuffle, mb.duplicate = shuffle, dup
            sp.sync.run_sync(mb, case_index, ACCOUNT, limiter=sp.fast_limiter(), sleep=self.clock.sleep, clock=self.clock, page_size=ps, chunk=2)
            rows = {r["id"]: tuple(r) for r in case_index.conn.execute("SELECT id,thread_id,internal_ms,size,sender,unread FROM messages")}
            labs = sorted(tuple(r) for r in case_index.conn.execute("SELECT message_id,label_id FROM message_labels"))
            tomb = sorted(tuple(r) for r in case_index.conn.execute("SELECT message_id,reason FROM message_tombstone"))
            results.append((rows, labs, tomb))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_a_second_run_with_nothing_new_changes_nothing(self):
        self.mailbox.add("n1")
        self.sync()
        digest = table_digest(self.index, ("messages", "message_labels", "message_tombstone"))
        self.clock.advance(60)
        self.sync()
        self.assertEqual(digest, table_digest(self.index, ("messages", "message_labels", "message_tombstone")))

    def test_summary_and_progress_contain_no_private_values(self):
        self.mailbox.add("private-id-123", ("INBOX",), sender="secret.person@private.example.test")
        out = self.sync()
        text = json.dumps(out) + "\n".join(self.logs)
        for needle in ("private-id-123", "secret.person", "private.example", "Private Label Name", ACCOUNT):
            self.assertNotIn(needle, text)

    def test_only_the_read_adapter_methods_were_used(self):
        self.mailbox.add("n1")
        self.sync()
        self.assertLessEqual(set(self.mailbox.calls), {"get_profile", "list_label_details", "list_message_ids", "get_message_metadata", "list_history"})
        self.assertNotIn("list_message_ids", self.mailbox.calls[self.mailbox.calls.index("list_history") - 1:])   # no automatic listing during a sync


class CheckpointSafetyTests(SyncCase):
    def setUp(self):
        super().setUp()
        self.baseline()
        self.clock.advance(60)
        self.h0 = self.state()["history_id"]
        for i in range(6):
            self.mailbox.add(f"n{i}")
        self.mailbox.labels_change("m001", add=("STARRED",))
        self.mailbox.delete("m002")

    def test_c1_the_checkpoint_never_moves_before_the_final_transaction_whatever_the_crash_point(self):
        points = ["acquired", "collected", "labels_saved", "chunk:1", "chunk:2", "chunk:3", "before_end"]
        for point in points:
            with self.subTest(crash=point):
                def hook(p, point=point):
                    if p == point:
                        raise Crash()
                with self.assertRaises(Crash):
                    self.sync(chunk=3, hook=hook)
                self.assertEqual(self.state()["history_id"], self.h0)
                self.assertIn("SYNC_IN_PROGRESS", self.health())            # a crash leaves M4 prohibited
                self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)  # the dead lease expires
        out = self.sync(chunk=3)                                              # one recovery run replays the whole range
        self.assertMatchesOracle()
        self.assertEqual(self.state()["status"], "OK")
        self.assertEqual(self.state()["history_id"], str(self.mailbox.hid))

    def test_c1_a_crash_after_the_final_transaction_keeps_the_new_checkpoint_and_ok(self):
        def hook(p):
            if p == "after_end":
                raise Crash()
        with self.assertRaises(Crash):
            self.sync(hook=hook)
        self.assertEqual((self.state()["status"], self.state()["history_id"]), ("OK", str(self.mailbox.hid)))
        self.assertEqual(self.health(), [])

    def test_c2_page_token_expiry_restarts_collection_from_the_checkpoint(self):
        self.at_call("list_history", 2, lambda: self.mailbox.faults.__setitem__("list_history", [gmail.GmailHistoryNotFoundError("e", 404)]))
        self.sync(page_size=3)
        self.assertMatchesOracle()
        self.assertGreater(self.mailbox.calls.count("list_history"), 3)          # collected again from the start after the expiry

    def test_c2_repeated_token_expiry_gives_up_without_moving_the_checkpoint(self):
        self.mailbox.faults["list_history"] = []
        orig = self.mailbox.list_history

        def failing(start, token=None, max_results=100):
            if token is not None:
                raise gmail.GmailHistoryNotFoundError("e", 404)
            return orig(start, token, max_results)
        self.mailbox.list_history = failing
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync(page_size=2)
        self.assertEqual(ctx.exception.code, "SYNC_API_ERROR")
        self.assertEqual((self.state()["status"], self.state()["history_id"], self.state()["reason"]), ("INTERRUPTED", self.h0, "API_ERROR"))

    def test_c3_a_400_on_a_page_token_restarts_like_an_expired_token(self):
        orig = self.mailbox.list_history
        state = {"n": 0}

        def flaky(start, token=None, max_results=100):
            if token is not None and state["n"] == 0:
                state["n"] += 1
                raise gmail.GmailApiError("bad token", 400)
            return orig(start, token, max_results)
        self.mailbox.list_history = flaky
        self.sync(page_size=2)
        self.assertMatchesOracle()

    def test_c5_expired_start_id_needs_reconcile_and_never_starts_a_scan(self):
        self.mailbox.expired_before = int(self.h0) + 1
        calls_before = len(self.mailbox.calls)
        before = table_digest(self.index, ("messages", "message_labels", "message_tombstone"))
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_NEEDS_RECONCILE")
        self.assertEqual((self.state()["status"], self.state()["reason"]), ("NEEDS_RECONCILE", "HISTORY_EXPIRED"))
        self.assertEqual(before, table_digest(self.index, ("messages", "message_labels", "message_tombstone")))
        self.assertNotIn("list_message_ids", self.mailbox.calls[calls_before:])   # no automatic full scan
        with self.assertRaises(sync_lease.SyncError) as again:             # incremental stays refused until a full scan reconciles
            self.sync()
        self.assertEqual(again.exception.code, "SYNC_NEEDS_RECONCILE")
        self.mailbox.expired_before = 0
        self.clock.advance(60)
        self.assertEqual(self.scan_all()["status"], "completed")
        self.assertEqual((self.state()["status"], self.health()), ("OK", []))

    def test_c5_invalid_start_id_and_other_anomalies_need_reconcile(self):
        cases = []
        mb = self.mailbox
        orig = mb.list_history

        def invalid(*a, **k):
            raise gmail.GmailApiError("bad", 400)
        mb.list_history = invalid
        with self.assertRaises(sync_lease.SyncError):
            self.sync()
        cases.append(self.state()["reason"])
        mb.list_history = orig
        self.assertEqual(self.scan_all()["status"], "completed")
        self.clock.advance(60)
        mb.profile_history_id = int(self.state()["history_id"]) - 1         # the mailbox id went backwards
        with self.assertRaises(sync_lease.SyncError):
            self.sync()
        cases.append(self.state()["reason"])
        mb.profile_history_id = None
        self.assertEqual(self.scan_all()["status"], "completed")
        self.clock.advance(60)
        other = FakeHistoryMailbox("someone.else@example.test")
        with self.assertRaises(sync_lease.SyncError):
            self.sync(mailbox=other)
        cases.append(self.state()["reason"])
        self.assertEqual(cases, ["HISTORY_INVALID", "ID_REGRESSION", "ACCOUNT_MISMATCH"])

    def test_c6_rate_limit_exhaustion_keeps_committed_chunks_and_the_checkpoint(self):
        self.at_call("get_message_metadata", 5, lambda: self.mailbox.faults.__setitem__(
            "get_message_metadata", [gmail.GmailRateLimitError("limit", 429) for _ in range(scanner.MAX_ATTEMPTS)]))
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync(chunk=2)
        self.assertEqual(ctx.exception.code, "SYNC_QUOTA")
        self.assertEqual((self.state()["status"], self.state()["reason"], self.state()["history_id"]), ("INTERRUPTED", "API_QUOTA", self.h0))
        self.assertTrue(self.clock.slept)                                   # bounded exponential backoff happened
        self.assertIn("SYNC_INTERRUPTED", self.health())
        self.clock.advance(60)
        self.sync(chunk=2)                                                  # the next run completes from the saved checkpoint
        self.assertMatchesOracle()

    def test_c6_transient_errors_are_retried_with_backoff(self):
        self.at_call("get_message_metadata", 2, lambda: self.mailbox.faults.__setitem__(
            "get_message_metadata", [gmail.GmailRateLimitError("limit", 429), gmail.GmailApiError("x", 503)]))
        self.sync()
        self.assertMatchesOracle()
        self.assertGreaterEqual(len(self.clock.slept), 2)

    def test_a_permanent_per_message_failure_blocks_the_checkpoint(self):
        self.mailbox.faults["get_message_metadata"] = [gmail.GmailApiError("bad", 400)]
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.sync()
        self.assertEqual(ctx.exception.code, "SYNC_INCOMPLETE")
        self.assertEqual((self.state()["history_id"], self.state()["status"]), (self.h0, "INTERRUPTED"))
        self.assertEqual(self.runs()[-1]["failed"], 1)

    def test_c9_an_oversized_range_goes_to_reconciliation(self):
        with self.assertRaises(sync_lease.SyncError):
            self.sync(max_range_ids=3)
        self.assertEqual((self.state()["status"], self.state()["reason"]), ("NEEDS_RECONCILE", "RANGE_TOO_LARGE"))

    def test_endless_pagination_is_bounded(self):
        orig = self.mailbox.list_history
        self.mailbox.list_history = lambda s, t=None, m=100: dict(orig(s, t, m), next="h0")
        with mock.patch.object(sync, "MAX_PAGES", 5), self.assertRaises(sync_lease.SyncError):
            self.sync(page_size=2)
        self.assertEqual(self.state()["reason"], "RANGE_TOO_LARGE")

    def test_c8_a_silently_truncated_history_response_is_NOT_detected_by_sync(self):
        """Documented residual risk (SYNC.md 7.1): sync cannot see a response that lost its nextPageToken."""
        self.mailbox.truncate_history_after = 1
        self.sync(page_size=2)
        self.assertNotEqual(self.index_rows(), self.oracle_rows())
        self.assertEqual(self.state()["status"], "OK")

    def test_cross_account_rows_and_state_are_never_touched(self):
        other = "second.owner@example.test"
        with self.index.conn:
            self.index.conn.execute("INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) VALUES (?,?,?,?,?,?,?,?)", (other, "o1", "t", 1, 1, "s@x.test", 0, 1))
            self.index.conn.execute("INSERT INTO message_tombstone VALUES (?,?,?,?,?)", (other, "gone", "2026-01-01T00:00:00Z", "HISTORY_DELETED", None))
            self.index.conn.execute("INSERT INTO sync_state VALUES (?,?,?,?,?,?,?,?)", (other, "5", "HISTORY_RESPONSE", 1, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "OK", None))
        before = [tuple(r) for t in ("messages", "message_tombstone", "sync_state") for r in self.index.conn.execute(f"SELECT * FROM {t} WHERE account=?", (other,))]
        self.sync()
        after = [tuple(r) for t in ("messages", "message_tombstone", "sync_state") for r in self.index.conn.execute(f"SELECT * FROM {t} WHERE account=?", (other,))]
        self.assertEqual(before, after)


class DeterminismTests(unittest.TestCase):
    def test_the_result_is_identical_under_different_hash_seeds(self):
        import tempfile
        ops = json.dumps([["add", "n1", ["INBOX"]], ["labels", "m001", ["STARRED"], []], ["delete", "m002"], ["labels", "m004", ["Label_1"], ["INBOX"]], ["add", "n2", ["INBOX", "UNREAD"]]])
        digests = set()
        for seed in ("0", "1", "42", "1234"):
            with tempfile.TemporaryDirectory() as tmp:
                db = os.path.join(tmp, "i.sqlite3")
                from gmail_intelligence import index as idx
                idx.Index(db).close()
                proc = subprocess.run([sys.executable, "-I", str(HERE / "sync_worker.py"), "--db", db, "--mode", "e2e", "--script", ops, "--n", "12"],
                                      capture_output=True, text=True, timeout=120, env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                digests.add(json.loads(proc.stdout.strip().splitlines()[-1])["ok"]["digest"])
        self.assertEqual(len(digests), 1)


if __name__ == "__main__":
    unittest.main()
