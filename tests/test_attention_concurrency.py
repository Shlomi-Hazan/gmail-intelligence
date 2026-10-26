"""M8A-1: consistent reads while a synthetic writer commits (data_version on ONE connection, bounded retries, no long read transaction)."""
import json
import sqlite3
import threading
import unittest

import attention_support as S
from attention_support import ACCOUNT, NOW, MailboxCase, attention


class ConcurrentWriterTests(MailboxCase):
    def setUp(self):
        super().setUp()
        self.original_batch = attention.BATCH
        attention.BATCH = 4  # many batches, so there are many moments in which a writer can interleave
        self.addCleanup(setattr, attention, "BATCH", self.original_batch)
        for k in range(30):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k + 1)
        self.writer = sqlite3.connect(self.mb.path, timeout=0.5)
        self.addCleanup(self.writer.close)

    def star_to_important(self, mid="00000001"):
        self.writer.execute("DELETE FROM message_labels WHERE account=? AND message_id=? AND label_id='STARRED'", (ACCOUNT, mid))
        self.writer.execute("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)", (ACCOUNT, mid, "IMPORTANT"))
        self.writer.commit()

    def quiet(self, **kw):
        return self.mb.compute(**kw)

    def test_a_write_between_batches_is_detected_and_the_result_is_one_consistent_state(self):
        calls = []

        def hook(n):
            calls.append(n)
            if len(calls) == 2:  # exactly once, in the middle of the first attempt
                self.star_to_important()

        res = self.mb.compute(limit=100, _after_batch=hook)
        after_state = self.quiet(limit=100)
        self.assertEqual(res["snapshot"], after_state["snapshot"])  # the retry saw the post-write state, completely
        self.assertEqual(res["items"], after_state["items"])
        self.assertGreater(len(calls), 8)  # the first attempt was thrown away and the whole computation ran again

    def test_a_writer_that_never_stops_gives_a_bounded_explicit_failure_with_no_items(self):
        calls = []
        counter = [0]

        def hook(n):
            calls.append(n)
            if n == 1:
                counter[0] += 1
                self.writer.execute("UPDATE messages SET size=size+1 WHERE account=? AND id='00000002'", (ACCOUNT,))
                self.writer.commit()

        with self.assertRaises(attention.AttentionError) as cm:
            self.mb.compute(limit=100, _after_batch=hook)
        self.assertEqual(cm.exception.code, "INDEX_CHANGED_DURING_READ")
        self.assertEqual(counter[0], attention.MAX_RETRIES + 1)  # bounded: first attempt plus the allowed retries, nothing more

    def test_a_writer_is_never_blocked_by_the_report_between_batches(self):
        outcomes = []

        def hook(n):
            if n == 1:
                try:
                    self.writer.execute("UPDATE messages SET size=size WHERE account=? AND id='00000003'", (ACCOUNT,))
                    self.writer.commit()  # would raise 'database is locked' if a read transaction were held open
                    outcomes.append("committed")
                except sqlite3.OperationalError as exc:
                    outcomes.append(str(exc))

        self.mb.compute(limit=100, _after_batch=hook)
        self.assertEqual(outcomes[0], "committed")

    def test_a_write_by_a_rolled_back_transaction_is_not_a_change(self):
        def hook(n):
            if n == 1:
                self.writer.execute("UPDATE messages SET size=size+1 WHERE account=? AND id='00000002'", (ACCOUNT,))
                self.writer.rollback()

        calls = []
        res = self.mb.compute(limit=100, _after_batch=lambda n: (calls.append(n), hook(n)))
        self.assertEqual(res["totals"]["total"], 30)
        self.assertLess(len(calls), 12)  # no retry happened

    def test_a_real_concurrent_writer_never_produces_a_result_assembled_from_two_states(self):
        state_a = self.quiet(limit=100)["snapshot"]
        self.star_to_important()
        state_b = self.quiet(limit=100)["snapshot"]
        self.assertNotEqual(state_a, state_b)
        stop = threading.Event()
        errors = []

        def toggler():
            conn = sqlite3.connect(self.mb.path, timeout=2)
            try:
                flip = False
                while not stop.is_set():
                    flip = not flip
                    try:
                        conn.execute("DELETE FROM message_labels WHERE account=? AND message_id='00000001' AND label_id IN ('STARRED','IMPORTANT')", (ACCOUNT,))
                        conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCOUNT, "00000001", "STARRED" if flip else "IMPORTANT"))
                        conn.commit()
                    except sqlite3.OperationalError as exc:  # the report must never be the cause of this
                        errors.append(str(exc))
                        conn.rollback()
                    stop.wait(0.003)
            finally:
                conn.close()

        thread = threading.Thread(target=toggler)
        thread.start()
        seen, failed = set(), 0
        try:
            for _ in range(12):
                try:
                    seen.add(self.mb.compute(limit=100)["snapshot"])
                except attention.AttentionError as exc:
                    self.assertEqual(exc.code, "INDEX_CHANGED_DURING_READ")
                    failed += 1
        finally:
            stop.set()
            thread.join()
        self.assertTrue(seen <= {state_a, state_b}, "a result mixed two states")
        self.assertGreater(len(seen) + failed, 0)
        self.assertEqual(errors, [])


class FreshnessConsistencyTests(MailboxCase):
    """The consistency check covers the list (items, totals, snapshot); the advisory freshness fields are read after it, on purpose (docs/ATTENTION.md section 5)."""

    ALLOWED_AFTER_THE_CHECK = ("SELECT * FROM scans WHERE", "SELECT COUNT(*) n, COUNT(DISTINCT thread_id) t", "SELECT * FROM sync_state WHERE",
                               "SELECT id, kind FROM sync_run WHERE", "SELECT 1 FROM scans WHERE", "SELECT finished_at FROM sync_run WHERE")

    def setUp(self):
        super().setUp()
        for k in range(12):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k + 1)

    def traced(self, on_first_freshness_statement=None):
        ro = self.mb.readonly()
        statements = []
        state = {"checks": 0, "fired": False}

        def trace(statement):
            statements.append(statement)
            if "data_version" in statement:
                state["checks"] += 1
            elif state["checks"] >= 2 and not state["fired"] and on_first_freshness_statement is not None:
                state["fired"] = True
                on_first_freshness_statement()

        ro.conn.set_trace_callback(trace)
        try:
            res = attention.compute(ro, ACCOUNT, now=NOW, limit=100)
        finally:
            ro.close()
        return res, statements

    def test_nothing_that_builds_an_item_is_read_after_the_final_check(self):
        res, statements = self.traced()
        last = max(i for i, st in enumerate(statements) if "data_version" in st)
        after = statements[last + 1:]
        self.assertTrue(after)  # the advisory freshness reads do happen there
        for st in after:
            self.assertTrue(st.lstrip().startswith(self.ALLOWED_AFTER_THE_CHECK), st[:80])
            self.assertNotIn("message_labels", st)
            self.assertNotIn("class_rules", st)
            self.assertNotIn("message_class", st)
        self.assertEqual(len(res["items"]), 12)

    def test_a_write_right_after_the_final_check_neither_blocks_nor_changes_the_list_but_may_change_the_warnings(self):
        before = self.mb.compute(limit=100)
        writer = sqlite3.connect(self.mb.path, timeout=0.5)
        self.addCleanup(writer.close)
        outcome = []

        def write_after_the_check():
            try:
                writer.execute("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)", (ACCOUNT, "00000001", "IMPORTANT"))
                writer.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'interrupted', '2026-10-21T11:55:00Z')", (ACCOUNT,))
                writer.commit()
                outcome.append("committed")
            except sqlite3.OperationalError as exc:
                outcome.append(str(exc))

        res, _ = self.traced(write_after_the_check)
        self.assertEqual(outcome, ["committed"])  # the report holds no lock between its statements
        self.assertEqual(res["items"], before["items"])  # the list is the state that was checked ...
        self.assertEqual(res["snapshot"], before["snapshot"])
        self.assertIn("INDEX_PARTIAL", res["warnings"])  # ... while the advisory warnings already show the newer state
        self.assertNotIn("INDEX_PARTIAL", before["warnings"])

    def test_the_warnings_are_not_part_of_the_snapshot_or_the_cursor_validity(self):
        first = self.mb.compute(limit=5)
        self.mb.sql("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'interrupted', '2026-10-21T11:55:00Z')", ACCOUNT)
        second = self.mb.compute(limit=5, cursor=first["next_cursor"])
        self.assertIn("INDEX_PARTIAL", second["warnings"])
        self.assertEqual(len(second["items"]), 5)


class ReadOnlyConnectionTests(MailboxCase):
    def test_a_write_through_the_engine_connection_is_impossible(self):
        self.mb.add(labels=("INBOX", "STARRED"))
        ro = self.mb.readonly()
        self.addCleanup(ro.close)
        with self.assertRaises(sqlite3.OperationalError):
            ro.conn.execute("DELETE FROM messages")
        res = S.attention.compute(ro, ACCOUNT, now=NOW)
        self.assertEqual(len(res["items"]), 1)
        self.assertEqual(json.loads(S.attention.as_json(res))["totals"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
