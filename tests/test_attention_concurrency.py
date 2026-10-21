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
