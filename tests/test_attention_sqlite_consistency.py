"""M8A-1: the SQLite facts the attention engine's consistency strategy relies on (synthetic temporary databases only).

* `PRAGMA data_version`, read on the SAME connection, changes when ANOTHER connection commits, is stable otherwise and ignores rollbacks and the reader's own reads.
* A long read transaction blocks a writer (so the engine must never keep one open); short, fully fetched reads do not.
* The keyset queries the engine uses are index-driven and need no temporary sort (no temporary files, no spill of metadata).
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from gmail_intelligence import index as idx  # noqa: E402

ACCOUNT = "owner@example.test"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "index.sqlite3")
        with idx.Index(self.path):
            pass
        self.writer = sqlite3.connect(self.path, timeout=0.3)
        self.addCleanup(self.writer.close)
        self.ro = idx.ReadOnlyIndex(self.path)
        self.addCleanup(self.ro.close)

    def dv(self):
        return self.ro.conn.execute("PRAGMA data_version").fetchone()[0]

    def commit_message(self, mid):
        self.writer.execute("INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) VALUES (?,?,?,?,?,?,?,?)",
                            (ACCOUNT, mid, "t" + mid, 1, 1, "a@example.test", 1, 1))
        self.writer.commit()


class DataVersionTests(Base):
    def test_it_is_readable_through_the_read_only_index_and_is_stable_without_other_writers(self):
        first = self.dv()
        self.assertEqual(first, self.dv())
        self.ro.conn.execute("SELECT COUNT(*) FROM messages").fetchall()
        self.assertEqual(first, self.dv())  # the reader's own reads never change it

    def test_a_commit_by_another_connection_changes_it_and_it_then_settles(self):
        before = self.dv()
        self.commit_message("a1")
        after = self.dv()
        self.assertNotEqual(before, after)
        self.assertEqual(after, self.dv())

    def test_every_further_commit_is_noticed(self):
        seen = {self.dv()}
        for mid in ("b1", "b2", "b3"):
            self.commit_message(mid)
            seen.add(self.dv())
        self.assertGreaterEqual(len(seen), 4)

    def test_a_rolled_back_write_is_not_a_change(self):
        before = self.dv()
        self.writer.execute("INSERT INTO messages (account,id,scan_id) VALUES (?,?,?)", (ACCOUNT, "c1", 1))
        self.writer.rollback()
        self.assertEqual(before, self.dv())

    def test_the_value_must_be_read_on_the_same_connection(self):
        """Documented limit: another connection has its own counter, so the engine compares values from ONE connection only."""
        other = idx.ReadOnlyIndex(self.path)
        self.addCleanup(other.close)
        mine_before = self.dv()
        self.commit_message("d1")
        self.assertNotEqual(mine_before, self.dv())


class ReadLockTests(Base):
    def test_short_fully_fetched_reads_never_block_a_writer(self):
        self.ro.conn.execute("SELECT * FROM messages").fetchall()
        self.commit_message("e1")  # would raise "database is locked" if the reader still held a lock
        self.ro.conn.execute("SELECT * FROM messages").fetchall()
        self.commit_message("e2")

    def test_an_open_read_transaction_does_block_a_writer(self):
        self.ro.conn.execute("BEGIN")
        self.ro.conn.execute("SELECT * FROM messages").fetchall()
        with self.assertRaises(sqlite3.OperationalError):
            self.commit_message("f1")
        self.writer.rollback()
        self.ro.conn.rollback()
        self.commit_message("f1")


class QueryPlanTests(Base):
    def plan(self, sql, params):
        return " | ".join(r[3] for r in self.ro.conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall())

    def test_label_streams_are_index_ordered_without_a_temporary_sort(self):
        plan = self.plan("SELECT message_id FROM message_labels WHERE account=? AND label_id=? AND message_id>? ORDER BY message_id LIMIT 10", (ACCOUNT, "STARRED", ""))
        self.assertIn("message_labels_label", plan)
        self.assertNotIn("TEMP B-TREE", plan)

    def test_the_full_stream_is_primary_key_ordered_without_a_temporary_sort(self):
        plan = self.plan("SELECT id, thread_id, internal_ms, sender, unread FROM messages WHERE account=? AND id>? ORDER BY id LIMIT 10", (ACCOUNT, ""))
        self.assertIn("PRIMARY KEY", plan)
        self.assertNotIn("TEMP B-TREE", plan)


if __name__ == "__main__":
    unittest.main()
