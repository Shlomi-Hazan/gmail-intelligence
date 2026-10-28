"""Synthetic fixtures for the M8A-1 attention tests: a temporary index filled with direct SQL (fast), no Gmail, no Keychain, no network."""
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(HERE))

from gmail_intelligence import attention, classifier, classify  # noqa: E402,F401
from gmail_intelligence import index as idx  # noqa: E402

ACCOUNT = "owner@example.test"
OTHER = "other@example.test"
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
TODAY = NOW.date()


def ms_ago(days, hours=0):
    return int((NOW - timedelta(days=days, hours=hours)).timestamp() * 1000)


class Mailbox:
    """A synthetic mailbox in a temporary directory (the index file is `self.path`)."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.path = os.path.join(self.dir, "index.sqlite3")
        with idx.Index(self.path):
            pass
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.n = 0
        self.scan(ACCOUNT)

    def close(self):
        self.conn.close()
        self.tmp.cleanup()

    def scan(self, account, finished=None):
        self.conn.execute("INSERT INTO scans (account, mode, status, started_at, finished_at) VALUES (?, 'full', 'completed', ?, ?)",
                          (account, "2026-10-21T10:00:00Z", finished or "2026-10-21T11:00:00Z"))
        self.conn.commit()

    def add(self, mid=None, *, account=ACCOUNT, thread="auto", age_days=1.0, sender="auto", labels=("INBOX",), unread=None, ms="auto"):
        self.n += 1
        mid = mid or f"{self.n:08x}"
        sender = f"s{self.n}@example.test" if sender == "auto" else sender
        thread = f"t{mid}" if thread == "auto" else thread
        when = ms_ago(age_days) if ms == "auto" else ms
        flag = ("UNREAD" in labels) if unread is None else unread
        self.conn.execute("INSERT OR REPLACE INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) VALUES (?,?,?,?,?,?,?,1)",
                          (account, mid, thread, when, 100, sender, 1 if flag else 0))
        self.conn.execute("DELETE FROM message_labels WHERE account=? AND message_id=?", (account, mid))
        self.conn.executemany("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)", [(account, mid, lab) for lab in labels])
        self.conn.commit()
        return mid

    def sql(self, statement, *params):
        self.conn.execute(statement, params)
        self.conn.commit()

    def set_labels(self, mid, labels, account=ACCOUNT):
        self.conn.execute("DELETE FROM message_labels WHERE account=? AND message_id=?", (account, mid))
        self.conn.executemany("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)", [(account, mid, lab) for lab in labels])
        self.conn.execute("UPDATE messages SET unread=? WHERE account=? AND id=?", (1 if "UNREAD" in labels else 0, account, mid))
        self.conn.commit()

    def add_rule(self, **fields):
        fields.setdefault("priority", 0)
        fields.setdefault("note", None)
        class Wrap:
            conn = self.conn

            @staticmethod
            def _q(sql, *params):
                return self.conn.execute(sql, params).fetchall()
        return classifier.add_rule(Wrap, ACCOUNT, **fields)

    def readonly(self):
        return idx.ReadOnlyIndex(self.path)

    def compute(self, account=ACCOUNT, **kw):
        kw.setdefault("now", NOW)
        ro = self.readonly()
        try:
            return attention.compute(ro, account, **kw)
        finally:
            ro.close()

    def tree(self):
        out = []
        for name in sorted(os.listdir(self.dir)):
            p = os.path.join(self.dir, name)
            st = os.stat(p)
            out.append((name, st.st_size, st.st_mtime_ns, st.st_mode, hashlib.sha256(Path(p).read_bytes()).hexdigest()))
        return out


class MailboxCase(unittest.TestCase):
    def setUp(self):
        self.mb = Mailbox()
        self.addCleanup(self.mb.close)
