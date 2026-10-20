"""Common fixtures for the M7 sync tests (synthetic, offline)."""
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(HERE))

from fake_history import ACCOUNT, standard_mailbox  # noqa: E402
from gmail_intelligence import config, scanner, sync, sync_health, sync_lease  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
OWN_TABLES = ("messages", "message_labels", "labels", "scans", "message_class", "sync_state", "sync_run", "message_tombstone")
M4_TABLES = ("cleanup_plan", "cleanup_item", "cleanup_approval", "cleanup_audit", "cleanup_execution", "cleanup_exec_slice", "cleanup_exec_item",
             "label_plan", "label_plan_op", "label_plan_approval")


class Clock:
    """Injectable UTC clock; `sleep` advances it so heartbeat/expiry logic is testable without waiting."""

    def __init__(self, start=T0):
        self.now = start
        self.slept = []

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.advance(seconds)


def fast_limiter():
    return scanner.RateLimiter(10 ** 9, clock=lambda: 0.0, sleep=lambda s: None)


def table_digest(index, tables):
    h = hashlib.sha256()
    for t in tables:
        rows = sorted((tuple(r) for r in index.conn.execute(f"SELECT * FROM {t}")), key=repr)
        h.update(repr((t, rows)).encode())
    return h.hexdigest()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SyncCase(unittest.TestCase):
    N = 12

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.db = str(self.tmp / "index.sqlite3")
        guard = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used"))
        guard.start()
        self.addCleanup(guard.stop)
        self.index = idx.Index(self.db)
        self.addCleanup(lambda: self.index.close())  # whichever index the test ends with
        self.clock = Clock()
        self.mailbox = standard_mailbox(self.N)
        self.logs = []

    # ---- operations ----
    def scan_all(self, mailbox=None, **kw):
        kw.setdefault("page_size", 3)
        return scanner.run_scan(mailbox or self.mailbox, self.index, ACCOUNT, mode="full", limiter=fast_limiter(), sleep=self.clock.sleep,
                                clock=self.clock, progress=self.logs.append, **kw)

    def sync(self, mailbox=None, **kw):
        return sync.run_sync(mailbox or self.mailbox, self.index, ACCOUNT, limiter=fast_limiter(), sleep=self.clock.sleep, clock=self.clock,
                             progress=self.logs.append, **kw)

    def baseline(self):
        row = self.scan_all()
        self.assertEqual(row["status"], "completed")
        return row

    def at_call(self, name, k, fn, mailbox=None):
        """Run `fn` just before the k-th FUTURE call of reader method `name` (counts are cumulative over the mailbox's life)."""
        mb = mailbox or self.mailbox
        mb.hooks[(name, mb.counts.get(name, 0) + k)] = fn

    # ---- inspection ----
    def state(self):
        return sync_health.state_row(self.index, ACCOUNT)

    def health(self):
        return sync_health.problems(self.index, ACCOUNT, self.clock.now)

    def runs(self):
        return [dict(r) for r in self.index._q("SELECT * FROM sync_run WHERE account=? ORDER BY id", ACCOUNT)]

    def index_rows(self):
        out = {}
        for r in self.index._q("SELECT id, thread_id, internal_ms, size, sender, unread FROM messages WHERE account=?", ACCOUNT):
            labels = sorted(x[0] for x in self.index._q("SELECT label_id FROM message_labels WHERE account=? AND message_id=?", ACCOUNT, r["id"]))
            out[r["id"]] = (r["thread_id"], r["internal_ms"], r["size"], r["sender"], r["unread"], tuple(labels))
        return out

    def oracle_rows(self, mailbox=None):
        mb = mailbox or self.mailbox
        return {i: (m["thread_id"], m["internal_ms"], m["size"], m["sender"], 1 if "UNREAD" in m["label_ids"] else 0, tuple(sorted(set(m["label_ids"]))))
                for i, m in mb.msgs.items()}

    def assertMatchesOracle(self, mailbox=None):
        self.assertEqual(self.index_rows(), self.oracle_rows(mailbox))

    def tombstones(self):
        return {r[0]: r[1] for r in self.index._q("SELECT message_id, reason FROM message_tombstone WHERE account=?", ACCOUNT)}


class WorkerMixin:
    """Run tests/sync_worker.py as a REAL separate process against the temp database."""

    def worker(self, mode, script=(), offset=0, pause_at=None, crash_at=None, wait=False, chunk=50, n=None):
        cmd = [sys.executable, "-I", str(HERE / "sync_worker.py"), "--db", self.db, "--mode", mode, "--n", str(n or self.N),
               "--script", json.dumps(list(script)), "--offset", str(offset), "--chunk", str(chunk)]
        self._n = getattr(self, "_n", 0) + 1
        paused, release = self.tmp / f"paused-{self._n}", self.tmp / f"release-{self._n}"
        if pause_at:
            cmd += ["--pause-at", pause_at, "--paused-file", str(paused), "--release-file", str(release)]
        if crash_at:
            cmd += ["--crash-at", crash_at]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SRC)})
        def reap():
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
        self.addCleanup(reap)
        if wait:
            return proc
        return proc, paused, release

    def finish(self, proc, timeout=60):
        out, err = proc.communicate(timeout=timeout)
        self.assertNotIn("Traceback", err, err)
        line = out.strip().splitlines()[-1] if out.strip() else "{}"
        return proc.returncode, json.loads(line)

    def wait_for(self, path, timeout=30):
        import time
        end = time.time() + timeout
        while not os.path.exists(path):
            if time.time() > end:
                self.fail("worker did not reach the boundary in time")
            time.sleep(0.02)
