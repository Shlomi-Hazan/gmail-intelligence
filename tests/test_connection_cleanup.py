"""Open SQLite connections must be closed on every error path of `ReadOnlyIndex.__init__` and of the maintenance report (CI run 40383476752).

Before the fix, a damaged file, a locked database or an injected failure left the connection open; it was finalised only by the cyclic garbage collector, so its
ResourceWarning appeared inside whichever test happened to be running (and failed two tests that compare stderr exactly). The tests here do not rely on that timing:
every connection the code opens is a tracked subclass, and each must report `closed` as soon as the call returns; a garbage collection afterwards must also stay silent.
Synthetic data only: nothing here touches Gmail, the Keychain or a personal index, and the files are checked to be unchanged.
"""
import gc
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from gmail_intelligence import index as idx, maintenance  # noqa: E402

ACCOUNT = "owner@example.test"
UNREADABLE = "the local index file is unreadable or corrupt; nothing was changed"


class Tracked(sqlite3.Connection):
    """Records every connection that is opened, whether it was closed, and fails chosen statements on demand."""
    instances = []
    fail_on = ()
    fail_with = sqlite3.DatabaseError

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.closed = False
        Tracked.instances.append(self)

    def close(self):
        self.closed = True
        super().close()

    def execute(self, sql, *a):
        if any(marker in sql for marker in Tracked.fail_on):
            raise Tracked.fail_with("synthetic failure")
        return super().execute(sql, *a)


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.path = os.path.join(self.dir, "index.sqlite3")
        Tracked.instances, Tracked.fail_on, Tracked.fail_with = [], (), sqlite3.DatabaseError

    def valid_index(self):
        with idx.Index(self.path):
            pass
        os.chmod(self.path, 0o600)

    def tracking(self, timeout=None):
        real = sqlite3.connect

        def connect(*a, **k):
            k.setdefault("factory", Tracked)
            if timeout is not None:
                k["timeout"] = timeout
            return real(*a, **k)
        return mock.patch.object(sqlite3, "connect", connect)

    def state(self):
        out = []
        for name in sorted(os.listdir(self.dir)):
            p = os.path.join(self.dir, name)
            st = os.stat(p)
            out.append((name, st.st_size, st.st_mtime_ns, st.st_mode, hashlib.sha256(Path(p).read_bytes()).hexdigest()))
        return out

    def assertNothingLeaked(self, expected_connections=None):
        if expected_connections is not None:
            self.assertEqual(len(Tracked.instances), expected_connections)
        self.assertTrue(all(c.closed for c in Tracked.instances), [c.closed for c in Tracked.instances])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            gc.collect()
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])


class ReadOnlyIndexCleanupTests(Base):
    def refused(self, **kw):
        with self.tracking(**kw):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.ReadOnlyIndex(self.path)
        return str(cm.exception)

    def test_a_file_that_is_not_a_database_leaves_no_open_connection(self):
        Path(self.path).write_bytes(b"this is not a database" * 40)
        before = self.state()
        self.assertEqual(self.refused(), UNREADABLE)
        self.assertNothingLeaked(expected_connections=1)
        self.assertEqual(self.state(), before)

    def test_a_truncated_header_leaves_no_open_connection(self):
        self.valid_index()
        data = Path(self.path).read_bytes()[:60]
        Path(self.path).write_bytes(data)
        before = self.state()
        message = self.refused()
        self.assertTrue(message == UNREADABLE or "schema version 0" in message, message)  # SQLite reads a short header as an empty file or as damage
        self.assertNothingLeaked(expected_connections=1)
        self.assertEqual(self.state(), before)

    def test_a_locked_database_leaves_no_open_connection(self):
        self.valid_index()
        holder = sqlite3.connect(self.path)
        self.addCleanup(holder.close)
        holder.execute("BEGIN EXCLUSIVE")
        before = self.state()
        self.assertEqual(self.refused(timeout=0.05), UNREADABLE)
        self.assertNothingLeaked(expected_connections=1)
        holder.rollback()
        self.assertEqual(self.state(), before)

    def test_a_failure_at_each_statement_closes_the_connection(self):
        self.valid_index()
        for marker in ("query_only", "user_version"):
            with self.subTest(marker):
                Tracked.instances, Tracked.fail_on = [], (marker,)
                self.assertEqual(self.refused(), UNREADABLE)
                self.assertNothingLeaked(expected_connections=1)

    def test_an_unexpected_exception_closes_the_connection_and_propagates_unchanged(self):
        self.valid_index()
        for exc in (RuntimeError, KeyboardInterrupt, sqlite3.InterfaceError):
            with self.subTest(exc.__name__):
                Tracked.instances, Tracked.fail_on, Tracked.fail_with = [], ("user_version",), exc
                with self.tracking(), self.assertRaises(exc):
                    idx.ReadOnlyIndex(self.path)
                self.assertNothingLeaked(expected_connections=1)

    def test_an_unsupported_schema_still_refuses_and_closes(self):
        self.valid_index()
        with sqlite3.connect(self.path) as c:
            c.execute("PRAGMA user_version = 6")
        c.close()
        message = self.refused()
        self.assertIn("index upgrade", message)
        self.assertNothingLeaked(expected_connections=1)

    def test_a_missing_file_opens_no_connection_at_all(self):
        message = self.refused()
        self.assertIn("no local index", message)
        self.assertEqual(Tracked.instances, [])
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_valid_index_keeps_its_connection_open_until_closed_and_works_as_before(self):
        self.valid_index()
        before = self.state()
        with self.tracking():
            ro = idx.ReadOnlyIndex(self.path)
            self.assertEqual(len(Tracked.instances), 1)
            self.assertFalse(Tracked.instances[0].closed)  # successful ownership passes to the caller
            self.assertEqual(ro.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
            with self.assertRaises(sqlite3.OperationalError):
                ro.conn.execute("CREATE TABLE x (y)")  # still genuinely read-only
            ro.close()
        self.assertNothingLeaked(expected_connections=1)
        self.assertEqual(self.state(), before)


class MaintenanceCleanupTests(Base):
    def run_report(self, deep=False, **kw):
        with self.tracking(**kw):
            return maintenance.run(self.path, ACCOUNT, deep=deep)

    def codes(self, report):
        return {f["code"] for f in report["findings"]}

    def test_a_file_that_is_not_a_database_is_reported_and_leaves_no_open_connection(self):
        Path(self.path).write_bytes(b"this is not a database" * 40)
        before = self.state()
        for deep in (False, True):
            Tracked.instances = []
            report = self.run_report(deep)
            self.assertIn("INDEX_UNREADABLE_OR_CORRUPT", self.codes(report))
            self.assertNothingLeaked(expected_connections=1)
        self.assertEqual(self.state(), before)

    def test_a_failure_at_each_step_is_reported_and_closes_the_connection(self):
        self.valid_index()
        before = self.state()
        for marker in ("query_only", "user_version", "sqlite_master", "quick_check", "integrity_check"):
            with self.subTest(marker):
                Tracked.instances, Tracked.fail_on = [], (marker,)
                report = self.run_report(deep=(marker == "integrity_check"))
                self.assertIn("INDEX_UNREADABLE_OR_CORRUPT", self.codes(report))
                self.assertNothingLeaked(expected_connections=1)
        self.assertEqual(self.state(), before)

    def test_an_unexpected_exception_closes_the_connection_and_propagates(self):
        self.valid_index()
        with mock.patch.object(maintenance, "_pragma_problems", side_effect=RuntimeError("synthetic")):
            with self.tracking(), self.assertRaises(RuntimeError):
                maintenance.run(self.path, ACCOUNT)
        self.assertNothingLeaked(expected_connections=1)

    def test_an_unopenable_backup_is_reported_and_closes_its_connection(self):
        self.valid_index()
        backup = self.path + ".pre-m7-backup-20261020T110000Z"
        Path(backup).write_bytes(b"this is not a database" * 40)
        os.chmod(backup, 0o600)
        before = self.state()
        for marker in ((), ("query_only",)):
            Tracked.instances, Tracked.fail_on = [], marker
            report = self.run_report()
            self.assertTrue(self.codes(report) & {"BACKUP_UNREADABLE", "BACKUP_INVALID"}, (marker, self.codes(report)))
            if marker:
                self.assertIn("BACKUP_UNREADABLE", self.codes(report))  # the failure happens while opening the backup itself
            self.assertNothingLeaked()
            self.assertGreaterEqual(len(Tracked.instances), 2)  # the index and the backup
        self.assertEqual(self.state(), before)

    def test_a_healthy_index_gives_the_same_report_and_closes_everything(self):
        self.valid_index()
        before = self.state()
        quick, deep = self.run_report(), self.run_report(deep=True)
        for report in (quick, deep):
            self.assertNotIn("INDEX_UNREADABLE_OR_CORRUPT", self.codes(report))
            self.assertEqual(report["properties"]["local_database"]["sqlite_integrity"], "OK")
        self.assertNothingLeaked()
        self.assertGreaterEqual(len(Tracked.instances), 2)
        self.assertEqual(self.state(), before)  # no write, no new file (no journal, WAL or SHM)
        self.assertEqual(sorted(os.listdir(self.dir)), ["index.sqlite3"])

    def test_the_report_is_deterministic_and_does_not_echo_stored_text_or_paths(self):
        marker = "stored-text-marker-3318"
        Path(self.path).write_bytes((marker.encode() + b" not a database ") * 40)
        reports = [repr(self.run_report()) for _ in range(3)]
        self.assertEqual(len(set(reports)), 1)
        self.assertNotIn(marker, reports[0])
        self.assertNotIn(self.dir, reports[0])


if __name__ == "__main__":
    unittest.main()
