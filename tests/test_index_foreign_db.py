"""Post-M7 acceptance correction: an existing file at the index path is judged BEFORE anything touches it.

A non-empty SQLite database with user_version 0 is somebody else's and is never adopted; a refused file keeps its bytes, mtime, mode, its directory's mode and
the directory inventory (no journal/WAL/SHM, no backup, no chmod); a file swapped in between the preflight and the writing connection is not adopted either.
Fresh-index creation and the explicit v6->v7 upgrade (D146) are unchanged. Synthetic temporary databases only.
"""
import contextlib
import hashlib
import io
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from gmail_intelligence import cli, config  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

FOREIGN_TABLE = "foreign_notes_zq"
ACCOUNT = "owner@example.test"


def snap(path):
    d = os.path.dirname(path)
    st = os.stat(path)
    return {"sha": hashlib.sha256(Path(path).read_bytes()).hexdigest(), "mode": stat.S_IMODE(st.st_mode), "mtime": st.st_mtime_ns, "size": st.st_size,
            "dir_mode": stat.S_IMODE(os.stat(d).st_mode), "listing": sorted(os.listdir(d))}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.join(tmp.name, "home")
        os.mkdir(self.dir, 0o755)
        os.chmod(self.dir, 0o755)
        self.path = os.path.join(self.dir, "index.sqlite3")

    def make_foreign(self, mode=0o644, wal=False):
        c = sqlite3.connect(self.path)
        if wal:
            c.execute("PRAGMA journal_mode=WAL")
        c.execute(f"CREATE TABLE {FOREIGN_TABLE} (x TEXT)")
        c.execute(f"INSERT INTO {FOREIGN_TABLE} VALUES ('unrelated')")
        c.commit()
        c.close()
        os.chmod(self.path, mode)
        os.chmod(self.dir, 0o755)

    def make_current(self):
        idx.Index(self.path).close()

    def downgrade(self, version):
        c = sqlite3.connect(self.path)
        if version <= 6:
            for t in ("sync_state", "sync_run", "message_tombstone"):
                c.execute(f"DROP TABLE {t}")
        c.execute(f"PRAGMA user_version = {version}")
        c.commit()
        c.close()
        os.chmod(self.path, 0o644)
        os.chmod(self.dir, 0o755)

    def assertRefusedUntouched(self, **kw):
        before = snap(self.path)
        with self.assertRaises(idx.IndexProblem) as cm:
            idx.Index(self.path, **kw)
        self.assertEqual(snap(self.path), before)
        msg = str(cm.exception)
        self.assertNotIn(FOREIGN_TABLE, msg)
        self.assertNotIn(self.dir, msg)
        return msg


class ForeignDatabaseTests(Base):
    def test_a_non_empty_database_with_user_version_zero_is_refused_without_any_change(self):
        self.make_foreign()
        self.assertRefusedUntouched()
        self.assertRefusedUntouched(create=False)
        self.assertRefusedUntouched(allow_upgrade=True)  # the upgrade flag never turns a foreign file into an index
        c = sqlite3.connect(self.path)
        self.assertEqual([r[0] for r in c.execute("SELECT name FROM sqlite_master")], [FOREIGN_TABLE])
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 0)
        c.close()

    def test_loose_permissions_stay_loose_on_a_refused_file_and_its_directory(self):
        self.make_foreign(mode=0o644)
        self.assertRefusedUntouched()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o755)

    def test_a_wal_mode_file_is_never_called_empty(self):
        c = sqlite3.connect(self.path)
        c.execute("PRAGMA journal_mode=WAL")
        c.close()
        os.chmod(self.path, 0o644)
        self.assertEqual(idx._inspect_existing(os.open(self.path, os.O_RDONLY))[1], False)

    def test_the_ordinary_cli_commands_refuse_it_unchanged(self):
        self.make_foreign()
        before = snap(self.path)
        with mock.patch.dict(os.environ, {config.HOME_ENV: self.dir}), mock.patch.object(config, "index_path", return_value=Path(self.path)):
            for argv in (["mailbox", "status", "--account", ACCOUNT], ["mailbox", "sync", "--status", "--account", ACCOUNT],
                         ["cleanup", "plan", "list", "--account", ACCOUNT]):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = cli.main(argv)
                self.assertNotEqual(code, 0, argv)
                self.assertNotIn(FOREIGN_TABLE, out.getvalue() + err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())
                self.assertEqual(snap(self.path), before, argv)

    def test_the_decision_is_made_again_on_the_writing_connection(self):
        """Even if the preflight were fooled (it says empty), the connection that would write sees a non-empty schema and refuses before any write."""
        self.make_foreign()
        before = snap(self.path)
        with mock.patch.object(idx, "_inspect_existing", return_value=(0, True)):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(self.path)
        self.assertEqual(snap(self.path), before)

    def test_a_file_swapped_in_after_the_preflight_is_not_adopted(self):
        self.make_current()
        other = os.path.join(self.dir, "other.tmp")
        c = sqlite3.connect(other)
        c.execute(f"CREATE TABLE {FOREIGN_TABLE} (x)")
        c.commit()
        c.close()
        os.chmod(other, 0o644)
        real = sqlite3.connect

        def swap_then_connect(*a, **k):
            os.replace(other, self.path)  # the path now names a different file than the one the preflight validated
            return real(*a, **k)

        with mock.patch.object(idx.sqlite3, "connect", side_effect=swap_then_connect):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.Index(self.path)
        self.assertIn("changed", str(cm.exception))
        c = sqlite3.connect(self.path)
        self.assertEqual([r[0] for r in c.execute("SELECT name FROM sqlite_master")], [FOREIGN_TABLE])
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 0)
        c.close()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)


class UnsupportedExistingFileTests(Base):
    def test_refused_versions_and_corrupt_files_get_no_chmod_and_no_backup(self):
        self.make_current()
        for v in (1, 3, 6):
            self.make_current_if_missing()
            self.downgrade(v)
            msg = self.assertRefusedUntouched()
            self.assertIn("index upgrade", msg)
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)
            os.remove(self.path)
        self.make_current()
        self.downgrade(9)
        self.assertIn("unsupported", self.assertRefusedUntouched())
        Path(self.path).write_bytes(b"this is not a database at all, just some text" * 4)
        os.chmod(self.path, 0o644)
        self.assertIn("unreadable or corrupt", self.assertRefusedUntouched())
        Path(self.path).write_bytes(b"short")
        self.assertIn("unreadable or corrupt", self.assertRefusedUntouched())

    def make_current_if_missing(self):
        if not os.path.exists(self.path):
            self.make_current()

    def test_the_explicit_upgrade_still_works_and_still_makes_the_private_backup(self):
        self.make_current()
        self.downgrade(6)
        with idx.Index(self.path, allow_upgrade=True) as i:
            self.assertEqual(i.migrated_from, 6)
            self.assertTrue(os.path.exists(i.backup_path))
            self.assertEqual(stat.S_IMODE(os.stat(i.backup_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        c = sqlite3.connect(self.path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
        c.close()


class SupportedAndFreshTests(Base):
    def test_a_missing_file_is_created_only_when_allowed(self):
        with self.assertRaises(idx.IndexProblem):
            idx.Index(self.path, create=False)
        self.assertEqual(os.listdir(self.dir), [])
        with idx.Index(self.path):
            pass
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        c = sqlite3.connect(self.path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0] > 17, True)
        c.close()

    def test_a_missing_parent_directory_is_still_created_private(self):
        nested = os.path.join(self.dir, "a", "b", "index.sqlite3")
        with idx.Index(nested):
            pass
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(nested)).st_mode), 0o700)

    def test_genuinely_empty_existing_databases_are_initialised(self):
        Path(self.path).write_bytes(b"")  # zero bytes
        os.chmod(self.path, 0o644)
        with idx.Index(self.path):
            pass
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        os.remove(self.path)
        c = sqlite3.connect(self.path)  # a real SQLite file whose schema is empty again
        c.execute("CREATE TABLE t (x)")
        c.commit()
        c.execute("DROP TABLE t")
        c.commit()
        c.close()
        self.assertGreater(os.stat(self.path).st_size, 0)
        with idx.Index(self.path) as i:
            self.assertEqual(i.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)

    def test_a_supported_index_opens_and_is_tightened_as_before(self):
        self.make_current()
        os.chmod(self.path, 0o644)
        os.chmod(self.dir, 0o755)
        with idx.Index(self.path) as i:
            self.assertIsNone(i.migrated_from)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)

    def test_inspecting_a_supported_index_creates_no_side_files(self):
        self.make_current()
        before = sorted(os.listdir(self.dir))
        fd = os.open(self.path, os.O_RDONLY)
        try:
            self.assertEqual(idx._inspect_existing(fd), (idx.SCHEMA_VERSION, False))
        finally:
            os.close(fd)
        self.assertEqual(sorted(os.listdir(self.dir)), before)


if __name__ == "__main__":
    unittest.main()
