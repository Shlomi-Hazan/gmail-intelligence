"""M7A: D146 explicit index upgrade (U1), schema v7 migration (M1) and the history adapter. Synthetic databases only; no personal index, no Gmail."""
import contextlib
import io
import os
import sqlite3
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_cleanup_plans as TCP
from test_auth import http_error
from test_cleanup import ACCT, msg

from sync_support import ACCOUNT, M4_TABLES, SyncCase, config, file_digest, idx, table_digest
from gmail_intelligence import cleanup_audit as audit, cli, gmail, sync_lease

NEW_TABLES = ("sync_state", "sync_run", "message_tombstone")


def downgrade_to_v6(path):
    """A faithful synthetic v6 index: v7 only ADDS the three sync tables, so dropping them and resetting user_version gives exactly the v6 schema."""
    c = sqlite3.connect(path)
    for t in NEW_TABLES:
        c.execute(f"DROP TABLE {t}")
    c.execute("PRAGMA user_version = 6")
    c.commit()
    c.close()


class V6Base(TCP.PlanBase):
    """A populated synthetic v6 index written through the real M4/M5 code paths (plans, approval, audit, label plan)."""

    def setUp(self):
        super().setUp()
        plan = self.approved()
        from gmail_intelligence import label_plans as lp
        self.index.save_labels(ACCT, [{"id": "Label_1", "name": "Receipts", "type": "user"}, {"id": "INBOX", "name": "INBOX", "type": "system"}])
        lp.create_plan(self.index, ACCT, [("CREATE", "Archive 2026")], now=TCP.T0)
        self.index.close()
        self.path = self.index.path
        downgrade_to_v6(self.path)
        self.home = Path(self.path).parent
        self.addCleanup(lambda: None)

    def digest(self):
        c = sqlite3.connect(self.path)
        try:
            out = {}
            for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
                out[t] = sorted(map(repr, c.execute(f"SELECT * FROM {t}")))
            return out
        finally:
            c.close()


class OrdinaryCommandsNeverUpgradeTests(V6Base):
    COMMANDS = (["mailbox", "status", "--account", ACCT], ["mailbox", "report", "--account", ACCT], ["mailbox", "top-senders", "--account", ACCT],
                ["mailbox", "insights", "--account", ACCT], ["mailbox", "purge", "--account", ACCT, "--yes"], ["classify", "status", "--account", ACCT],
                ["cleanup", "plan", "list", "--account", ACCT], ["mailbox", "sync", "--status", "--account", ACCT], ["mailbox", "sync", "--account", ACCT],
                ["mailbox", "scan", "--all"], ["mailbox", "scan", "--limit", "5"], ["mailbox", "scan", "--resume"])

    def test_u1_a_v6_index_stays_byte_for_byte_unchanged_when_any_ordinary_command_refuses_it(self):
        store = mock.Mock()
        store.load.return_value = {"account": ACCT}
        before, mtime, listing = file_digest(self.path), os.stat(self.path).st_mtime_ns, sorted(os.listdir(self.home))
        with mock.patch.object(cli, "_store", return_value=store), mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail must not be touched")):
            for argv in self.COMMANDS:
                with self.subTest(argv=" ".join(argv)):
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = cli.main(argv)
                    self.assertEqual(code, 1)
                    self.assertIn("index upgrade", err.getvalue())
                    self.assertEqual(before, file_digest(self.path))
                    self.assertEqual(mtime, os.stat(self.path).st_mtime_ns)
                    self.assertEqual(listing, sorted(os.listdir(self.home)))                 # no backup, no journal, no new file
        c = sqlite3.connect(self.path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 6)
        c.close()

    def test_the_library_entry_points_refuse_without_the_explicit_flag(self):
        before = file_digest(self.path)
        for kwargs in ({}, {"create": False}):
            with self.assertRaises(idx.IndexProblem) as ctx:
                idx.Index(self.path, **kwargs)
            self.assertIn("index upgrade", str(ctx.exception))
        self.assertEqual(before, file_digest(self.path))
        with self.assertRaises(idx.IndexProblem):
            idx.ReadOnlyIndex(self.path)                                                    # read-only access never upgrades either
        self.assertEqual(before, file_digest(self.path))


class UpgradeCommandTests(V6Base):
    def run_upgrade(self, tty=True, answer="UPGRADE", eof=False):
        stdin = mock.Mock()
        stdin.isatty.return_value = tty
        out, err = io.StringIO(), io.StringIO()
        reply = mock.Mock(side_effect=EOFError) if eof else mock.Mock(return_value=answer)
        with mock.patch.object(sys, "stdin", stdin), mock.patch("builtins.input", reply), mock.patch.object(config, "index_path", return_value=Path(self.path)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["index", "upgrade"])
        return code, out.getvalue(), err.getvalue()

    def test_piped_input_eof_and_wrong_text_are_refused_without_any_change(self):
        before = file_digest(self.path)
        for kwargs in ({"tty": False}, {"eof": True}, {"answer": "upgrade"}, {"answer": "yes"}, {"answer": ""}):
            with self.subTest(**kwargs):
                code, out, err = self.run_upgrade(**kwargs)
                self.assertEqual(code, 1)
                self.assertEqual(before, file_digest(self.path))
                self.assertFalse([f for f in os.listdir(self.home) if "backup" in f])

    def test_the_proposal_is_shown_without_private_data(self):
        code, out, err = self.run_upgrade(answer="no")
        for needle in (str(self.path), str(self.home), ACCT, "Archive 2026", "shop.example"):
            self.assertNotIn(needle, out + err)
        self.assertIn("v6", out)
        self.assertIn("v7", out)

    def test_a_confirmed_upgrade_is_atomic_additive_and_backed_up_privately(self):
        before = self.digest()
        code, out, err = self.run_upgrade()
        self.assertEqual(code, 0, err)
        self.assertNotIn(str(self.path), out + err)
        self.assertNotIn(str(self.home), out + err)
        after = self.digest()
        self.assertEqual({k: v for k, v in after.items() if k not in NEW_TABLES}, before)       # every one of the existing tables is identical, row for row
        self.assertEqual(set(after) - set(before), set(NEW_TABLES))
        backups = [f for f in os.listdir(self.home) if "pre-m7-backup" in f]
        self.assertEqual(len(backups), 1)
        bpath = self.home / backups[0]
        self.assertEqual(stat.S_IMODE(os.stat(bpath).st_mode), 0o600)
        c = sqlite3.connect(bpath)
        self.assertEqual((c.execute("PRAGMA user_version").fetchone()[0], c.execute("PRAGMA quick_check").fetchone()[0]), (6, "ok"))
        c.close()
        with idx.ReadOnlyIndex(self.path) as ro:
            self.assertEqual(ro.conn.execute("PRAGMA user_version").fetchone()[0], 7)
        ix = idx.Index(self.path, create=False)
        self.addCleanup(ix.close)
        self.assertTrue(audit.verify_chain(ix, ACCT)[0])                                          # the M4 audit chain is intact
        self.assertEqual(sorted(r[0] for r in ix._q("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'sync_run%'")), ["sync_run_account", "sync_run_one_running"])

    def test_running_it_again_is_a_no_op(self):
        self.assertEqual(self.run_upgrade()[0], 0)
        digest = file_digest(self.path)
        code, out, err = self.run_upgrade()
        self.assertEqual(code, 0)
        self.assertIn("already", out)
        self.assertEqual(digest, file_digest(self.path))

    def test_a_failing_upgrade_leaves_the_file_unchanged_and_keeps_the_verified_backup(self):
        before = file_digest(self.path)
        with mock.patch.object(idx, "SCHEMA_V7", "CREATE TABLE sync_state (x); CREATE TABLE broken ("):
            code, out, err = self.run_upgrade()
        self.assertEqual(code, 1)
        self.assertIn("backup", err)
        self.assertNotIn(str(self.home), err)
        self.assertEqual(before, file_digest(self.path))
        self.assertEqual(len([f for f in os.listdir(self.home) if "pre-m7-backup" in f]), 1)

    def test_a_missing_or_corrupt_index_is_reported_without_creating_anything(self):
        os.remove(self.path)
        code, out, err = self.run_upgrade()
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.path))


class SchemaTests(SyncCase):
    def test_m1_a_fresh_index_is_v7_with_exactly_the_three_new_tables_and_their_constraints(self):
        self.assertEqual(idx.SCHEMA_VERSION, 7)
        self.assertEqual(self.index.conn.execute("PRAGMA user_version").fetchone()[0], 7)
        tables = {r[0] for r in self.index._q("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        self.assertTrue(set(NEW_TABLES) <= tables)
        self.assertEqual(len(tables), 17 + 3)
        for bad in ("UPDATE sync_state SET status='BOGUS'", "UPDATE sync_state SET source='X'"):
            self.baseline()
            with self.assertRaises(sqlite3.IntegrityError), self.index.conn:
                self.index.conn.execute(bad)

    def test_m1_a_migrated_index_has_the_same_new_schema_as_a_fresh_one(self):
        self.index.close()
        downgrade_to_v6(self.db)
        migrated = idx.Index(self.db, allow_upgrade=True)
        self.addCleanup(migrated.close)
        fresh = idx.Index(str(self.tmp / "fresh.sqlite3"))
        self.addCleanup(fresh.close)
        q = "SELECT name, sql FROM sqlite_master WHERE name IN ('sync_state','sync_run','message_tombstone','sync_run_account','sync_run_one_running') ORDER BY name"
        self.assertEqual([tuple(r) for r in migrated.conn.execute(q)], [tuple(r) for r in fresh.conn.execute(q)])
        self.assertEqual(migrated.migrated_from, 6)
        self.index = migrated

    def test_m1_readonly_index_accepts_v7_and_still_cannot_write(self):
        self.baseline()
        ro = idx.ReadOnlyIndex(self.db)
        self.addCleanup(ro.conn.close)
        self.assertEqual(ro.overview(ACCOUNT)["n"], self.N)
        for fn in (lambda: ro.save_labels(ACCOUNT, []), lambda: ro.conn.execute("DELETE FROM sync_state"), lambda: ro.conn.execute("UPDATE sync_run SET status='x'")):
            with self.assertRaises((sqlite3.Error, AttributeError)):
                fn()


class HistoryAdapterTests(unittest.TestCase):
    def service(self, data=None, error=None):
        req = mock.Mock()
        if error:
            req.execute.side_effect = error
        else:
            req.execute.return_value = data
        svc = mock.MagicMock()
        svc.users.return_value.history.return_value.list.return_value = req
        return svc, req

    def test_the_request_asks_for_ids_only_and_the_response_is_normalised(self):
        svc, req = self.service({"historyId": 777, "nextPageToken": "t2", "history": [
            {"id": "5", "messagesAdded": [{"message": {"id": "a", "threadId": "t"}}], "labelsAdded": [{"message": {"id": "b"}, "labelIds": ["STARRED"]}],
             "labelsRemoved": [{"message": {"id": "c"}, "labelIds": ["UNREAD"]}], "messagesDeleted": [{"message": {"id": "d"}}], "messages": [{"id": "ignored"}]},
            {"id": "6"}, "garbage"][:2]})
        out = gmail.GmailReader(svc).list_history(42, "tok", 100)
        self.assertEqual(out, {"records": [{"id": "5", "added": ["a"], "deleted": ["d"], "labels": ["b", "c"]}, {"id": "6", "added": [], "deleted": [], "labels": []}],
                               "next": "t2", "history_id": "777"})
        kwargs = svc.users.return_value.history.return_value.list.call_args.kwargs
        self.assertEqual((kwargs["userId"], kwargs["startHistoryId"], kwargs["pageToken"], kwargs["maxResults"]), ("me", "42", "tok", 100))
        self.assertEqual(kwargs["historyTypes"], ["messageAdded", "messageDeleted", "labelAdded", "labelRemoved"])
        for banned in ("subject", "snippet", "body", "payload", "raw", "attachment", "labelIds", "Subject"):
            self.assertNotIn(banned, kwargs["fields"])                                         # ids only: not even label ids, no content
        req.execute.assert_called_with(num_retries=3)

    def test_404_is_the_history_expired_error_and_other_errors_keep_their_types(self):
        for status, body, exc_type in ((404, b"{}", gmail.GmailHistoryNotFoundError), (429, b"{}", gmail.GmailRateLimitError), (401, b"{}", gmail.GmailAuthError),
                                       (500, b"{}", gmail.GmailApiError)):
            svc, _ = self.service(error=http_error(status, body))
            with self.assertRaises(exc_type) as ctx:
                gmail.GmailReader(svc).list_history("1")
            self.assertIs(type(ctx.exception), exc_type)
        svc, _ = self.service(error=OSError("down"))
        with self.assertRaisesRegex(gmail.GmailApiError, "network"):
            gmail.GmailReader(svc).list_history("1")

    def test_an_empty_response_and_a_missing_history_id_are_handled(self):
        svc, _ = self.service({})
        self.assertEqual(gmail.GmailReader(svc).list_history("1"), {"records": [], "next": None, "history_id": None})

    def test_only_the_read_scope_exists(self):
        from gmail_intelligence import oauth
        self.assertEqual(oauth.EXPECTED_SCOPES, frozenset({"https://www.googleapis.com/auth/gmail.readonly"}))


if __name__ == "__main__":
    unittest.main()
