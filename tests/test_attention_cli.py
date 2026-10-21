"""M8A-1: `mailbox attention` (CLI). Offline: a synthetic temporary index, no Gmail, no Keychain."""
import contextlib
import io
import json
import os
import re
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import attention_support as S
from attention_support import ACCOUNT, MailboxCase, attention
from gmail_intelligence import cli, config

MARK = "marker-cli-5521"


class CliCase(MailboxCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(config, "index_path", return_value=Path(self.mb.path))
        patcher.start()
        self.addCleanup(patcher.stop)
        clock = mock.patch.object(attention, "datetime", wraps=datetime)
        fake = clock.start()
        fake.now.return_value = S.NOW
        self.addCleanup(clock.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["mailbox", "attention", "--account", ACCOUNT, *argv])
        return code, out.getvalue(), err.getvalue()


class OutputTests(CliCase):
    def setUp(self):
        super().setUp()
        for k in range(40):
            self.mb.add(f"{k:08x}", sender=f"{MARK}{k}@bulk.example.test", labels=("INBOX", "STARRED", "UNREAD"), age_days=k + 1)

    def test_json_and_text_succeed_and_agree(self):
        code, out, err = self.run_cli("--json", "--limit", "10")
        self.assertEqual((code, err), (0, ""))
        data = json.loads(out)
        self.assertEqual((data["section"], len(data["items"]), data["weights_status"]), ("attention", 10, "PROVISIONAL"))
        code, text, err = self.run_cli("--limit", "10")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("possibly needs attention", text)
        self.assertIn(data["next_cursor"], text)
        self.assertEqual(len(re.findall(r"^\s*\d+\. \[", text, re.M)), 10)

    def test_the_cursor_chain_through_the_cli_reaches_the_end(self):
        got, cursor = [], None
        while True:
            code, out, err = self.run_cli("--json", "--limit", "15", *(["--cursor", cursor] if cursor else []), "--sender-limit", "0")
            self.assertEqual((code, err), (0, ""))
            data = json.loads(out)
            got += data["items"]
            cursor = data["next_cursor"]
            if not cursor:
                break
        self.assertEqual([i["rank"] for i in got], list(range(1, 41)))

    def test_identical_snapshots_give_identical_output(self):
        first = self.run_cli("--json", "--limit", "20")
        second = self.run_cli("--json", "--limit", "20")
        self.assertEqual(first, second)

    def test_no_marker_url_or_identifier_is_ever_printed(self):
        for argv in (("--json",), (), ("--json", "--no-collapse"), ("--include-low-score",)):
            code, out, err = self.run_cli(*argv)
            blob = out + err
            for needle in (MARK, "http", "mail.google", ACCOUNT, "00000001", "Traceback"):
                self.assertNotIn(needle, blob, (argv, needle))

    def test_addresses_are_revealed_only_on_request(self):
        shown = self.run_cli("--json", "--reveal-senders", "--limit", "3")[1]
        self.assertIn(MARK, shown)
        self.assertNotIn(MARK, self.run_cli("--json", "--limit", "3")[1])

    def test_unknown_link_flags_do_not_exist(self):
        for flag in ("--gmail-links", "--link-account", "--accept-unverified-links", "--links"):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                cli.main(["mailbox", "attention", "--account", ACCOUNT, flag])
            self.assertEqual(cm.exception.code, 2)


class ErrorTests(CliCase):
    def setUp(self):
        super().setUp()
        for k in range(30):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k + 1)

    def test_bad_parameters_are_refused_with_a_plain_message(self):
        for argv in (("--limit", "0"), ("--limit", "101"), ("--sender-limit", "11"), ("--sender-limit", "-1")):
            code, out, err = self.run_cli(*argv)
            self.assertEqual((code, out), (1, ""), argv)
            self.assertTrue(err.startswith("error: --"), err)

    def test_cursor_failures_are_fixed_text_with_no_items_and_no_echo(self):
        code, out, err = self.run_cli("--limit", "5", "--json")
        cursor = json.loads(out)["next_cursor"]
        for bad, expected in ((cursor + "x", "CURSOR_INVALID"), ("garbage-" + MARK, "CURSOR_INVALID"),
                              (cursor.replace(".5.", ".7."), "CURSOR_INVALID")):
            code, out, err = self.run_cli("--cursor", bad)
            self.assertEqual((code, out), (1, ""))
            self.assertTrue(err.startswith(f"error: {expected}:"), err)
            self.assertNotIn(MARK, err)
            self.assertNotIn(bad, err)
        self.mb.set_labels("00000001", ("INBOX",))
        code, out, err = self.run_cli("--cursor", cursor, "--limit", "5")
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: SNAPSHOT_CHANGED:"), err)

    def test_over_budget_prints_the_fixed_failure_and_no_items(self):
        with mock.patch.object(attention, "RETAINED_THREAD_BUDGET", 3):
            code, out, err = self.run_cli()
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: RESULT_INCOMPLETE:"), err)

    def test_an_unexpected_internal_error_is_generic(self):
        with mock.patch.object(attention, "compute", side_effect=RuntimeError("boom " + MARK)):
            code, out, err = self.run_cli("--json")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, "error: " + cli._REPORT_UNEXPECTED + "\n")

    def test_a_missing_or_unsupported_index_is_refused_without_creating_anything(self):
        os.remove(self.mb.path)
        code, out, err = self.run_cli()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("no local index", err)
        self.assertFalse(os.path.exists(self.mb.path))

    def test_an_old_schema_is_refused_without_an_upgrade(self):
        c = sqlite3.connect(self.mb.path)
        for t in ("sync_state", "sync_run", "message_tombstone"):
            c.execute(f"DROP TABLE {t}")
        c.execute("PRAGMA user_version = 6")
        c.commit()
        c.close()
        before = self.mb.tree()
        code, out, err = self.run_cli()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("index upgrade", err)
        self.assertEqual(self.mb.tree(), before)

    def test_a_foreign_database_is_not_adopted(self):
        os.remove(self.mb.path)
        c = sqlite3.connect(self.mb.path)
        c.execute("CREATE TABLE foreign_notes (x)")
        c.commit()
        c.close()
        before = self.mb.tree()
        code, out, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(self.mb.tree(), before)


class ReadOnlyCliTests(CliCase):
    def test_the_command_changes_nothing_on_disk(self):
        for k in range(20):
            self.mb.add(labels=("INBOX", "STARRED", "UNREAD"), age_days=k)
        self.mb.conn.close()
        before = self.mb.tree()
        for argv in ((), ("--json",), ("--sort", "date", "--include-low-score")):
            self.assertEqual(self.run_cli(*argv)[0], 0)
        self.assertEqual(self.mb.tree(), before)
        self.assertEqual(os.listdir(self.mb.dir), ["index.sqlite3"])
        self.mb.conn = sqlite3.connect(self.mb.path)


if __name__ == "__main__":
    unittest.main()
