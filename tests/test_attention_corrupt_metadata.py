"""M8A-1 acceptance: malformed stored values (a corrupted or tampered synthetic index) fail SAFELY through the CLI.

SQLite is typeless, so a damaged index can hold values the scanner never writes. These tests pin the CURRENT safe behaviour only: no traceback, one fixed message, no
stored value in any output, no partial result presented as complete (stdout stays empty), the index file untouched, no extra file and no network connection.
The two cases that used to echo stored text (an exception message, the `types`/`rule` output fields) are covered by test_attention_output_privacy.py. Synthetic data only.
"""
import contextlib
import gc
import io
import json
import os
import socket
import unittest
import warnings
from pathlib import Path
from unittest import mock

import attention_support as S
from attention_support import ACCOUNT, NOW, attention
from gmail_intelligence import cli
from test_attention_cli import CliCase
from leak_support import isolate_known_leaks  # noqa: E402

MARK = "stored-text-marker-9913"
GENERIC = "error: " + cli._REPORT_UNEXPECTED + "\n"
RULE = ("INSERT INTO class_rules (account,id,kind,value,c_domain,confidence,priority,enabled,created_at) "
        "VALUES ('%s','u1','attention','POTENTIALLY_IMPORTANT','example.test',%%s,%%s,1,'x')" % ACCOUNT)

# corruption -> SQL, for values the engine cannot process: the command must fail closed
FAIL_CLOSED = {
    "internal_ms as text": f"UPDATE messages SET internal_ms='{MARK}' WHERE id='00000001'",
    "internal_ms as blob": "UPDATE messages SET internal_ms=x'ff00' WHERE id='00000001'",
    "sender as blob": "UPDATE messages SET sender=x'ff00' WHERE id='00000001'",
    "thread_id as blob": "UPDATE messages SET thread_id=x'0102' WHERE id='00000001'",
    "rule confidence not LOW/MEDIUM/HIGH": RULE % (f"'{MARK}'", "0"),
    "rule priority as text": RULE % ("'LOW'", f"'{MARK}'"),
}
# corruption -> SQL, for values the engine tolerates: a normal, complete result and nothing echoed
TOLERATED = {
    "internal_ms as real": "UPDATE messages SET internal_ms=1.7e12 WHERE id='00000001'",
    "internal_ms beyond any date": "UPDATE messages SET internal_ms=1e300 WHERE id='00000001'",
    "internal_ms hugely negative": "UPDATE messages SET internal_ms=-1000000000000000000 WHERE id='00000001'",
    "internal_ms null": "UPDATE messages SET internal_ms=NULL WHERE id='00000001'",
    "sender null": "UPDATE messages SET sender=NULL WHERE id='00000001'",
    "sender without an @ sign": f"UPDATE messages SET sender='{MARK}' WHERE id='00000001'",
    "sender as integer": "UPDATE messages SET sender=12345 WHERE id='00000001'",
    "thread_id as integer": "UPDATE messages SET thread_id=77 WHERE id='00000001'",
    "unread flag as text": f"UPDATE messages SET unread='{MARK}' WHERE id='00000001'",
    "label id as blob": "UPDATE message_labels SET label_id=x'ff' WHERE message_id='00000001' AND label_id='UNREAD'",
    "label name as blob": "INSERT INTO labels VALUES ('owner@example.test','Label_1',x'ff00','user')",
    "scan status is arbitrary text": f"UPDATE scans SET status='{MARK}' WHERE account='owner@example.test'",
    "scan finished_at null": "UPDATE scans SET finished_at=NULL WHERE account='owner@example.test'",
    "sync_state advanced_at is not a timestamp": ("INSERT INTO sync_state (account,history_id,source,basis_scan_id,established_at,advanced_at,status) "
                                                  f"VALUES ('owner@example.test','1','HISTORY_RESPONSE',1,'2026-10-21T10:00:00Z','{MARK}','OK')"),
    "sync_run finished_at is not a timestamp": ("INSERT INTO sync_run (account,kind,status,started_at,finished_at,lease_token,lease_expires_at,heartbeat_at) "
                                                f"VALUES ('owner@example.test','INCREMENTAL','completed','2026-10-21T10:00:00Z','{MARK}','{'a' * 64}','2026-10-21T10:05:00Z','2026-10-21T10:00:00Z')"),
}


class Case(CliCase):
    def setUp(self):
        super().setUp()
        self.reset()

    def reset(self):
        """A fresh synthetic mailbox of four starred, unread messages (the one the corruption statements target is 00000001)."""
        self.mb = S.Mailbox()
        self.addCleanup(self.mb.close)
        for k in range(4):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED", "UNREAD"), age_days=k + 1, sender=f"s{k}@example.test")
        self.index_path.return_value = Path(self.mb.path)

    def run_checked(self, *argv):
        """Run the CLI with the network forbidden; return (code, stdout, stderr, connection attempts)."""
        attempts = []
        out, err = io.StringIO(), io.StringIO()
        gc.collect()  # connections leaked by OTHER tests must not print their ResourceWarning into the stderr captured below
        with warnings.catch_warnings(), mock.patch.object(socket.socket, "connect", side_effect=lambda *a, **k: attempts.append(1)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            warnings.simplefilter("ignore", ResourceWarning)
            code = cli.main(["mailbox", "attention", "--account", ACCOUNT, *argv])
        return code, out.getvalue(), err.getvalue(), attempts

    def corrupt(self, statement):
        self.mb.sql(statement)
        self.before = self.mb.tree()

    def assertUntouched(self):
        self.assertEqual(self.mb.tree(), self.before)  # bytes, size, mtime and mode of the index
        self.assertEqual(os.listdir(self.mb.dir), ["index.sqlite3"])  # no journal, WAL, SHM, temporary or other file


class FailClosedTests(Case):
    def test_each_unprocessable_value_gives_one_fixed_message_and_no_output_at_all(self):
        for name, statement in FAIL_CLOSED.items():
            with self.subTest(name):
                self.reset()
                self.corrupt(statement)
                for argv in (("--json",), (), ("--json", "--reveal-senders"), ("--json", "--sort", "date")):
                    code, out, err, attempts = self.run_checked(*argv)
                    self.assertEqual((code, out, err, attempts), (1, "", GENERIC, []), (name, argv))  # nothing printed that could look like a complete result
                    self.assertNotIn(MARK, out + err)
                    self.assertNotIn("Traceback", err)
                self.assertUntouched()

    def test_the_library_never_returns_a_result_for_them(self):
        for name, statement in FAIL_CLOSED.items():
            with self.subTest(name):
                self.reset()
                self.corrupt(statement)
                ro = S.idx.ReadOnlyIndex(self.mb.path)
                try:
                    with self.assertRaises(Exception) as cm:
                        attention.compute(ro, ACCOUNT, now=NOW)
                    self.assertNotIsInstance(cm.exception, attention.AttentionError)  # an unexpected error, which the CLI turns into the generic message
                finally:
                    ro.close()
                self.assertUntouched()

    def test_the_failure_is_deterministic(self):
        self.corrupt(FAIL_CLOSED["internal_ms as text"])
        runs = {self.run_checked("--json")[:3] for _ in range(3)}
        self.assertEqual(len(runs), 1)
        self.assertUntouched()


class ToleratedTests(Case):
    def test_each_tolerated_value_gives_a_normal_complete_result_with_nothing_echoed(self):
        for name, statement in TOLERATED.items():
            with self.subTest(name):
                self.reset()
                self.corrupt(statement)
                code, out, err, attempts = self.run_checked("--json")
                self.assertEqual((code, err, attempts), (0, "", []), name)
                data = json.loads(out)
                self.assertEqual(data["totals"]["total"], 4, name)
                self.assertNotIn(MARK, out)
                self.assertUntouched()

    def test_a_date_that_cannot_be_read_is_flagged_not_hidden(self):
        self.corrupt(TOLERATED["internal_ms beyond any date"])
        data = json.loads(self.run_checked("--json")[1])
        self.assertEqual(sum("DATE_MISSING" in i["flags"] for i in data["items"]), 1)
        self.assertEqual(sum(i["date"] is None for i in data["items"]), 1)


class DamagedFileTests(Case):
    @isolate_known_leaks
    def test_a_file_of_random_bytes_is_refused_with_the_known_message_and_left_alone(self):
        self.mb.conn.close()
        with open(self.mb.path, "wb") as fh:
            fh.write(os.urandom(4096))
        self.before = self.mb.tree()
        code, out, err, attempts = self.run_checked("--json")
        self.assertEqual((code, out, attempts), (1, "", []))
        self.assertTrue(err.startswith("error: "), err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn(self.mb.dir, err)
        self.assertUntouched()


if __name__ == "__main__":
    unittest.main()
