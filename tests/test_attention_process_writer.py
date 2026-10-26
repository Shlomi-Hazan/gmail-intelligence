"""M8A-1: consistent reads against a writer in a SEPARATE OS process (issue #51: "concurrent synthetic writer processes").

The writer is a child interpreter that executes one command per line from the parent and answers with one line (WRITE, FLIP, ROLLBACK, QUIT). The parent sends the commands
from the engine's per-batch hook and waits for the answer before the engine continues, so every interleaving is deterministic (no sleeps, no timing). Only temporary
synthetic SQLite files are used; nothing touches Gmail, the Keychain or a personal index.
"""
import subprocess
import sys
import threading
import unittest

import attention_support as S
from attention_support import ACCOUNT, NOW, MailboxCase, attention

CHILD = r"""
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1], timeout=1.0)
account = sys.argv[2]
for line in sys.stdin:
    cmd = line.strip()
    try:
        if cmd == "WRITE":      # a commit that changes nothing the report shows: only data_version moves
            conn.execute("UPDATE messages SET size = size + 1 WHERE account = ? AND id = '00000002'", (account,))
            conn.commit(); print("COMMITTED", flush=True)
        elif cmd == "FLIP":     # a commit that changes the visible list: message 1 goes from STARRED to IMPORTANT (and back)
            row = conn.execute("SELECT label_id FROM message_labels WHERE account = ? AND message_id = '00000001' AND label_id IN ('STARRED', 'IMPORTANT')", (account,)).fetchone()
            new = "IMPORTANT" if row[0] == "STARRED" else "STARRED"
            conn.execute("UPDATE message_labels SET label_id = ? WHERE account = ? AND message_id = '00000001' AND label_id = ?", (new, account, row[0]))
            conn.commit(); print("COMMITTED", flush=True)
        elif cmd == "ROLLBACK":
            conn.execute("UPDATE messages SET size = size + 1 WHERE account = ? AND id = '00000002'", (account,))
            conn.rollback(); print("ROLLED_BACK", flush=True)
        elif cmd == "QUIT":
            break
    except sqlite3.OperationalError:
        conn.rollback(); print("LOCKED", flush=True)
"""


class ProcessWriterCase(MailboxCase):
    def setUp(self):
        super().setUp()
        original = attention.BATCH
        attention.BATCH = 4  # about eight batches per pass: many moments at which the writer can commit
        self.addCleanup(setattr, attention, "BATCH", original)
        for k in range(30):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k + 1)
        self.proc = subprocess.Popen([sys.executable, "-I", "-c", CHILD, self.mb.path, ACCOUNT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        watchdog = threading.Timer(60, self.proc.kill)  # a safety net only; the protocol itself never waits on a clock
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.addCleanup(self.stop)
        self.answers = []

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write("QUIT\n")
                self.proc.stdin.flush()
            except OSError:
                pass
            self.proc.wait(timeout=30)
        self.proc.stdin.close()
        self.proc.stdout.close()

    def ask(self, command):
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline().strip()
        self.answers.append((command, answer))
        return answer

    def run_report(self, hook):
        ro = self.mb.readonly()
        try:
            return attention.compute(ro, ACCOUNT, now=NOW, limit=100, _after_batch=hook)
        finally:
            ro.close()


class ProcessWriterTests(ProcessWriterCase):
    def test_a_commit_from_another_process_between_batches_is_detected_and_the_result_is_one_state(self):
        state_a = self.mb.compute(limit=100)
        passes, fired = [], []

        def hook(n):
            passes.append(n)
            if n == 2 and not fired:  # once, in the middle of the first pass
                fired.append(self.ask("FLIP"))

        result = self.run_report(hook)
        self.assertEqual(fired, ["COMMITTED"])  # the writer in the other process was not blocked by the report
        self.assertGreater(len(passes), 8)  # the first pass was thrown away and the whole computation ran again
        state_b = self.mb.compute(limit=100)  # the writer has finished: a quiet read of the final state
        self.assertEqual((result["snapshot"], result["items"]), (state_b["snapshot"], state_b["items"]))
        self.assertNotEqual(result["snapshot"], state_a["snapshot"])  # and it really is the NEW state, completely, never a mixture
        self.assertEqual(sorted(i["score"] for i in result["items"]).count(20), 1)

    def test_several_commits_in_one_pass_still_give_one_consistent_state(self):
        fired = []

        def hook(n):
            if len(fired) < 3 and n in (1, 3, 5):
                fired.append(self.ask("FLIP"))

        result = self.run_report(hook)
        self.assertEqual(fired, ["COMMITTED"] * 3)
        quiet = self.mb.compute(limit=100)
        self.assertEqual((result["snapshot"], result["items"]), (quiet["snapshot"], quiet["items"]))

    def test_a_writer_that_commits_in_every_pass_ends_in_a_bounded_explicit_failure_without_items(self):
        commits = []
        passes = []

        def hook(n):
            if n == 1:
                passes.append(n)
                commits.append(self.ask("WRITE"))

        with self.assertRaises(attention.AttentionError) as cm:
            self.run_report(hook)
        self.assertEqual(cm.exception.code, "INDEX_CHANGED_DURING_READ")
        self.assertEqual(commits, ["COMMITTED"] * (attention.MAX_RETRIES + 1))  # first pass plus the allowed retries, never more
        self.assertEqual(len(passes), attention.MAX_RETRIES + 1)

    def test_a_rolled_back_write_in_the_other_process_is_not_a_change(self):
        passes, answers = [], []

        def hook(n):
            passes.append(n)
            if n == 2 and not answers:
                answers.append(self.ask("ROLLBACK"))

        result = self.run_report(hook)
        self.assertEqual(answers, ["ROLLED_BACK"])
        self.assertEqual(result["totals"]["total"], 30)
        self.assertLess(len(passes), 16)  # a single pass: nothing was retried

    def test_a_commit_from_the_other_process_is_visible_to_the_next_report(self):
        first = self.mb.compute(limit=100)
        self.assertEqual(self.ask("FLIP"), "COMMITTED")
        second = self.mb.compute(limit=100)
        self.assertNotEqual(first["snapshot"], second["snapshot"])

    def test_the_test_can_see_a_lock_when_there_is_one(self):
        """Control: if the reader DID hold a read transaction, the writer process could not commit. The engine never does, so the tests above pass."""
        ro = self.mb.readonly()
        self.addCleanup(ro.close)
        ro.conn.execute("BEGIN")
        ro.conn.execute("SELECT * FROM messages").fetchall()
        self.assertEqual(self.ask("WRITE"), "LOCKED")
        ro.conn.rollback()
        self.assertEqual(self.ask("WRITE"), "COMMITTED")


if __name__ == "__main__":
    unittest.main()
