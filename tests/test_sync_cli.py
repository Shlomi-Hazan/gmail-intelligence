"""M7A: the owner-triggered commands `mailbox sync`, `mailbox sync --status` and the scan flags, with a fake reader (no Gmail, no Keychain, no network)."""
import argparse
import contextlib
import io
import os
import unittest
from pathlib import Path
from unittest import mock

from sync_support import ACCOUNT, SyncCase, config, file_digest, idx, standard_mailbox, sync_health
from gmail_intelligence import cli, scanner, sync_lease

PRIVATE = ("secret.sender@private.example.test", "Private Label Name", "private-id-777")


class CliCase(SyncCase):
    def setUp(self):
        super().setUp()
        self.index.close()
        self.home = self.tmp / "cli-home"
        self.env = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.index = idx.Index()                                        # at config.index_path() inside the temp home
        self.addCleanup(self.index.close)
        self.db = str(config.index_path())
        store = mock.Mock()
        store.load.return_value = {"account": ACCOUNT}
        patch = mock.patch.object(cli, "_store", return_value=store)
        patch.start()
        self.addCleanup(patch.stop)

    def run_cli(self, argv, reader=None):
        out, err = io.StringIO(), io.StringIO()
        opener = mock.patch.object(cli, "_open_reader", return_value=(reader or self.mailbox, {"account": ACCOUNT}))
        real = scanner.RateLimiter
        with opener, mock.patch.object(scanner, "RateLimiter", side_effect=lambda *a, **k: real(10 ** 9, clock=lambda: 0.0, sleep=lambda s: None)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()


class SyncCommandTests(CliCase):
    def test_scan_all_then_sync_then_status_end_to_end(self):
        code, out, err = self.run_cli(["mailbox", "scan", "--all"])
        self.assertEqual(code, 0, err)
        self.assertEqual(sync_health.problems(self.index, ACCOUNT), [])
        self.mailbox.add("private-id-777", ("INBOX",), sender="secret.sender@private.example.test")
        self.mailbox.labels.append({"id": "Label_9", "name": "Private Label Name", "type": "user"})
        code, out, err = self.run_cli(["mailbox", "sync"])
        self.assertEqual(code, 0, err)
        self.assertIn("Sync completed", out)
        for needle in PRIVATE + (str(self.home),):
            self.assertNotIn(needle, out + err)
        code, status, err = self.run_cli(["mailbox", "sync", "--status"])
        self.assertEqual(code, 0)
        self.assertIn("state: OK", status)
        self.assertIn("allowed", status)
        for needle in PRIVATE + (str(self.home), ACCOUNT):
            self.assertNotIn(needle, status + err)

    def test_sync_without_a_checkpoint_refuses_locally_before_any_gmail_request(self):
        before = file_digest(self.db)
        with mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail must not be touched")):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["mailbox", "sync"])
        self.assertEqual(code, 1)
        self.assertIn("SYNC_CHECKPOINT_MISSING", err.getvalue())
        self.assertEqual(before, file_digest(self.db))

    def test_a_busy_lease_and_an_unfinished_full_scan_are_reported_with_their_codes(self):
        self.assertEqual(self.run_cli(["mailbox", "scan", "--all"])[0], 0)
        lease = sync_lease.acquire(self.index, ACCOUNT, "INCREMENTAL")
        other_conn_code, out, err = self.run_cli(["mailbox", "sync"])
        self.assertEqual(other_conn_code, 1)
        self.assertIn("SYNC_BUSY", err)
        lease.finish("interrupted", "INTERRUPTED", "FULL_SCAN_INTERRUPTED")

    def test_status_shows_the_prohibition_when_health_is_not_ok(self):
        self.assertEqual(self.run_cli(["mailbox", "scan", "--all"])[0], 0)
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='NEEDS_RECONCILE', reason='HISTORY_EXPIRED'")
        code, status, err = self.run_cli(["mailbox", "sync", "--status"])
        self.assertIn("PROHIBITED", status)
        self.assertIn("SYNC_NEEDS_RECONCILE", status)
        code, out, err = self.run_cli(["mailbox", "sync"])
        self.assertEqual(code, 1)
        self.assertIn("SYNC_NEEDS_RECONCILE", err)

    def test_scan_flags_guide_the_owner_and_never_prune_silently(self):
        self.mailbox.profile_total = 500
        code, out, err = self.run_cli(["mailbox", "scan", "--all"])
        self.assertEqual(code, 1)
        self.assertIn("--accept-count-mismatch", out)
        self.assertIsNone(sync_health.state_row(self.index, ACCOUNT))
        code, out, err = self.run_cli(["mailbox", "scan", "--all", "--accept-count-mismatch"])
        self.assertEqual(code, 0, err)

    def test_the_new_commands_are_registered_and_there_is_no_schedule_or_automatic_trigger(self):
        parser = cli.build_parser()
        text = parser.format_help()
        self.assertIn("index", text)
        for banned in ("schedule", "daemon", "launchd", "cron", "watch"):
            self.assertNotIn(banned, text.lower())
        import inspect
        from gmail_intelligence import sync
        self.assertNotRegex(inspect.getsource(sync), r"\b(threading|Timer|sched|schedule|subprocess)\b")


class MutationOfTheDesignTests(SyncCase):
    """C7: a naive per-page watermark implementation FAILS the very scenario the real algorithm passes (proves the suite can see the rejected design)."""

    def naive_sync(self, crash_after_pages):
        """The REJECTED design: apply each history page as it arrives and advance the checkpoint to the largest record id seen in that page."""
        lease = sync_lease.acquire(self.index, ACCOUNT, "INCREMENTAL", clock=self.clock)
        pages = 0
        token = None
        start = self.state()["history_id"]
        while True:
            page = self.mailbox.list_history(start, token, 2)
            ids = sorted({m for r in page["records"] for k in ("added", "labels", "deleted") for m in r[k]})
            fetched, gone = [], []
            for mid in ids:
                try:
                    fetched.append(self.mailbox.get_message_metadata(mid))
                except Exception:
                    gone.append(mid)
            from gmail_intelligence import sync as sync_mod
            sync_mod.apply_chunk(self.index, lease, fetched, gone)
            with lease.fence_txn() as conn:
                if page["records"]:
                    conn.execute("UPDATE sync_state SET history_id=? WHERE account=?", (str(max(int(r["id"]) for r in page["records"])), ACCOUNT))
            pages += 1
            if pages >= crash_after_pages:
                raise RuntimeError("crash")
            token = page["next"]
            if not token:
                break

    def scenario(self):
        self.baseline()
        self.clock.advance(60)
        for i in range(8):
            self.mailbox.add(f"n{i}")
        self.mailbox.reverse = True

    def test_the_naive_watermark_loses_events_when_pages_arrive_newest_first(self):
        self.scenario()
        orig = self.mailbox.list_history

        def newest_first(start, token=None, max_results=100):
            self.mailbox.events.sort(key=lambda e: -e["id"])               # an ordering the API does not rule out
            out = orig(start, token, max_results)
            self.mailbox.events.sort(key=lambda e: e["id"])
            return out
        self.mailbox.list_history = newest_first
        with self.assertRaises(RuntimeError):
            self.naive_sync(crash_after_pages=1)
        sync_lease.release(self.index)
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)
        self.mailbox.list_history = orig                                    # the API behaves normally on the retry
        self.naive_sync(crash_after_pages=99)                               # resume from the advanced watermark
        sync_lease.release(self.index)
        self.assertNotEqual(self.index_rows(), self.oracle_rows())          # events below the watermark were skipped forever

    def test_the_real_algorithm_passes_the_same_scenario(self):
        self.scenario()
        orig = self.mailbox.list_history

        def newest_first(start, token=None, max_results=100):
            self.mailbox.events.sort(key=lambda e: -e["id"])
            out = orig(start, token, max_results)
            self.mailbox.events.sort(key=lambda e: e["id"])
            return out
        self.mailbox.list_history = newest_first

        def crash(point):
            if point == "chunk:1":
                raise KeyboardInterrupt
        with self.assertRaises(Exception):
            self.sync(page_size=2, chunk=3, hook=crash)
        self.clock.advance(sync_lease.LEASE_TTL.total_seconds() + 1)
        self.mailbox.list_history = orig
        self.sync(page_size=2, chunk=3)
        self.assertMatchesOracle()


if __name__ == "__main__":
    unittest.main()
