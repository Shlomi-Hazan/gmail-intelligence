"""Offline tests for the M2 mailbox index: scanner, SQLite index, reports and mailbox CLI.

Everything uses synthetic Gmail data, temporary SQLite files and fake readers. No network, no Google
account, no real mailbox. A socket guard in the CLI tests fails on any connection attempt.
"""
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_auth import ACCOUNT, Base, SENTINELS, http_error  # noqa: E402

from gmail_intelligence import cli, config, gmail, index as idx, report, scanner  # noqa: E402

BODY_SENTINEL, SUBJECT_SENTINEL = "SYNTH-BODY-TEXT", "SYNTH-SUBJECT-TEXT"


def ms(y, m, d):
    return int(datetime(y, m, d, 12, tzinfo=timezone.utc).timestamp() * 1000)


def mk(i, sender="a@x.test", labels=("INBOX",), thread=None, when=None, size=1000):
    return {"id": f"m{i}", "thread_id": thread or f"t{i}", "internal_ms": when or ms(2024, 1, 1) + i,
            "size": size, "sender": sender, "label_ids": list(labels)}


class FakeReader:
    """Read-only reader double. Pages are served newest first; failures can be scheduled."""

    def __init__(self, messages, labels=None):
        self.messages = list(messages)
        self.labels = labels or [{"id": "INBOX", "name": "INBOX", "type": "system"}]
        self.list_calls, self.get_calls = [], []
        self.get_failures, self.list_failures, self.bad_tokens, self.gone = {}, [], set(), set()
        self.after_gets = None  # (n, callback) -> callback() after n successful gets
        self.duplicate_pages = False

    def list_label_details(self):
        return self.labels

    def list_message_ids(self, page_token=None, max_results=500):
        self.list_calls.append((page_token, max_results))
        if self.list_failures:
            raise self.list_failures.pop(0)
        if page_token in self.bad_tokens:
            self.bad_tokens.discard(page_token)  # a fresh token for the same offset is valid again
            raise gmail.GmailApiError("bad token", 400)
        start = int(page_token[1:]) if page_token else 0
        chunk = self.messages[start:start + max_results]
        ids = [m["id"] for m in chunk]
        if self.duplicate_pages and ids:
            ids = ids + ids[:1]
        nxt = f"o{start + max_results}" if start + max_results < len(self.messages) else None
        return ids, nxt

    def get_message_metadata(self, message_id):
        self.get_calls.append(message_id)
        queue = self.get_failures.get(message_id)
        if queue:
            raise queue.pop(0)
        if message_id in self.gone:
            raise gmail.GmailNotFoundError("gone", 404)
        if self.after_gets and len(self.get_calls) == self.after_gets[0]:
            self.after_gets[1]()
        return dict(next(m for m in self.messages if m["id"] == message_id))

    def get_profile(self):
        return {"emailAddress": ACCOUNT, "messagesTotal": len(self.messages), "threadsTotal": 1, "historyId": "1"}


def fast_limiter():
    return scanner.RateLimiter(10 ** 9, clock=(lambda it=__import__('itertools').count(): next(it) * 1000.0), sleep=lambda s: None)


class IndexCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gi-idx-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.index = idx.Index(os.path.join(self.tmp, "data", "index.sqlite3"))
        self.addCleanup(self.index.close)
        self.sleeps, self.messages = [], []
        patcher = mock.patch.object(scanner, "BATCH", 2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, reader, account="a@example.test", **kw):
        kw.setdefault("mode", "full")
        return scanner.run_scan(reader, self.index, account, limiter=fast_limiter(), sleep=self.sleeps.append,
                                progress=self.messages.append, page_size=kw.pop("page_size", 3), **kw)

    def count(self, table="messages", account="a@example.test"):
        return self.index.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE account=?", (account,)).fetchone()[0]


class ScanBehaviour(IndexCase):
    def test_pagination_collects_every_page(self):
        reader = FakeReader([mk(i) for i in range(7)])
        row = self.scan(reader)
        self.assertEqual([c[0] for c in reader.list_calls], [None, "o3", "o6"])
        self.assertEqual((row["status"], row["listed"], row["indexed"]), ("completed", 7, 7))
        self.assertEqual(self.count(), 7)

    def test_empty_mailbox(self):
        row = self.scan(FakeReader([]))
        self.assertEqual((row["status"], row["indexed"]), ("completed", 0))
        self.assertEqual(report.completeness(self.index, "a@example.test")[0], "complete")
        self.assertIn("No messages indexed", report.report_text(self.index, "a@example.test"))

    def test_limited_scan_takes_newest_and_is_partial(self):
        reader = FakeReader([mk(i) for i in range(10)])
        row = self.scan(reader, mode="limited", limit=4)
        self.assertEqual((row["status"], row["indexed"], row["mode"]), ("completed", 4, "limited"))
        self.assertEqual(reader.get_calls, ["m0", "m1", "m2", "m3"])
        self.assertTrue(all(c[1] <= 3 for c in reader.list_calls))
        state, _ = report.completeness(self.index, "a@example.test")
        self.assertEqual(state, "partial")
        self.assertIn("PARTIAL", report.report_text(self.index, "a@example.test"))

    def test_duplicate_ids_are_fetched_and_stored_once(self):
        reader = FakeReader([mk(i) for i in range(6)])
        reader.duplicate_pages = True
        self.scan(reader)
        self.assertEqual(sorted(reader.get_calls), sorted(set(reader.get_calls)))
        self.assertEqual(self.count(), 6)

    def test_vanished_message_is_counted_not_failed(self):
        reader = FakeReader([mk(i) for i in range(4)])
        reader.gone.add("m2")
        row = self.scan(reader)
        self.assertEqual((row["status"], row["vanished"], row["failed"], row["indexed"]), ("completed", 1, 0, 3))

    def test_only_read_methods_are_used(self):
        used = set()

        class Spy:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                used.add(name)
                if name not in ("get_profile", "list_label_details", "list_message_ids", "get_message_metadata"):
                    raise AssertionError(f"scanner used {name}")
                return getattr(self._inner, name)

        self.scan(Spy(FakeReader([mk(1), mk(2)])))
        self.assertEqual(used, {"get_profile", "list_label_details", "list_message_ids", "get_message_metadata"})


class ResumeAndFailures(IndexCase):
    def test_interrupt_then_resume_without_duplicates_or_refetch(self):
        reader = FakeReader([mk(i) for i in range(8)])

        def stop():
            raise KeyboardInterrupt

        reader.after_gets = (5, stop)
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan(reader)
        scan = self.index.find_resumable("a@example.test")
        self.assertEqual(scan["status"], "interrupted")
        saved = self.count()
        self.assertGreaterEqual(saved, 3)  # committed batches survive the interrupt
        self.assertEqual(report.completeness(self.index, "a@example.test")[0], "partial")
        reader.after_gets = None
        row = self.scan(reader, resume=True)
        self.assertEqual(row["status"], "completed")
        self.assertEqual(self.count(), 8)
        self.assertLessEqual(len(reader.get_calls) - 8, scanner.BATCH)  # at most the uncommitted batch is refetched
        self.assertEqual(report.completeness(self.index, "a@example.test")[0], "complete")

    def test_stop_callback_interrupts(self):
        reader = FakeReader([mk(i) for i in range(6)])
        flag = {"n": 0}

        def stop():
            flag["n"] += 1
            return flag["n"] > 3

        with self.assertRaises(scanner.ScanInterrupted):
            self.scan(reader, stop=stop)
        self.assertEqual(self.index.find_resumable("a@example.test")["status"], "interrupted")

    def test_invalid_page_token_falls_back_to_restart_keeping_work(self):
        reader = FakeReader([mk(i) for i in range(9)])
        stops = {"n": 0}

        def stop():
            stops["n"] += 1
            return stops["n"] > 5

        with self.assertRaises(scanner.ScanInterrupted):
            self.scan(reader, stop=stop)
        prev = self.index.find_resumable("a@example.test")
        self.index.set_page_token(prev["id"], "o3")
        reader.bad_tokens.add("o3")
        before = len(reader.get_calls)
        row = self.scan(reader, resume=True)
        self.assertEqual((row["status"], row["indexed"]), ("completed", 9))
        self.assertTrue(any("no longer valid" in m for m in self.messages))
        self.assertEqual(self.count(), 9)
        self.assertLess(len(reader.get_calls) - before, 9)  # earlier messages were not refetched

    def test_resume_without_scan_or_for_other_account(self):
        reader = FakeReader([mk(i) for i in range(4)])
        with self.assertRaises(scanner.ScanError):
            self.scan(reader, resume=True)
        reader.after_gets = (2, lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan(reader)
        with self.assertRaises(scanner.ScanError):
            self.scan(FakeReader([mk(1)]), account="b@example.test", resume=True)
        self.assertIsNotNone(self.index.find_resumable("a@example.test"))

    def test_transient_errors_back_off_exponentially_then_succeed(self):
        reader = FakeReader([mk(1)])
        reader.get_failures["m1"] = [gmail.GmailApiError("x", 503), gmail.GmailRateLimitError("slow", 429),
                                     gmail.GmailApiError("net")]
        row = self.scan(reader)
        self.assertEqual(row["status"], "completed")
        self.assertEqual(self.sleeps, [2.0, 4.0, 8.0])

    def test_retries_are_bounded_and_scan_stays_resumable(self):
        reader = FakeReader([mk(1), mk(2)])
        reader.get_failures["m1"] = [gmail.GmailApiError("x", 500)] * 10
        with self.assertRaises(scanner.ScanInterrupted):
            self.scan(reader)
        self.assertEqual(len(self.sleeps), scanner.MAX_ATTEMPTS - 1)
        self.assertEqual(self.index.find_resumable("a@example.test")["status"], "interrupted")
        self.assertEqual(self.count(), 0)

    def test_auth_failure_is_not_retried(self):
        reader = FakeReader([mk(1), mk(2)])
        reader.get_failures["m1"] = [gmail.GmailAuthError("rejected", 401)]
        with self.assertRaises(gmail.GmailAuthError):
            self.scan(reader)
        self.assertEqual((reader.get_calls, self.sleeps), (["m1"], []))
        self.assertEqual(self.index.recent_scans("a@example.test")[0]["status"], "failed")

    def test_permanent_message_error_makes_scan_incomplete_and_prevents_pruning(self):
        reader = FakeReader([mk(i) for i in range(4)])
        self.scan(reader)  # complete baseline
        reader.messages = reader.messages[:3]  # m3 left Gmail
        reader.get_failures["m1"] = [gmail.GmailApiError("bad request", 400)]
        row = self.scan(reader)
        self.assertEqual((row["status"], row["failed"], row["pruned"]), ("incomplete", 1, 0))
        self.assertEqual(self.count(), 4)  # nothing deleted after a failed scan
        state, why = report.completeness(self.index, "a@example.test")
        self.assertEqual(state, "partial")

    def test_complete_full_scan_prunes_messages_gone_from_gmail_but_limited_never_does(self):
        reader = FakeReader([mk(i) for i in range(5)])
        self.scan(reader, mode="limited", limit=5)  # M7A: a limited scan is refused once a checkpoint exists, so the limited scans come first
        reader.messages = reader.messages[:3]
        self.scan(reader, mode="limited", limit=2)
        self.assertEqual(self.count(), 5)
        row = self.scan(reader)
        self.assertEqual((row["status"], row["pruned"]), ("completed", 2))
        self.assertEqual((self.count(), self.count("message_labels")), (3, 3))

    def test_rate_limiter_spreads_requests_under_budget(self):
        now = {"t": 0.0}
        slept = []

        def sleep(s):
            slept.append(s)
            now["t"] += s

        lim = scanner.RateLimiter(600, clock=lambda: now["t"], sleep=sleep)  # 10 units/s
        for _ in range(3):
            lim.acquire(20)
        self.assertEqual([round(x, 3) for x in slept], [2.0, 2.0])
        self.assertAlmostEqual(now["t"], 4.0)
        with self.assertRaises(ValueError):
            scanner.RateLimiter(0)

    def test_scan_stays_within_unit_budget(self):
        now = {"t": 0.0}

        def sleep(s):
            now["t"] += s

        lim = scanner.RateLimiter(4500, clock=lambda: now["t"], sleep=sleep)
        reader = FakeReader([mk(i) for i in range(30)])
        scanner.run_scan(reader, self.index, "a@example.test", mode="full", limiter=lim, sleep=sleep)
        units = 30 * scanner.GET_COST + 2 * scanner.LIST_COST  # labels call + one list page + 30 gets
        self.assertGreaterEqual(now["t"], (units - scanner.GET_COST) * 60 / 4500 - 0.01)


class IndexStorage(IndexCase):
    def test_permissions_schema_and_no_content_columns(self):
        self.scan(FakeReader([mk(1)]))
        self.assertEqual(stat.S_IMODE(os.stat(self.index.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.index.path)).st_mode), 0o700)
        self.assertEqual(self.index.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
        cols = {r[1] for t in ("messages", "message_labels", "labels", "scans")
                for r in self.index.conn.execute(f"PRAGMA table_info({t})")}
        for banned in ("body", "snippet", "subject", "payload", "raw", "token", "attachment", "recipient", "to"):
            self.assertNotIn(banned, cols)

    def test_upsert_is_idempotent_and_refreshes_labels(self):
        reader = FakeReader([mk(1, labels=("INBOX", "UNREAD")), mk(2)])
        self.scan(reader)
        self.assertEqual(self.index.overview("a@example.test")["u"], 1)
        reader.messages[0] = mk(1, labels=("INBOX", "STARRED"))
        self.scan(reader)
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.index.overview("a@example.test")["u"], 0)
        labs = {r[0] for r in self.index.conn.execute("SELECT label_id FROM message_labels WHERE message_id='m1'")}
        self.assertEqual(labs, {"INBOX", "STARRED"})

    def test_batch_is_transactional(self):
        scan_id = self.index.start_scan("a@example.test", "full")
        good, bad = mk(1), dict(mk(2), label_ids=None)
        with self.assertRaises(TypeError):
            self.index.save_batch("a@example.test", scan_id, [good, bad])
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.index.scan(scan_id)["indexed"], 0)

    def test_accounts_are_isolated(self):
        self.scan(FakeReader([mk(1, sender="s1@x.test"), mk(2)]), account="a@example.test")
        self.scan(FakeReader([mk(1, sender="s2@y.test")]), account="b@example.test")  # same message id!
        self.assertEqual(self.count(account="a@example.test"), 2)
        self.assertEqual(self.count(account="b@example.test"), 1)
        self.assertEqual([r["who"] for r in self.index.top_senders("b@example.test")], ["s2@y.test"])
        self.assertNotIn("s1@x.test", report.senders_text(self.index, "b@example.test", 10, False, False))
        self.index.purge("b@example.test")
        self.assertEqual((self.count(account="a@example.test"), self.count(account="b@example.test")), (2, 0))

    def test_no_body_or_subject_ever_reaches_the_database(self):
        # The adapter drops everything but ids, dates, size, labels and the From address.
        data = {"id": "m1", "threadId": "t1", "internalDate": "1700000000000", "sizeEstimate": 99,
                "labelIds": ["INBOX"], "snippet": BODY_SENTINEL,
                "payload": {"headers": [{"name": "Subject", "value": SUBJECT_SENTINEL},
                                        {"name": "From", "value": "Al <AL@Example.TEST>"}], "body": BODY_SENTINEL}}
        meta = _reader_for(data).get_message_metadata("m1")
        self.assertEqual(meta["sender"], "al@example.test")
        self.assertNotIn(BODY_SENTINEL, json.dumps(meta))
        self.assertNotIn(SUBJECT_SENTINEL, json.dumps(meta))
        self.scan(FakeReader([meta]))
        dump = "\n".join(self.index.conn.iterdump())
        for s in (BODY_SENTINEL, SUBJECT_SENTINEL):
            self.assertNotIn(s, dump)

    def test_newer_schema_is_refused(self):
        self.index.conn.execute(f"PRAGMA user_version = {idx.SCHEMA_VERSION + 1}")
        with self.assertRaises(idx.IndexProblem):
            idx.Index(self.index.path)

    def test_missing_index_is_reported_without_creating_it(self):
        path = os.path.join(self.tmp, "none", "x.sqlite3")
        with self.assertRaises(idx.IndexProblem):
            idx.Index(path, create=False)
        self.assertFalse(os.path.exists(path))


def _reader_for(data=None, error=None):
    req = mock.Mock()
    if error:
        req.execute.side_effect = error
    else:
        req.execute.return_value = data
    svc = mock.MagicMock()
    svc.users.return_value.messages.return_value.get.return_value = req
    svc.users.return_value.messages.return_value.list.return_value = req
    reader = gmail.GmailReader(svc)
    reader._svc, reader._req = svc, req
    return reader


class AdapterMetadata(unittest.TestCase):
    def test_requests_only_metadata_fields_and_parses_optional_fields(self):
        reader = _reader_for({"id": "m1", "internalDate": "abc", "payload": {"headers": []}})
        meta = reader.get_message_metadata("m1")
        self.assertEqual(meta, {"id": "m1", "thread_id": None, "internal_ms": None, "size": None,
                                "sender": None, "label_ids": []})
        kwargs = reader._svc.users().messages().get.call_args.kwargs
        self.assertEqual((kwargs["format"], kwargs["metadataHeaders"]), ("metadata", ["From"]))
        for banned in ("snippet", "body", "raw", "parts"):
            self.assertNotIn(banned, kwargs["fields"])

    def test_malformed_response_and_list_paging(self):
        with self.assertRaises(gmail.GmailApiError):
            _reader_for({"threadId": "t"}).get_message_metadata("m1")
        reader = _reader_for({"messages": [{"id": "a"}, {}, {"id": "b"}], "nextPageToken": "n"})
        self.assertEqual(reader.list_message_ids("tok", 500), (["a", "b"], "n"))
        kwargs = reader._svc.users().messages().list.call_args.kwargs
        self.assertEqual((kwargs["maxResults"], kwargs["pageToken"], kwargs["includeSpamTrash"]), (500, "tok", True))
        self.assertEqual(_reader_for({}).list_message_ids(), ([], None))

    def test_404_and_other_statuses_are_translated(self):
        with self.assertRaises(gmail.GmailNotFoundError):
            _reader_for(error=http_error(404)).get_message_metadata("m1")
        with self.assertRaises(gmail.GmailApiError) as ctx:
            _reader_for(error=http_error(400)).list_message_ids("bad")
        self.assertEqual(ctx.exception.status, 400)


class Reports(IndexCase):
    def setUp(self):
        super().setUp()
        reader = FakeReader([
            mk(1, "a@big.test", ("INBOX", "UNREAD", "CATEGORY_PROMOTIONS"), "t1", ms(2023, 1, 15), 2_000_000),
            mk(2, "a@big.test", ("INBOX", "CATEGORY_PROMOTIONS", "Label_7"), "t1", ms(2023, 2, 1), 3_000_000),
            mk(3, "b@big.test", ("INBOX", "UNREAD", "CATEGORY_UPDATES"), "t3", ms(2024, 3, 10), 1_000_000),
            mk(4, None, ("SENT",), "t4", ms(2024, 3, 11), None),
        ], labels=[{"id": "Label_7", "name": "Receipts", "type": "user"}])
        for m in reader.messages:
            m["size"] = m["size"] or 0
        self.scan(reader)
        self.acc = "a@example.test"

    def test_message_versus_thread_counts(self):
        ov = self.index.overview(self.acc)
        self.assertEqual((ov["n"], ov["t"], ov["u"]), (4, 3, 2))
        text = report.report_text(self.index, self.acc)
        self.assertIn("messages: 4", text)
        self.assertIn("threads represented: 3", text)

    def test_categories_and_overlapping_labels(self):
        text = report.report_text(self.index, self.acc)
        self.assertRegex(text, r"Promotions\s+2\b")
        self.assertRegex(text, r"Updates\s+1\b")
        counts = {l["id"]: l["n"] for l in self.index.label_counts(self.acc)}
        self.assertGreater(sum(counts.values()), 4)  # labels overlap
        self.assertIn("can exceed the message count", text)
        self.assertIn("Receipts", text)  # user label shown by name, system labels by id
        self.assertIn("system:", text)

    def test_sender_statistics_and_privacy_of_default_report(self):
        top = self.index.top_senders(self.acc, 10)
        self.assertEqual([(r["who"], r["n"], r["unread"]) for r in top],
                         [("a@big.test", 2, 1), ("(unknown)", 1, 0), ("b@big.test", 1, 1)])
        self.assertEqual([r["who"] for r in self.index.top_senders(self.acc, 10, unread_only=True)],
                         ["a@big.test", "b@big.test"])
        dom = self.index.top_senders(self.acc, 10, domains=True)
        self.assertEqual((dom[0]["who"], dom[0]["n"]), ("big.test", 3))
        text = report.report_text(self.index, self.acc)
        self.assertIn("big.test", text)
        self.assertNotIn("a@big.test", text)  # the general report never prints full addresses
        self.assertIn("a@big.test", report.senders_text(self.index, self.acc, 5, False, False))

    def test_year_and_month_grouping(self):
        self.assertEqual(self.index.by_period(self.acc, "%Y"), [("2023", 2), ("2024", 2)])
        self.assertEqual(self.index.by_period(self.acc, "%Y-%m"), [("2023-01", 1), ("2023-02", 1), ("2024-03", 2)])
        text = report.report_text(self.index, self.acc)
        self.assertIn("oldest: 2023-01-15", text)
        self.assertIn("newest: 2024-03-11", text)

    def test_size_is_labelled_as_an_estimate(self):
        text = report.report_text(self.index, self.acc)
        self.assertIn("size estimate: 6.0 MB", text)
        self.assertIn("NOT your account storage usage", text)

    def test_completeness_and_no_deletion_advice(self):
        text = report.report_text(self.index, self.acc)
        self.assertIn("COMPLETE", text)
        self.assertNotIn("PARTIAL", text)
        self.assertIn("Nothing here is a recommendation to delete", text)
        for banned in ("safe to delete", "you should delete", "recommend deleting"):
            self.assertNotIn(banned, text.lower())

    def test_status_lists_scans(self):
        text = report.status_text(self.index, self.acc)
        self.assertIn("[full] completed", text)
        self.assertIn("Indexed messages: 4", text)


class MailboxCli(Base):
    def setUp(self):
        super().setUp()
        self.reader = FakeReader([mk(i, sender=f"s{i % 2}@x.test") for i in range(7)])
        self.blob = self.stored_blob()
        patch = mock.patch.object(cli, "_open_reader", lambda: (self.reader, self.blob))
        patch.start()
        self.addCleanup(patch.stop)

    def scan_cli(self, *args):
        return self.run_cli("mailbox", "scan", "--max-units-per-minute", "1000000000", *args)

    def test_scan_requires_explicit_mode_and_valid_limit(self):
        self.assertEqual(self.run_cli("mailbox", "scan")[0], 2)
        self.assertEqual(self.run_cli("mailbox", "scan", "--all", "--limit", "5")[0], 2)
        self.assertEqual(self.run_cli("mailbox", "scan", "--limit", "0")[0], 1)
        self.assertEqual(self.reader.get_calls, [])

    def test_limited_scan_then_local_only_commands(self):
        code, out, _ = self.scan_cli("--limit", "3")
        self.assertEqual(code, 0, out)
        self.assertIn("PARTIAL", out)
        self.assertEqual(len(self.reader.get_calls), 3)
        # reports/status/top-senders never touch Gmail (reader replaced by a bomb; sockets are blocked)
        with mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")):
            for argv in (("mailbox", "report"), ("mailbox", "status"), ("mailbox", "top-senders"),
                         ("mailbox", "top-senders", "--domains", "--unread", "--limit", "2")):
                code, out, _ = self.run_cli(*argv)
                self.assertEqual(code, 0, (argv, out))
            self.assertEqual(self.run_cli("auth", "status")[0], 1)  # no token stored; still no Gmail
            self.assertEqual(self.run_cli("doctor")[0] in (0, 1), True)
        self.assertEqual(len(self.reader.get_calls), 3)

    def test_full_scan_resume_flow_and_exit_codes(self):
        self.reader.after_gets = (3, lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        code, _, err = self.scan_cli("--all")
        self.assertEqual(code, 130)
        self.assertIn("--resume", err)
        self.assertIn("PARTIAL", self.run_cli("mailbox", "status")[1])
        self.reader.after_gets = None
        code, out, _ = self.scan_cli("--resume")
        self.assertEqual(code, 0, out)
        self.assertIn("COMPLETE", self.run_cli("mailbox", "report")[1])
        self.assertEqual(self.scan_cli("--resume")[0], 1)  # nothing left to resume

    def test_reports_without_index_or_account(self):
        code, _, err = self.run_cli("mailbox", "report")
        self.assertEqual(code, 1)
        self.assertIn("no local index", err)
        self.store.delete()
        self.assertEqual(self.run_cli("mailbox", "status")[0], 1)
        self.assertEqual(self.run_cli("mailbox", "status", "--account", "x@example.test")[0], 1)

    def test_account_mismatch_is_refused_before_scanning(self):
        self.reader.get_profile = lambda: {"emailAddress": "other@example.test", "messagesTotal": 1}
        code, _, err = self.scan_cli("--limit", "2")
        self.assertEqual(code, 1)
        self.assertIn("differs", err)
        self.assertEqual(self.reader.get_calls, [])

    def test_auth_failure_exit_code_and_no_secret_in_output(self):
        self.reader.get_failures["m0"] = [gmail.GmailAuthError("rejected", 401)]
        code, out, err = self.scan_cli("--limit", "2")
        self.assertEqual(code, 1)
        self.assertNotIn("m0", out + err.replace("scan", ""))  # no mailbox ids needed in messages
        for s in SENTINELS:
            self.assertNotIn(s, out + err)

    def test_purge_requires_confirmation_and_only_touches_local_data(self):
        self.scan_cli("--limit", "2")
        self.assertEqual(self.run_cli("mailbox", "purge", stdin="n")[0], 1)
        self.assertIn("Indexed messages: 2", self.run_cli("mailbox", "status")[1])
        code, out, _ = self.run_cli("mailbox", "purge", stdin="y")
        self.assertEqual(code, 0)
        self.assertIn("Gmail was not touched", out)
        self.assertIn("Indexed messages: 0", self.run_cli("mailbox", "status")[1])

    def test_database_lives_in_app_dir_outside_the_repository(self):
        self.scan_cli("--limit", "1")
        path = config.index_path()
        self.assertTrue(path.exists())
        self.assertFalse(config.inside_git_repo(path.parent))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_top_senders_rejects_bad_limit(self):
        self.assertEqual(self.run_cli("mailbox", "top-senders", "--limit", "0")[0], 1)


class SourceGuards(unittest.TestCase):
    def test_new_modules_make_no_gmail_write_calls_and_use_parameterized_sql(self):
        import re
        for name in ("scanner.py", "index.py", "report.py"):
            text = (ROOT / "src" / "gmail_intelligence" / name).read_text()
            self.assertIsNone(re.search(r"\.(send|modify|batchModify|trash|untrash|batchDelete|insert|drafts)\(", text.replace("INSERT", "")), name)
            self.assertNotIn("googleapiclient", text)
        text = (ROOT / "src" / "gmail_intelligence" / "index.py").read_text()
        self.assertNotRegex(text, r"execute\(\s*f?[\"'][^\"']*['\"]\s*%")  # no %-formatted SQL


if __name__ == "__main__":
    unittest.main()
