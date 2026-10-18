"""Offline tests for the DISABLED single-message live canary entry point (`cleanup_canary.run_canary`).

Synthetic only: the genuine archive adapter and the genuine credential-opening code run over the in-memory fake wire (the adapter's default connection is replaced by it), a fake
credential store that records every touch, fake write credentials, controlled step clocks, the switch flipped only by a patch inside a test, and temporary SQLite databases.
Nothing contacts Gmail, no real credential or Keychain item exists.
"""
import ast
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_live as TL  # noqa: E402
import test_write_auth as TWA  # noqa: E402
from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_executor import AFTER, HEX, LABELS, THREADS, gerr  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_canary as cc, cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, cleanup_protect  # noqa: E402
from gmail_intelligence import exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, oauth, oauth_write  # noqa: E402

Step = fm.Step
M0 = HEX[0]


class BombIndex:
    """An index that fails the test on ANY access: a disabled canary must refuse before touching the local database."""
    def __getattr__(self, name):
        raise AssertionError(f"the local index was accessed ({name}) while the canary is disabled")


class RecordingStore:
    """Stands in for the write-token store: records every touch and hands out a synthetic write authorization."""
    def __init__(self, blob):
        self.blob, self.touched = blob, []

    def load(self):
        self.touched.append("load")
        return self.blob


class CanaryBase(TL.LiveBase):
    def setUp(self):
        super().setUp()
        self.client_path = self.tmp / "client_secret_write.json"
        self.client_path.write_text(json.dumps(TWA.write_client_config()))
        os.chmod(self.client_path, 0o600)

    def blob(self, account=ACCT, minutes=60):
        return oauth_write.write_blob(TWA.WCreds(minutes=minutes), account, [oauth_write.WRITE_SCOPE], TWA.write_client_config())

    def prepare(self, ids=(M0,), script=(), account=ACCT, minutes=60):
        """An approved, reserved and started execution; the live switch on; the adapter's default connection replaced by the in-memory fake wire."""
        ex = self.execution(ids=tuple(ids))
        self.enable()
        self.svc = fm._Service(ACCT, self.fake_state(), tuple(script))
        patcher = mock.patch.object(gw, "_default_connection", fm._Factory(self.svc))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = RecordingStore(self.blob(account, minutes))
        return ex

    def phrase(self, ex):
        return cc.canary_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"])

    def canary(self, ex, phrase=None, token=None):
        try:
            return cc.run_canary(self.index, ACCT, ex["exec_id"], token or self.token, self.phrase(ex) if phrase is None else phrase, self.store, self.client_path)
        finally:
            self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
            keys = [k for kind, k in self.svc.log if kind == "POST"]
            self.assertLessEqual(len(keys), 1)

    def events(self, kind):
        return [json.loads(r["meta"]) for r in self.index._q("SELECT meta FROM cleanup_audit WHERE event_type=? ORDER BY seq", kind)]


class DisabledTests(CanaryBase):
    def test_disabled_refuses_before_the_index_the_credentials_the_client_file_or_the_network(self):
        store = RecordingStore(self.blob())
        env = {"LIVE_EXECUTION_ENABLED": "1", "GMAIL_LIVE": "1", "GMAIL_INTELLIGENCE_LIVE": "true", "CANARY": "1"}
        with mock.patch.dict(os.environ, env), mock.patch.object(gw, "_default_connection", side_effect=AssertionError("network")):
            with self.assertRaises(ce.ExecError) as ctx:
                cc.run_canary(BombIndex(), ACCT, "exec-00000000", "t" * 40, "CANARY ARCHIVE 1", store, self.tmp / "does-not-exist.json")
        self.assertEqual(ctx.exception.code, "LIVE_DISABLED")
        self.assertEqual(store.touched, [])  # no environment variable, configuration value or argument enables it

    def test_no_environment_configuration_or_cli_path_can_reach_it(self):
        for name in ("cleanup_canary.py", "exec_live_mailbox.py", "cleanup_live.py"):
            tree = ast.parse((SRC / name).read_text())
            imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            self.assertEqual(imported & {"os", "argparse", "configparser", "dotenv"}, set(), name)
            names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertEqual(names & {"environ", "getenv", "putenv"}, set(), name)
        cli = (SRC / "cli.py").read_text()
        for word in ("canary", "cleanup_canary", "run_canary", "CANARY"):
            self.assertNotIn(word, cli)
        self.assertIn("execution is not available in this version", cli)
        self.assertIs(live.LIVE_EXECUTION_ENABLED, False)

    def test_the_canary_is_the_only_caller_and_adds_no_archive_path_of_its_own(self):
        tree = ast.parse((SRC / "cleanup_canary.py").read_text())
        called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        for forbidden in ("archive_message", "verify_account", "message_state", "thread_state", "observe", "open_archive_adapter", "restore_inbox", "record_intent", "record_outcome"):
            self.assertNotIn(forbidden, called)
        self.assertIn("execute_live_batch", called)
        self.assertIn("open_live_mailbox", called)


class RefusalTests(CanaryBase):
    def test_a_wrong_or_missing_confirmation_is_refused_recorded_and_locked_out_before_any_credential_is_touched(self):
        ex = self.prepare()
        plan = cp.get_plan(self.index, ACCT, ex["plan_id"])
        for wrong in (cp.approval_phrase(plan), ce.execution_phrase(plan, 1), "UNDO 1 " + ex["exec_id"], cc.canary_phrase(plan, "exec-00000000"), "", None, self.phrase(ex).lower()):
            with self.assertRaises(ce.ExecError) as ctx:
                self.canary(ex, phrase=wrong if wrong is not None else "")
            self.assertIn(ctx.exception.code, ("BAD_CONFIRMATION", "LOCKED_OUT"))
        self.assertEqual((self.store.touched, self.svc.log, self.events("CANARY_CONFIRMED")), ([], [], []))
        self.assertGreaterEqual(len(self.events("CANARY_REJECTED")), 1)
        for i in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(ce.ExecError):
                self.canary(ex, phrase=f"wrong {i}")
        with self.assertRaises(ce.ExecError) as ctx:  # locked out: even the right phrase is refused for a while
            self.canary(ex)
        self.assertEqual(ctx.exception.code, "LOCKED_OUT")
        self.assertEqual((self.store.touched, self.svc.log, self.item(M0)["state"]), ([], [], "PENDING"))

    def test_more_than_one_target_or_a_wrong_state_or_lease_is_refused_before_credentials(self):
        ex = self.prepare(ids=(M0, HEX[1]))
        with self.assertRaises(ce.ExecError) as ctx:
            self.canary(ex)
        self.assertEqual(ctx.exception.code, "NOT_A_CANARY")
        self.setUp()
        ex = self.prepare()
        for token, code in (("x" * 40, "LEASE_LOST"), ("short", "LEASE_LOST")):
            with self.assertRaises(ce.ExecError) as ctx:
                self.canary(ex, token=token)
            self.assertEqual(ctx.exception.code, code)
        self.setUp()
        ex = self.reserve(self.approved_plan([M0]))  # reserved but never started: no lease
        self.enable()
        self.svc = fm._Service(ACCT, self.fake_state(), ())
        self.store = RecordingStore(self.blob())
        with self.assertRaises(ce.ExecError) as ctx:
            cc.run_canary(self.index, ACCT, ex["exec_id"], "x" * 40, "anything", self.store, self.client_path)
        self.assertEqual(ctx.exception.code, "LEASE_LOST")
        self.assertEqual((self.store.touched, self.svc.log), ([], []))

    def test_a_second_confirmation_for_the_same_execution_is_never_accepted(self):
        ex = self.prepare()
        with cp._txn(self.index):
            audit.append(self.index, ACCT, ex["plan_id"], "CANARY_CONFIRMED", cp._iso(live._utcnow()), {"exec": ex["exec_id"], "phrase_sha256": "0" * 64})
        with self.assertRaises(ce.ExecError) as ctx:
            self.canary(ex)
        self.assertEqual(ctx.exception.code, "CANARY_ALREADY_CONFIRMED")
        self.assertEqual((self.store.touched, self.svc.log), ([], []))

    def test_credential_problems_refuse_without_consuming_the_confirmation_and_the_canary_can_then_run(self):
        ex = self.prepare(minutes=5)  # less than the 10 minutes of access-token life the write authorization needs
        with self.assertRaises(oauth.AuthError):
            self.canary(ex)
        self.assertEqual((self.events("CANARY_CONFIRMED"), self.svc.log, self.item(M0)["state"]), ([], [], "PENDING"))
        self.store.blob = self.blob()
        wrong_account = RecordingStore(self.blob(OTHER))
        self.store, good = wrong_account, self.store
        with self.assertRaises(gw.AccountMismatch):  # a stored authorization for another account
            self.canary(ex)
        self.assertEqual((self.events("CANARY_CONFIRMED"), self.svc.log), ([], []))
        self.store = good
        self.assertEqual(self.canary(ex).item_state, "APPLIED")
        self.assertEqual(len(self.events("CANARY_CONFIRMED")), 1)

    def test_altered_plan_or_missing_approval_or_wrong_live_account_stop_before_any_request_that_could_change_anything(self):
        ex = self.prepare()
        real_q = self.index._q
        with mock.patch.object(self.index, "_q", side_effect=lambda sql, *a, **kw: [] if "FROM cleanup_approval" in sql else real_q(sql, *a, **kw)):
            with self.assertRaises(ce.ExecError) as ctx:
                self.canary(ex)
        self.assertEqual(ctx.exception.code, "APPROVAL_NOT_CONSUMED")
        self.setUp()
        ex = self.prepare()
        with mock.patch.object(cp, "integrity_problems", return_value=["PLAN_HASH_MISMATCH"]):
            with self.assertRaises(ce.ExecError) as ctx:
                self.canary(ex)
        self.assertEqual(ctx.exception.code, "PLAN_CHANGED")
        self.assertEqual(self.svc.posts(), 0)
        self.setUp()
        ex = self.prepare(script=[Step("PROFILE", status=200, body=json.dumps({"emailAddress": OTHER}).encode())])
        res = self.canary(ex)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts, self.svc.posts()), ("NOT_APPLIED", "NEVER_ATTEMPTED", "FAILED", 0, 0))

    def test_protected_or_changed_state_is_skipped_and_nothing_is_archived(self):
        cases = (("a new protection rule", None, ("SKIPPED_DRIFT", "STATE_CHANGED")),
                 ("labels changed", Step("GET_MESSAGE", before=lambda f: f.set_labels(M0, list(LABELS) + ["STARRED"])), ("SKIPPED_DRIFT", "LABELS_CHANGED")),
                 ("an unknown sibling joined the thread", Step("GET_THREAD", before=lambda f: f.add_message(HEX[6], THREADS[0], ["INBOX"])), ("SKIPPED_DRIFT", "THREAD_CHANGED")),
                 ("the message is gone", Step("GET_MESSAGE", before=lambda f: f.remove_message(M0)), ("SKIPPED_GONE", "NOT_FOUND")))
        for label, step, expected in cases:
            with self.subTest(label):
                self.setUp()
                ex = self.prepare(script=[step] if step else [])
                if step is None:
                    cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")
                res = self.canary(ex)
                self.assertEqual((res.item_state, res.code, res.posts, self.svc.posts()), (expected[0], expected[1], 0, 0))


class RaceTests(CanaryBase):
    """Anything that changes between the first local checks and the durable confirmation must be caught IN the confirmation transaction."""

    def changing_store(self, change):
        class Store(RecordingStore):
            def load(inner):
                change()  # the world changes exactly while the credentials are being opened
                return super().load()
        return Store(self.blob())

    def assert_refused_without_confirmation(self, ex, code, phrase=None):
        with self.assertRaises(ce.ExecError) as ctx:
            self.canary(ex, phrase=phrase)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual((self.events("CANARY_CONFIRMED"), self.svc.log), ([], []))  # no misleading authorization, no request

    def test_a_lease_that_is_lost_while_credentials_are_opened_records_no_confirmation(self):
        ex = self.prepare()
        normal, late = live._utcnow, {"on": False}
        later = normal() + ce.LEASE_TTL + timedelta(seconds=30)

        def lose_the_lease():
            late["on"] = True  # time jumps past the lease while the credentials are being opened, and a recovery runs
            ce.recover_interrupted(self.index, ACCT, now=later)
        self.store = self.changing_store(lose_the_lease)
        with mock.patch.object(live, "_utcnow", lambda: later + timedelta(seconds=1) if late["on"] else normal()):
            self.assert_refused_without_confirmation(ex, "LEASE_LOST")
        self.assertEqual(self.exec_state(ex["exec_id"]), "FAILED")

    def test_an_execution_that_stops_or_is_taken_over_while_credentials_are_opened_records_no_confirmation(self):
        ex = self.prepare()
        self.store = self.changing_store(lambda: ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "OWNER_REQUEST", now=live._utcnow()))
        self.assert_refused_without_confirmation(ex, "LEASE_LOST")

    def test_plan_or_approval_changes_while_credentials_are_opened_record_no_confirmation(self):
        flag = {}
        real_integrity, real_q = cp.integrity_problems, self.index._q
        ex = self.prepare()
        self.store = self.changing_store(lambda: flag.update(plan=True))
        with mock.patch.object(cp, "integrity_problems", side_effect=lambda plan: ["PLAN_HASH_MISMATCH"] if flag.get("plan") else real_integrity(plan)):
            self.assert_refused_without_confirmation(ex, "PLAN_CHANGED")
        self.setUp()
        ex = self.prepare()
        self.store = self.changing_store(lambda: flag.update(approval=True))
        real_q = self.index._q  # of the NEW index
        phrase = self.phrase(ex)
        with mock.patch.object(self.index, "_q", side_effect=lambda sql, *a, **kw: [] if flag.get("approval") and "FROM cleanup_approval" in sql else real_q(sql, *a, **kw)):
            self.assert_refused_without_confirmation(ex, "APPROVAL_NOT_CONSUMED", phrase)

    def test_two_callers_racing_for_the_confirmation_record_exactly_one(self):
        ex = self.prepare()
        second = []
        self.store = self.changing_store(lambda: second.append(cc.run_canary(self.index, ACCT, ex["exec_id"], self.token, self.phrase(ex),
                                                                              RecordingStore(self.blob()), self.client_path)) if not second else None)
        with self.assertRaises(ce.ExecError):
            self.canary(ex)  # the first caller finds the execution already finished by the second one
        self.assertEqual((len(self.events("CANARY_CONFIRMED")), self.svc.posts(), second[0].item_state), (1, 1, "APPLIED"))


class ExecutionTests(CanaryBase):
    def test_a_confirmed_canary_archives_exactly_one_message_through_the_shared_live_flow(self):
        seen = {}
        ex = self.prepare(script=[Step("POST", before=lambda f: seen.update(state=self.item(M0)["state"], prev=self.item(M0)["prev_label_ids"], confirmed=len(self.events("CANARY_CONFIRMED"))))])
        res = self.canary(ex)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("APPLIED", "APPLIED", "EXECUTED", 1))
        self.assertEqual((seen["state"], seen["confirmed"]), ("INTENT", 1))  # the intent and the owner's confirmation are durable before the request
        self.assertIsNotNone(seen["prev"])
        self.assertEqual(self.svc.posts(), 1)
        self.assertEqual(self.svc.messages[M0][1], set(AFTER))
        self.assertEqual(self.svc.messages[HEX[1]][1], set(LABELS))  # nothing else is touched
        self.assertEqual({k for k, _ in self.svc.log}, {"PROFILE", "GET_MESSAGE", "GET_THREAD", "POST"})
        row = self.item(M0)
        self.assertEqual((row["evidence_checked"], row["evidence_source"]), (1, "TRUSTED_ADAPTER"))
        self.assertEqual(self.svc.undos(), 0)
        self.assertEqual(self.store.touched, ["load"])  # the credentials were opened once, locally, after the confirmation was checked
        with self.assertRaises(ce.ExecError):  # a finished canary cannot be run again
            self.canary(ex)
        self.assertEqual(self.svc.posts(), 1)

    def test_every_ambiguous_outcome_is_unknown_never_retried_and_recovered_by_fresh_evidence(self):
        cases = ((Step("POST", raises=TimeoutError(), apply=True), "TIMEOUT", True), (Step("POST", raises=ConnectionResetError(), apply=False), "NETWORK_ERROR", False),
                 (Step("POST", status=429, body=gerr(429)[1], apply=False), "AMBIGUOUS_RESULT", False), (Step("POST", status=503, body=b"x", apply=True), "SERVER_ERROR", True),
                 (Step("POST", status=500, body=b"x", apply=False), "SERVER_ERROR", False), (Step("POST", status=200, body=b"not json", apply=True), "AMBIGUOUS_RESULT", True),
                 (Step("GET_MESSAGE", nth=2, raises=TimeoutError()), "TIMEOUT", True))
        for step, code, applied in cases:
            with self.subTest(step.request, status=step.status):
                self.setUp()
                ex = self.prepare(script=[step])
                res = self.canary(ex)
                self.assertEqual((res.item_state, res.code, res.execution_state, res.posts, self.svc.posts()), ("UNKNOWN", code, "RECONCILIATION_REQUIRED", 1, 1))
                with self.assertRaises(ce.ExecError):  # the canary is not repeated
                    self.canary(ex)
                self.assertEqual(self.svc.posts(), 1)
                self.svc.script.clear()
                lm = cl.recover_live  # recovery only observes
                report = lm(self.index, ACCT, live.open_live_mailbox(ACCT, self.store, self.client_path))
                self.assertEqual((self.svc.posts(), self.svc.undos()), (1, 0))
                self.assertEqual(self.item(M0)["state"], "APPLIED" if self.svc.messages[M0][1] == set(AFTER) else "NOT_APPLIED")
                self.assertFalse(report.needs_owner)

    def test_a_refusal_proven_to_be_before_dispatch_is_not_applied_and_makes_no_request(self):
        opened = []
        real_open = live.open_live_mailbox

        def recording_open(*a, **kw):
            opened.append(real_open(*a, **kw))
            return opened[-1]
        # the credentials stop being usable (the access token expires) between the preflight and the request
        ex = self.prepare(script=[Step("GET_THREAD", after=lambda f: setattr(opened[0]._adapter._t._creds, "expiry", datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)))])
        with mock.patch.object(live, "open_live_mailbox", side_effect=recording_open):
            res = self.canary(ex)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts, self.svc.posts()), ("NOT_APPLIED", "REJECTED", "FAILED", 0, 0))

    def test_a_crash_during_the_request_is_recovered_without_any_second_request(self):
        for apply in (True, False):
            with self.subTest(apply=apply):
                self.setUp()
                ex = self.prepare(script=[Step("POST", raises=Crash(), apply=apply)])
                with self.assertRaises(Crash):
                    self.canary(ex)
                self.assertEqual((self.svc.posts(), self.item(M0)["state"]), (1, "INTENT"))
                self.clk.at = self.clk.at + ce.LEASE_TTL + timedelta(seconds=10)
                self.svc.script.clear()
                report = cl.recover_live(self.index, ACCT, live.open_live_mailbox(ACCT, self.store, self.client_path))
                self.assertEqual(report.interrupted, (ex["exec_id"],))
                self.assertEqual(self.item(M0)["state"], "APPLIED" if apply else "NOT_APPLIED")
                self.assertEqual(self.svc.posts(), 1)
                with self.assertRaises(ce.ExecError):
                    self.canary(ex)
                self.assertEqual(self.svc.posts(), 1)


class DocumentationTests(unittest.TestCase):
    def test_the_authorization_readiness_document_states_the_exact_boundaries(self):
        text = (ROOT / "docs" / "CANARY.md").read_text()
        for needle in (oauth_write.WRITE_SCOPE, "gmail-intelligence-write", "oauth-token:gmail.modify", "client_secret_write.json", "auth setup-write", "auth login-write",
                       "--expect-account", "separate Google Cloud project", "LIVE_EXECUTION_ENABLED", "NOT approved", "run_canary", "Zero Additional Cost"):
            self.assertIn(needle, text)
        for secret_shape in ("@gmail.com", "client_secret\":", "refresh_token\":", "AIza"):
            self.assertNotIn(secret_shape, text)


if __name__ == "__main__":
    unittest.main()
