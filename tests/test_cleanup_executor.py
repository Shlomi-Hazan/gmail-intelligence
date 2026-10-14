"""Tests for the M4C-C2 single-item executor (library only, fake mailbox only).

Everything here is synthetic: a synthetic account, an in-memory fake mailbox that runs the real adapter code over a connection class which never
touches a socket, a controlled step clock and temporary SQLite databases. Sockets are blocked by the base classes. Nothing contacts Gmail.
"""
import ast
import http.client
import inspect
import json
import sqlite3
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_exec as TCE  # noqa: E402
import test_write_transport as TWT  # noqa: E402
from test_cleanup import ACCT, OTHER, msg  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_executor as cx, cleanup_plans as cp, cleanup_protect  # noqa: E402
from gmail_intelligence import exec_evidence as ee, exec_fake_mailbox as fm, gmail_write as gw  # noqa: E402

HEX = [f"18c0ffee0000{i:04x}" for i in range(1, 8)]
THREADS = [f"28c0ffee0000{i:04x}" for i in range(1, 8)]
LABELS = ("INBOX", "CATEGORY_PROMOTIONS")
AFTER = ("CATEGORY_PROMOTIONS",)
M0, T0_ = HEX[0], THREADS[0]
Step = fm.Step


class StepClock:
    """A controlled UTC clock for the fake boundary: returns `start`, then advances by `step` on every read; keeps every value it returned."""
    def __init__(self, start, step=timedelta(seconds=1)):
        self.at, self.step, self.seen = start, step, []

    def __call__(self):
        value = self.at
        self.seen.append(value)
        self.at = self.at + self.step
        return value


def gerr(status, reason=None):
    return TWT.gerr(status, reason)


class ExecutorBase(TCE.ExecBase):
    sql = TCE.HardeningTests.sql

    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed(self.messages())
        self.ids = list(HEX[:5])

    def messages(self):
        return [dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(1, 6)]

    def fake_state(self, extra=None):
        state = {HEX[i]: (THREADS[i], list(LABELS)) for i in range(5)}
        state.update(extra or {})
        return state

    def clock(self, ahead=1):
        self.step_clock = StepClock(self.t + timedelta(seconds=ahead))
        return self.step_clock

    def mailbox(self, script=(), account=ACCT, state=None, clock=None):
        return fm.FakeMailbox(account, state or self.fake_state(), clock=clock or self.clock(), script=script)

    def execution(self, ids=(M0,)):
        ex = self.started(self.approved_plan(list(ids)))
        return ex

    def item(self, mid=M0):
        return dict(self.index._q("SELECT * FROM cleanup_exec_item WHERE message_id=?", mid)[0])

    def exec_state(self, exec_id):
        return ce.get_execution(self.index, ACCT, exec_id)["state"]

    def snapshot(self):
        q = self.index._q
        return ([tuple(r) for r in q("SELECT * FROM cleanup_exec_item ORDER BY message_id")], [tuple(r) for r in q("SELECT * FROM cleanup_execution")],
                [tuple(r) for r in q("SELECT * FROM cleanup_exec_slice")], q("SELECT COUNT(*) FROM cleanup_audit")[0][0])

    def run_one(self, ex, mailbox, mid=M0, token=None):
        """Run the executor and check the invariants every scenario must keep: at most one POST, an intact audit chain, a consistent execution."""
        try:
            return cx.execute_one(self.index, ACCT, ex["exec_id"], token or self.token, mid, mailbox)
        finally:
            self.assertLessEqual(mailbox.service.posts(), 1)
            self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
            self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])

    def reconcile_trusted(self, ex, mailbox, mid=M0):
        """Reconcile an UNKNOWN item from a fresh trusted observation made with the library-derived reconciliation context."""
        mailbox.service.script.clear()
        mailbox.verify_account()
        obs = mailbox.observe(mid, context=ce.reconcile_context(self.index, ACCT, ex["exec_id"], mid))
        return ce.reconcile_item(self.index, ACCT, ex["exec_id"], mid, obs, now=mailbox.clock(), require_source="TRUSTED_ADAPTER")


# ====================================================================== the successful path
class SuccessTests(ExecutorBase):
    def test_a_single_item_is_archived_end_to_end_and_recorded_with_a_trusted_observation(self):
        ex = self.execution()
        mb = self.mailbox()
        res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("APPLIED", "APPLIED", "EXECUTED", 1))
        self.assertEqual(mb.service.messages[M0][1], set(AFTER))
        self.assertEqual([k for k, _ in mb.service.log], ["PROFILE", "GET_MESSAGE", "GET_THREAD", "POST", "GET_MESSAGE"])
        row = self.item()
        self.assertEqual((row["evidence_checked"], row["evidence_source"], json.loads(row["prev_label_ids"])), (1, "TRUSTED_ADAPTER", sorted(LABELS)))
        meta = json.loads(self.index._q("SELECT meta FROM cleanup_audit WHERE event_type='ITEM_TRANSITION' AND meta LIKE '%APPLIED%' ORDER BY seq DESC LIMIT 1")[0][0])
        self.assertEqual((meta["obs"], meta["src"]), ("ARCHIVED", "TRUSTED_ADAPTER"))
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTED")

    def test_only_the_four_allowed_request_families_are_ever_made(self):
        ex = self.execution()
        mb = self.mailbox()
        self.run_one(ex, mb)
        self.assertEqual({k for k, _ in mb.service.log}, {"PROFILE", "GET_MESSAGE", "GET_THREAD", "POST"})
        self.assertEqual(len(pol_routes()), 4)

    def test_the_intent_is_committed_with_the_previous_labels_before_the_post(self):
        ex = self.execution()
        seen = {}

        def at_post(fake):
            seen["row"] = dict(self.index._q("SELECT state, prev_label_ids, intent_at FROM cleanup_exec_item WHERE message_id=?", M0)[0])
        mb = self.mailbox([Step("POST", before=at_post)])
        self.run_one(ex, mb)
        self.assertEqual(seen["row"]["state"], "INTENT")
        self.assertEqual(json.loads(seen["row"]["prev_label_ids"]), sorted(LABELS))
        self.assertIsNotNone(seen["row"]["intent_at"])

    def test_a_failed_intent_write_means_no_post_and_the_item_stays_pending(self):
        ex = self.execution()
        mb = self.mailbox()
        with mock.patch.object(ce, "record_intent", side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_one(ex, mb)
        self.assertEqual(mb.service.posts(), 0)
        self.assertEqual(self.item()["state"], "PENDING")

    def test_lease_lost_between_intent_and_post_means_no_post_and_recovery_reconciles_as_unmodified(self):
        ex = self.execution()
        mb = self.mailbox()
        real, calls = ce.renew_lease, []

        def flaky(*a, **kw):
            calls.append(1)
            if len(calls) == 2:  # the recheck right before the POST
                raise ce.ExecError("LEASE_LOST", "this process does not hold a live execution lease; stop")
            return real(*a, **kw)
        with mock.patch.object(ce, "renew_lease", side_effect=flaky):
            with self.assertRaises(ce.ExecError) as ctx:
                self.run_one(ex, mb)
        self.assertEqual(ctx.exception.code, "LEASE_LOST")
        self.assertEqual((mb.service.posts(), self.item()["state"]), (0, "INTENT"))
        later = self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=5)
        self.assertEqual(ce.recover_interrupted(self.index, ACCT, now=later), [ex["exec_id"]])
        self.assertEqual((self.item()["state"], self.item()["error_code"]), ("UNKNOWN", "INTERRUPTED"))
        mb2 = self.mailbox(clock=StepClock(later + timedelta(seconds=1)))
        self.reconcile_trusted(ex, mb2)
        self.assertEqual((self.item()["state"], self.item()["error_code"]), ("NOT_APPLIED", "RECONCILED_UNMODIFIED"))

    def test_a_database_failure_after_the_post_leaves_an_open_intent_that_recovery_reconciles_as_archived(self):
        ex = self.execution()
        mb = self.mailbox()
        with mock.patch.object(ce, "record_outcome", side_effect=sqlite3.OperationalError("database is locked")):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_one(ex, mb)
        self.assertEqual((mb.service.posts(), self.item()["state"]), (1, "INTENT"))
        later = self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=5)
        ce.recover_interrupted(self.index, ACCT, now=later)
        self.assertEqual(self.item()["state"], "UNKNOWN")
        self.reconcile_trusted(ex, self.mailbox(state={M0: (T0_, list(AFTER))}, clock=StepClock(later + timedelta(seconds=1))))
        self.assertEqual((self.item()["state"], self.item()["error_code"], self.item()["evidence_source"]), ("APPLIED", "RECONCILED_OBSERVED_ARCHIVED", "TRUSTED_ADAPTER"))


    def test_calling_the_executor_again_never_posts_again(self):
        ex = self.execution()
        mb = self.mailbox()
        self.run_one(ex, mb)
        again = self.mailbox()
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, again)
        self.assertEqual(ctx.exception.code, "BAD_STATE")
        self.assertEqual((mb.service.posts(), again.service.posts()), (1, 0))

    def test_two_executors_racing_on_the_same_item_cannot_both_post(self):
        ex = self.execution()
        second = self.mailbox()
        results = []
        first = self.mailbox([Step("GET_THREAD", after=lambda f: results.append(cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, second)))])
        with self.assertRaises(ce.ExecError):
            cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, first)  # its intent write finds the item already taken
        self.assertEqual((first.service.posts(), second.service.posts()), (0, 1))
        self.assertEqual(results[0].item_state, "APPLIED")


def pol_routes():
    from gmail_intelligence import gmail_write_policy as pol
    return pol._ROUTES


# ====================================================================== refusals that change nothing, and safe stops before any intent
class PreconditionTests(ExecutorBase):
    def refused(self, ex, mb, code, **kw):
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_one(self.index, ACCT, ex["exec_id"], kw.get("token", self.token), M0, mb)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(mb.service.posts(), 0)
        return before

    def test_more_than_one_item_is_refused_before_anything_changes(self):
        ex = self.execution(ids=(M0, HEX[1]))
        mb = self.mailbox()
        before = self.refused(ex, mb, "NOT_SUPPORTED")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(mb.service.log, [])

    def test_an_execution_that_is_not_running_is_refused(self):
        ex = self.reserve(self.approved_plan([M0]))
        mb = self.mailbox()
        self.assertEqual(self.refused(ex, mb, "BAD_STATE", token="x" * 40), self.snapshot())

    def test_a_wrong_malformed_or_expired_lease_is_refused_without_any_read(self):
        ex = self.execution()
        mb = self.mailbox()
        for bad, code in (("x" * 40, "LEASE_LOST"), ("short", "BAD_LEASE"), (None, "BAD_LEASE")):
            self.assertEqual(self.refused(ex, mb, code, token=bad), self.snapshot())
        self.assertEqual(mb.service.log, [])
        late = self.mailbox(clock=StepClock(self.t + ce.LEASE_TTL + timedelta(seconds=30)))
        self.refused(ex, late, "LEASE_LOST")
        self.assertEqual(late.service.log, [])

    def test_a_missing_or_foreign_approval_or_a_changed_plan_is_refused(self):
        ex = self.execution()
        mb = self.mailbox()
        real_q = self.index._q

        def without_approval(sql, *a, **kw):
            return [] if "FROM cleanup_approval" in sql else real_q(sql, *a, **kw)
        with mock.patch.object(self.index, "_q", side_effect=without_approval):
            self.refused(ex, mb, "APPROVAL_NOT_CONSUMED")
        with mock.patch.object(cp, "integrity_problems", return_value=["PLAN_HASH_MISMATCH"]):
            self.refused(ex, mb, "PLAN_CHANGED")
        self.assertEqual(mb.service.log, [])

    def test_a_clock_that_goes_backwards_or_is_naive_changes_nothing_and_sends_nothing(self):
        ex = self.execution()
        back = self.mailbox(clock=lambda: self.t - timedelta(days=1))
        with self.assertRaises(cp.PlanError) as ctx:
            cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, back)
        self.assertEqual(ctx.exception.code, "CLOCK_ROLLBACK")
        self.assertEqual((back.service.posts(), back.service.log), (0, []))
        naive = self.mailbox(clock=lambda: datetime(2027, 1, 1))
        with self.assertRaises(ValueError):
            cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, naive)
        self.assertEqual(naive.service.log, [])
        self.assertEqual(self.item()["state"], "PENDING")

    def test_account_mismatch_stops_safely_before_any_intent_or_post(self):
        wrong_profile = [Step("PROFILE", status=200, body=json.dumps({"emailAddress": OTHER}).encode())]
        for label, kwargs in (("a mailbox for another account", dict(account=OTHER)), ("a profile that names another account", dict(script=wrong_profile))):
            with self.subTest(label):
                self.setUp()
                ex = self.execution()
                mb = self.mailbox(**kwargs)
                res = self.run_one(ex, mb)
                self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("NOT_APPLIED", "NEVER_ATTEMPTED", "FAILED", 0))
                self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE intent_at IS NOT NULL")[0][0], 0)
                self.assertEqual(mb.service.posts(), 0)

    def test_a_read_failure_before_the_intent_stops_safely_with_no_post(self):
        cases = (("timeout", Step("GET_MESSAGE", raises=TimeoutError()), "AMBIGUOUS_RESULT"),
                 ("401 on the message read", Step("GET_MESSAGE", status=gerr(401)[0], body=gerr(401)[1]), "AUTH_PROBLEM"),
                 ("429 on the thread read", Step("GET_THREAD", status=gerr(429)[0], body=gerr(429)[1]), "RATE_LIMITED"),
                 ("5xx on the thread read", Step("GET_THREAD", status=503, body=b"x"), "AMBIGUOUS_RESULT"),
                 ("an unconfirmed 404", Step("GET_MESSAGE", status=404, body=b"<html>nope</html>"), "AMBIGUOUS_RESULT"))
        for label, step, _ in cases:
            with self.subTest(label):
                self.setUp()
                ex = self.execution()
                mb = self.mailbox([step])
                res = self.run_one(ex, mb)
                self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("NOT_APPLIED", "NEVER_ATTEMPTED", "FAILED", 0))
                self.assertEqual(mb.service.posts(), 0)
                self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE intent_at IS NOT NULL")[0][0], 0)


# ====================================================================== drift, protection and sibling messages
class DriftTests(ExecutorBase):
    def skipped(self, script=(), state=None, expect=("SKIPPED_DRIFT", "LABELS_CHANGED"), ids=(M0,)):
        self.setUp()
        ex = self.execution(ids)
        mb = self.mailbox(script, state=state)
        res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.code, res.posts), (expect[0], expect[1], 0), res)
        self.assertEqual(mb.service.posts(), 0)
        self.assertEqual(res.execution_state, "FAILED")
        return mb

    def test_live_drift_of_the_message_is_skipped_without_a_post(self):
        self.skipped([Step("GET_MESSAGE", before=lambda f: f.set_labels(M0, list(LABELS) + ["STARRED"]))])
        self.skipped([Step("GET_MESSAGE", before=lambda f: f.set_labels(M0, list(LABELS) + ["UNREAD"]))])  # exact equality: even UNREAD is drift
        self.skipped([Step("GET_MESSAGE", before=lambda f: f.set_labels(M0, list(AFTER)))], expect=("SKIPPED_DRIFT", "NOT_IN_INBOX"))
        self.skipped([Step("GET_MESSAGE", before=lambda f: f.remove_message(M0))], expect=("SKIPPED_GONE", "NOT_FOUND"))
        self.skipped(state=self.fake_state({M0: ("28c0ffee0000ffff", list(LABELS))}), expect=("SKIPPED_DRIFT", "THREAD_CHANGED"))

    def test_an_unknown_missing_or_changed_sibling_is_skipped(self):
        self.skipped([Step("GET_THREAD", before=lambda f: f.add_message(HEX[6], T0_, ["INBOX"]))], expect=("SKIPPED_DRIFT", "THREAD_CHANGED"))

    def sibling_messages(self):
        return [dict(msg(1, sender="s1@shop.example.test"), id=M0, thread_id=T0_), dict(msg(2, sender="s2@shop.example.test"), id=HEX[1], thread_id=T0_)] + [
            dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(3, 6)]

    def test_a_known_sibling_that_changed_or_vanished_is_skipped(self):
        cases = (("an untouched sibling is fine", ()),
                 ("a sibling gained a label", [Step("GET_THREAD", before=lambda f: f.set_labels(HEX[1], list(LABELS) + ["STARRED"]))]),
                 ("a sibling vanished", [Step("GET_THREAD", before=lambda f: f.remove_message(HEX[1]))]))
        for label, script in cases:
            with self.subTest(label):
                self.setUp()
                self.index.purge(ACCT)
                self.seed(self.sibling_messages())
                state = self.fake_state()
                state[M0], state[HEX[1]] = (T0_, list(LABELS)), (T0_, list(LABELS))
                ex = self.execution()
                mb = fm.FakeMailbox(ACCT, state, clock=self.clock(), script=script)
                res = self.run_one(ex, mb)
                if script:
                    self.assertEqual((res.item_state, res.code, res.posts), ("SKIPPED_DRIFT", "THREAD_CHANGED", 0))
                else:
                    self.assertEqual((res.item_state, res.posts), ("APPLIED", 1))
                    self.assertEqual(mb.service.messages[HEX[1]][1], set(LABELS))  # the sibling is never touched

    def test_a_protected_label_on_a_sibling_is_recognised(self):
        cleanup_protect.add(self.index, ACCT, label="STARRED")
        self.assertTrue(cx._protected_label(self.index, ACCT, ["INBOX", "STARRED"]))
        self.assertFalse(cx._protected_label(self.index, ACCT, ["INBOX", "CATEGORY_PROMOTIONS"]))

    def test_a_local_change_after_approval_is_skipped_before_anything_is_read_from_the_thread(self):
        ex = self.execution()
        cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")  # a new protection rule: the plan is stale
        mb = self.mailbox()
        res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.code, res.posts), ("SKIPPED_DRIFT", "STATE_CHANGED", 0))
        self.assertNotIn("GET_THREAD", [k for k, _ in mb.service.log])
        self.assertEqual(mb.service.posts(), 0)


# ====================================================================== the archive request and what follows it
class PostFailureTests(ExecutorBase):
    def unknown(self, step, code="AMBIGUOUS_RESULT", stop=None, apply=False):
        self.setUp()
        ex = self.execution()
        mb = self.mailbox([step])
        res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.execution_state, res.posts), ("UNKNOWN", "RECONCILIATION_REQUIRED", 1), (step, res))
        self.assertEqual(res.code, code, step)
        self.assertEqual(mb.service.posts(), 1)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE state='APPLIED'")[0][0], 0)
        return ex, mb

    def test_every_error_after_the_post_may_have_been_sent_is_unknown_and_never_retried(self):
        for status in (400, 401, 403, 404, 429):
            with self.subTest(status):
                s, b = gerr(status)
                self.unknown(Step("POST", status=s, body=b))
        for status in (500, 502, 503):
            with self.subTest(status):
                self.unknown(Step("POST", status=status, body=b"x"), code="SERVER_ERROR")
        with self.subTest("timeout"):
            self.unknown(Step("POST", raises=TimeoutError()), code="TIMEOUT")
        with self.subTest("network"):
            self.unknown(Step("POST", raises=ConnectionResetError()), code="NETWORK_ERROR")
        with self.subTest("http client exception"):
            self.unknown(Step("POST", raises=http.client.RemoteDisconnected("synthetic")), code="NETWORK_ERROR")
        with self.subTest("redirect"):
            self.unknown(Step("POST", status=302, body=b""))
        with self.subTest("malformed answer"):
            self.unknown(Step("POST", status=200, body=b"not json"))
        with self.subTest("unexpected exception"):
            self.unknown(Step("POST", raises=RuntimeError("synthetic")))

    def test_an_ambiguous_post_whose_effect_happened_is_unknown_then_reconciles_as_archived(self):
        ex, mb = self.unknown(Step("POST", raises=TimeoutError(), apply=True), code="TIMEOUT")
        self.assertEqual(mb.service.messages[M0][1], set(AFTER))
        self.reconcile_trusted(ex, mb)
        self.assertEqual((self.item()["state"], self.item()["error_code"]), ("APPLIED", "RECONCILED_OBSERVED_ARCHIVED"))

    def test_an_ambiguous_post_that_did_not_happen_reconciles_as_unmodified(self):
        ex, mb = self.unknown(Step("POST", raises=TimeoutError(), apply=False), code="TIMEOUT")
        self.reconcile_trusted(ex, mb)
        self.assertEqual((self.item()["state"], self.item()["error_code"]), ("NOT_APPLIED", "RECONCILED_UNMODIFIED"))

    def test_a_refusal_proven_to_be_before_dispatch_is_not_applied_and_rejected(self):
        ex = self.execution()
        mb = self.mailbox([Step("GET_THREAD", after=lambda f: setattr(f.creds, "live", False))])  # the credentials stop being usable before the POST
        res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("NOT_APPLIED", "REJECTED", "FAILED", 0))
        self.assertNotIn("POST", [k for k, _ in mb.service.log])
        self.assertEqual(mb.service.messages[M0][1], set(LABELS))

    def test_a_post_that_succeeds_but_the_post_read_fails_is_unknown(self):
        for step, code in ((Step("GET_MESSAGE", nth=2, raises=TimeoutError()), "TIMEOUT"), (Step("GET_MESSAGE", nth=2, status=500, body=b"x"), "SERVER_ERROR"),
                           (Step("GET_MESSAGE", nth=2, status=200, body=b"nope"), "AMBIGUOUS_RESULT")):
            with self.subTest(step):
                self.unknown(step, code=code)

    def test_a_post_read_with_other_labels_or_still_in_the_inbox_or_absent_is_unknown_then_reconciles_honestly(self):
        cases = (("conflicting labels", lambda f: f.set_labels(M0, ["CATEGORY_PROMOTIONS", "STARRED"]), "CONFLICT", "RECONCILED_CONFLICT"),
                 ("still in the inbox", lambda f: f.set_labels(M0, list(LABELS)), "NOT_APPLIED", "RECONCILED_UNMODIFIED"),
                 ("absent", lambda f: f.remove_message(M0), "CONFLICT", "RECONCILED_CONFLICT"))
        for label, change, state, code in cases:
            with self.subTest(label):
                ex, mb = self.unknown(Step("GET_MESSAGE", nth=2, before=change))
                self.reconcile_trusted(ex, mb)
                self.assertEqual((self.item()["state"], self.item()["error_code"]), (state, code))

    def test_a_concurrent_change_between_the_preflight_and_the_post_is_never_recorded_as_applied(self):
        ex, mb = self.unknown(Step("POST", before=lambda f: f.set_labels(M0, list(LABELS) + ["STARRED"])))
        self.assertEqual(mb.service.messages[M0][1], {"CATEGORY_PROMOTIONS", "STARRED"})  # only INBOX was removed, nothing else touched

    def test_the_post_is_never_retried_whatever_the_answer(self):
        for step, code in ((Step("POST", status=429, body=gerr(429)[1]), "AMBIGUOUS_RESULT"), (Step("POST", raises=TimeoutError()), "TIMEOUT"),
                           (Step("POST", status=503, body=b"x"), "SERVER_ERROR")):
            ex, mb = self.unknown(step, code=code)
            self.assertEqual([k for k, _ in mb.service.log].count("POST"), 1)

    def test_an_observation_that_fails_validation_never_becomes_applied(self):
        ex = self.execution()
        mb = self.mailbox()
        with mock.patch.object(ce, "postread_context", return_value="f" * 64):  # the observation carries a context the state machine does not expect
            res = self.run_one(ex, mb)
        self.assertEqual((res.item_state, res.execution_state, res.posts), ("UNKNOWN", "RECONCILIATION_REQUIRED", 1))


class StopReasonAndCrashTests(ExecutorBase):
    unknown = PostFailureTests.unknown

    def last_stop_reason(self):
        rows = self.index._q("SELECT meta FROM cleanup_audit WHERE event_type='EXECUTION_TRANSITION' ORDER BY seq DESC LIMIT 1")
        return json.loads(rows[0][0]).get("reason")

    def test_the_stop_reason_follows_the_kind_of_failure_and_the_execution_requires_reconciliation(self):
        cases = ((Step("POST", status=401, body=gerr(401)[1]), "AUTH_PROBLEM"), (Step("POST", status=403, body=gerr(403)[1]), "AUTH_PROBLEM"),
                 (Step("POST", status=403, body=gerr(403, "rateLimitExceeded")[1]), "RATE_LIMITED"), (Step("POST", status=429, body=gerr(429)[1]), "RATE_LIMITED"),
                 (Step("POST", status=400, body=gerr(400)[1]), "AMBIGUOUS_RESULT"), (Step("POST", status=404, body=gerr(404)[1]), "AMBIGUOUS_RESULT"),
                 (Step("POST", raises=TimeoutError()), "AMBIGUOUS_RESULT"))
        for step, reason in cases:
            with self.subTest(step.status or step.raises):
                self.unknown(step, code=self.unknown_code(step))
                self.assertEqual(self.last_stop_reason(), reason)

    @staticmethod
    def unknown_code(step):
        return "TIMEOUT" if step.raises is not None else "AMBIGUOUS_RESULT"

    def test_a_crash_at_every_transition_leaves_a_state_that_recovery_and_reconciliation_resolve_without_a_second_post(self):
        class Crash(BaseException):
            """Simulates the process dying: it is not an Exception, so nothing in the executor can swallow it."""
        points = {
            "after the intent": (ce, "renew_lease", None),  # replaced below with a call-counting wrapper
            "during the post (not applied)": None, "during the post (applied)": None,
            "after the post, before the post-read": (ce, "postread_context", Crash),
            "after the observation, before the outcome": (ce, "record_outcome", Crash),
            "after the outcome, before the slice ends": (ce, "end_slice", Crash),
        }
        for label in points:
            with self.subTest(label):
                self.setUp()
                ex = self.execution()
                script = []
                if label.startswith("during the post"):
                    script = [Step("POST", raises=Crash(), apply=label.endswith("(applied)"))]
                mb = self.mailbox(script)
                patches = []
                if label == "after the intent":
                    real, calls = ce.renew_lease, []

                    def second_call_crashes(*a, **kw):
                        calls.append(1)
                        if len(calls) == 2:
                            raise Crash()
                        return real(*a, **kw)
                    patches.append(mock.patch.object(ce, "renew_lease", side_effect=second_call_crashes))
                elif points[label]:
                    patches.append(mock.patch.object(points[label][0], points[label][1], side_effect=Crash()))
                for pt in patches:
                    pt.start()
                try:
                    with self.assertRaises(Crash):
                        cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, mb)
                finally:
                    for pt in patches:
                        pt.stop()
                self.assertLessEqual(mb.service.posts(), 1)
                state = self.item()["state"]
                self.assertNotEqual(state, "UNKNOWN")  # nothing is recorded as an answer the process never saw
                later = self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=5)
                ce.recover_interrupted(self.index, ACCT, now=later)
                self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
                final = self.item()["state"]
                if state == "PENDING":
                    self.assertEqual(final, "NOT_APPLIED")
                elif state == "APPLIED":
                    self.assertEqual(final, "APPLIED")
                else:
                    self.assertEqual((state, final), ("INTENT", "UNKNOWN"))
                    mb2 = self.mailbox(state={m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}, clock=StepClock(later + timedelta(seconds=1)))
                    self.reconcile_trusted(ex, mb2)
                    self.assertEqual(self.item()["state"], "APPLIED" if mb.service.messages[M0][1] == set(AFTER) else "NOT_APPLIED")
                self.assertEqual(mb.service.posts(), 1 if label not in ("after the intent",) else 0)


# ====================================================================== C2-GATE-1: execution binding
class BindingTests(ExecutorBase):
    def intent_ready(self, ids=(M0,)):
        ex = self.execution(ids)
        mid = ids[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, LABELS, now=self.tick())
        return ex, mid

    def attempt(self, ex, mid, obs):
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertTrue(ee.is_pending(obs))  # a rejected observation is not consumed
        self.assertEqual(self.item(mid)["state"], "INTENT")

    def observe_with(self, context, mid=M0):
        mb = self.mailbox(state=self.fake_state({mid: (THREADS[HEX.index(mid)], list(AFTER))}), clock=StepClock(self.t + timedelta(seconds=30)))
        mb.verify_account()
        return mb.observe(mid, context=context)

    def test_the_right_context_is_accepted_and_every_wrong_binding_is_rejected(self):
        ex, mid = self.intent_ready()
        row = dict(ce.get_execution(self.index, ACCT, ex["exec_id"]))
        good = ce._context(row, mid, "POSTREAD", row["lease_token"])
        variants = {"another execution": dict(row, exec_id="exec-deadbeef"), "another plan": dict(row, plan_id="plan-other"),
                    "another plan hash": dict(row, plan_hash="0" * 64), "another approval": dict(row, approval_nonce="n" * 32),
                    "another account": dict(row, account=OTHER)}
        for label, other in variants.items():
            with self.subTest(label):
                self.attempt(ex, mid, self.observe_with(ce._context(other, mid, "POSTREAD", row["lease_token"])))
        with self.subTest("another message"):
            self.attempt(ex, mid, self.observe_with(ce._context(row, HEX[1], "POSTREAD", row["lease_token"])))
        with self.subTest("another lease"):
            self.attempt(ex, mid, self.observe_with(ce._context(row, mid, "POSTREAD", ce.sha256("another-lease"))))
        with self.subTest("another phase"):
            self.attempt(ex, mid, self.observe_with(ce._context(row, mid, "RECONCILE", row["lease_token"])))
            self.attempt(ex, mid, self.observe_with(ce._context(row, mid, "PREFLIGHT", row["lease_token"])))
        with self.subTest("arbitrary text"):
            self.attempt(ex, mid, self.observe_with("c" * 32))
        obs = self.observe_with(good)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(self.item(mid)["state"], "APPLIED")

    def test_an_observation_made_for_one_execution_cannot_be_used_in_another(self):
        ex1 = self.execution()
        first = dict(ce.get_execution(self.index, ACCT, ex1["exec_id"]))
        ce.record_skip(self.index, ACCT, ex1["exec_id"], self.token, M0, "SKIPPED_DRIFT", "STATE_CHANGED", now=self.tick())
        ce.end_slice(self.index, ACCT, ex1["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex1["exec_id"]), "FAILED")
        ex2, mid = self.intent_ready((HEX[1],))
        stolen = self.observe_with(ce._context(first, mid, "POSTREAD", first["lease_token"]), mid)
        self.attempt(ex2, mid, stolen)

    def test_a_reconciliation_context_binds_to_the_unknown_episode(self):
        ex = self.execution()
        mb = self.mailbox([Step("POST", raises=TimeoutError(), apply=True)])
        self.run_one(ex, mb)
        mb.service.script.clear()
        mb.verify_account()
        wrong = mb.observe(M0, context=ce._context(dict(ce.get_execution(self.index, ACCT, ex["exec_id"])), M0, "RECONCILE", "2000-01-01T00:00:00.000000Z"))
        with self.assertRaises(ce.ExecError) as ctx:
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], M0, wrong, now=mb.clock(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.item()["state"], "UNKNOWN")
        self.assertTrue(ee.is_pending(wrong))
        self.reconcile_trusted(ex, mb)
        self.assertEqual(self.item()["state"], "APPLIED")

    def test_trusted_evidence_without_the_context_is_refused_by_construction(self):
        mb = self.mailbox()
        mb.verify_account()
        with self.assertRaises(TypeError):
            mb.observe(M0)
        for bad in (None, "", 5, b"x", "é", "x" * 129):
            with self.assertRaises(gw.WriteTransportError) as ctx:
                mb.observe(M0, context=bad)
            self.assertIs(ctx.exception.dispatched, False)
        self.assertEqual([k for k, _ in mb.service.log], ["PROFILE"])  # nothing was requested without a context

    def test_replay_and_revocation_of_a_bound_observation(self):
        ex, mid = self.intent_ready()
        row = dict(ce.get_execution(self.index, ACCT, ex["exec_id"]))
        good = ce._context(row, mid, "POSTREAD", row["lease_token"])
        mb = self.mailbox(state=self.fake_state({mid: (T0_, list(AFTER))}), clock=StepClock(self.t + timedelta(seconds=30)))
        mb.verify_account()
        revoked = mb.observe(mid, context=good)
        mb._adapter._verified = False  # verification lost: every unused observation dies
        self.attempt_revoked(ex, mid, revoked)
        mb.verify_account()
        fresh = mb.observe(mid, context=good)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=fresh, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertFalse(ee.is_pending(fresh))
        self.assertFalse(ee.consume(fresh))

    def attempt_revoked(self, ex, mid, obs):
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertFalse(ee.is_pending(obs))


# ====================================================================== C2-GATE-2: the executor owns its clock
class ClockTests(ExecutorBase):
    def test_the_executor_has_no_clock_or_time_parameter(self):
        params = set(inspect.signature(cx.execute_one).parameters)
        self.assertEqual(params, {"index", "account", "exec_id", "token", "message_id", "mailbox"})

    def test_every_recorded_time_comes_from_the_mailbox_clock(self):
        ex = self.execution()
        mb = self.mailbox()
        self.run_one(ex, mb)
        stamps = {ce._us(t) for t in self.step_clock.seen}
        row = self.item()
        self.assertIn(row["intent_at"], stamps)
        self.assertIn(row["result_at"], stamps)
        self.assertIn(row["evidence_observed_at"], stamps)
        self.assertGreater(len(self.step_clock.seen), 5)

    def test_no_production_factory_or_public_constructor_accepts_a_clock(self):
        self.assertNotIn("clock", inspect.signature(gw.open_archive_adapter).parameters)
        params = inspect.signature(gw.ArchiveAdapter.__init__).parameters
        self.assertEqual([n for n in params if "clock" in n], ["_clock"])
        self.assertEqual(params["_clock"].kind, inspect.Parameter.KEYWORD_ONLY)
        passers = []
        for path in (SRC / "gmail_intelligence").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and any(k.arg == "_clock" for k in node.keywords):
                    passers.append(path.name)
        self.assertEqual(sorted(passers), ["exec_fake_mailbox.py"])
        self.assertEqual([n for n in inspect.signature(fm.FakeMailbox.__init__).parameters], ["self", "account", "messages", "clock", "script"])


# ====================================================================== fake-only enforcement
class FakeOnlyTests(ExecutorBase):
    def untouched(self, ex, mailbox):
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, mailbox)
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual(self.snapshot(), before)

    def test_a_real_archive_adapter_is_refused_before_anything_is_read_or_written(self):
        ex = self.execution()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        real = TWT.adapter(net, expected=ACCT)
        self.untouched(ex, real)
        self.assertEqual((net.opened, net.log), (0, []))

    def test_arbitrary_look_alike_mailboxes_are_refused(self):
        ex = self.execution()
        good = self.mailbox()

        class Duck:
            account = ACCT
            clock = staticmethod(lambda: datetime.now(timezone.utc))

            def __getattr__(self, name):
                return lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be called"))

        class Impostor:
            __class__ = fm.FakeMailbox
        for other in (Duck(), Impostor(), mock.MagicMock(spec=fm.FakeMailbox), object(), None, "mailbox", good._adapter, good.service):
            self.untouched(ex, other)
        with self.assertRaises(TypeError):
            type("SubFake", (fm.FakeMailbox,), {})

    def test_the_fake_mailbox_cannot_be_given_credentials_a_factory_or_a_transport(self):
        for name in ("credentials", "creds", "connection_factory", "factory", "transport", "token", "store", "client_path"):
            with self.assertRaises(TypeError, msg=name):
                fm.FakeMailbox(ACCT, self.fake_state(), clock=self.clock(), **{name: object()})
        mb = self.mailbox()
        transport = mb._adapter._t
        self.assertIsNot(transport._factory, gw._default_connection)
        self.assertEqual(type(transport._factory).__name__, "_Factory")
        self.assertEqual(type(transport._creds).__name__, "_FakeCreds")

    def test_a_fake_mailbox_cannot_be_rewired_to_a_real_adapter_by_ordinary_assignment(self):
        ex = self.execution()
        mb = self.mailbox()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        real = TWT.adapter(net, expected=ACCT, verified=False)
        for name in ("_adapter", "_service", "_clock", "service", "anything"):
            with self.assertRaises(AttributeError, msg=name):
                setattr(mb, name, real if name == "_adapter" else object())
        with self.assertRaises(AttributeError):
            del mb._adapter
        before = self.snapshot()
        res = self.run_one(ex, mb)  # the untouched fake still works
        self.assertEqual(res.item_state, "APPLIED")
        self.assertEqual((net.opened, net.log), (0, []))
        self.assertNotEqual(before, self.snapshot())

    def test_a_swapped_inner_adapter_or_transport_is_detected_before_any_request(self):
        for label, swap in (("the adapter", lambda mb, net: object.__setattr__(mb, "_adapter", TWT.adapter(net, expected=ACCT, verified=False))),
                            ("the connection factory", lambda mb, net: setattr(mb._adapter._t, "_factory", net)),
                            ("the credentials", lambda mb, net: setattr(mb._adapter._t, "_creds", TWT.WCreds()))):
            with self.subTest(label):
                self.setUp()
                ex = self.execution()
                mb = self.mailbox()
                net = TWT.Net(TWT.ok(emailAddress=ACCT))
                swap(mb, net)
                self.assertFalse(fm.wiring_is_fake(mb))
                self.untouched(ex, mb)
                self.assertEqual((net.opened, net.log), (0, []))

    def test_a_rewiring_between_the_intent_and_the_post_makes_no_request(self):
        ex = self.execution()
        net = TWT.Net()
        mb = self.mailbox()
        real = ce.record_intent

        def intent_then_rewire(*a, **kw):
            real(*a, **kw)
            setattr(mb._adapter._t, "_factory", net)
        with mock.patch.object(ce, "record_intent", side_effect=intent_then_rewire):
            with self.assertRaises(ce.ExecError) as ctx:
                cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, M0, mb)
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual((net.opened, net.log, mb.service.posts()), (0, [], 0))
        self.assertEqual(self.item()["state"], "INTENT")  # left open: lease expiry makes it UNKNOWN for reconciliation

    def test_a_full_run_works_while_every_real_connection_path_is_a_bomb(self):
        ex = self.execution()
        mb = self.mailbox()
        boom = AssertionError("a real connection path was used")
        with mock.patch.object(gw, "_default_connection", side_effect=boom), mock.patch.object(http.client.HTTPSConnection, "__init__", side_effect=boom), \
                mock.patch("socket.create_connection", side_effect=boom), mock.patch("ssl.create_default_context", side_effect=boom):
            res = self.run_one(ex, mb)
        self.assertEqual(res.item_state, "APPLIED")

    def test_importing_the_executor_loads_no_oauth_keychain_or_cli_module(self):
        code = ("import sys; sys.path.insert(0, %r); import gmail_intelligence.cleanup_executor as x; "
                "bad = [m for m in sys.modules if m.startswith('gmail_intelligence.') and m.split('.')[-1] in "
                "('oauth', 'oauth_write', 'keystore', 'keystore_write', 'cli', 'gmail', 'scanner')]; "
                "print(sorted(bad)); print([m for m in sys.modules if m.startswith(('google', 'keyring', 'requests'))])") % str(SRC)
        out = subprocess.run([sys.executable, "-W", "ignore", "-c", code], capture_output=True, text=True, timeout=60).stdout.strip().splitlines()
        self.assertEqual(out, ["[]", "[]"])

    def test_the_executor_module_imports_only_local_state_modules_and_the_fake_mailbox(self):
        tree = ast.parse((SRC / "gmail_intelligence" / "cleanup_executor.py").read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("gmail_intelligence"):
                names |= {node.module.split(".")[-1]} if node.module != "gmail_intelligence" else {a.name for a in node.names}
            if isinstance(node, ast.Import):
                names |= {a.name for a in node.names}
        self.assertEqual(names, {"cleanup_exec", "cleanup_plans", "cleanup_protect", "cleanup_audit", "exec_fake_mailbox", "json"})  # json: stdlib, for the recorded previous labels

    def test_no_production_path_can_reach_the_executor(self):
        cli = (SRC / "gmail_intelligence" / "cli.py").read_text()
        for name in ("cleanup_executor", "exec_fake_mailbox", "execute_one", "FakeMailbox"):
            self.assertNotIn(name, cli)
        self.assertIn("execution is not available in this version", cli)
        importers = []
        for path in (SRC / "gmail_intelligence").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module or ""] + [a.name for a in node.names] if isinstance(node, ast.ImportFrom) else [])
                if any(m.split(".")[-1] in ("cleanup_executor", "exec_fake_mailbox") for m in mods):
                    importers.append(path.name)
        self.assertEqual(sorted(set(importers)), ["cleanup_executor.py", "cleanup_recovery.py", "cleanup_undo.py"])  # the fake-only library modules; never the CLI


if __name__ == "__main__":
    unittest.main()
