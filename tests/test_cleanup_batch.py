"""Tests for the fake-only batch executor (M4C-C2b): `execute_batch` over a multi-item approved execution.

Synthetic only: a synthetic account, the in-memory fake mailbox (real adapter code over a connection class that never touches a socket), a controlled step
clock and temporary SQLite databases. Nothing contacts Gmail.
"""
import json
import sqlite3
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_executor as TX  # noqa: E402
import test_write_transport as TWT  # noqa: E402
from test_cleanup import ACCT, OTHER, msg  # noqa: E402
from test_cleanup_executor import AFTER, HEX, LABELS, StepClock, THREADS  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_executor as cx, cleanup_plans as cp, cleanup_protect  # noqa: E402
from gmail_intelligence import exec_fake_mailbox as fm, gmail_write_policy as pol  # noqa: E402

Step = fm.Step
IDS = HEX[:4]


class Crash(BaseException):
    """Simulates the process dying: not an Exception, so nothing in the executor can swallow it."""


class BatchBase(TX.ExecutorBase):
    def batch_execution(self, ids=IDS):
        return self.execution(ids=tuple(ids))

    def run_batch(self, ex, mb, token=None):
        try:
            return cx.execute_batch(self.index, ACCT, ex["exec_id"], token or self.token, mb)
        finally:
            self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
            self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])
            # one POST attempt per item at most: never two POSTs for the same message
            keys = [k for kind, k in mb.service.log if kind == "POST"]
            self.assertEqual(len(keys), len(set(keys)))

    def states(self, ids=IDS):
        return [self.item(m)["state"] for m in ids]

    def codes(self, ids=IDS):
        return [self.item(m)["error_code"] for m in ids]

    def posted(self, mb):
        return [k for kind, k in mb.service.log if kind == "POST"]

    def later(self, mb=None):
        return self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=5)

    def recover(self, ex):
        later = self.later()
        self.assertEqual(ce.recover_interrupted(self.index, ACCT, now=later), [ex["exec_id"]])
        return later

    def fresh_mailbox_like(self, mb, later):
        return self.mailbox(state={m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}, clock=StepClock(later + timedelta(seconds=1)))


class SuccessAndOrderTests(BatchBase):
    def test_a_batch_archives_every_approved_item_in_the_plans_fixed_order(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        res = self.run_batch(ex, mb)
        self.assertEqual((res.slice_no, res.execution_state, res.posts, res.stopped), (1, "EXECUTED", 4, False))
        self.assertEqual([seq for seq, _ in res.items], [1, 2, 3, 4])
        self.assertEqual([r.item_state for _, r in res.items], ["APPLIED"] * 4)
        self.assertEqual(self.posted(mb), sorted(IDS))  # deterministic: the plan's sorted order
        self.assertEqual(self.states(), ["APPLIED"] * 4)
        for mid in IDS:
            self.assertEqual(mb.service.messages[mid][1], set(AFTER))
            self.assertEqual((self.item(mid)["evidence_checked"], self.item(mid)["evidence_source"]), (1, "TRUSTED_ADAPTER"))
        self.assertEqual(mb.service.messages[HEX[4]][1], set(LABELS))  # a message outside the approved plan is never touched
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTED")

    def test_the_order_does_not_depend_on_the_order_the_ids_were_given(self):
        ex = self.batch_execution(list(reversed(IDS)))
        mb = self.mailbox()
        self.run_batch(ex, mb)
        self.assertEqual(self.posted(mb), sorted(IDS))

    def test_each_intent_is_committed_before_that_items_post_and_later_items_are_still_pending(self):
        ex = self.batch_execution()
        seen = {}

        def capture(n):
            def hook(fake):
                seen[n] = (self.states(), [dict(self.index._q("SELECT prev_label_ids FROM cleanup_exec_item WHERE message_id=?", m)[0])["prev_label_ids"] is not None for m in IDS])
            return hook
        mb = self.mailbox([Step("POST", nth=n, before=capture(n)) for n in (1, 2, 3, 4)])
        self.run_batch(ex, mb)
        self.assertEqual(seen[1][0], ["INTENT", "PENDING", "PENDING", "PENDING"])
        self.assertEqual(seen[3][0], ["APPLIED", "APPLIED", "INTENT", "PENDING"])
        self.assertEqual(seen[4][0], ["APPLIED", "APPLIED", "APPLIED", "INTENT"])
        self.assertEqual(seen[2][1], [True, True, False, False])

    def test_only_the_four_allowed_request_families_are_made_and_the_account_is_verified_once(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        self.run_batch(ex, mb)
        kinds = [k for k, _ in mb.service.log]
        self.assertEqual(set(kinds), {"PROFILE", "GET_MESSAGE", "GET_THREAD", "POST"})
        self.assertEqual(kinds.count("PROFILE"), 1)
        self.assertEqual(len(pol._ROUTES), 4)

    def test_a_batch_that_is_run_again_never_posts_again(self):
        ex = self.batch_execution()
        first = self.mailbox()
        self.run_batch(ex, first)
        again = self.mailbox()
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, again)
        self.assertEqual(ctx.exception.code, "BAD_STATE")
        self.assertEqual((len(self.posted(first)), len(self.posted(again))), (4, 0))


class SkipTests(BatchBase):
    def test_a_drifted_item_is_skipped_and_the_batch_goes_on(self):
        ex = self.batch_execution()
        mb = self.mailbox([Step("GET_MESSAGE", nth=3, before=lambda f: f.set_labels(sorted(IDS)[1], list(LABELS) + ["STARRED"]))])  # item 2's preflight read
        res = self.run_batch(ex, mb)
        self.assertEqual(self.states(), ["APPLIED", "SKIPPED_DRIFT", "APPLIED", "APPLIED"])
        self.assertEqual((res.execution_state, res.posts, res.stopped), ("EXECUTED", 3, False))
        self.assertEqual(self.item(IDS[1])["error_code"], "LABELS_CHANGED")
        self.assertEqual(mb.service.messages[IDS[1]][1], set(LABELS) | {"STARRED"})  # the drifted message is left exactly as it was

    def test_a_vanished_message_and_an_unknown_sibling_are_skipped(self):
        ex = self.batch_execution()
        mb = self.mailbox([Step("GET_MESSAGE", nth=3, before=lambda f: f.remove_message(IDS[1])),
                           Step("GET_THREAD", nth=2, before=lambda f: f.add_message(HEX[6], THREADS[2], ["INBOX"]))])
        self.run_batch(ex, mb)
        self.assertEqual(self.states(), ["APPLIED", "SKIPPED_GONE", "SKIPPED_DRIFT", "APPLIED"])
        self.assertEqual(self.codes(), ["APPLIED", "NOT_FOUND", "THREAD_CHANGED", "APPLIED"])

    def test_a_local_change_after_approval_skips_every_item_and_nothing_is_posted(self):
        ex = self.batch_execution()
        cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")  # the plan is stale for all of its items
        mb = self.mailbox()
        res = self.run_batch(ex, mb)
        self.assertEqual(self.states(), ["SKIPPED_DRIFT"] * 4)
        self.assertEqual((res.posts, self.posted(mb), res.execution_state), (0, [], "FAILED"))

    def test_when_every_item_is_skipped_nothing_is_applied_and_the_execution_fails(self):
        ex = self.batch_execution()
        mb = self.mailbox([Step("GET_MESSAGE", nth=n, before=lambda f: [f.set_labels(m, list(LABELS) + ["STARRED"]) for m in IDS]) for n in (1,)])
        res = self.run_batch(ex, mb)
        self.assertEqual(self.states(), ["SKIPPED_DRIFT"] * 4)
        self.assertEqual(res.execution_state, "FAILED")  # nothing was applied: the existing rule ends the execution


class SameThreadTests(BatchBase):
    """Two approved messages in ONE thread (plus an unapproved third message in it): earlier archived changes made by this execution are legitimate."""
    A, B, C = HEX[0], HEX[1], HEX[5]  # A and B are approved; C shares the thread but is not part of the plan
    TID = THREADS[0]

    def messages(self):
        base = [dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(3, 6)]
        thread = [dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[j], thread_id=self.TID) for i, j in ((1, 0), (2, 1), (6, 5))]
        return thread + base

    def state(self, c_labels=LABELS):
        st = {HEX[i]: (THREADS[i], list(LABELS)) for i in range(2, 5)}
        st[self.A], st[self.B], st[self.C] = (self.TID, list(LABELS)), (self.TID, list(LABELS)), (self.TID, list(c_labels))
        return st

    def start(self, script=(), c_labels=LABELS, ids=None):
        ex = self.execution(ids=tuple(ids or (self.A, self.B)))
        return ex, fm.FakeMailbox(ACCT, self.state(c_labels), clock=self.clock(), script=script)

    def test_a_later_item_is_not_skipped_because_an_earlier_item_of_the_same_batch_was_archived(self):
        ex, mb = self.start()
        res = self.run_batch(ex, mb)
        self.assertEqual([r.item_state for _, r in res.items], ["APPLIED", "APPLIED"])
        self.assertEqual((res.execution_state, res.posts), ("EXECUTED", 2))
        self.assertEqual(mb.service.messages[self.C][1], set(LABELS))  # the unapproved sibling is never touched

    def test_the_exemption_is_exact_it_covers_only_inbox_removal_by_this_execution(self):
        cases = (("an unapproved sibling changed", [Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.C, list(AFTER)))]),
                 ("an unapproved sibling gained a label", [Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.C, list(LABELS) + ["STARRED"]))]),
                 ("the archived sibling gained a label afterwards", [Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.A, list(AFTER) + ["STARRED"]))]),
                 ("the archived sibling returned to the inbox", [Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.A, list(LABELS)))]),  # not its recorded state
                 ("the archived sibling lost a label other than INBOX", [Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.A, []))]),
                 ("a new message joined the thread", [Step("GET_THREAD", nth=2, before=lambda f: f.add_message(HEX[6], self.TID, ["INBOX"]))]))
        for label, script in cases:
            with self.subTest(label):
                self.setUp()
                ex, mb = self.start(script)
                res = self.run_batch(ex, mb)
                self.assertEqual([r.item_state for _, r in res.items], ["APPLIED", "SKIPPED_DRIFT"], label)
                self.assertEqual(self.item(self.B)["error_code"], "THREAD_CHANGED")
                self.assertEqual(len(self.posted(mb)), 1)

    def test_a_sibling_that_was_not_archived_by_this_execution_is_never_exempt(self):
        # the approved sibling was skipped (not APPLIED): any change to it is still drift for the next item
        ex, mb = self.start([Step("GET_MESSAGE", nth=1, before=lambda f: f.set_labels(self.A, list(LABELS) + ["STARRED"]))])
        res = self.run_batch(ex, mb)
        self.assertEqual([r.item_state for _, r in res.items], ["SKIPPED_DRIFT", "SKIPPED_DRIFT"])
        self.assertEqual(self.posted(mb), [])

    def test_a_protected_label_on_an_archived_sibling_is_not_ignored(self):
        ex, mb = self.start([Step("GET_THREAD", nth=2, before=lambda f: f.set_labels(self.A, list(AFTER) + ["STARRED"]))])
        res = self.run_batch(ex, mb)
        self.assertEqual([r.item_state for _, r in res.items], ["APPLIED", "SKIPPED_DRIFT"])
        # and directly: even an archived sibling in its exact recorded state is refused if its labels include a protected one
        cleanup_protect.add(self.index, ACCT, label="CATEGORY_PROMOTIONS")
        thread = ((self.A, tuple(AFTER)), (self.B, tuple(LABELS)), (self.C, tuple(LABELS)))
        self.assertEqual(cx._thread_problem(self.index, ACCT, self.B, self.TID, thread, {self.A: set(AFTER)}), "THREAD_CHANGED")


class StopTests(BatchBase):
    def test_partial_success_followed_by_an_unknown_post_stops_the_batch_and_reconciles_later(self):
        ex = self.batch_execution()
        mb = self.mailbox([Step("POST", nth=3, raises=TimeoutError(), apply=True)])
        res = self.run_batch(ex, mb)
        self.assertEqual(self.states(), ["APPLIED", "APPLIED", "UNKNOWN", "NOT_APPLIED"])
        self.assertEqual(self.codes()[2:], ["TIMEOUT", "NEVER_ATTEMPTED"])
        self.assertEqual((res.execution_state, res.posts, res.stopped), ("RECONCILIATION_REQUIRED", 3, True))
        self.assertEqual(len(self.posted(mb)), 3)  # the fourth item was never attempted
        with self.assertRaises(ce.ExecError) as ctx:  # no further batch while the execution needs reconciliation
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual(ctx.exception.code, "BAD_STATE")
        self.reconcile_trusted(ex, mb, IDS[2])
        self.assertEqual(self.item(IDS[2])["state"], "APPLIED")
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        self.assertEqual(len(self.posted(mb)), 3)

    def test_each_kind_of_failure_stops_where_it_happens_and_never_touches_later_items(self):
        wrong_profile = json.dumps({"emailAddress": OTHER}).encode()
        cases = (("read timeout on item 3's thread", Step("GET_THREAD", nth=3, raises=TimeoutError()), ["APPLIED", "APPLIED", "NOT_APPLIED", "NOT_APPLIED"], 2),
                 ("credentials stop working before item 2's post", Step("GET_THREAD", nth=2, after=lambda f: setattr(f.creds, "live", False)),
                  ["APPLIED", "NOT_APPLIED", "NOT_APPLIED", "NOT_APPLIED"], 1),
                 ("rate limit on item 2's post", Step("POST", nth=2, status=429, body=TX.gerr(429)[1]), ["APPLIED", "UNKNOWN", "NOT_APPLIED", "NOT_APPLIED"], 2),
                 ("an erroring answer on item 1's post", Step("POST", nth=1, status=503, body=b"x"), ["UNKNOWN", "NOT_APPLIED", "NOT_APPLIED", "NOT_APPLIED"], 1))
        for label, step, states, posts in cases:
            with self.subTest(label):
                self.setUp()
                ex = self.batch_execution()
                mb = self.mailbox([step])
                res = self.run_batch(ex, mb)
                self.assertEqual(self.states(), states)
                self.assertEqual((res.posts, len(self.posted(mb)), res.stopped), (posts, posts, True))

    def test_an_account_that_changes_is_caught_before_the_first_item_and_nothing_is_attempted(self):
        wrong = json.dumps({"emailAddress": OTHER}).encode()
        ex = self.batch_execution()
        mb = self.mailbox([Step("PROFILE", status=200, body=wrong)])
        res = self.run_batch(ex, mb)
        self.assertEqual((self.states(), res.posts, res.execution_state), (["NOT_APPLIED"] * 4, 0, "FAILED"))
        self.setUp()
        ex = self.batch_execution()
        res = self.run_batch(ex, self.mailbox(account=OTHER))
        self.assertEqual((self.states(), res.posts), (["NOT_APPLIED"] * 4, 0))

    def test_the_request_budget_running_out_stops_the_batch_without_an_unsafe_post(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        mb._adapter._t._sent = pol.MAX_REQUESTS - 7  # profile + two full items fit, the third item runs out of budget
        res = self.run_batch(ex, mb)
        self.assertEqual(res.stopped, True)
        self.assertLessEqual(len(self.posted(mb)), 2)
        self.assertNotIn("INTENT", self.states())
        self.assertEqual(self.states().count("APPLIED"), len(self.posted(mb)))


class SafetyTests(BatchBase):
    def test_a_batch_refuses_to_start_while_an_item_is_intent_or_unknown(self):
        ex = self.batch_execution()
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, IDS[0], LABELS, now=self.tick())
        mb = self.mailbox()
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual((ctx.exception.code, self.snapshot(), mb.service.log), ("OPEN_UNCERTAIN_ITEM", before, []))

    def test_wrong_expired_or_lost_leases_and_integrity_failures_change_nothing(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        before = self.snapshot()
        for token in ("x" * 40, "short"):
            with self.assertRaises(ce.ExecError):
                cx.execute_batch(self.index, ACCT, ex["exec_id"], token, mb)
        late = self.mailbox(clock=StepClock(self.t + ce.LEASE_TTL + timedelta(seconds=30)))
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, late)
        self.assertEqual(ctx.exception.code, "LEASE_LOST")
        with mock.patch.object(cp, "integrity_problems", return_value=["PLAN_HASH_MISMATCH"]):
            with self.assertRaises(ce.ExecError) as ctx:
                cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual(ctx.exception.code, "PLAN_CHANGED")
        self.assertEqual((self.snapshot(), mb.service.log, late.service.log), (before, [], []))

    def test_a_plan_integrity_failure_between_items_stops_after_the_items_already_done(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        real, calls = cp.integrity_problems, []

        def flaky(plan):
            calls.append(1)
            return ["PLAN_HASH_MISMATCH"] if len(calls) >= 3 else real(plan)  # two checks per item (preconditions, revalidation): the third call is item 2's
        with mock.patch.object(cp, "integrity_problems", side_effect=flaky):
            with self.assertRaises(ce.ExecError) as ctx:
                cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual(ctx.exception.code, "PLAN_CHANGED")
        self.assertEqual((self.states(), len(self.posted(mb))), (["APPLIED", "PENDING", "PENDING", "PENDING"], 1))

    def test_a_lease_lost_between_items_leaves_the_rest_pending_and_recovery_never_resumes(self):
        ex = self.batch_execution()
        mb = self.mailbox()
        real, calls = ce.renew_lease, []

        def flaky(*a, **kw):
            calls.append(1)
            if len(calls) == 3:  # the first renewal of the second item
                raise ce.ExecError("LEASE_LOST", "this process does not hold a live execution lease; stop")
            return real(*a, **kw)
        with mock.patch.object(ce, "renew_lease", side_effect=flaky):
            with self.assertRaises(ce.ExecError):
                cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual((self.states(), len(self.posted(mb))), (["APPLIED", "PENDING", "PENDING", "PENDING"], 1))
        self.recover(ex)
        self.assertEqual(self.states(), ["APPLIED", "NOT_APPLIED", "NOT_APPLIED", "NOT_APPLIED"])
        self.assertEqual(self.codes()[1:], ["NEVER_ATTEMPTED"] * 3)
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        self.assertEqual(len(self.posted(mb)), 1)

    def test_two_executors_racing_on_one_batch_never_post_the_same_item_twice(self):
        ex = self.batch_execution()
        second = self.mailbox()
        out = []
        first = self.mailbox([Step("GET_THREAD", nth=1, after=lambda f: out.append(cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, second)))])
        with self.assertRaises(ce.ExecError):
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, first)  # its first intent finds the item already taken
        self.assertEqual((len(self.posted(first)), len(self.posted(second))), (0, 4))
        self.assertEqual(out[0].execution_state, "EXECUTED")
        self.assertEqual(self.states(), ["APPLIED"] * 4)

    def test_a_database_failure_before_or_after_an_intent_never_causes_a_second_post(self):
        for patched, expected in (("record_intent", ["APPLIED", "PENDING", "PENDING", "PENDING"]), ("record_outcome", ["APPLIED", "INTENT", "PENDING", "PENDING"])):
            with self.subTest(patched):
                self.setUp()
                ex = self.batch_execution()
                mb = self.mailbox()
                real, calls = getattr(ce, patched), []

                def flaky(*a, _real=real, **kw):
                    calls.append(1)
                    if len(calls) == 2:
                        raise sqlite3.OperationalError("disk I/O error")
                    return _real(*a, **kw)
                with mock.patch.object(ce, patched, side_effect=flaky):
                    with self.assertRaises(sqlite3.OperationalError):
                        cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
                self.assertEqual(self.states(), expected)
                self.assertEqual(len(self.posted(mb)), 1 if patched == "record_intent" else 2)
                self.recover(ex)
                self.assertEqual(self.states()[1], "NOT_APPLIED" if patched == "record_intent" else "UNKNOWN")
                self.assertEqual(self.states()[2:], ["NOT_APPLIED", "NOT_APPLIED"])
                self.assertEqual(len(self.posted(mb)), 1 if patched == "record_intent" else 2)  # recovery never posts
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_a_crash_at_an_item_boundary_or_during_a_post_is_recovered_without_any_retry(self):
        cases = (("between items", None), ("during the second post (not applied)", Step("POST", nth=2, raises=Crash(), apply=False)),
                 ("during the second post (applied)", Step("POST", nth=2, raises=Crash(), apply=True)))
        for label, step in cases:
            with self.subTest(label):
                self.setUp()
                ex = self.batch_execution()
                mb = self.mailbox([step] if step else [])
                real, calls = ce.renew_lease, []

                def crash_at_third(*a, **kw):
                    calls.append(1)
                    if len(calls) == 3:
                        raise Crash()
                    return real(*a, **kw)
                patch = mock.patch.object(ce, "renew_lease", side_effect=crash_at_third) if step is None else mock.patch.object(ce, "renew_lease", wraps=real)
                with patch:
                    with self.assertRaises(Crash):
                        cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
                posts_before = len(self.posted(mb))
                later = self.recover(ex)
                if step is None:
                    self.assertEqual(self.states(), ["APPLIED", "NOT_APPLIED", "NOT_APPLIED", "NOT_APPLIED"])
                else:
                    self.assertEqual(self.states(), ["APPLIED", "UNKNOWN", "NOT_APPLIED", "NOT_APPLIED"])
                    self.assertEqual(self.item(IDS[1])["error_code"], "INTERRUPTED")
                    self.reconcile_trusted(ex, self.fresh_mailbox_like(mb, later), IDS[1])
                    self.assertEqual(self.item(IDS[1])["state"], "APPLIED" if step.apply else "NOT_APPLIED")
                self.assertEqual(len(self.posted(mb)), posts_before)  # no retry of anything
                with self.assertRaises(ce.ExecError):
                    cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, self.mailbox())


class FakeOnlyAndBindingTests(BatchBase):
    def test_real_adapters_and_look_alikes_are_refused_and_a_rewiring_between_items_stops_before_any_request(self):
        ex = self.batch_execution()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        for other in (TWT.adapter(net, expected=ACCT), mock.MagicMock(spec=fm.FakeMailbox), object(), None):
            before = self.snapshot()
            with self.assertRaises(ce.ExecError) as ctx:
                cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, other)
            self.assertEqual((ctx.exception.code, self.snapshot()), ("MAILBOX_NOT_ALLOWED", before))
        self.assertEqual((net.opened, net.log), (0, []))
        mb = self.mailbox([Step("GET_MESSAGE", nth=2, after=lambda f: setattr(mb._adapter._t, "_factory", net))])  # after item 1's post-read
        with self.assertRaises(ce.ExecError) as ctx:
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual((net.opened, net.log), (0, []))
        self.assertEqual(self.states(), ["APPLIED", "PENDING", "PENDING", "PENDING"])

    def test_an_observation_for_one_item_is_rejected_for_another_item(self):
        ex = self.batch_execution()
        for mid in IDS[:2]:
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, LABELS, now=self.tick())
        mb = self.mailbox(state=self.fake_state({m: (THREADS[HEX.index(m)], list(AFTER)) for m in IDS}), clock=StepClock(self.t + timedelta(seconds=30)))
        mb.verify_account()
        ctx_item1 = ce.postread_context(self.index, ACCT, ex["exec_id"], self.token, IDS[0])
        ctx_item2 = ce.postread_context(self.index, ACCT, ex["exec_id"], self.token, IDS[1])
        self.assertNotEqual(ctx_item1, ctx_item2)
        wrong = mb.observe(IDS[1], context=ctx_item1)  # item 2's message, item 1's context
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, IDS[1], "APPLIED", evidence=wrong, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        right = mb.observe(IDS[1], context=ctx_item2)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, IDS[1], "APPLIED", evidence=right, now=self.tick(), require_source="TRUSTED_ADAPTER")

    def test_the_batch_has_no_clock_parameter_and_is_not_reachable_from_the_cli(self):
        import inspect
        self.assertEqual(list(inspect.signature(cx.execute_batch).parameters), ["index", "account", "exec_id", "token", "mailbox"])
        cli = (ROOT / "src" / "gmail_intelligence" / "cli.py").read_text()
        for name in ("execute_batch", "cleanup_executor", "exec_fake_mailbox", "FakeMailbox"):
            self.assertNotIn(name, cli)
        self.assertIn("execution is not available in this version", cli)


class SliceProgressionTests(BatchBase):
    N = 101  # more than one slice: a canary of 25 and then the rest

    def messages(self):
        return [dict(msg(i, sender=f"s{i}@shop.example.test"), id=f"18c0ffee{i:08x}", thread_id=f"28c0ffee{i:08x}") for i in range(1, self.N + 1)]

    def test_a_batch_runs_one_slice_and_the_next_needs_the_owners_confirmation_and_a_new_lease(self):
        ids = [f"18c0ffee{i:08x}" for i in range(1, self.N + 1)]
        state = {m: (f"28c0ffee{m[-8:]}", list(LABELS)) for m in ids}
        plan = self.approved_plan(ids)
        ex = self.reserve(plan)
        first_token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        mb = fm.FakeMailbox(ACCT, state, clock=self.clock(), script=())
        res = cx.execute_batch(self.index, ACCT, ex["exec_id"], first_token, mb)
        self.assertEqual((res.slice_no, len(res.items), res.posts, res.execution_state, res.stopped), (1, 25, 25, "AWAITING_CONTINUATION", False))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE state='APPLIED'")[0][0], 25)
        with self.assertRaises(ce.ExecError):  # no continuation without the typed confirmation and a new lease
            cx.execute_batch(self.index, ACCT, ex["exec_id"], first_token, mb)
        later = self.step_clock.at + timedelta(seconds=5)
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(cp.get_plan(self.index, ACCT, plan["plan_id"]), 2, 76), now=later)
        second_token = ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=later + timedelta(seconds=1))
        self.assertNotEqual(first_token, second_token)
        with self.assertRaises(ce.ExecError) as ctx:  # the old lease no longer authorizes anything
            cx.execute_batch(self.index, ACCT, ex["exec_id"], first_token, fm.FakeMailbox(ACCT, state, clock=StepClock(later + timedelta(seconds=2))))
        self.assertEqual(ctx.exception.code, "LEASE_LOST")
        res2 = cx.execute_batch(self.index, ACCT, ex["exec_id"], second_token, fm.FakeMailbox(ACCT, {m: (t, list(l) if m in ids[25:] else list(AFTER)) for m, (t, l) in state.items()},
                                                                                              clock=StepClock(later + timedelta(seconds=3))))
        self.assertEqual((res2.slice_no, len(res2.items), res2.posts, res2.execution_state), (2, 76, 76, "EXECUTED"))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE state='APPLIED'")[0][0], 101)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


if __name__ == "__main__":
    unittest.main()
