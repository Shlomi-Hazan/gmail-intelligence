"""Offline tests for the narrow canary exception, the canary-only restriction of live execution and the owner-operated entry point.

Synthetic only: synthetic accounts and messages, temporary SQLite, the in-memory fake wire (the genuine adapter's default connection is replaced by it), a recording credential
store with fake write credentials, controlled step clocks, and the live switch flipped only by a patch inside a test. Nothing contacts Gmail.
"""
import ast
import json
import sqlite3
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_canary as TC  # noqa: E402
from test_cleanup import ACCT, OTHER, msg  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_executor import HEX, THREADS  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_candidates as cand, cleanup_canary as cc, cleanup_canary_cli as cli, cleanup_exec as ce  # noqa: E402
from gmail_intelligence import cleanup_executor as cx, cleanup_plans as cp, cleanup_protect, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

Step = fm.Step
CM = HEX[0]  # the canary message
ONLY = ("INBOX",)  # a fresh message with no other label: after the archive it has NO labels at all
SENDER = "tester@canary.example.test"


class ExceptionBase(TC.CanaryBase):
    canary_labels = ONLY
    canary_days = 0
    canary_extra = {}
    fresh_twin = False  # a SECOND fresh, unclassified-type message that the exception must never cover

    def messages(self):
        first = dict(msg(1, days=self.canary_days, sender=SENDER, labels=self.canary_labels), id=CM, thread_id=THREADS[0], **self.canary_extra)
        twin = [dict(msg(7, days=0, sender="twin@canary.example.test", labels=ONLY), id=HEX[6], thread_id=THREADS[6])] if self.fresh_twin else []
        return [first] + [dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(2, 6)] + twin

    def fake_state(self, extra=None):
        state = super().fake_state(extra)
        state[CM] = (THREADS[0], list(self.canary_labels))
        return state

    def switch_on(self):
        """The live switch on for this test, a controlled clock under it, and the adapter's default connection replaced by the in-memory fake wire."""
        self.enable()
        self.svc = fm._Service(ACCT, self.fake_state(), ())
        patcher = mock.patch.object(gw, "_default_connection", fm._Factory(self.svc))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = TC.RecordingStore(self.blob())

    def canary_plan(self, message_id=CM):
        return cc.create_canary_plan(self.index, ACCT, message_id, cc.canary_plan_phrase(ACCT, message_id))

    def approved_canary(self):
        plan = self.canary_plan()
        self.t = max(self.t, self.clk.at)
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
        return cp.get_plan(self.index, ACCT, plan["plan_id"])

    def started_canary(self):
        plan = self.approved_canary()
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.clk.at = self.t + timedelta(seconds=1)
        return ce.get_execution(self.index, ACCT, ex["exec_id"])


class DisabledTests(ExceptionBase):
    def clock_only(self):
        """A controlled clock, and NOTHING else: the live switch stays off, no wire, no credentials."""
        self.clk = self.step_clock = TC.TL.LazyStepClock(self)
        for target, name in ((live, "_utcnow"), (gw, "_utcnow")):
            patcher = mock.patch.object(target, name, self.clk)
            patcher.start()
            self.addCleanup(patcher.stop)

    def forbid_everything_live(self):
        """Any attempt to reach credentials, OAuth, the network or the archive path fails the test."""
        boom = AssertionError("a live resource was reached while preparing locally")
        from gmail_intelligence import keystore_write, oauth_write
        for target, name in ((keystore_write, "WriteTokenStore"), (gw, "_default_connection"), (gw, "open_archive_adapter"), (oauth_write, "refresh_write_credentials"),
                             (live, "open_live_mailbox"), (cc, "run_canary")):
            patcher = mock.patch.object(target, name, side_effect=boom)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, argv, typed=()):
        said, inputs = [], list(typed)
        code = cli.main(argv, input_fn=lambda _: inputs.pop(0), out=said.append, store_factory=lambda: self.fail("a credential store was created"))
        return code, "\n".join(said)

    def test_run_is_refused_while_disabled_before_the_index_a_reservation_or_any_credential_store(self):
        self.assertIs(live.LIVE_EXECUTION_ENABLED, False)
        with mock.patch.object(idx, "Index", side_effect=AssertionError("the index was opened")), mock.patch.object(ce, "reserve_execution", side_effect=AssertionError("reserved")), \
                mock.patch.object(ce, "start_slice", side_effect=AssertionError("started")):
            code, text = self.run_cli(["run", "--account", ACCT, "--plan-id", "plan-1"])
        self.assertEqual(code, 2)
        self.assertIn("disabled", text)
        self.assertEqual((self.count("cleanup_plan"), self.count("cleanup_execution")), (0, 0))
        with self.assertRaises(ce.ExecError) as ctx:  # the library entry point refuses first as well
            cc.run_canary(TC.BombIndex(), ACCT, "exec-00000000", "t" * 40, "x", TC.RecordingStore(self.blob()), self.tmp / "none.json")
        self.assertEqual(ctx.exception.code, "LIVE_DISABLED")
        with self.assertRaises(SystemExit):  # arguments are validated first (pure string handling), then nothing runs
            with mock.patch("sys.stderr"):
                cli.main(["not", "valid"], out=lambda _: None)

    def test_describe_and_plan_work_while_live_execution_is_disabled_and_touch_nothing_live(self):
        self.assertIs(live.LIVE_EXECUTION_ENABLED, False)
        self.clock_only()
        self.forbid_everything_live()
        code, text = self.run_cli(["describe", "--account", ACCT, "--message-id", CM])
        self.assertEqual(code, 0)
        self.assertIn("canary: ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION", text)
        code, text = self.run_cli(["plan", "--account", ACCT, "--message-id", CM], ["wrong"])
        self.assertEqual((code, self.count("cleanup_plan")), (1, 0))  # the typed phrase is still required
        code, text = self.run_cli(["plan", "--account", ACCT, "--message-id", CM], [cc.canary_plan_phrase(ACCT, CM)])
        self.assertEqual((code, self.count("cleanup_plan")), (0, 1))
        plan = cp.get_plan(self.index, ACCT, self.index._q("SELECT plan_id FROM cleanup_plan")[0][0])
        self.assertIs(cp.snapshot_of(plan)["policy"]["canary_exception"], True)
        self.t = max(self.t, self.clk.at)  # review and approval use the ordinary commands and keep every approval requirement
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        with self.assertRaises(cp.PlanError):
            cp.approve(self.index, ACCT, plan["plan_id"], "wrong phrase", now=self.tick())
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "APPROVED")
        self.assertEqual(self.count("cleanup_execution"), 0)  # preparing never reserves or executes anything
        # and the prepared plan still cannot run live while the switch is off
        code, text = self.run_cli(["run", "--account", ACCT, "--plan-id", plan["plan_id"]])
        self.assertEqual((code, self.count("cleanup_execution")), (2, 0))

    def test_preparation_keeps_every_protection_while_disabled(self):
        self.canary_labels = ("INBOX", "SENT")
        self.setUp()
        self.clock_only()
        self.forbid_everything_live()
        code, text = self.run_cli(["describe", "--account", ACCT, "--message-id", CM])
        self.assertIn("SENT", text)
        self.assertIn("will NOT apply", text)
        with self.assertRaises(cp.PlanError) as ctx:
            cc.create_canary_plan(self.index, ACCT, CM, cc.canary_plan_phrase(ACCT, CM))
        self.assertEqual(ctx.exception.code, "CANARY_SELF_SENT")
        self.assertEqual(self.count("cleanup_plan"), 0)
        self.canary_labels = ONLY

    def test_the_entry_point_itself_makes_no_gmail_call_and_no_archive_of_its_own(self):
        tree = ast.parse((SRC / "cleanup_canary_cli.py").read_text())
        called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        for forbidden in ("archive_message", "verify_account", "message_state", "thread_state", "observe", "open_archive_adapter", "open_live_mailbox", "execute_live_batch",
                          "record_intent", "record_outcome", "restore_inbox", "refresh_write_credentials"):
            self.assertNotIn(forbidden, called)
        self.assertIn("run_canary", called)  # the only way it reaches a live mailbox

    def test_nothing_in_the_canary_code_reads_the_environment_or_enables_the_switch(self):
        for name in ("cleanup_canary.py", "cleanup_canary_cli.py"):
            tree = ast.parse((SRC / name).read_text())
            names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertEqual(names & {"environ", "getenv", "putenv"}, set(), name)
        cli_text = (SRC / "cli.py").read_text()
        for word in ("canary", "cleanup_canary", "CANARY"):
            self.assertNotIn(word, cli_text)


class ExceptionPolicyTests(ExceptionBase):
    def test_the_ordinary_policy_is_unchanged_and_the_exception_judges_one_message_only(self):
        self.switch_on()
        before = [(d.message_id, d.outcome, d.codes) for d in cand.evaluate_all(self.index, ACCT, now_ms=cp._ms(live._utcnow())).decisions]
        v = cc.describe_candidate(self.index, ACCT, CM)
        self.assertEqual(v["ordinary"]["outcome"], cand.EXCLUDED)
        self.assertIn("TOO_RECENT", v["ordinary"]["reasons"])
        self.assertEqual((v["canary"]["outcome"], v["canary"]["reasons"], v["self_sent"]), (cand.ELIGIBLE, (), False))
        after = [(d.message_id, d.outcome, d.codes) for d in cand.evaluate_all(self.index, ACCT, now_ms=cp._ms(live._utcnow())).decisions]
        self.assertEqual(before, after)  # describing changed nothing and the ordinary evaluation never sees an exception
        for other in HEX[1:5]:
            self.assertEqual(cc.describe_candidate(self.index, ACCT, other)["ordinary"], cc.describe_candidate(self.index, ACCT, other)["canary"])  # other messages: no waiver
        with self.assertRaises(cp.PlanError) as ctx:
            cp.create_plan(self.index, ACCT, [CM], now=live._utcnow())
        self.assertEqual(ctx.exception.code, "NOT_ELIGIBLE")
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, [CM], min_age_days=1, now=live._utcnow())
        with self.assertRaises(ValueError):
            cand.evaluate_all(self.index, ACCT, min_age_days=1, canary_ids=frozenset({CM}))
        self.assertEqual(self.count("cleanup_plan"), 0)

    def test_the_exception_never_covers_any_other_message_even_an_identical_one(self):
        self.fresh_twin = True
        self.setUp()
        self.switch_on()
        twin = HEX[6]
        now_ms = cp._ms(live._utcnow())
        by_id = {d.message_id: d for d in cand.evaluate_all(self.index, ACCT, now_ms=now_ms, canary_ids=frozenset({CM})).decisions}
        self.assertEqual(by_id[CM].outcome, cand.ELIGIBLE)
        self.assertEqual(by_id[twin].outcome, cand.EXCLUDED)  # same age, labels and classification as the canary message: still refused
        self.assertIn("TOO_RECENT", by_id[twin].codes)
        plan = self.canary_plan()
        self.assertEqual([i["message_id"] for i in plan["items"]], [CM])
        self.assertEqual(cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, plan["plan_id"]), live._utcnow()), {})
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, [twin], now=live._utcnow())
        with self.assertRaises(cp.PlanError) as ctx:  # an ordinary plan with both is refused as a whole: nothing is trimmed or widened
            cp.create_plan(self.index, ACCT, [CM, twin], now=live._utcnow())
        self.assertEqual(ctx.exception.code, "NOT_ELIGIBLE")
        self.fresh_twin = False

    def test_the_canary_plan_covers_exactly_one_message_and_carries_the_marker(self):
        self.switch_on()
        plan = self.canary_plan()
        snap = cp.snapshot_of(plan)
        self.assertEqual((plan["item_count"], plan["state"], plan["version"], [i["id"] for i in snap["items"]]), (1, "DRAFT", 1, [CM]))
        self.assertIs(snap["policy"]["canary_exception"], True)
        self.assertEqual(cp.integrity_problems(plan), [])
        created = json.loads(self.index._q("SELECT meta FROM cleanup_audit WHERE event_type='PLAN_CREATED'")[0][0])
        self.assertEqual(created["canary_exception"], 1)
        ordinary = self.approved_plan([HEX[1]])
        self.assertNotIn("canary_exception", cp.snapshot_of(ordinary)["policy"])  # ordinary snapshots are unchanged
        for bad in ([CM, HEX[1]], [], None, "", 5):
            with self.assertRaises((cp.PlanError, TypeError)):
                cc.create_canary_plan(self.index, ACCT, bad, "x")
        with self.assertRaises(cp.PlanError) as ctx:  # the internal builder refuses two targets and revisions
            with cp._txn(self.index):
                cp._insert_plan(self.index, ACCT, [CM, HEX[1]], 90, live._utcnow(), canary=True)
        self.assertEqual(ctx.exception.code, "BAD_INPUT")
        with self.assertRaises(cp.PlanError):  # a one-message plan cannot be "revised" into anything else
            cp.revise_exclude(self.index, ACCT, plan["plan_id"], [CM], now=live._utcnow())

    def test_the_separate_owner_confirmation_is_required_and_bound_to_the_message(self):
        self.switch_on()
        for wrong in ("", None, "CANARY PLAN", cc.canary_plan_phrase(ACCT, HEX[1]), cc.canary_plan_phrase(OTHER, CM), cc.canary_plan_phrase(ACCT, CM).lower(), "ARCHIVE 1 abcdef12"):
            with self.assertRaises(cp.PlanError) as ctx:
                cc.create_canary_plan(self.index, ACCT, CM, wrong)
            self.assertEqual(ctx.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(self.count("cleanup_plan"), 0)
        with self.assertRaises(cp.PlanError):
            cc.describe_candidate(self.index, ACCT, "not-in-the-index")

    def test_the_exception_waives_only_age_and_classification_everything_else_still_refuses(self):
        cases = (("self-sent (SENT)", ("INBOX", "SENT"), {}, "CANARY_SELF_SENT"), ("starred", ("INBOX", "STARRED"), {}, "NOT_ELIGIBLE"), ("draft", ("INBOX", "DRAFT"), {}, "NOT_ELIGIBLE"),
                 ("spam", ("INBOX", "SPAM"), {}, "NOT_ELIGIBLE"), ("trash", ("INBOX", "TRASH"), {}, "NOT_ELIGIBLE"), ("not in the inbox", ("CATEGORY_PROMOTIONS",), {}, "NOT_ELIGIBLE"),
                 ("important", ("INBOX", "IMPORTANT"), {}, "NOT_ELIGIBLE"), ("a user label", ("INBOX", "Label_7"), {}, "NOT_ELIGIBLE"), ("unread", ("INBOX", "UNREAD"), {"unread": True}, "NOT_ELIGIBLE"))
        for label, labels, extra, code in cases:
            with self.subTest(label):
                self.canary_labels, self.canary_extra = labels, extra
                self.setUp()
                self.switch_on()
                v = cc.describe_candidate(self.index, ACCT, CM)
                self.assertNotEqual(v["canary"]["outcome"], cand.ELIGIBLE)
                with self.assertRaises(cp.PlanError) as ctx:
                    self.canary_plan()
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(self.count("cleanup_plan"), 0)
        self.canary_labels, self.canary_extra = ONLY, {}

    def test_self_sent_is_never_bypassed_and_the_refusal_says_to_use_another_account(self):
        self.canary_labels = ("INBOX", "SENT")
        self.setUp()
        self.switch_on()
        v = cc.describe_candidate(self.index, ACCT, CM)
        self.assertTrue(v["self_sent"])
        self.assertIn("SENT", v["canary"]["reasons"])
        with self.assertRaises(cp.PlanError) as ctx:
            self.canary_plan()
        self.assertEqual(ctx.exception.code, "CANARY_SELF_SENT")
        self.assertIn("DIFFERENT account", str(ctx.exception))
        self.canary_labels = ONLY

    def test_protection_rules_missing_classification_and_risky_threads_still_refuse(self):
        self.switch_on()
        cleanup_protect.add(self.index, ACCT, sender=SENDER)
        with self.assertRaises(cp.PlanError) as ctx:
            self.canary_plan()
        self.assertEqual(ctx.exception.code, "NOT_ELIGIBLE")
        self.assertIn("USER_PROTECTED", cc.describe_candidate(self.index, ACCT, CM)["canary"]["reasons"])
        self.setUp()
        self.switch_on()
        self.index.conn.execute("DELETE FROM message_class WHERE message_id=?", (CM,))
        self.index.conn.commit()
        self.assertIn("CLASSIFICATION_MISSING", cc.describe_candidate(self.index, ACCT, CM)["canary"]["reasons"])
        with self.assertRaises(cp.PlanError):
            self.canary_plan()
        # a sibling in the same thread that is itself protected makes the thread mixed
        self.setUp()
        self.switch_on()
        sibling = dict(msg(7, sender="sibling@shop.example.test", labels=("INBOX", "STARRED")), id=HEX[6], thread_id=THREADS[0])
        scan = self.index.start_scan(ACCT, "full", None)
        self.index.save_batch(ACCT, scan, [sibling])
        self.index.finish_scan(scan, "completed")
        import gmail_intelligence.classifier as classifier
        classifier.run(self.index, ACCT, persist=True)
        self.assertIn("MIXED_THREAD", cc.describe_candidate(self.index, ACCT, CM)["canary"]["reasons"])
        with self.assertRaises(cp.PlanError):
            self.canary_plan()

    def test_a_forged_marker_is_caught_by_the_plan_integrity_check(self):
        self.switch_on()
        plan = self.canary_plan()
        snap = json.loads(plan["snapshot"])
        snap["policy"]["canary_exception"] = "yes"
        forged = dict(plan, snapshot=audit.canonical(snap))
        forged["plan_hash"] = audit.sha256(forged["snapshot"])
        self.assertIn("CANARY_SHAPE", cp.integrity_problems(forged))
        ordinary = cp.get_plan(self.index, ACCT, self.approved_plan([HEX[1]])["plan_id"])
        snap2 = json.loads(ordinary["snapshot"])
        snap2["policy"]["canary_exception"] = True  # claiming the exception on an ordinary plan changes its policy and hash, so it no longer matches what was approved
        forged2 = dict(ordinary, snapshot=audit.canonical(snap2))
        forged2["plan_hash"] = audit.sha256(forged2["snapshot"])
        self.assertNotEqual(forged2["plan_hash"], ordinary["plan_hash"])
        self.assertNotIn("POLICY_CHANGED", cp.revalidate(self.index, ACCT, ordinary, live._utcnow()))


class FlowTests(ExceptionBase):
    def test_a_canary_plan_goes_through_the_ordinary_review_and_approval_and_stays_protected(self):
        self.switch_on()
        plan = self.approved_canary()
        self.assertEqual((plan["state"], plan["item_count"]), ("APPROVED", 1))
        self.assertEqual(cp.verify_approved(self.index, ACCT, plan["plan_id"], self.t), {})
        cleanup_protect.add(self.index, ACCT, sender=SENDER)  # a later protection stales the plan like any other
        problems = cp.verify_approved(self.index, ACCT, plan["plan_id"], self.t)
        self.assertIn("PROTECTION_RULES_CHANGED", problems)
        self.assertIn("ITEM_NOT_ELIGIBLE", problems)

    def test_the_canary_runs_end_to_end_through_the_shared_executor_and_the_live_adapter(self):
        self.switch_on()
        ex = self.started_canary()
        res = cc.run_canary(self.index, ACCT, ex["exec_id"], self.token, cc.canary_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"]), self.store, self.client_path)
        self.assertEqual((res.item_state, res.code, res.execution_state, res.posts), ("APPLIED", "APPLIED", "EXECUTED", 1))
        self.assertEqual((self.svc.posts(), self.svc.messages[CM][1]), (1, set()))  # a message with only INBOX has no label at all afterwards
        self.assertEqual(self.svc.messages[HEX[1]][1], set(TC.LABELS))
        row = self.item(CM)
        self.assertEqual((row["evidence_checked"], row["evidence_source"], json.loads(row["prev_label_ids"])), (1, "TRUSTED_ADAPTER", ["INBOX"]))
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_drift_protection_and_ambiguity_still_apply_to_the_exception_message(self):
        cases = (("labels changed", Step("GET_MESSAGE", before=lambda f: f.set_labels(CM, ["INBOX", "STARRED"])), "SKIPPED_DRIFT", 0),
                 ("an unknown sibling", Step("GET_THREAD", before=lambda f: f.add_message(HEX[6], THREADS[0], ["INBOX"])), "SKIPPED_DRIFT", 0),
                 ("the message is gone", Step("GET_MESSAGE", before=lambda f: f.remove_message(CM)), "SKIPPED_GONE", 0),
                 ("a timeout on the request", Step("POST", raises=TimeoutError(), apply=True), "UNKNOWN", 1),
                 ("a 503", Step("POST", status=503, body=b"x"), "UNKNOWN", 1))
        for label, step, state, posts in cases:
            with self.subTest(label):
                self.setUp()
                self.switch_on()
                self.svc.script.append(step)
                ex = self.started_canary()
                res = cc.run_canary(self.index, ACCT, ex["exec_id"], self.token, cc.canary_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"]), self.store, self.client_path)
                self.assertEqual((res.item_state, res.posts, self.svc.posts()), (state, posts, posts))

    def test_the_fake_only_executor_runs_a_canary_plan_too_and_a_crash_is_recovered_without_a_second_request(self):
        self.switch_on()
        ex = self.started_canary()
        mb = fm.FakeMailbox(ACCT, self.fake_state(), clock=self.clock(), script=[Step("POST", raises=Crash(), apply=True)])
        with self.assertRaises(Crash):
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.assertEqual((mb.service.posts(), self.item(CM)["state"]), (1, "INTENT"))
        later = self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=10)
        ce.recover_interrupted(self.index, ACCT, now=later)
        fresh = fm.FakeMailbox(ACCT, {m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}, clock=TC.TL.StepClock(later + timedelta(seconds=1)))
        self.reconcile_trusted(ex, fresh, CM)
        self.assertEqual((self.item(CM)["state"], mb.service.posts(), fresh.service.posts()), ("APPLIED", 1, 0))


class EntryPointTests(ExceptionBase):
    def run_cli(self, argv, typed, **kw):
        said, inputs = [], list(typed)
        code = cli.main(argv, input_fn=lambda _: inputs.pop(0), out=said.append, store_factory=lambda: self.store, **kw)
        return code, "\n".join(said), inputs

    def test_describe_and_plan_work_when_enabled_and_print_only_codes_and_counts(self):
        self.switch_on()
        code, text, _ = self.run_cli(["describe", "--account", ACCT, "--message-id", CM], [])
        self.assertEqual(code, 0)
        self.assertIn("canary: ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION", text)
        self.assertIn("TOO_RECENT", text)
        for private in (CM, SENDER, ACCT):
            self.assertNotIn(private, text)
        code, text, left = self.run_cli(["plan", "--account", ACCT, "--message-id", CM], ["wrong phrase"])
        self.assertEqual((code, self.count("cleanup_plan")), (1, 0))
        code, text, left = self.run_cli(["plan", "--account", ACCT, "--message-id", CM], [cc.canary_plan_phrase(ACCT, CM)])
        self.assertEqual((code, self.count("cleanup_plan")), (0, 1))
        self.assertIn("cleanup plan review", text)
        self.assertNotIn(CM, text)

    def test_run_reserves_starts_and_runs_the_canary_after_two_typed_confirmations(self):
        self.switch_on()
        plan = self.approved_canary()
        self.clk.at = self.t + timedelta(seconds=1)
        code, text, left = self.run_cli(["run", "--account", ACCT, "--plan-id", plan["plan_id"]], ["wrong"])
        self.assertEqual((code, self.count("cleanup_execution"), self.svc.log), (1, 0, []))  # a wrong first phrase reserves nothing
        ex_phrase = ce.execution_phrase(plan, 1)
        with mock.patch.object(ce, "start_slice", wraps=ce.start_slice) as started:
            code, text, left = self.run_cli(["run", "--account", ACCT, "--plan-id", plan["plan_id"]], [ex_phrase, "wrong"])
        self.assertEqual((code, self.svc.log, self.store.touched), (1, [], []))  # a wrong canary phrase sends nothing and touches no credential
        self.assertEqual(self.count("cleanup_execution"), 1)
        self.assertEqual(self.exec_state(self.index._q("SELECT exec_id FROM cleanup_execution")[0][0]), "EXECUTING")

    def test_run_end_to_end_with_the_right_phrases(self):
        self.switch_on()
        plan = self.approved_canary()
        self.clk.at = self.t + timedelta(seconds=1)
        from gmail_intelligence import config
        config.ensure_app_dir()
        config.write_client_secret_path().write_text(self.client_path.read_text())  # the owner's imported write client file, in the (temporary) application directory
        config.write_client_secret_path().chmod(0o600)
        phrases = []

        def typed(prompt):
            phrases.append(prompt)
            if len(phrases) == 1:
                return ce.execution_phrase(plan, 1)
            return cc.canary_phrase(plan, self.index._q("SELECT exec_id FROM cleanup_execution")[0][0])
        said = []
        code = cli.main(["run", "--account", ACCT, "--plan-id", plan["plan_id"]], input_fn=typed, out=said.append, store_factory=lambda: self.store)
        self.assertEqual((code, self.svc.posts(), self.svc.messages[CM][1]), (0, 1, set()))
        self.assertIn("item APPLIED", "\n".join(said))
        for private in (CM, SENDER, ACCT):
            self.assertNotIn(private, "\n".join(said))

    def test_run_refuses_unapproved_or_multi_target_plans_and_unexpected_failures_leak_nothing(self):
        self.switch_on()
        plan = self.canary_plan()  # DRAFT, not approved
        code, text, _ = self.run_cli(["run", "--account", ACCT, "--plan-id", plan["plan_id"]], [])
        self.assertEqual((code, self.count("cleanup_execution")), (1, 0))
        ordinary = self.approved_plan([HEX[1], HEX[2]])
        code, text, _ = self.run_cli(["run", "--account", ACCT, "--plan-id", ordinary["plan_id"]], [])
        self.assertEqual((code, self.count("cleanup_execution")), (1, 0))
        code, text, _ = self.run_cli(["run", "--account", ACCT, "--plan-id", "plan-0000"], [])
        self.assertEqual(code, 1)
        with mock.patch.object(cc, "describe_candidate", side_effect=RuntimeError(f"secret {CM} {SENDER}")):
            code, text, _ = self.run_cli(["describe", "--account", ACCT, "--message-id", CM], [])
        self.assertEqual(code, 1)
        for private in (CM, SENDER, "secret"):
            self.assertNotIn(private, text)


if __name__ == "__main__":
    unittest.main()
