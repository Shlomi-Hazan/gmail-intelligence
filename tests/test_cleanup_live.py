"""Tests for the DISABLED real-execution boundary (`exec_live_mailbox`, `cleanup_live`).

Everything is offline and synthetic: the genuine archive adapter runs over the in-memory fake wire (never a socket), the enabled switch is flipped only inside tests with a
patch, time is a controlled step clock patched into the two clock functions, and the database is a temporary SQLite file. Nothing contacts Gmail, no credential exists.
"""
import ast
import inspect
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_recovery as TR  # noqa: E402
import test_write_transport as TWT  # noqa: E402
from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_batch import Crash, IDS  # noqa: E402
from test_cleanup_executor import AFTER, HEX, LABELS, StepClock, gerr  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_executor as cx, cleanup_live as cl, cleanup_plans as cp, cleanup_recovery as cr, cleanup_undo as cu  # noqa: E402
from gmail_intelligence import exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, gmail_write_policy as pol  # noqa: E402

Step = fm.Step


class LazyStepClock(StepClock):
    """A step clock that starts one second after the test's current time, read at its first use (after the test has built its execution)."""
    def __init__(self, owner):
        super().__init__(None)
        self.owner = owner

    def __call__(self):
        if self.at is None:
            self.at = self.owner.t + timedelta(seconds=1)
        return super().__call__()


class LiveBase(TR.RecoveryBase):
    def enable(self):
        """Switch live execution on for THIS test only and put one controlled clock under the live mailbox and the adapter."""
        self.clk = self.step_clock = LazyStepClock(self)
        for target, name, value in ((live, "LIVE_EXECUTION_ENABLED", True), (live, "_utcnow", self.clk), (gw, "_utcnow", self.clk)):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def live_mailbox(self, script=(), state=None, account=ACCT):
        svc = fm._Service(account, state or self.fake_state(), tuple(script))
        factory = fm._Factory(svc)
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, factory), account)
        return live._wrap(adapter, account, factory), svc

    def single(self):
        return self.batch_execution(ids=(IDS[0],))

    def confirm(self, ex):
        """Record the owner's canary confirmation exactly as run_canary does before it hands over to the live batch."""
        with cp._txn(self.index):
            audit.append(self.index, ACCT, ex["plan_id"], "CANARY_CONFIRMED", cp._iso(live._utcnow()), {"exec": ex["exec_id"], "phrase_sha256": "0" * 64})

    def run_live(self, ex, lm, svc, token=None):
        try:
            if not any(json.loads(r["meta"]).get("exec") == ex["exec_id"] for r in self.index._q("SELECT meta FROM cleanup_audit WHERE event_type='CANARY_CONFIRMED'")):
                self.confirm(ex)
            return cl.execute_live_batch(self.index, ACCT, ex["exec_id"], token or self.token, lm, _permit=live._CANARY_PERMIT)
        finally:
            keys = [k for kind, k in svc.log if kind == "POST"]
            self.assertEqual(len(keys), len(set(keys)))  # never two POSTs for one message
            self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
            self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])


class DisabledByDefaultTests(LiveBase):
    def test_the_switch_is_a_false_constant_and_nothing_in_the_program_changes_it(self):
        self.assertIs(live.LIVE_EXECUTION_ENABLED, False)
        assigned = []
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AugAssign) else []
                for t in targets:
                    if (isinstance(t, ast.Name) and t.id == "LIVE_EXECUTION_ENABLED") or (isinstance(t, ast.Attribute) and t.attr == "LIVE_EXECUTION_ENABLED"):
                        assigned.append((path.name, getattr(node.value, "value", None)))
        self.assertEqual(assigned, [("exec_live_mailbox.py", False)])

    def test_every_live_function_is_refused_before_anything_is_read_or_written(self):
        ex = self.batch_execution()
        before = self.snapshot()
        store = mock.MagicMock()
        with self.assertRaises(live.LiveExecutionDisabled):
            live.open_live_mailbox(ACCT, store, "client.json")
        self.assertEqual(store.mock_calls, [])  # not even the write token store was touched
        svc = fm._Service(ACCT, self.fake_state(), ())
        factory = fm._Factory(svc)
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, factory), ACCT)
        with self.assertRaises(live.LiveExecutionDisabled):
            live._wrap(adapter, ACCT, factory)
        lm = live.LiveMailbox(_mint=live._MINT, _adapter=adapter, _account=ACCT, _test_factory=factory)  # built by hand with the private mint, bypassing the switch
        for call in (lambda: cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm), lambda: cl.recover_live(self.index, ACCT, lm)):
            with self.assertRaises(ce.ExecError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, "LIVE_DISABLED")
        with self.assertRaises(live.LiveExecutionDisabled):
            lm.archive_message(HEX[0])  # even the mutation method checks the switch itself
        self.assertEqual((svc.log, self.snapshot(), live.LiveExecutionDisabled.code), ([], before, "LIVE_DISABLED"))

    def test_there_is_no_production_entry_point(self):
        cli = (SRC / "cli.py").read_text()
        for name in ("exec_live_mailbox", "cleanup_live", "LiveMailbox", "LIVE_EXECUTION_ENABLED", "execute_live_batch", "recover_live", "open_live_mailbox"):
            self.assertNotIn(name, cli)
        self.assertIn("execution is not available in this version", cli)
        importers = {}
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module or ""] + [a.name for a in node.names] if isinstance(node, ast.ImportFrom) else [])
                for target in ("exec_live_mailbox", "cleanup_live"):
                    if any(m.split(".")[-1] == target for m in mods):
                        importers.setdefault(target, set()).add(path.name)
        self.assertEqual(importers, {"exec_live_mailbox": {"cleanup_executor.py", "cleanup_canary.py", "cleanup_live.py", "cleanup_canary_cli.py"}, "cleanup_live": {"cleanup_canary.py"}})  # the live modules are imported only by the disabled canary code
        callers = set()
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) in ("_wrap", "open_live_mailbox", "execute_live_batch", "recover_live"):
                    callers.add((path.name, getattr(node.func, "id", getattr(node.func, "attr", None)), len(node.args) + len(node.keywords)))
        self.assertEqual(callers, {("exec_live_mailbox.py", "_wrap", 2), ("cleanup_canary.py", "open_live_mailbox", 3), ("cleanup_canary.py", "execute_live_batch", 6)})  # without a test factory; canary only

    def test_the_public_constructor_has_no_clock_factory_or_transport_parameter(self):
        self.assertEqual(list(inspect.signature(live.open_live_mailbox).parameters), ["expected_account", "store", "client_path"])
        self.assertEqual(list(inspect.signature(live.LiveMailbox.__init__).parameters), ["self", "_mint", "_adapter", "_account", "_test_factory"])
        self.assertEqual(list(inspect.signature(cl.execute_live_batch).parameters), ["index", "account", "exec_id", "token", "mailbox", "_permit"])
        self.assertEqual(list(inspect.signature(cl.recover_live).parameters), ["index", "account", "mailbox"])
        now = live._utcnow()
        self.assertEqual(now.utcoffset(), timedelta(0))
        self.assertLess(abs(datetime.now(timezone.utc) - now), timedelta(seconds=5))


class SeamTests(LiveBase):
    """The private constructor, the test-factory seam and the points where the disabled switch is checked."""

    def adapter_on_fake_wire(self):
        svc = fm._Service(ACCT, self.fake_state(), ())
        factory = fm._Factory(svc)
        return gw.ArchiveAdapter(gw._Transport(svc.creds, factory), ACCT), factory, svc

    def test_an_ordinary_caller_cannot_construct_a_live_mailbox_or_choose_its_wiring(self):
        self.enable()
        adapter, factory, svc = self.adapter_on_fake_wire()
        for kwargs in (dict(_adapter=adapter, _account=ACCT), dict(_adapter=adapter, _account=ACCT, _test_factory=factory), dict(_mint=object(), _adapter=adapter, _account=ACCT)):
            with self.assertRaises(TypeError):
                live.LiveMailbox(**kwargs)

    def test_the_test_seam_accepts_only_the_in_memory_fake_wire_never_a_real_connection_factory(self):
        self.enable()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        svc_creds = fm._FakeCreds()
        for factory in (net, gw._default_connection, lambda: None, object()):
            adapter = gw.ArchiveAdapter(gw._Transport(svc_creds, factory), ACCT)
            if factory is gw._default_connection:
                live._wrap(adapter, ACCT)  # the production wiring is accepted
                continue
            with self.assertRaises(ValueError):
                live._wrap(adapter, ACCT, factory)
            minted = live.LiveMailbox(_mint=live._MINT, _adapter=adapter, _account=ACCT, _test_factory=factory)  # even a hand-minted one is not wired acceptably
            self.assertFalse(live.live_wiring_ok(minted))
            ex = self.batch_execution()
            with self.assertRaises(ce.ExecError) as ctx:
                cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, minted)
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
            self.assertEqual((net.opened, net.log), (0, []))
            self.setUp()
            self.enable()

    def test_while_disabled_no_port_method_of_a_live_mailbox_can_reach_the_wire(self):
        adapter, factory, svc = self.adapter_on_fake_wire()
        minted = live.LiveMailbox(_mint=live._MINT, _adapter=adapter, _account=ACCT, _test_factory=factory)  # hand-minted while the switch is off
        for call in (lambda: minted.verify_account(), lambda: minted.message_state(HEX[0]), lambda: minted.thread_state(HEX[0]), lambda: minted.archive_message(HEX[0]),
                     lambda: minted.observe(HEX[0], context="c" * 32)):
            with self.assertRaises(live.LiveExecutionDisabled):
                call()
        self.assertEqual(svc.log, [])

    def test_only_the_disabled_live_entry_points_pass_the_live_selector(self):
        users = set()
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and any(isinstance(a, ast.Constant) and a.value == "LIVE" for a in list(node.args) + [k.value for k in node.keywords]):
                    users.add(path.name)
        self.assertEqual(users, {"cleanup_live.py"})
        for public in (cx.execute_one, cx.execute_batch, cr.recover):
            self.assertNotIn("allow", inspect.signature(public).parameters)


class TypeIsolationTests(LiveBase):
    def test_a_live_mailbox_is_refused_by_every_fake_only_api_and_vice_versa(self):
        self.enable()
        ex = self.batch_execution()
        lm, svc = self.live_mailbox()
        before = self.snapshot()
        fake = self.mailbox()
        for call in (lambda: cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, lm), lambda: cx.execute_one(self.index, ACCT, ex["exec_id"], self.token, IDS[0], lm),
                     lambda: cr.recover(self.index, ACCT, lm), lambda: cu.undo_item(self.index, ACCT, ex["exec_id"], 1, lm),
                     lambda: cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, lm), lambda: cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, fake),
                     lambda: cl.recover_live(self.index, ACCT, fake)):
            with self.assertRaises(ce.ExecError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        for other in (TWT.adapter(net, expected=ACCT), mock.MagicMock(spec=live.LiveMailbox), object(), None):  # a raw adapter must be wrapped; look-alikes are refused
            with self.assertRaises(ce.ExecError) as ctx:
                cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, other)
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual((svc.log, fake.service.log, net.log, self.snapshot()), ([], [], [], before))
        with self.assertRaises(TypeError):
            type("Sub", (live.LiveMailbox,), {})

    def test_the_live_mailbox_exposes_only_the_executor_port_and_cannot_be_rewired(self):
        self.enable()
        lm, svc = self.live_mailbox()
        public = sorted(n for n in dir(lm) if not n.startswith("_"))
        self.assertEqual(public, ["account", "archive_message", "clock", "message_state", "observe", "thread_state", "verify_account"])
        self.assertFalse(hasattr(lm, "restore_inbox"))  # no undo, no other Gmail operation
        for name in ("_adapter", "_account", "_test_factory", "anything"):
            with self.assertRaises(AttributeError):
                setattr(lm, name, object())
        ex = self.batch_execution()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        for label, swap in (("the connection factory", lambda: setattr(lm._adapter._t, "_factory", net)), ("the adapter", lambda: object.__setattr__(lm, "_adapter", TWT.adapter(net, expected=ACCT)))):
            lm2, svc2 = self.live_mailbox()
            if label == "the connection factory":
                setattr(lm2._adapter._t, "_factory", net)
            else:
                object.__setattr__(lm2, "_adapter", TWT.adapter(net, expected=ACCT))
            self.assertFalse(live.live_wiring_ok(lm2), label)
            before = self.snapshot()
            with self.assertRaises(ce.ExecError) as ctx:
                cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm2)
            self.assertEqual((ctx.exception.code, self.snapshot(), net.log, net.opened), ("MAILBOX_NOT_ALLOWED", before, [], 0))


class LiveBatchTests(LiveBase):
    """The live path now runs ONLY the single approved canary item; these tests drive it exactly as `run_canary` does (confirmation recorded, permit passed)."""

    def test_a_live_run_executes_the_very_same_flow_over_the_genuine_adapter(self):
        self.enable()
        ex = self.single()
        lm, svc = self.live_mailbox()
        boom = AssertionError("the default real connection path was used")
        with mock.patch.object(gw, "_default_connection", side_effect=boom):
            res = self.run_live(ex, lm, svc)
        self.assertEqual((res.execution_state, res.posts, res.stopped), ("EXECUTED", 1, False))
        self.assertEqual([r.item_state for _, r in res.items], ["APPLIED"])
        self.assertEqual([k for kind, k in svc.log if kind == "POST"], [IDS[0]])
        self.assertEqual({k for k, _ in svc.log}, {"PROFILE", "GET_MESSAGE", "GET_THREAD", "POST"})
        self.assertEqual(svc.messages[IDS[0]][1], set(AFTER))
        self.assertEqual((self.item(IDS[0])["evidence_checked"], self.item(IDS[0])["evidence_source"]), (1, "TRUSTED_ADAPTER"))
        for other in HEX[1:5]:
            self.assertEqual(svc.messages[other][1], set(LABELS))  # nothing else is touched
        self.assertEqual(svc.undos(), 0)
        self.assertTrue(live.live_wiring_ok(lm))

    def test_the_live_modules_call_only_the_archive_adapters_five_operations_and_the_policy_is_unchanged(self):
        self.assertEqual(pol.MODIFY_BODY, b'{"removeLabelIds":["INBOX"]}')
        self.assertEqual(len(pol._ROUTES), 4)
        for name in ("exec_live_mailbox.py", "cleanup_live.py"):
            tree = ast.parse((SRC / name).read_text())
            self.assertNotIn("addLabelIds", (SRC / name).read_text())
            called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "_adapter"}
            self.assertLessEqual(called, {"verify_account", "message_state", "thread_state", "archive_message", "observe"}, name)

    def test_intent_is_durable_before_the_post_and_an_unknown_post_stops_without_retry(self):
        self.enable()
        ex = self.single()
        seen = {}
        lm, svc = self.live_mailbox([Step("POST", nth=1, before=lambda f: seen.setdefault("state", self.item(IDS[0])["state"]), raises=TimeoutError(), apply=True)])
        res = self.run_live(ex, lm, svc)
        self.assertEqual(seen["state"], "INTENT")
        self.assertEqual(self.item(IDS[0])["state"], "UNKNOWN")
        self.assertEqual((res.execution_state, res.posts, res.stopped, svc.posts()), ("RECONCILIATION_REQUIRED", 1, True, 1))
        with self.assertRaises(ce.ExecError) as ctx:
            self.run_live(ex, lm, svc)
        self.assertEqual((ctx.exception.code, svc.posts()), ("BAD_STATE", 1))

    def test_each_kind_of_failure_stops_the_live_run_where_it_happens(self):
        cases = (("rate limit on the post", Step("POST", nth=1, status=429, body=gerr(429)[1]), "UNKNOWN", 1),
                 ("server error on the post", Step("POST", nth=1, status=503, body=b"x"), "UNKNOWN", 1),
                 ("a refused post proven to be before dispatch", Step("GET_THREAD", nth=1, after=lambda f: setattr(f.creds, "live", False)), "NOT_APPLIED", 0),
                 ("a read timeout before the intent", Step("GET_THREAD", nth=1, raises=TimeoutError()), "NOT_APPLIED", 0),
                 ("a drifted item is skipped", Step("GET_MESSAGE", nth=1, before=lambda f: f.set_labels(IDS[0], list(LABELS) + ["STARRED"])), "SKIPPED_DRIFT", 0))
        for label, step, state, posts in cases:
            with self.subTest(label):
                self.setUp()
                self.enable()
                ex = self.single()
                lm, svc = self.live_mailbox([step])
                res = self.run_live(ex, lm, svc)
                self.assertEqual(self.item(IDS[0])["state"], state)
                self.assertEqual((res.posts, svc.posts()), (posts, posts))

    def test_account_mismatch_and_a_bad_lease_change_nothing(self):
        self.enable()
        ex = self.single()
        wrong, svc = self.live_mailbox([Step("PROFILE", status=200, body=json.dumps({"emailAddress": OTHER}).encode())])
        res = self.run_live(ex, wrong, svc)
        self.assertEqual((self.item(IDS[0])["state"], res.posts, svc.posts()), ("NOT_APPLIED", 0, 0))
        self.setUp()
        self.enable()
        ex = self.single()
        lm, svc = self.live_mailbox()
        with self.assertRaises(ce.ExecError):
            self.run_live(ex, lm, svc, token="x" * 40)
        other, osvc = self.live_mailbox(account=OTHER)
        res = self.run_live(ex, other, osvc)
        self.assertEqual((res.posts, osvc.posts(), svc.log), (0, 0, []))

    def test_switching_the_build_off_during_a_run_stops_it_before_the_post(self):
        self.enable()
        ex = self.single()
        lm, svc = self.live_mailbox([Step("GET_THREAD", nth=1, after=lambda f: setattr(live, "LIVE_EXECUTION_ENABLED", False))])
        with self.assertRaises(ce.ExecError) as ctx:
            self.run_live(ex, lm, svc)
        self.assertEqual(ctx.exception.code, "LIVE_DISABLED")
        self.assertEqual((svc.posts(), self.item(IDS[0])["state"]), (0, "INTENT"))  # the intent stays open for recovery; no request was made

    def test_a_crash_is_recovered_through_the_live_boundary_without_any_mutation(self):
        for apply in (True, False):
            with self.subTest(apply=apply):
                self.setUp()
                self.enable()
                ex = self.single()
                lm, svc = self.live_mailbox([Step("POST", nth=1, raises=Crash(), apply=apply)])
                with self.assertRaises(Crash):
                    self.run_live(ex, lm, svc)
                posts = svc.posts()
                self.clk.at = self.clk.at + ce.LEASE_TTL + timedelta(seconds=10)
                lm2, svc2 = self.live_mailbox(state={m: (t, list(l)) for m, (t, l) in svc.messages.items()})
                report = cl.recover_live(self.index, ACCT, lm2)
                self.assertEqual(report.interrupted, (ex["exec_id"],))
                self.assertEqual(self.item(IDS[0])["state"], "APPLIED" if apply else "NOT_APPLIED")
                self.assertEqual((svc.posts(), svc2.posts(), svc2.undos(), posts), (posts, 0, 0, posts))
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
                wrong, wsvc = self.live_mailbox(account=OTHER)
                with self.assertRaises(ce.ExecError) as ctx:
                    cl.recover_live(self.index, ACCT, wrong)
                self.assertEqual(ctx.exception.code, "ACCOUNT_MISMATCH")


class RestrictionTests(LiveBase):
    """Live execution is only the approved single-message canary, entered through run_canary."""

    def test_a_direct_call_without_the_permit_is_refused_even_with_everything_else_valid(self):
        self.enable()
        ex = self.single()
        self.confirm(ex)
        lm, svc = self.live_mailbox()
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm)
        self.assertEqual((ctx.exception.code, self.snapshot(), svc.log), ("CANARY_ONLY", before, []))
        for fake_permit in (object(), True, "permit", live._MINT):
            with self.assertRaises(ce.ExecError):
                cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm, _permit=fake_permit)
        self.assertEqual(svc.log, [])

    def test_more_than_one_target_or_no_recorded_confirmation_is_refused_even_with_the_permit(self):
        self.enable()
        ex = self.batch_execution()  # four targets
        self.confirm(ex)
        lm, svc = self.live_mailbox()
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm, _permit=live._CANARY_PERMIT)
        self.assertEqual((ctx.exception.code, self.snapshot(), svc.log), ("NOT_A_CANARY", before, []))
        self.setUp()
        self.enable()
        ex = self.single()  # one target but the owner's canary confirmation is not recorded
        lm, svc = self.live_mailbox()
        with self.assertRaises(ce.ExecError) as ctx:
            cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm, _permit=live._CANARY_PERMIT)
        self.assertEqual((ctx.exception.code, svc.log), ("CANARY_NOT_CONFIRMED", []))
        with cp._txn(self.index):  # a confirmation recorded for ANOTHER execution does not count
            audit.append(self.index, ACCT, ex["plan_id"], "CANARY_CONFIRMED", cp._iso(live._utcnow()), {"exec": "exec-00000000", "phrase_sha256": "0" * 64})
        with self.assertRaises(ce.ExecError) as ctx:
            cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm, _permit=live._CANARY_PERMIT)
        self.assertEqual((ctx.exception.code, svc.log), ("CANARY_NOT_CONFIRMED", []))

    def test_only_run_canary_holds_the_permit_and_nothing_else_can_run_the_live_batch(self):
        users = set()
        for path in SRC.glob("*.py"):
            text = path.read_text()
            if "_CANARY_PERMIT" in text:
                users.add(path.name)
        self.assertEqual(users, {"exec_live_mailbox.py", "cleanup_live.py", "cleanup_canary.py"})  # defined, checked, and passed (only) by run_canary
        passers = set()
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and any(k.arg == "_permit" for k in node.keywords):
                    passers.add(path.name)
        self.assertEqual(passers, {"cleanup_canary.py"})
        self.assertNotIn("canary_ok", inspect.signature(cl.execute_live_batch).parameters)

    def test_recovery_stays_read_only_through_the_live_boundary(self):
        self.enable()
        ex = self.single()
        lm, svc = self.live_mailbox([Step("POST", nth=1, raises=Crash(), apply=True)])
        with self.assertRaises(Crash):
            self.run_live(ex, lm, svc)
        self.clk.at = self.clk.at + ce.LEASE_TTL + timedelta(seconds=10)
        lm2, svc2 = self.live_mailbox(state={m: (t, list(l)) for m, (t, l) in svc.messages.items()})
        cl.recover_live(self.index, ACCT, lm2)
        self.assertEqual((svc2.posts(), svc2.undos()), (0, 0))
        self.assertEqual({k for k, _ in svc2.log} - {"PROFILE", "GET_MESSAGE"}, set())  # only the profile read and observations


class UndoDeferredTests(LiveBase):
    def test_live_undo_is_deferred_and_documented(self):
        self.enable()
        lm, svc = self.live_mailbox()
        self.assertFalse(hasattr(lm, "restore_inbox"))
        self.assertFalse(hasattr(gw.ArchiveAdapter, "restore_inbox"))
        with self.assertRaises(ce.ExecError) as ctx:
            cu.undo_item(self.index, ACCT, "exec-00000000", 1, lm)
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertIn("Live undo is deferred", (ROOT / "docs" / "CLEANUP.md").read_text())


if __name__ == "__main__":
    unittest.main()
