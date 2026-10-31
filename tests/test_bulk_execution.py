"""M12D: controlled BULK archive execution (issue #62), DISABLED in this build. Fake Gmail wire and mocked credentials only: no Gmail, no OAuth, no Keychain, no network; the live
execution gate is patched on for one test at a time. The execution state machine, the per-item executor, the trusted observations and recovery are the unchanged M4 components - these
tests prove the owner-facing orchestration around them: typed per-slice authorization, bounded slices, stop-on-uncertainty, no resume, no retry, gates and efficiency."""
import contextlib
import io
import json
import os
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from bulk_support import BulkBase  # noqa: E402
from test_cleanup import ACCT  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_canary import BombIndex, RecordingStore  # noqa: E402
from test_cleanup_executor import AFTER, LABELS  # noqa: E402

from gmail_intelligence import bulk_cli, cleanup_audit as audit, cleanup_bulk as bulk, cleanup_candidates as cc, cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, cleanup_protect  # noqa: E402
from gmail_intelligence import cli, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, index as idx, keystore_write  # noqa: E402

Step = fm.Step


class ArchiveBulkTests(BulkBase):
    def test_an_approved_multi_slice_plan_archives_every_target_with_a_separate_confirmation_per_slice(self):
        plan, ex = self.prepare_bulk()
        self.assertEqual((ex["state"], ex["slice_count"], [s["size"] for s in ce.slices(self.index, ACCT, ex["exec_id"])]), ("PREPARED", 3, [25, 100, 5]))
        d = bulk.describe(self.index, ACCT, ex["exec_id"])
        self.assertEqual((d["operation"], d["items"], d["next"], [s["items"] for s in d["slices"]]), ("ARCHIVE", 130, {"action": "RUN", "slice": 1}, [[1, 25], [26, 125], [126, 130]]))
        r1 = self.run_slice(ex)
        self.assertEqual((r1.slice_no, r1.applied, r1.posts, r1.execution_state, r1.stopped), (1, 25, 25, "AWAITING_CONTINUATION", False))
        d = bulk.describe(self.index, ACCT, ex["exec_id"])
        self.assertEqual(d["next"], {"action": "CONFIRM", "slice": 2})
        with self.assertRaises(ce.ExecError) as ctx:                        # slice 2 has no confirmation of its own: it cannot run
            self.run_slice(ex, phrase="whatever")
        self.assertIn(ctx.exception.code, ("SLICE_NOT_CONFIRMED", "BAD_CONFIRMATION"))
        self.assertEqual(self.svc.posts(), 25)
        self.assertEqual(self.confirm_next(ex), 2)
        r2 = self.run_slice(ex)
        self.assertEqual((r2.applied, r2.posts, r2.execution_state), (100, 100, "AWAITING_CONTINUATION"))
        self.confirm_next(ex)
        r3 = self.run_slice(ex)
        self.assertEqual((r3.applied, r3.posts, r3.execution_state), (5, 5, "EXECUTED"))
        self.assertEqual((self.svc.posts(), self.svc.undos(), len(self.archived_ids())), (130, 0, 130))
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"APPLIED": 130})
        self.assertEqual(sorted(self.bids()), self.archived_ids())                    # exactly the reviewed targets, nothing else
        for mid, (tid, labels) in self.svc.messages.items():
            self.assertEqual(set(labels), set(AFTER), mid)                           # only INBOX was removed
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        self.assertEqual(len([m for m in bulk._confirmations(self.index, ACCT) if m["exec"] == ex["exec_id"]]), 3)

    def test_wrong_stale_or_foreign_phrases_start_nothing_and_are_locked_out(self):
        plan, ex = self.prepare_bulk(30)
        good = self.run_phrase(ex)
        for wrong in ("", "RUN", good.replace("slice 1", "slice 2"), good.replace(ex["exec_id"], "exec-00000000"), ce.execution_phrase(plan, 25), cp.approval_phrase(plan), good.lower()):
            with self.assertRaises(ce.ExecError) as ctx:
                self.run_slice(ex, phrase=wrong)
            self.assertIn(ctx.exception.code, ("BAD_CONFIRMATION", "LOCKED_OUT"))
        self.assertEqual((self.svc.log, self.store.touched, self.exec_row(ex)["state"]), ([], [], "PREPARED"))
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(ce.ExecError):
                self.run_slice(ex, phrase="x")
        with self.assertRaises(ce.ExecError) as ctx:
            self.run_slice(ex)                                                        # even the right phrase is refused while locked out
        self.assertEqual(ctx.exception.code, "LOCKED_OUT")
        self.assertEqual(self.svc.log, [])

    def test_an_unapproved_expired_or_already_used_plan_cannot_be_reserved(self):
        plan = cp.create_plan(self.index, ACCT, self.bids(5), now=self.tick())
        with self.assertRaises(ce.ExecError) as ctx:
            ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, 5), now=self.tick())
        self.assertEqual(ctx.exception.code, "NOT_APPROVED")
        approved = self.approved_plan(self.bids(5)[:4])
        with self.assertRaises(ce.ExecError):
            ce.reserve_execution(self.index, ACCT, approved["plan_id"], "x", now=self.tick())
        ex = ce.reserve_execution(self.index, ACCT, approved["plan_id"], ce.execution_phrase(approved, 4), now=self.tick())
        for again in (lambda: ce.reserve_execution(self.index, ACCT, approved["plan_id"], ce.execution_phrase(approved, 4), now=self.tick()),):
            with self.assertRaises(ce.ExecError) as ctx:
                again()
            self.assertEqual(ctx.exception.code, "PLAN_ALREADY_HAS_EXECUTION")
        other = self.approved_plan(self.bids(9)[5:])
        with self.assertRaises(ce.ExecError) as ctx:                                  # another unfinished execution of this account: refused
            ce.reserve_execution(self.index, ACCT, other["plan_id"], ce.execution_phrase(other, 4), now=self.tick())
        self.assertEqual(ctx.exception.code, "ACTIVE_EXECUTION_EXISTS")
        expired = self.approved_plan(self.bids(14)[10:])
        with self.assertRaises(ce.ExecError):
            ce.reserve_execution(self.index, ACCT, expired["plan_id"], ce.execution_phrase(expired, 4), now=self.t + cp.APPROVAL_TTL + timedelta(hours=1))
        self.assertEqual(ex["state"], "PREPARED")

    def test_changed_labels_and_protected_or_changed_threads_are_skipped_without_any_request(self):
        self.SHARED = {}
        plan, ex = self.prepare_bulk(10, [Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid(2), list(LABELS) + ["STARRED"]))])
        r = self.run_slice(ex)
        self.assertEqual((r.applied, r.skipped, r.posts, r.execution_state), (9, 1, 9, "EXECUTED"))
        self.assertEqual(self.item(self.mid(2))["state"], "SKIPPED_DRIFT")
        self.assertIn("INBOX", self.svc.messages[self.mid(2)][1])                       # never touched
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_an_ambiguous_result_stops_everything_and_nothing_is_retried_or_continued(self):
        plan, ex = self.prepare_bulk(130, [Step("POST", nth=3, raises=TimeoutError(), apply=True)])
        r = self.run_slice(ex)
        self.assertEqual((r.applied, r.unknown, r.posts, r.stopped, r.execution_state), (2, 1, 3, True, "RECONCILIATION_REQUIRED"))
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]).get("NOT_APPLIED"), 127)    # every remaining target is NEVER_ATTEMPTED
        self.assertEqual(self.svc.posts(), 3)
        for blocked in (lambda: self.run_slice(ex), lambda: ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, "x", now=self.clk())):
            with self.assertRaises(ce.ExecError):
                blocked()
        self.assertEqual(self.svc.posts(), 3)

    def test_an_interrupted_execution_never_resumes_and_a_lease_is_never_permission(self):
        plan, ex = self.prepare_bulk(130, [Step("POST", nth=4, raises=Crash(), apply=True)])
        with self.assertRaises(Crash):
            self.run_slice(ex)
        posts = self.svc.posts()
        self.assertEqual((self.exec_row(ex)["state"], self.item(self.mid(4))["state"]), ("EXECUTING", "INTENT"))
        with self.assertRaises(ce.ExecError) as ctx:                                  # the lease is not permission: nothing resumes, nothing is retried
            self.run_slice(ex, phrase=self.run_phrase(ex) if False else "x")
        self.assertIn(ctx.exception.code, ("BAD_STATE", "SLICE_NOT_CONFIRMED", "BAD_CONFIRMATION"))
        self.clk.at = self.clk.at + ce.LEASE_TTL + timedelta(seconds=30)
        with mock.patch.object(live, "LIVE_OBSERVE_ENABLED", True):
            factory = fm._Factory(self.svc)
            om = live._wrap_observe(gw.ArchiveAdapter(gw._Transport(self.svc.creds, factory, capabilities=("OBSERVE",)), ACCT, _clock=self.clk), ACCT, factory)
            report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.interrupted, self.item(self.mid(4))["state"], self.svc.posts()), ((ex["exec_id"],), "APPLIED", posts))     # read-only reconciliation
        self.assertEqual(self.exec_row(ex)["state"], "PARTIAL")
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]).get("NOT_APPLIED"), 126)
        with self.assertRaises(ce.ExecError):
            self.run_slice(ex)
        self.assertEqual(self.svc.posts(), posts)

    def test_the_gate_the_wrong_mailbox_and_hidden_state_refuse_before_any_request(self):
        plan, ex = self.prepare_bulk(10)
        phrase = self.run_phrase(ex)
        with mock.patch.object(live, "LIVE_EXECUTION_ENABLED", False), mock.patch.object(gw, "_default_connection", side_effect=AssertionError("network")):
            with self.assertRaises(ce.ExecError) as ctx:
                bulk.run_bulk_slice(BombIndex(), ACCT, ex["exec_id"], phrase, RecordingStore(self.blob()), self.client_path)   # the index is not even touched
            self.assertEqual(ctx.exception.code, "LIVE_DISABLED")
        # the permit is the only way into the live slice entry point
        factory = fm._Factory(self.svc)
        lm = live._wrap(gw.ArchiveAdapter(gw._Transport(self.svc.creds, factory), ACCT), ACCT, factory)
        token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.clk())
        for kw in ({}, {"_permit": object()}, {"_permit": live._CANARY_PERMIT}):
            with self.assertRaises(ce.ExecError) as ctx:
                cl.execute_live_slice(self.index, ACCT, ex["exec_id"], token, lm, **kw)
            self.assertEqual(ctx.exception.code, "CANARY_ONLY")
        with self.assertRaises(ce.ExecError) as ctx:                                   # even with the permit: no recorded owner run confirmation, no run
            cl.execute_live_slice(self.index, ACCT, ex["exec_id"], token, lm, _permit=live._BULK_PERMIT)
        self.assertEqual(ctx.exception.code, "SLICE_RUN_NOT_CONFIRMED")
        self.assertEqual((self.svc.log, self.svc.posts()), ([], 0))

    def test_a_slice_is_never_run_twice_and_a_second_runner_is_refused(self):
        plan, ex = self.prepare_bulk(40)
        phrase = self.run_phrase(ex)
        self.run_slice(ex, phrase=phrase)
        for _ in range(2):
            with self.assertRaises(ce.ExecError):
                self.run_slice(ex, phrase=phrase)
        self.assertEqual(self.svc.posts(), 40)                                          # 40 targets are ONE slice; it ran exactly once
        self.assertEqual(len([m for m in bulk._confirmations(self.index, ACCT) if m["exec"] == ex["exec_id"]]), 1)

    def test_a_concurrent_change_by_another_connection_is_noticed_not_cached(self):
        plan, ex = self.prepare_bulk(25)
        other = idx.Index()
        self.addCleanup(other.close)
        fired = []

        def another_process_protects_a_domain(f):
            if not fired:
                fired.append(True)
                cleanup_protect.add(other, ACCT, domain="shop.example.test", note="synthetic")
        self.svc.script.append(Step("GET_THREAD", nth=5, after=another_process_protects_a_domain))
        r = self.run_slice(ex)
        self.assertEqual((r.applied, r.posts), (5, 5))                                  # items 1-5 were archived before the protection rule existed
        self.assertEqual((r.skipped, ce.item_counts(self.index, ACCT, ex["exec_id"]).get("SKIPPED_DRIFT")), (20, 20))    # the rest is re-evaluated and skipped, never served from a stale cache
        self.assertEqual(self.svc.posts(), 5)

    def test_eligibility_is_evaluated_once_per_slice_not_once_per_item(self):
        plan, ex = self.prepare_bulk(100)
        calls = []
        real = cc.evaluate_all
        with mock.patch.object(cc, "evaluate_all", side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            r = self.run_slice(ex)
        self.assertEqual((r.applied, r.posts), (100, 100))
        self.assertLessEqual(len(calls), 3)                                             # 100 items, a handful of full evaluations (not 100)

    def test_a_larger_deterministic_run_of_the_maximum_plan_and_its_progress(self):
        type(self).N = 500
        try:
            self.setUp()
            plan, ex = self.prepare_bulk()
            self.assertEqual([s["size"] for s in ce.slices(self.index, ACCT, ex["exec_id"])], [25, 100, 100, 100, 100, 75])
            results = self.run_all(ex)
            self.assertEqual([r.applied for r in results], [25, 100, 100, 100, 100, 75])
            self.assertEqual((self.exec_row(ex)["state"], self.svc.posts(), len(self.archived_ids())), ("EXECUTED", 500, 500))
            self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        finally:
            type(self).N = 130


class CommandTests(BulkBase):
    def now(self):
        from datetime import datetime, timezone
        return self.clk() if hasattr(self, "clk") else datetime.now(timezone.utc)

    def run_cmd(self, *argv, typed=()):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(typed)
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")),
                   mock.patch.object(cli, "_tty_input", side_effect=lambda prompt: next(feed)), mock.patch.object(cp, "_utc", side_effect=lambda n: n if n is not None else self.now()),
                   mock.patch.object(ce, "_utc", side_effect=lambda n: n if n is not None else self.now()),
                   mock.patch.object(cli.config, "write_client_secret_path", lambda: self.client_path),
                   mock.patch.object(keystore_write, "WriteTokenStore", lambda: self.store)]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(["cleanup", *argv, "--account", ACCT])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_the_live_commands_refuse_before_the_index_credentials_or_network_while_disabled(self):
        plan = self.approved_plan(self.bids(5))
        before = self.snapshot()
        with mock.patch.object(idx, "Index", side_effect=AssertionError("the index must not be opened")), mock.patch.object(keystore_write, "WriteTokenStore", side_effect=AssertionError("store")):
            for argv in (("execute", plan["plan_id"], "--reserve"), ("exec", "run", "exec-00000000"), ("exec", "confirm", "exec-00000000")):
                self.assertEqual(self.run_cmd(*argv), (2, bulk_cli.DISABLED + "\n", ""), argv)
        self.assertEqual(self.snapshot(), before)
        code, out, err = self.run_cmd("execute", plan["plan_id"], "--dry-run")           # local preview stays available
        self.assertEqual((code, err), (0, ""))
        self.assertIn("slice sizes if executed", out)
        self.assertEqual(self.run_cmd("execute", plan["plan_id"])[0], 1)                  # neither --dry-run nor --reserve

    def test_the_complete_owner_workflow_through_the_cli_with_the_gate_enabled_over_the_fake_wire(self):
        plan = self.approved_plan(self.bids(130))
        self.enable()
        self.svc = fm._Service(ACCT, self.fake_state(), ())
        patcher = mock.patch.object(gw, "_default_connection", fm._Factory(self.svc))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = RecordingStore(self.blob())
        code, out, err = self.run_cmd("execute", plan["plan_id"], "--reserve", typed=["nope"])
        self.assertEqual(code, 1)
        code, out, err = self.run_cmd("execute", plan["plan_id"], "--reserve", typed=[ce.execution_phrase(plan, 25)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("slice 1 is confirmed", out)
        exec_id = ce.list_executions(self.index, ACCT)[0]["exec_id"]
        ex = ce.get_execution(self.index, ACCT, exec_id)
        self.assertEqual(self.run_cmd("exec", "run", exec_id, typed=["bad"])[0], 1)
        self.assertEqual(self.svc.posts(), 0)
        code, out, err = self.run_cmd("exec", "run", exec_id, typed=[self.run_phrase(ex)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("slice 1 finished: 25 archived", out)
        self.assertIn("cleanup exec confirm", out)
        self.assertEqual(self.run_cmd("exec", "run", exec_id, typed=["x"])[0], 1)          # slice 2 is not confirmed: it cannot run
        code, out, err = self.run_cmd("exec", "confirm", exec_id, typed=[ce.continuation_phrase(plan, 2, 100)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.svc.posts(), 25)                                               # confirming sent nothing
        code, out, err = self.run_cmd("exec", "show", exec_id)
        self.assertEqual(code, 0)
        self.assertNotRegex(out, r"18c0ffee|s\d+@")
        code, out, err = self.run_cmd("exec", "abort", exec_id, typed=[bulk_cli.abort_phrase(exec_id)])          # the owner stops here: local, needs no gate
        self.assertEqual(code, 0)
        self.assertEqual((self.exec_row(ex)["state"], self.svc.posts()), ("ABORTED", 25))
        self.assertEqual(len(self.archived_ids()), 25)

    def test_the_ordinary_cli_reaches_bulk_execution_only_through_the_gated_module(self):
        src = (SRC / "cli.py").read_text()
        for name in ("cleanup_bulk", "execute_live_slice", "run_bulk_slice", "_BULK_PERMIT", "LIVE_EXECUTION_ENABLED", "exec_live_mailbox"):
            self.assertNotIn(name, src)
        body = (SRC / "bulk_cli.py").read_text()
        self.assertLess(body.index("live.LIVE_EXECUTION_ENABLED is not True"), body.index("def go(index, account):"))


if __name__ == "__main__":
    unittest.main()
