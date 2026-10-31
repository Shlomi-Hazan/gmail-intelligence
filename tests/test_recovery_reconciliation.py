"""M12C.4: end-to-end SYNTHETIC acceptance of live-style recovery and reconciliation, DISABLED in this build. Fake Gmail wire and mocked credentials only: no Gmail, no OAuth, no Keychain, no
network. The live-OBSERVE gate is patched on for one test at a time; the archive and undo gates stay off (which is itself part of what is proved).

Scenarios (existing M4D/M12C.3 suites already cover the lower layers; these run the whole pathway through the real adapter, policy, trusted observations and the recovery engine):
archive succeeded / did not take effect / changed externally / message gone / interrupted; wrong account; cross-phase evidence; undo succeeded with a lost post-read / stays UNKNOWN / ends in
CONFLICT; credential failure; the disabled gates; audit validity; no mutation during reconciliation."""
import contextlib
import io
import sys
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_executor import AFTER, HEX, THREADS, LABELS, gerr  # noqa: E402
from test_undo_infrastructure import LiveUndoBase  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_exec_report as rep, cleanup_live as cl, cleanup_plans as cp, cleanup_recovery as cr  # noqa: E402
from gmail_intelligence import cleanup_undo as cu, cli, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, index as idx, keystore_write, reconcile_cli  # noqa: E402

Step = fm.Step


class Base(LiveUndoBase):
    def enable_observe(self):
        """Switch ONLY the live-observation gate on, with the controlled clock under the live mailbox and the adapter."""
        for target, name, value in ((live, "LIVE_OBSERVE_ENABLED", True), (live, "_utcnow", self.uc), (gw, "_utcnow", self.uc)):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def observer(self, mb, script=(), state=None, account=ACCT):
        return self.live_observe_mailbox(mb, script, state, account)

    def reads_only(self, svc):
        self.assertEqual((svc.posts(), svc.undos()), (0, 0))
        self.assertTrue({k for k, _ in svc.log} <= {"PROFILE", "GET_MESSAGE"}, svc.log)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class ArchiveRecoveryTests(Base):
    def crashed(self, apply):
        ex, mb = self.crashed_batch(apply)
        self.enable_observe()
        return ex, mb

    def test_1_archive_succeeded_and_the_post_read_was_lost(self):
        ex, mb = self.crashed(True)
        rows = [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")]
        om, svc = self.observer(mb)
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.interrupted, report.stopped, report.needs_owner), ((ex["exec_id"],), "", False))
        self.assertEqual((self.item(self.mid(2))["state"], self.exec_state(ex["exec_id"])), ("APPLIED", "PARTIAL"))
        self.reads_only(svc)
        self.assertEqual([tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")][:len(rows)], rows)    # append-only

    def test_2_the_archive_did_not_take_effect(self):
        ex, mb = self.crashed(False)
        om, svc = self.observer(mb)
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((self.item(self.mid(2))["state"], report.needs_owner), ("NOT_APPLIED", False))
        self.reads_only(svc)

    def test_3_labels_changed_externally_are_a_conflict_that_needs_the_owner(self):
        ex, mb = self.crashed(True)
        om, svc = self.observer(mb, [Step("GET_MESSAGE", before=lambda f: f.set_labels(self.mid(2), list(AFTER) + ["STARRED"]))])
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((self.item(self.mid(2))["state"], report.needs_owner, report.executions[0].unresolved), ("CONFLICT", True, (2,)))
        self.reads_only(svc)

    def test_4_a_message_that_disappeared_is_never_guessed_as_success(self):
        ex, mb = self.crashed(True)
        om, svc = self.observer(mb, [Step("GET_MESSAGE", before=lambda f: f.remove_message(self.mid(2)))])
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((self.item(self.mid(2))["state"], report.needs_owner), ("CONFLICT", True))      # an authoritative "absent" is neither applied nor unmodified
        self.reads_only(svc)

    def test_5_an_interrupted_execution_is_recovered_from_its_expired_lease_without_resuming(self):
        ex, mb = self.crashed(True)
        om, svc = self.observer(mb)
        before_posts = mb.service.posts()
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual(report.interrupted, (ex["exec_id"],))
        self.assertEqual(dict(report.executions[0].counts).get("NEVER_ATTEMPTED"), 2)        # the rest of the plan was never attempted, and still is not
        self.assertEqual((mb.service.posts(), svc.posts()), (before_posts, 0))
        self.reads_only(svc)

    def test_6_a_wrong_account_stops_everything_before_any_read_of_a_message(self):
        ex, mb = self.crashed(True)
        before = self.snapshot()
        om, svc = self.observer(mb, account=OTHER)                  # Gmail answers as another account
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.stopped, report.interrupted, report.needs_owner), ("ACCOUNT_NOT_VERIFIED", (), True))
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("GET_MESSAGE", [k for k, _ in svc.log])
        self.assertEqual(self.item(self.mid(2))["state"], "INTENT")

    def test_7_cross_phase_and_foreign_evidence_cannot_reconcile(self):
        ex, mb = self.crashed(True)
        cl.recover_observed(self.index, ACCT, self.observer(mb, [Step("GET_MESSAGE", raises=TimeoutError())])[0])           # leaves item 2 UNKNOWN
        self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")
        om, svc = self.observer(mb)
        om.verify_account()
        row = dict(ce.get_execution(self.index, ACCT, ex["exec_id"]))
        for context in (ce._context(row, self.mid(2), "POSTREAD", row["lease_token"] or ""), ce._context(row, self.mid(1), "RECONCILE", "x"), "something-else"):
            obs = om.observe(self.mid(2), context=context)
            with self.assertRaises(ce.ExecError) as ctx:
                ce.reconcile_item(self.index, ACCT, ex["exec_id"], self.mid(2), obs, now=self.uc(), require_source=ce.TRUSTED_EVIDENCE_SOURCE)
            self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")                  # still unknown: only the exact bound context can settle it

    def test_9_an_unobservable_item_stays_unknown_and_the_report_says_so(self):
        ex, mb = self.crashed(True)
        om, svc = self.observer(mb, [Step("GET_MESSAGE", status=503, body=b"x")])
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((self.item(self.mid(2))["state"], report.needs_owner), ("UNKNOWN", True))
        self.assertIn("still unresolved", " ".join(report.executions[0].notes))
        self.reads_only(svc)

    def test_11_a_credential_failure_fails_closed_and_changes_nothing(self):
        ex, mb = self.crashed(True)
        before = self.snapshot()
        om, svc = self.observer(mb)
        svc.creds.live = False                                       # expired / unusable credentials: the transport stops before anything is sent
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.stopped, svc.log, self.snapshot()), ("ACCOUNT_NOT_VERIFIED", [], before))
        om2, svc2 = self.observer(mb, [Step("GET_MESSAGE", status=401, body=gerr(401)[1])])
        report = cl.recover_observed(self.index, ACCT, om2)           # authorization lost mid-run
        self.assertIn(report.stopped, ("AUTH_PROBLEM", "ACCOUNT_NOT_VERIFIED"))
        self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")


class UndoReconciliationTests(Base):
    def unknown_undo(self, script):
        ex, mb = self.archived()
        self.enable_undo()
        lm, svc = self.live_undo(mb, script)
        self.authorize(ex, 1)
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "UNKNOWN")
        self.enable_observe()
        return ex, mb, svc

    def test_8_an_undo_that_succeeded_but_lost_its_post_read_is_reconciled_read_only(self):
        ex, mb, usvc = self.unknown_undo([Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        with mock.patch.object(live, "LIVE_UNDO_ENABLED", False), mock.patch.object(live, "LIVE_EXECUTION_ENABLED", False):    # the mutation gates are off; observation needs only its own
            om, svc = self.observer(mb, state=self.current(usvc))
            report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.undos_resolved, report.undos, cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), (1, (), "RESTORED"))
        self.reads_only(svc)
        self.assertEqual(usvc.undos(), 1)                                               # exactly the one original mutation

    def test_9b_an_undo_with_no_usable_observation_stays_unknown_and_is_reported(self):
        ex, mb, usvc = self.unknown_undo([Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        om, svc = self.observer(mb, [Step("GET_MESSAGE", raises=TimeoutError())], state=self.current(usvc))
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.undos, report.needs_owner, cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), (((ex["exec_id"], 1, "UNKNOWN"),), True, "UNKNOWN"))
        with self.assertRaises(ce.ExecError) as ctx:
            cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 1, self.observer(mb, [Step("GET_MESSAGE", status=503, body=b"x")], state=self.current(usvc))[0])
        self.assertEqual(ctx.exception.code, "NO_EVIDENCE")
        self.reads_only(svc)

    def test_10_a_conflicting_undo_reconciliation_stays_visible_for_manual_action(self):
        ex, mb, usvc = self.unknown_undo([Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        st = self.current(usvc)
        st[self.mid(1)] = (st[self.mid(1)][0], list(LABELS) + ["STARRED"])
        om, svc = self.observer(mb, state=st)
        res = cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 1, om)
        self.assertEqual((res.status, res.mutations), ("CONFLICT", 0))
        data = rep.recovery_data(self.index, ACCT, self.uc())
        self.assertEqual([(u["status"], u["category"]) for u in data["undos"]], [("CONFLICT", "conflict")])
        self.assertTrue(data["needs_owner"])
        self.reads_only(svc)

    def test_an_inconsistent_undo_ledger_is_detected_reported_and_never_acted_on(self):
        ex, mb = self.archived()
        self.enable_observe()
        cp_iso = cp._iso(self.uc())
        with cp._txn(self.index):                                    # two intents without an authorization between them: a sequence the state machine does not allow
            for kind in ("UNDO_INTENT", "UNDO_INTENT"):
                audit.append(self.index, ACCT, ex["plan_id"], kind, cp_iso, {"exec": ex["exec_id"], "item": 1, "auth": "0" * 64, "t": cp_iso})
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "INCONSISTENT")
        om, svc = self.observer(mb)
        report = cl.recover_observed(self.index, ACCT, om)
        self.assertEqual((report.undos, report.needs_owner), (((ex["exec_id"], 1, "INCONSISTENT"),), True))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "INCONSISTENT")
        self.assertEqual([k for k, _ in svc.log if k not in ("PROFILE",)], [])                  # nothing was even read for it
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class GateTests(Base):
    def test_12_the_observation_gate_is_a_false_source_constant_independent_of_the_others(self):
        self.assertIs(live.LIVE_OBSERVE_ENABLED, False)
        text = (SRC / "exec_live_mailbox.py").read_text()
        import ast
        assigned = [(t.id, getattr(n.value, "value", None)) for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name) and t.id.startswith("LIVE_")]
        self.assertEqual(sorted(assigned), [("LIVE_EXECUTION_ENABLED", False), ("LIVE_OBSERVE_ENABLED", False), ("LIVE_UNDO_ENABLED", False)])
        for name in ("exec_live_mailbox.py", "reconcile_cli.py", "cleanup_live.py"):
            self.assertNotRegex((SRC / name).read_text(), r"os\.environ|getenv")

    def test_12b_a_disabled_observation_fails_closed_before_any_request_or_credential_access(self):
        ex, mb = self.crashed_batch(True)
        self.enable_observe()
        om, svc = self.observer(mb)
        before = self.snapshot()
        with mock.patch.object(live, "LIVE_OBSERVE_ENABLED", False):
            for call in (lambda: cl.recover_observed(self.index, ACCT, om), lambda: cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 1, om)):
                with self.assertRaises(ce.ExecError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, "LIVE_OBSERVE_DISABLED")
            with self.assertRaises(live.LiveObserveDisabled):
                om.observe(self.mid(2), context="x")
            store = mock.MagicMock()
            with self.assertRaises(live.LiveObserveDisabled):
                live.open_live_observe_mailbox(ACCT, store, "x")
            store.load.assert_not_called()
        self.assertEqual((svc.log, self.snapshot()), ([], before))

    def test_13_archive_and_undo_gates_do_not_enable_observation_and_observation_cannot_mutate(self):
        ex, mb = self.crashed_batch(True)
        with mock.patch.object(live, "LIVE_EXECUTION_ENABLED", True), mock.patch.object(live, "LIVE_UNDO_ENABLED", True):
            with self.assertRaises(live.LiveObserveDisabled):
                self.observer(mb)                                    # both mutation switches on: still no observation
        self.enable_observe()
        om, svc = self.observer(mb)
        self.assertFalse(hasattr(om, "archive_message") or hasattr(om, "restore_inbox"))
        self.assertEqual(om._adapter._t._caps, frozenset({"OBSERVE"}))
        for call in (lambda: om._adapter.archive_message(self.mid(2)), lambda: om._adapter.restore_inbox(self.mid(2))):
            om._adapter._verified = True
            with self.assertRaises(gw.Denied) as ctx:
                call()
            self.assertEqual((ctx.exception.code, gw.definitely_not_dispatched(ctx.exception)), ("DENIED_CAPABILITY", True))
        for kind in ("MESSAGE_MODIFY", "MESSAGE_MODIFY_UNDO"):
            with self.assertRaises(gw.Denied):
                om._adapter._t._require_capability(kind)
        self.assertEqual(svc.log, [])
        for mailbox in (om,):                                        # the mutation entry points refuse an observe mailbox, and vice versa
            for call in (lambda: cl.undo_live(self.index, ACCT, ex["exec_id"], 1, mailbox), lambda: cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, mailbox),
                         lambda: cl.recover_live(self.index, ACCT, mailbox), lambda: cu.undo_item(self.index, ACCT, ex["exec_id"], 1, mailbox)):
                with self.assertRaises(ce.ExecError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        with self.assertRaises(ce.ExecError) as ctx:
            cl.recover_observed(self.index, ACCT, self.umb(mb))      # a fake or mutation-capable mailbox is not an observe mailbox
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")

    def test_the_local_status_needs_no_gate_and_no_gmail(self):
        ex, mb = self.crashed_batch(True)
        data = rep.recovery_data(self.index, ACCT, self.uc())
        self.assertEqual((data["executions"][0]["unknown"], data["gmail_contacted"]), (1, False))


class CliTests(Base):
    def run_cmd(self, *argv, typed=(), observe_mailbox=None):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(typed)
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")),
                   mock.patch.object(cli, "_write_store", side_effect=AssertionError("write Keychain used")), mock.patch.object(cli, "_tty_input", side_effect=lambda prompt: next(feed)),
                   mock.patch.object(cp, "_utc", side_effect=lambda n: n if n is not None else self.uc()), mock.patch.object(keystore_write, "WriteTokenStore", mock.MagicMock())]
        if observe_mailbox is not None:
            patches.append(mock.patch.object(live, "open_live_observe_mailbox", return_value=observe_mailbox))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(["cleanup", *argv, "--account", ACCT])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_12c_the_live_commands_refuse_before_the_index_credentials_or_network_while_disabled(self):
        ex, mb = self.crashed_batch(True)
        before = self.snapshot()
        with mock.patch.object(idx, "Index", side_effect=AssertionError("the index must not be opened")):
            for argv in (("exec", "recovery", "--reconcile"), ("undo", "reconcile", ex["exec_id"], "1")):
                self.assertEqual(self.run_cmd(*argv), (2, reconcile_cli.DISABLED + "\n", ""), argv)
        self.assertEqual(self.snapshot(), before)
        code, out, err = self.run_cmd("exec", "recovery")                                    # the local status stays available
        self.assertEqual((code, err), (0, ""))
        self.assertIn("UNKNOWN: 1", out)

    def test_the_owner_workflow_needs_a_typed_intent_and_reports_privacy_safely(self):
        ex, mb = self.crashed_batch(True)
        self.enable_observe()
        om, svc = self.observer(mb)
        code, out, err = self.run_cmd("exec", "recovery", "--reconcile", typed=["yes"], observe_mailbox=om)
        self.assertEqual(code, 1)
        self.assertIn("declined", err)
        self.assertEqual(svc.log, [])                                                         # nothing was read without the typed intent
        code, out, err = self.run_cmd("exec", "recovery", "--reconcile", typed=[reconcile_cli.OBSERVE_PHRASE], observe_mailbox=om)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Recovery report", out)
        self.assertIn("Nothing was retried, archived or restored", out)
        for private in (ACCT, OTHER, "example", "INBOX", *HEX, *THREADS, ex["plan_id"]):
            self.assertNotIn(private, out)
        self.reads_only(svc)

    def test_the_ordinary_cli_cannot_reach_observation_except_through_the_gated_module(self):
        src = (SRC / "cli.py").read_text()
        for name in ("exec_live_mailbox", "cleanup_live", "LiveObserveMailbox", "LIVE_OBSERVE_ENABLED", "open_live_observe_mailbox", "recover_observed", "reconcile_undo_observed",
                     "cleanup_recovery", "cleanup_undo", "observe"):
            self.assertNotIn(name, src)
        body = (SRC / "reconcile_cli.py").read_text()
        self.assertLess(body.index("live.LIVE_OBSERVE_ENABLED is not True"), body.index("with_index(args, go)"))


if __name__ == "__main__":
    unittest.main()
