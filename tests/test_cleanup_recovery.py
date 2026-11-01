"""Tests for M4D: the recovery workflow and the owner-approved FAKE undo (`cleanup_recovery`, `cleanup_undo`).

Synthetic only: a synthetic account, the in-memory fake mailbox (real adapter code over a connection class that never touches a socket; its undo exists only in memory),
controlled step clocks and temporary SQLite databases. Nothing contacts Gmail.
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

import test_cleanup_batch as TB  # noqa: E402
import test_write_transport as TWT  # noqa: E402
from test_cleanup import ACCT, OTHER, msg  # noqa: E402
from test_cleanup_batch import Crash, IDS  # noqa: E402
from test_cleanup_executor import AFTER, HEX, LABELS, StepClock, THREADS, gerr  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_executor as cx, cleanup_plans as cp, cleanup_recovery as cr  # noqa: E402
from gmail_intelligence import cleanup_undo as cu, exec_fake_mailbox as fm, gmail_write as gw, gmail_write_policy as pol  # noqa: E402

Step = fm.Step


class RecoveryBase(TB.BatchBase):
    def crashed_batch(self, apply=True):
        """A batch whose process died while the second item's POST was in flight."""
        ex = self.batch_execution()
        mb = self.mailbox([Step("POST", nth=2, raises=Crash(), apply=apply)])
        with self.assertRaises(Crash):
            cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)
        self.uc = StepClock(self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=10))
        return ex, mb

    def umb(self, mb, script=(), account=ACCT, state=None):
        st = state or {m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}
        return fm.FakeMailbox(account, st, clock=self.uc, script=script)

    def mid(self, seq):
        return sorted(IDS)[seq - 1]


class RecoveryTests(RecoveryBase):
    def test_an_interrupted_execution_is_recovered_and_reconciled_from_a_fresh_observation_without_any_mutation(self):
        for apply, state in ((True, "APPLIED"), (False, "NOT_APPLIED")):
            with self.subTest(apply=apply):
                self.setUp()
                ex, mb = self.crashed_batch(apply)
                fresh = self.umb(mb)
                report = cr.recover(self.index, ACCT, fresh)
                self.assertEqual(report.interrupted, (ex["exec_id"],))
                (er,) = report.executions
                self.assertEqual((er.state, er.resolved_now, er.unresolved), ("PARTIAL", 1, ()))
                self.assertEqual(dict(er.counts), {"APPLIED": 2 if apply else 1, "NEVER_ATTEMPTED": 2, **({} if apply else {"NOT_APPLIED": 1})})
                self.assertEqual(self.item(self.mid(2))["state"], state)
                self.assertEqual((fresh.service.posts(), fresh.service.undos()), (0, 0))  # recovery never mutates
                self.assertFalse(report.needs_owner)
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
                again = cr.recover(self.index, ACCT, self.umb(mb))  # nothing left to do
                self.assertEqual((again.interrupted, again.executions[0].resolved_now if again.executions else 0), ((), 0))

    def test_without_usable_evidence_the_item_stays_unknown_and_the_report_says_so(self):
        cases = (("a read failure", Step("GET_MESSAGE", raises=TimeoutError())), ("an unconfirmed 404", Step("GET_MESSAGE", status=404, body=b"<html>")),
                 ("a 5xx", Step("GET_MESSAGE", status=503, body=b"x")))
        for label, step in cases:
            with self.subTest(label):
                self.setUp()
                ex, mb = self.crashed_batch()
                report = cr.recover(self.index, ACCT, self.umb(mb, [step]))
                self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")
                (er,) = report.executions
                self.assertEqual((er.state, er.unresolved, er.resolved_now), ("RECONCILIATION_REQUIRED", (2,), 0))
                self.assertTrue(report.needs_owner)
                self.assertIn("still unresolved", " ".join(er.notes))

    def test_a_conflicting_observation_is_resolved_as_conflict_and_still_needs_the_owner(self):
        ex, mb = self.crashed_batch()
        report = cr.recover(self.index, ACCT, self.umb(mb, [Step("GET_MESSAGE", before=lambda f: f.set_labels(self.mid(2), list(AFTER) + ["STARRED"]))]))
        self.assertEqual(self.item(self.mid(2))["state"], "CONFLICT")
        self.assertEqual(report.executions[0].unresolved, (2,))
        self.assertTrue(report.needs_owner)

    def test_another_account_or_an_unverifiable_account_fails_closed(self):
        ex, mb = self.crashed_batch()
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            cr.recover(self.index, ACCT, self.umb(mb, account=OTHER))
        self.assertEqual((ctx.exception.code, self.snapshot()), ("ACCOUNT_MISMATCH", before))
        wrong = json.dumps({"emailAddress": OTHER}).encode()
        other = self.umb(mb, [Step("PROFILE", status=200, body=wrong)])
        report = cr.recover(self.index, ACCT, other)
        self.assertEqual(report.stopped, "ACCOUNT_NOT_VERIFIED")
        self.assertEqual(self.item(self.mid(2))["state"], "INTENT")  # not even the local recovery transition was made
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(report.interrupted, ())
        self.assertNotIn("GET_MESSAGE", [k for k, _ in other.service.log])  # no observation was even requested
        self.assertTrue(report.needs_owner)

    def test_an_authorization_problem_while_reading_stops_the_whole_recovery(self):
        ex, mb = self.crashed_batch()
        report = cr.recover(self.index, ACCT, self.umb(mb, [Step("GET_MESSAGE", status=401, body=gerr(401)[1])]))
        self.assertIn(report.stopped, ("AUTH_PROBLEM", "ACCOUNT_NOT_VERIFIED"))
        self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")

    def test_a_database_failure_stops_recovery_and_leaves_the_item_unknown(self):
        ex, mb = self.crashed_batch()
        with mock.patch.object(ce, "reconcile_item", side_effect=sqlite3.OperationalError("disk I/O error")):
            report = cr.recover(self.index, ACCT, self.umb(mb))
        self.assertEqual(report.stopped, "DATABASE_ERROR")
        self.assertEqual(self.item(self.mid(2))["state"], "UNKNOWN")
        self.assertTrue(report.needs_owner)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_an_execution_with_a_live_lease_is_never_touched(self):
        ex = self.batch_execution()
        before = self.snapshot()
        report = cr.recover(self.index, ACCT, self.mailbox())
        self.assertEqual(report.interrupted, ())
        (er,) = report.executions
        self.assertEqual(er.state, "EXECUTING")
        self.assertIn("in progress", " ".join(er.notes))
        self.assertEqual(self.snapshot()[0], before[0])
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTING")

    def test_the_status_report_is_read_only_and_the_text_report_is_privacy_safe(self):
        ex, mb = self.crashed_batch()
        before = self.snapshot()
        status = cr.status_report(self.index, ACCT)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(status.needs_owner)
        report = cr.recover(self.index, ACCT, self.umb(mb, [Step("GET_MESSAGE", raises=TimeoutError())]))
        text = cr.format_report(report) + cr.format_report(status)
        for private in (ACCT, OTHER, "example", "CATEGORY_PROMOTIONS", "INBOX", *HEX, *THREADS, ex["plan_id"]):
            self.assertNotIn(private, text)
        self.assertIn("OWNER ACTION REQUIRED", text)
        self.assertIn("items 2", text)

    def test_a_real_adapter_or_a_rewired_mailbox_is_refused(self):
        ex, mb = self.crashed_batch()
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        before = self.snapshot()
        for other in (TWT.adapter(net, expected=ACCT), object(), None):
            with self.assertRaises(ce.ExecError) as ctx:
                cr.recover(self.index, ACCT, other)
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        rewired = self.umb(mb)
        setattr(rewired._adapter._t, "_factory", net)
        with self.assertRaises(ce.ExecError):
            cr.recover(self.index, ACCT, rewired)
        self.assertEqual((net.opened, net.log, self.snapshot()), (0, [], before))


class UndoBase(RecoveryBase):
    def archived(self, ids=IDS[:2]):
        ex = self.batch_execution(ids)
        mb = self.mailbox()
        self.run_batch(ex, mb)
        self.uc = StepClock(self.step_clock.at + timedelta(seconds=60))
        return ex, mb

    def phrase(self, ex, seq):
        return cu.undo_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"], seq)

    def authorize(self, ex, seq=1):
        return cu.authorize_undo(self.index, ACCT, ex["exec_id"], seq, self.phrase(ex, seq), now=self.uc())

    def undo(self, ex, mb, seq=1):
        return cu.undo_item(self.index, ACCT, ex["exec_id"], seq, mb)

    def undo_events(self):
        return [(r["event_type"], json.loads(r["meta"])) for r in self.index._q("SELECT event_type, meta FROM cleanup_audit WHERE event_type LIKE 'UNDO_%' ORDER BY seq")]

    def history(self):
        return ([tuple(r) for r in self.index._q("SELECT * FROM cleanup_exec_item ORDER BY message_id")], [tuple(r) for r in self.index._q("SELECT * FROM cleanup_execution")],
                self.index._q("SELECT COUNT(*) FROM cleanup_audit WHERE event_type NOT LIKE 'UNDO_%'")[0][0])


class UndoSuccessTests(UndoBase):
    def test_an_authorized_undo_restores_only_inbox_and_never_rewrites_the_archive_history(self):
        ex, mb = self.archived()
        history = self.history()
        before_labels = {m: set(l) for m, (t, l) in mb.service.messages.items()}
        self.assertEqual(self.authorize(ex, 1), "AUTHORIZED")
        um = self.umb(mb)
        res = self.undo(ex, um, 1)
        self.assertEqual((res.status, res.mutations), ("RESTORED", 1))
        mid = self.mid(1)
        self.assertEqual(um.service.messages[mid][1], set(LABELS))  # INBOX is back and the unrelated label is preserved
        self.assertEqual(um.service.messages[self.mid(2)][1], before_labels[self.mid(2)])  # the other archived item is untouched
        self.assertEqual((um.service.undos(), um.service.posts()), (1, 0))
        self.assertEqual(self.history(), history)  # the original execution, item rows, evidence and archive audit events are unchanged
        self.assertEqual(self.item(mid)["state"], "APPLIED")
        types = [t for t, _ in self.undo_events()]
        self.assertEqual(types, ["UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT"])
        result = self.undo_events()[-1][1]
        self.assertEqual((result["result"], result["via"], result["src"]), ("RESTORED", "DIRECT", "TRUSTED_ADAPTER"))
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "RESTORED")
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 2), "NONE")

    def test_the_undo_events_carry_no_message_ids_labels_or_the_phrase(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        self.undo(ex, self.umb(mb), 1)
        text = json.dumps(self.undo_events())
        for private in (*HEX, *THREADS, "INBOX", "CATEGORY_PROMOTIONS", ACCT, self.phrase(ex, 1)):
            self.assertNotIn(private, text)

    def test_an_item_is_undone_at_most_once_and_cannot_be_authorized_again_after_success(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        um = self.umb(mb)
        self.undo(ex, um, 1)
        for call in (lambda: self.undo(ex, um, 1), lambda: self.authorize(ex, 1)):
            with self.assertRaises(ce.ExecError) as ctx:
                call()
            self.assertIn(ctx.exception.code, ("UNDO_NOT_AUTHORIZED", "UNDO_NOT_ALLOWED"))
        self.assertEqual(um.service.undos(), 1)


class UndoRefusalTests(UndoBase):
    def test_no_undo_without_a_separate_owner_authorization(self):
        ex, mb = self.archived()
        history = self.history()
        um = self.umb(mb)
        with self.assertRaises(ce.ExecError) as ctx:
            self.undo(ex, um, 1)
        self.assertEqual(ctx.exception.code, "UNDO_NOT_AUTHORIZED")
        self.assertEqual((um.service.undos(), um.service.log, self.undo_events()), (0, [], []))
        plan = cp.get_plan(self.index, ACCT, ex["plan_id"])
        for wrong in (cp.approval_phrase(plan), ce.execution_phrase(plan, 4), "", "UNDO", self.phrase(ex, 2), self.phrase(ex, 1).lower(), None):
            with self.assertRaises(ce.ExecError) as ctx:
                cu.authorize_undo(self.index, ACCT, ex["exec_id"], 1, wrong, now=self.uc())
            self.assertIn(ctx.exception.code, ("BAD_CONFIRMATION", "LOCKED_OUT"))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "NONE")
        self.assertEqual(self.history(), history)

    def test_repeated_wrong_phrases_are_locked_out_and_recorded(self):
        ex, mb = self.archived()
        codes = []
        for _ in range(cp.MAX_FAILED_ATTEMPTS + 2):
            with self.assertRaises(ce.ExecError) as ctx:
                cu.authorize_undo(self.index, ACCT, ex["exec_id"], 1, "nope", now=self.uc())
            codes.append(ctx.exception.code)
        self.assertEqual(codes[-1], "LOCKED_OUT")
        with self.assertRaises(ce.ExecError) as ctx:  # even the right phrase is refused while locked out
            self.authorize(ex, 1)
        self.assertEqual(ctx.exception.code, "LOCKED_OUT")
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_only_a_verified_archive_can_be_undone(self):
        ex = self.batch_execution()
        with self.assertRaises(ce.ExecError) as ctx:  # the execution is still running
            cu.authorize_undo(self.index, ACCT, ex["exec_id"], 1, "x", now=self.t + timedelta(seconds=5))
        self.assertEqual(ctx.exception.code, "EXECUTION_RUNNING")
        # a skipped, a pending, an unknown and a caller-supplied item are not undoable
        mb = self.mailbox([Step("GET_MESSAGE", nth=1, before=lambda f: f.set_labels(self.mid(1), list(LABELS) + ["STARRED"])), Step("POST", nth=1, raises=TimeoutError())])
        cx.execute_batch(self.index, ACCT, ex["exec_id"], self.token, mb)  # item 1 skipped, item 2 UNKNOWN, items 3-4 never attempted
        self.uc = StepClock(self.step_clock.at + timedelta(seconds=30))
        for seq in (1, 2, 3, 4):
            with self.assertRaises(ce.ExecError) as ctx:
                cu.authorize_undo(self.index, ACCT, ex["exec_id"], seq, "x", now=self.uc())
            self.assertEqual(ctx.exception.code, "NOT_UNDOABLE", seq)
        with self.assertRaises(ce.ExecError) as ctx:
            cu.authorize_undo(self.index, ACCT, ex["exec_id"], 99, "x", now=self.uc())
        self.assertEqual(ctx.exception.code, "NO_SUCH_ITEM")

    def test_an_item_recorded_with_caller_supplied_evidence_is_not_undoable(self):
        ex = self.started(self.approved_plan([HEX[0]]))
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, HEX[0], LABELS, now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, HEX[0], "APPLIED", evidence=self.ev(HEX[0], AFTER), now=self.tick())
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        with self.assertRaises(ce.ExecError) as ctx:
            cu.authorize_undo(self.index, ACCT, ex["exec_id"], 1, "x", now=self.tick())
        self.assertEqual(ctx.exception.code, "NOT_UNDOABLE")

    def test_changed_or_protected_state_is_refused_before_any_mutation_and_the_authorization_survives(self):
        cases = (("labels changed", lambda f: f.set_labels(self.mid(1), list(AFTER) + ["STARRED"]), "UNDO_DRIFT"),
                 ("already back in the inbox", lambda f: f.set_labels(self.mid(1), list(LABELS)), "UNDO_DRIFT"),
                 ("lost its other label", lambda f: f.set_labels(self.mid(1), []), "UNDO_DRIFT"),
                 ("a new message joined the thread", lambda f: f.add_message(HEX[6], THREADS[0], ["INBOX"]), "UNDO_DRIFT"),
                 ("the message is gone", lambda f: f.remove_message(self.mid(1)), "UNDO_PREFLIGHT_FAILED"))
        for label, change, code in cases:
            with self.subTest(label):
                self.setUp()
                ex, mb = self.archived()
                self.authorize(ex, 1)
                um = self.umb(mb, [Step("GET_MESSAGE", before=change)])
                with self.assertRaises(ce.ExecError) as ctx:
                    self.undo(ex, um, 1)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual((um.service.undos(), cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), (0, "AUTHORIZED"))
                self.assertNotIn("UNDO_INTENT", [t for t, _ in self.undo_events()])

    def test_an_expired_authorization_or_another_account_changes_nothing(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        late = fm.FakeMailbox(ACCT, {m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}, clock=StepClock(self.uc.at + cu.UNDO_AUTH_TTL + timedelta(minutes=1)))
        with self.assertRaises(ce.ExecError) as ctx:
            self.undo(ex, late, 1)
        self.assertEqual((ctx.exception.code, late.service.log), ("UNDO_AUTH_EXPIRED", []))
        with self.assertRaises(ce.ExecError) as ctx:
            self.undo(ex, self.umb(mb, account=OTHER), 1)
        self.assertEqual(ctx.exception.code, "ACCOUNT_MISMATCH")
        wrong = self.umb(mb, [Step("PROFILE", status=200, body=json.dumps({"emailAddress": OTHER}).encode())])
        with self.assertRaises(ce.ExecError) as ctx:
            self.undo(ex, wrong, 1)
        self.assertEqual((ctx.exception.code, wrong.service.undos()), ("UNDO_PREFLIGHT_FAILED", 0))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "AUTHORIZED")

    def test_a_real_adapter_look_alike_or_rewired_mailbox_cannot_undo(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        for other in (TWT.adapter(net, expected=ACCT), object(), None, mock.MagicMock(spec=fm.FakeMailbox)):
            with self.assertRaises(ce.ExecError) as ctx:
                self.undo(ex, other, 1)
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        rewired = self.umb(mb)
        setattr(rewired._adapter._t, "_factory", net)
        with self.assertRaises(ce.ExecError):
            self.undo(ex, rewired, 1)
        self.assertEqual((net.opened, net.log), (0, []))
        self.assertTrue(hasattr(gw.ArchiveAdapter, "restore_inbox"))  # M12C.3: the real adapter has the undo operation, but this public fake-only entry point never accepts it (above)


class UndoUncertaintyTests(UndoBase):
    def run_undo(self, step):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        um = self.umb(mb, [step] if step else [])
        return ex, mb, um

    def test_an_ambiguous_mutation_is_unknown_never_retried_and_reconciled_from_evidence(self):
        cases = ((Step("UNDO", raises=TimeoutError(), apply=True), "TIMEOUT", True), (Step("UNDO", raises=ConnectionResetError(), apply=False), "NETWORK_ERROR", False),
                 (Step("UNDO", status=503, body=b"x", apply=True), "SERVER_ERROR", True), (Step("UNDO", status=429, body=gerr(429)[1], apply=False), "AMBIGUOUS_RESULT", False),
                 (Step("UNDO", status=400, body=gerr(400)[1], apply=False), "AMBIGUOUS_RESULT", False), (Step("UNDO", status=200, body=b"not json", apply=True), "AMBIGUOUS_RESULT", True),
                 (Step("UNDO", raises=RuntimeError("synthetic"), apply=False), "AMBIGUOUS_RESULT", False))
        for step, code, applied in cases:
            with self.subTest(step.status or step.raises):
                self.setUp()
                ex, mb, um = self.run_undo(step)
                res = self.undo(ex, um, 1)
                self.assertEqual((res.status, res.code, res.mutations, um.service.undos()), ("UNKNOWN", code, 1, 1))
                with self.assertRaises(ce.ExecError) as ctx:  # never an automatic retry, and the authorization is used up
                    self.undo(ex, um, 1)
                self.assertEqual(ctx.exception.code, "UNDO_NOT_AUTHORIZED")
                with self.assertRaises(ce.ExecError):
                    self.authorize(ex, 1)
                um.service.script.clear()
                res2 = cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)
                self.assertEqual((res2.status, res2.mutations), ("RESTORED" if applied else "NOT_RESTORED", 0))
                self.assertEqual(um.service.undos(), 1)  # the reconciliation made no mutation
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_a_refusal_proven_to_be_before_dispatch_is_not_restored_and_allows_a_fresh_authorization(self):
        ex, mb, um = self.run_undo(Step("GET_THREAD", after=lambda f: setattr(f.creds, "live", False)))
        res = self.undo(ex, um, 1)
        self.assertEqual((res.status, res.code, res.mutations, um.service.undos()), ("NOT_RESTORED", "REJECTED", 0, 0))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "NOT_RESTORED")
        um.service.creds.live = True
        self.authorize(ex, 1)  # a NEW owner authorization is possible after a proven non-mutation
        self.assertEqual(self.undo(ex, um, 1).status, "RESTORED")
        self.assertEqual(um.service.undos(), 1)

    def test_a_failed_or_mismatching_post_read_is_unknown_not_restored(self):
        cases = ((Step("GET_MESSAGE", nth=2, raises=TimeoutError()),), (Step("GET_MESSAGE", nth=2, status=500, body=b"x"),),
                 (Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid(1), list(LABELS) + ["STARRED"])),),
                 (Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid(1), list(AFTER))),), (Step("GET_MESSAGE", nth=2, before=lambda f: f.remove_message(self.mid(1))),))
        for (step,) in cases:
            with self.subTest(step):
                self.setUp()
                ex, mb, um = self.run_undo(step)
                res = self.undo(ex, um, 1)
                self.assertEqual((res.status, um.service.undos()), ("UNKNOWN", 1))
                self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "UNKNOWN")

    def test_a_crash_before_the_intent_leaves_the_authorization_and_no_mutation(self):
        ex, mb, um = self.run_undo(Step("GET_THREAD", raises=Crash()))
        with self.assertRaises(Crash):
            self.undo(ex, um, 1)
        self.assertEqual((um.service.undos(), cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), (0, "AUTHORIZED"))
        um.service.script.clear()
        self.assertEqual(self.undo(ex, um, 1).status, "RESTORED")

    def test_a_crash_after_the_intent_or_during_or_after_the_mutation_is_open_and_resolved_by_observation_only(self):
        cases = (("during the mutation (not applied)", Step("UNDO", raises=Crash(), apply=False), None, False),
                 ("during the mutation (applied)", Step("UNDO", raises=Crash(), apply=True), None, True),
                 ("after the mutation, before the result", None, "_validated", True))
        for label, step, patched, applied in cases:
            with self.subTest(label):
                self.setUp()
                ex, mb, um = self.run_undo(step)
                ctxm = mock.patch.object(cu, patched, side_effect=Crash()) if patched else mock.patch.object(cu, "_unknown", wraps=cu._unknown)
                with ctxm:
                    with self.assertRaises(Crash):
                        self.undo(ex, um, 1)
                self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "OPEN")
                self.assertEqual(um.service.undos(), 1)
                self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_AUTHORIZED", "UNDO_INTENT"])
                with self.assertRaises(ce.ExecError) as ctx:  # an open intent blocks any second attempt
                    self.undo(ex, self.umb(mb, state={m: (t, list(l)) for m, (t, l) in um.service.messages.items()}), 1)
                self.assertEqual(ctx.exception.code, "UNDO_NOT_AUTHORIZED")
                fresh = self.umb(mb, state={m: (t, list(l)) for m, (t, l) in um.service.messages.items()})
                report = cr.recover(self.index, ACCT, fresh)
                self.assertEqual((report.undos_resolved, report.undos, fresh.service.undos()), (1, (), 0))
                self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "RESTORED" if applied else "NOT_RESTORED")

    def test_a_database_failure_after_the_mutation_leaves_an_open_intent_and_never_a_second_mutation(self):
        ex, mb, um = self.run_undo(None)
        with mock.patch.object(cu, "_record", side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(sqlite3.OperationalError):
                self.undo(ex, um, 1)
        self.assertEqual((cu.undo_status(self.index, ACCT, ex["exec_id"], 1), um.service.undos()), ("OPEN", 1))
        self.assertEqual(cr.status_report(self.index, ACCT).undos, ((ex["exec_id"], 1, "OPEN"),))
        self.assertEqual(cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um).status, "RESTORED")
        self.assertEqual(um.service.undos(), 1)

    def test_reconciliation_needs_fresh_bound_evidence_and_an_unresolved_undo_stays_open(self):
        ex, mb, um = self.run_undo(Step("UNDO", raises=TimeoutError(), apply=True))
        self.undo(ex, um, 1)
        um.service.script[:] = [Step("GET_MESSAGE", nth=um.service.counts["GET_MESSAGE"] + 1, raises=TimeoutError())]
        with self.assertRaises(ce.ExecError) as ctx:
            cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)
        self.assertEqual(ctx.exception.code, "NO_EVIDENCE")
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "UNKNOWN")
        um.service.script.clear()
        with self.assertRaises(ce.ExecError):
            cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 2, um)  # item 2 has nothing to reconcile
        um.verify_account()
        # observations made for another phase, another intent or the archive cannot reconcile it
        row = dict(ce.get_execution(self.index, ACCT, ex["exec_id"]))
        for context in (ce._context(row, self.mid(1), "POSTREAD", row["lease_token"] or ""), ce._context(row, self.mid(1), "UNDO_RECONCILE", "0" * 64),
                        ce._context(row, self.mid(1), "UNDO_POSTREAD", "0" * 64)):
            obs = um.observe(self.mid(1), context=context)
            with self.assertRaises(ce.ExecError) as ctx:
                cu._validated(obs, cu._item_by_seq(self.index, ACCT, ex["exec_id"], 1), "2000-01-01T00:00:00.000000Z", "different", ACCT, um)
            self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")

    def test_two_callers_racing_on_one_authorization_mutate_once(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        second = self.umb(mb)
        out = []
        first = self.umb(mb, [Step("GET_THREAD", after=lambda f: out.append(self.undo(ex, second, 1)))])
        with self.assertRaises(ce.ExecError) as ctx:
            self.undo(ex, first, 1)
        self.assertEqual(ctx.exception.code, "UNDO_NOT_AUTHORIZED")
        self.assertEqual((first.service.undos(), second.service.undos(), out[0].status), (0, 1, "RESTORED"))
        self.assertEqual([t for t, _ in self.undo_events()].count("UNDO_INTENT"), 1)


class UndoLedgerTests(UndoBase):
    """The audit chain is the undo ledger: its state machine is strict, and anything it does not recognise authorizes nothing."""

    def put(self, ex, kind, **meta):
        with cp._txn(self.index):
            return audit.append(self.index, ACCT, ex["plan_id"], kind, cp._iso(self.uc()), {"exec": ex["exec_id"], "item": 1, **meta})

    def intent_meta(self, ex):
        auth = cu._state(cu._ledger(self.index, ACCT, ex["exec_id"], 1))[1]
        return {"auth": auth["hash"], "t": ce._us(self.uc())}

    def test_every_unsupported_or_inconsistent_sequence_fails_closed_and_is_reported(self):
        sequences = {
            "a second intent": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)), self.put(ex, "UNDO_INTENT", **self.intent_meta(ex))),
            "an authorization while an attempt is open": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)), self.put(ex, "UNDO_AUTHORIZED", phrase_sha256="x")),
            "a second authorization": lambda ex: self.put(ex, "UNDO_AUTHORIZED", phrase_sha256="x"),
            "a result for another intent": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)),
                                                       self.put(ex, "UNDO_RESULT", intent="0" * 64, result="RESTORED", via="DIRECT")),
            "a result without an intent": lambda ex: self.put(ex, "UNDO_RESULT", intent="0" * 64, result="RESTORED", via="DIRECT"),
            "an intent for another authorization": lambda ex: self.put(ex, "UNDO_INTENT", auth="f" * 64, t=ce._us(self.uc())),
            "an unknown result value": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)),
                                                   self.put(ex, "UNDO_RESULT", intent=cu._state(cu._ledger(self.index, ACCT, ex["exec_id"], 1))[2]["hash"], result="WHATEVER", via="DIRECT")),
            "a reconciliation that claims UNKNOWN": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)),
                                                                self.put(ex, "UNDO_RESULT", intent=cu._state(cu._ledger(self.index, ACCT, ex["exec_id"], 1))[2]["hash"], result="UNKNOWN", via="RECONCILE")),
            "a result without its fields": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)), self.put(ex, "UNDO_RESULT")),
            "an intent right after a not-restored result": lambda ex: (self.put(ex, "UNDO_INTENT", **self.intent_meta(ex)), self.put(
                ex, "UNDO_RESULT", intent=cu._state(cu._ledger(self.index, ACCT, ex["exec_id"], 1))[2]["hash"], result="NOT_RESTORED", via="DIRECT", code="REJECTED"),
                self.put(ex, "UNDO_INTENT", **self.intent_meta(ex))),
        }
        for label, build in sequences.items():
            with self.subTest(label):
                self.setUp()
                ex, mb = self.archived()
                self.authorize(ex, 1)
                build(ex)
                um = self.umb(mb)
                self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "INCONSISTENT")
                for call in (lambda: self.undo(ex, um, 1), lambda: self.authorize(ex, 1), lambda: cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)):
                    with self.assertRaises(ce.ExecError) as ctx:
                        call()
                    self.assertIn(ctx.exception.code, ("UNDO_NOT_AUTHORIZED", "UNDO_NOT_ALLOWED", "NOTHING_TO_RECONCILE"))
                self.assertEqual(um.service.undos(), 0)
                status = cr.status_report(self.index, ACCT)
                self.assertEqual(status.undos, ((ex["exec_id"], 1, "INCONSISTENT"),))
                self.assertTrue(status.needs_owner)
                report = cr.recover(self.index, ACCT, um)
                self.assertEqual((report.undos, um.service.undos()), (((ex["exec_id"], 1, "INCONSISTENT"),), 0))
                self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_events_after_a_final_result_make_the_ledger_inconsistent(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        self.undo(ex, self.umb(mb), 1)
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "RESTORED")
        self.put(ex, "UNDO_AUTHORIZED", phrase_sha256="x")
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "INCONSISTENT")

    def test_not_restored_followed_by_a_new_authorization_is_a_valid_second_cycle_and_the_second_attempt_is_separate(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        first = self.umb(mb, [Step("UNDO", raises=Crash(), apply=False)])
        with self.assertRaises(Crash):
            self.undo(ex, first, 1)
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "OPEN")
        self.assertEqual(cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, self.umb(mb)).status, "NOT_RESTORED")
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "NOT_RESTORED")
        self.authorize(ex, 1)
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "AUTHORIZED")
        second = self.umb(mb)
        self.assertEqual(self.undo(ex, second, 1).status, "RESTORED")
        self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT", "UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT"])
        intents = {m["intent"] for t, m in self.undo_events() if t == "UNDO_RESULT"}
        self.assertEqual(len(intents), 2)  # each result refers to its own attempt
        self.assertEqual((first.service.undos(), second.service.undos()), (1, 1))
        with self.assertRaises(ce.ExecError):
            self.authorize(ex, 1)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_consuming_the_observation_before_persisting_cannot_produce_a_false_restored_or_a_second_mutation(self):
        ex, mb = self.archived()
        self.authorize(ex, 1)
        um = self.umb(mb)
        with mock.patch.object(cu, "_record", side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(sqlite3.OperationalError):
                self.undo(ex, um, 1)
        self.assertNotIn("UNDO_RESULT", [t for t, _ in self.undo_events()])  # nothing claims RESTORED
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "OPEN")
        with self.assertRaises(ce.ExecError):
            self.undo(ex, um, 1)
        self.assertEqual(um.service.undos(), 1)
        self.assertEqual(cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um).status, "RESTORED")  # resolved by a FRESH observation
        self.assertEqual(um.service.undos(), 1)


class UndoSameThreadTests(UndoBase):
    A, B, C, TID = HEX[0], HEX[1], HEX[5], THREADS[0]
    messages = TB.SameThreadTests.messages
    state = TB.SameThreadTests.state

    def test_a_sibling_archived_by_the_same_execution_is_fine_but_a_changed_one_is_not(self):
        for label, change in (('untouched siblings', None), ('an unapproved sibling changed', lambda f: f.set_labels(self.C, list(AFTER)))):
            with self.subTest(label):
                self.setUp()
                ex = self.execution(ids=(self.A, self.B))
                mb = fm.FakeMailbox(ACCT, self.state(), clock=self.clock())
                self.run_batch(ex, mb)
                self.uc = StepClock(self.step_clock.at + timedelta(seconds=60))
                self.authorize(ex, 1)
                um = self.umb(mb, [Step('GET_THREAD', before=change)] if change else [])
                if change:
                    with self.assertRaises(ce.ExecError) as ctx:
                        self.undo(ex, um, 1)
                    self.assertEqual((ctx.exception.code, um.service.undos()), ('UNDO_DRIFT', 0))
                else:
                    self.assertEqual(self.undo(ex, um, 1).status, 'RESTORED')
                    self.assertEqual(um.service.messages[self.B][1], set(AFTER))  # the other archived approved item stays archived


class UndoBoundaryTests(UndoBase):
    def test_the_real_write_boundary_allows_exactly_two_fixed_mutations(self):
        """M12C.3 deliberately widened the boundary by ONE fixed request body (archive-undo). Everything else stays closed."""
        self.assertEqual(pol.MODIFY_BODY, b'{"removeLabelIds":["INBOX"]}')
        self.assertEqual(pol.UNDO_BODY, b'{"addLabelIds":["INBOX"]}')
        self.assertEqual(len(pol._ROUTES), 4)  # no new route: the undo uses the same modify path, told apart by its exact body
        self.assertEqual(pol.MUTATIONS, ("MESSAGE_MODIFY", "MESSAGE_MODIFY_UNDO"))
        names = ("gmail_write.py", "gmail_write_policy.py", "oauth_write.py")
        texts = {n: (ROOT / "src" / "gmail_intelligence" / n).read_text() for n in names}
        self.assertEqual({n: t.count("addLabelIds") for n, t in texts.items()}, {"gmail_write.py": 0, "gmail_write_policy.py": 1, "oauth_write.py": 0})  # only the UNDO_BODY definition
        self.assertEqual({n: t.count("restore_inbox") for n, t in texts.items() if "restore_inbox" in t}.keys(), {"gmail_write.py"})  # the adapter operation only
        for n in ("gmail_write.py", "gmail_write_policy.py"):  # no other mutation class is expressible: no batch, trash, send, draft or delete endpoint
            for forbidden in ("batchModify", "batchDelete", "/trash", "/untrash", "messages/send", "/drafts", "/delete"):
                self.assertNotIn(forbidden, texts[n], (n, forbidden))
        policy_text = texts["gmail_write_policy.py"]
        self.assertNotIn("unarchive", policy_text.lower())
        self.assertNotIn("removeLabelIds", policy_text.split("UNDO_BODY =", 1)[1].split("\n", 1)[0])  # the undo body never removes anything

    def test_no_production_path_reaches_recovery_or_undo(self):
        cli = (ROOT / "src" / "gmail_intelligence" / "cli.py").read_text()
        for name in ("cleanup_undo", "cleanup_recovery", "authorize_undo", "undo_item", "reconcile_undo", "restore_inbox", "FakeMailbox"):
            self.assertNotIn(name, cli)
        self.assertIn("execution is not available in this version", cli)
        import ast
        importers = set()
        for path in (ROOT / "src" / "gmail_intelligence").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module or ""] + [a.name for a in node.names] if isinstance(node, ast.ImportFrom) else [])
                if any(m.split(".")[-1] in ("cleanup_undo", "cleanup_recovery") for m in mods):
                    importers.add((path.name))
        self.assertEqual(importers, {"cleanup_recovery.py", "cleanup_live.py", "undo_cli.py", "reconcile_cli.py", "cleanup_reversal.py"})  # undo only by recovery; recovery only by the disabled live entry points; never the CLI

    def test_the_fake_undo_is_only_in_memory(self):
        mb = self.mailbox()
        mb.verify_account()
        before = list(mb.service.log)
        mb.service.set_labels(HEX[0], AFTER)
        labels = mb.restore_inbox(HEX[0])
        self.assertEqual(set(labels), set(LABELS))
        self.assertEqual(mb.service.log[len(before):], [("UNDO", HEX[0])])  # no HTTP-shaped request exists for it
        unverified = self.mailbox()
        with self.assertRaises(gw.AccountNotVerified) as ctx:
            unverified.restore_inbox(HEX[0])
        self.assertIs(ctx.exception.dispatched, False)


if __name__ == "__main__":
    unittest.main()
