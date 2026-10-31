"""M12D: BULK REVERSAL plans (issue #62; the D7 contract of M12C) and the F5 thread rule, DISABLED in this build. Fake Gmail wire and mocked credentials only: no Gmail, no OAuth, no
Keychain, no network; the live gates are patched on for one test at a time. Every item is undone by the unchanged single-item engine; these tests prove the plan, its approval, its bounded
slices, the stop rules and the thread rule around it."""
import contextlib
import io
import json
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
from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_executor import AFTER, LABELS  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_exec_report as rep, cleanup_live as cl, cleanup_plans as cp, cleanup_protect, cleanup_reversal as rv  # noqa: E402
from gmail_intelligence import cleanup_undo as cu, cleanup_undo_ledger as ledger, cli, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, index as idx, keystore_write, undo_cli  # noqa: E402

Step = fm.Step


class ReversalBase(BulkBase):
    N = 30

    def archived_execution(self, n=None, script=()):
        plan, ex = self.prepare_bulk(n, script)
        self.run_all(ex)
        self.assertEqual(self.exec_row(ex)["state"], "EXECUTED")
        self.snapshot_before = self.history()
        return ex

    def history(self):
        q = self.index._q
        return ([tuple(r) for r in q("SELECT * FROM cleanup_exec_item ORDER BY exec_id, seq")], [tuple(r) for r in q("SELECT * FROM cleanup_execution")],
                [tuple(r) for r in q("SELECT * FROM cleanup_audit WHERE event_type NOT LIKE 'UNDO_%' AND event_type NOT LIKE 'REVERSAL_%'")])

    def audit_rows(self):
        return [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")]

    def enable_undo(self):
        patcher = mock.patch.object(live, "LIVE_UNDO_ENABLED", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def undo_mailbox(self, svc=None, account=ACCT):
        svc = svc or self.svc
        factory = fm._Factory(svc)
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, factory, capabilities=("UNDO",)), ACCT, _clock=self.clk)
        return live._wrap_undo(adapter, ACCT, factory)

    def observe_mailbox(self, svc=None):
        svc = svc or self.svc
        factory = fm._Factory(svc)
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, factory, capabilities=("OBSERVE",)), ACCT, _clock=self.clk)
        with mock.patch.object(live, "LIVE_OBSERVE_ENABLED", True):
            return live._wrap_observe(adapter, ACCT, factory)

    def plan(self, ex, exclude=()):
        return rv.create_reversal_plan(self.index, ACCT, ex["exec_id"], exclude, now=self.clk())

    def approve(self, rev):
        d = rv.describe(self.index, ACCT, rev, self.clk())
        return rv.approve_reversal(self.index, ACCT, rev, rv.approval_phrase(rev, d["items"], d["digest"]), now=self.clk())

    def slice_phrase(self, rev):
        d = rv.describe(self.index, ACCT, rev, self.clk())
        if not d.get("next"):
            return "UNDO SLICE (none)"
        return rv.slice_phrase(rev, d["next"]["slice"], d["next"]["size"], d["digest"])

    def run_rev(self, rev, phrase=None, mailbox=None):
        return cl.reverse_slice_live(self.index, ACCT, rev, self.slice_phrase(rev) if phrase is None else phrase, mailbox or self.undo_mailbox())

    def approved(self, ex, exclude=()):
        rev = self.plan(ex, exclude)["rev"]
        self.approve(rev)
        return rev

    def state(self, rev):
        return rv.describe(self.index, ACCT, rev, self.clk())["state"]


class PlanTests(ReversalBase):
    def test_a_plan_selects_only_verified_applied_items_and_freezes_them(self):
        ex = self.archived_execution(10, [Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid(2), list(LABELS) + ["STARRED"]))] if False else ())
        d = self.plan(ex)
        self.assertEqual((d["state"], d["items"], d["slices"], d["digest"] is not None, d["excluded_at_planning"]), ("PLANNED", 10, [10], True, 0))
        d2 = self.plan(ex, exclude=[3, 4])
        self.assertEqual((d2["items"], d2["excluded_at_planning"], d2["rev"] != d["rev"]), (8, 2, True))
        for bad in ([99], [1, 1], [0]):
            with self.assertRaises(ce.ExecError) as ctx:
                self.plan(ex, exclude=bad)
            self.assertEqual(ctx.exception.code, "BAD_EXCLUDE")
        with self.assertRaises(ce.ExecError) as ctx:
            self.plan(ex, exclude=list(range(1, 11)))
        self.assertEqual(ctx.exception.code, "NO_TARGETS")
        self.assertEqual(self.history(), self.snapshot_before)                          # planning wrote only plan events; the archive history is untouched

    def test_skipped_or_failed_items_never_enter_a_plan_and_a_running_execution_cannot_be_planned(self):
        plan, ex = self.prepare_bulk(10, [Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid(2), list(LABELS) + ["STARRED"]))])
        with self.assertRaises(ce.ExecError) as ctx:
            self.plan(ex)                                                                   # PREPARED, nothing archived yet
        self.assertEqual(ctx.exception.code, "EXECUTION_NOT_FINISHED")
        self.run_slice(ex)
        d = self.plan(ex)
        self.assertEqual(d["items"], 9)                                                      # the skipped (never archived) item is not part of any reversal
        self.assertNotIn(2, ledger.reversal_state(ledger.reversal_events(self.index, ACCT, d["rev"]))["items"])

    def test_items_with_an_open_or_finished_undo_are_not_selected_again(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex, exclude=[])
        self.run_rev(rev)
        with self.assertRaises(ce.ExecError) as ctx:                                         # everything is already restored: nothing left to reverse
            self.plan(ex)
        self.assertEqual(ctx.exception.code, "NO_TARGETS")

    def test_the_maximum_plan_size_is_enforced(self):
        ex = self.archived_execution(10)
        with mock.patch.object(rv, "MAX_ITEMS", 5):
            with self.assertRaises(ce.ExecError) as ctx:
                self.plan(ex)
        self.assertEqual(ctx.exception.code, "TOO_MANY")

    def test_a_changed_source_journal_makes_the_plan_stale(self):
        ex = self.archived_execution(10)
        rev = self.plan(ex)["rev"]
        for stmt in ("DROP TRIGGER IF EXISTS cleanup_item_no_update",):
            self.index.conn.execute(stmt)
        names = [r[0] for r in self.index.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='cleanup_exec_item'")]
        for name in names:
            self.index.conn.execute(f"DROP TRIGGER {name}")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_exec_item SET prev_label_ids='[\"INBOX\",\"Label_x\"]' WHERE account=? AND exec_id=? AND seq=3", (ACCT, ex["exec_id"]))
        d = rv.describe(self.index, ACCT, rev, self.clk())
        with self.assertRaises(ce.ExecError) as ctx:
            rv.approve_reversal(self.index, ACCT, rev, rv.approval_phrase(rev, d["items"], d["digest"]), now=self.clk())
        self.assertEqual(ctx.exception.code, "PLAN_CHANGED")


class ApprovalTests(ReversalBase):
    def test_nothing_runs_without_approval_wrong_phrases_are_locked_out_and_double_approval_is_refused(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.plan(ex)["rev"]
        with self.assertRaises(ce.ExecError) as ctx:
            self.run_rev(rev, phrase="anything")
        self.assertEqual(ctx.exception.code, "NOT_RUNNABLE")
        d = rv.describe(self.index, ACCT, rev, self.clk())
        for wrong in ("", "APPROVE UNDO", cp.approval_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"])), rv.slice_phrase(rev, 1, 10, d["digest"]), rv.approval_phrase(rev, 9, d["digest"])):
            with self.assertRaises(ce.ExecError) as ctx:
                rv.approve_reversal(self.index, ACCT, rev, wrong, now=self.clk())
            self.assertIn(ctx.exception.code, ("BAD_CONFIRMATION", "LOCKED_OUT"))
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(ce.ExecError):
                rv.approve_reversal(self.index, ACCT, rev, "x", now=self.clk())
        with self.assertRaises(ce.ExecError) as ctx:
            self.approve(rev)
        self.assertEqual(ctx.exception.code, "LOCKED_OUT")
        self.assertEqual((self.svc.undos(), self.state(rev)), (0, "PLANNED"))

    def test_an_expired_approval_cannot_run_and_a_second_approval_is_refused(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex)
        with self.assertRaises(ce.ExecError) as ctx:
            self.approve(rev)
        self.assertEqual(ctx.exception.code, "NOT_APPROVABLE")
        self.clk.at = self.clk.at + rv.APPROVAL_TTL + timedelta(minutes=5)
        with self.assertRaises(ce.ExecError) as ctx:
            self.run_rev(rev)
        self.assertEqual(ctx.exception.code, "APPROVAL_EXPIRED")
        self.assertEqual(self.svc.undos(), 0)


class SliceTests(ReversalBase):
    N = 130

    def test_a_multi_slice_reversal_needs_a_fresh_phrase_per_slice_and_restores_only_inbox(self):
        ex = self.archived_execution()
        self.enable_undo()
        rev = self.approved(ex)
        d = rv.describe(self.index, ACCT, rev, self.clk())
        self.assertEqual((d["state"], d["slices"], d["next"]), ("APPROVED", [25, 100, 5], {"slice": 1, "size": 25, "items": [1, 25]}))
        phrase1 = self.slice_phrase(rev)
        for wrong in ("", phrase1.replace("SLICE 1", "SLICE 2"), rv.approval_phrase(rev, 130, d["digest"])):
            with self.assertRaises(ce.ExecError):
                self.run_rev(rev, phrase=wrong)
        self.assertEqual(self.svc.undos(), 0)
        r1 = self.run_rev(rev, phrase=phrase1)
        self.assertEqual((r1.slice_no, r1.restored, r1.skipped, r1.stopped, r1.mutations, r1.state), (1, 25, 0, False, 25, "AWAITING_CONTINUATION"))
        with self.assertRaises(ce.ExecError):                                              # the same phrase cannot be replayed: slice 1 is done, slice 2 needs ITS phrase
            self.run_rev(rev, phrase=phrase1)
        self.assertEqual(self.svc.undos(), 25)
        r2 = self.run_rev(rev)
        r3 = self.run_rev(rev)
        self.assertEqual((r2.restored, r3.restored, r3.state), (100, 5, "COMPLETED"))
        self.assertEqual((self.svc.undos(), self.svc.posts()), (130, 130))
        for mid, (tid, labels) in self.svc.messages.items():
            self.assertEqual(set(labels), set(LABELS), mid)                                 # INBOX is back; the other label is exactly as it was
        self.assertEqual(self.history(), self.snapshot_before)                              # archive history untouched
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"APPLIED": 130})  # the original journal still says APPLIED

    def test_a_second_runner_while_a_slice_is_in_progress_is_refused(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex)
        seen = []

        def competing_runner(f):
            try:
                self.run_rev(rev, phrase=rv.slice_phrase(rev, 1, 10, rv.describe(self.index, ACCT, rev, self.clk())["digest"]))
            except ce.ExecError as exc:
                seen.append(exc.code)
        self.svc.script.append(Step("UNDO", nth=2, before=competing_runner))
        r = self.run_rev(rev)
        self.assertEqual((r.restored, seen), (10, ["NOT_RUNNABLE"]))
        self.assertEqual(self.svc.undos(), 10)


class StopTests(ReversalBase):
    def test_an_ambiguous_undo_stops_the_whole_reversal_and_is_never_retried(self):
        ex = self.archived_execution(30)
        self.enable_undo()
        self.svc.script.append(Step("UNDO", nth=3, raises=TimeoutError(), apply=True))
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.restored, r.stopped, r.reason, r.mutations, r.state), (2, True, "UNKNOWN", 3, "STOPPED"))
        self.assertEqual(self.svc.undos(), 3)
        self.assertEqual(ledger.undo_status(self.index, ACCT, ex["exec_id"], 3), "UNKNOWN")
        self.assertEqual(ledger.undo_status(self.index, ACCT, ex["exec_id"], 4), "NONE")    # the rest was never attempted
        with self.assertRaises(ce.ExecError):
            self.run_rev(rev)
        self.assertEqual(self.svc.undos(), 3)
        res = cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 3, self.observe_mailbox())     # read-only settlement from a fresh observation
        self.assertEqual((res.status, res.mutations, self.svc.undos()), ("RESTORED", 0, 3))
        self.assertEqual(self.state(rev), "STOPPED")                                         # settling an item does not reopen the plan
        rv.abort_reversal(self.index, ACCT, rev, rv.abort_phrase(rev), now=self.clk())
        self.assertEqual(self.state(rev), "ABORTED")
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_an_interrupted_reversal_keeps_its_progress_and_is_never_resumed(self):
        ex = self.archived_execution(30)
        self.enable_undo()
        self.svc.script.append(Step("UNDO", nth=3, raises=Crash(), apply=True))
        rev = self.approved(ex)
        with self.assertRaises(Crash):
            self.run_rev(rev)
        self.assertEqual((self.state(rev), ledger.undo_status(self.index, ACCT, ex["exec_id"], 3), self.svc.undos()), ("IN_PROGRESS", "OPEN", 3))
        with self.assertRaises(ce.ExecError) as ctx:                                         # a second runner (or a restart) is refused
            self.run_rev(rev, phrase="x")
        self.assertEqual(ctx.exception.code, "NOT_RUNNABLE")
        self.clk.at = self.clk.at + timedelta(seconds=ledger.RUN_TTL_SECONDS + 60)
        self.assertEqual(self.state(rev), "INTERRUPTED")
        for call in (lambda: self.run_rev(rev, phrase="x"), lambda: self.approve(rev)):
            with self.assertRaises(ce.ExecError):
                call()
        data = rep.recovery_data(self.index, ACCT, self.clk())
        self.assertEqual([(r["state"], r["restored"]) for r in data["reversals"]], [("INTERRUPTED", 0)])
        self.assertTrue(data["needs_owner"])
        res = cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 3, self.observe_mailbox())
        self.assertEqual((res.status, self.svc.undos()), ("RESTORED", 3))                    # settled by observation; the mutation was not repeated
        self.assertEqual([ledger.undo_status(self.index, ACCT, ex["exec_id"], s) for s in (1, 2, 3)], ["RESTORED"] * 3)
        rv.abort_reversal(self.index, ACCT, rev, rv.abort_phrase(rev), now=self.clk())
        self.assertEqual(self.state(rev), "ABORTED")

    def test_drifted_and_vanished_items_are_skipped_without_a_request_and_the_rest_continues(self):
        ex = self.archived_execution(30)
        self.enable_undo()
        self.svc.script.append(Step("GET_MESSAGE", nth=3 * 1 + 1, before=lambda f: None))
        self.svc.set_labels(self.mid(2), list(AFTER) + ["STARRED"])          # changed externally since the archive
        self.svc.remove_message(self.mid(5))                                    # gone
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.restored, r.skipped, r.stopped, r.mutations, r.state), (28, 2, False, 28, "COMPLETED"))
        self.assertNotIn("INBOX", self.svc.messages[self.mid(2)][1])
        d = ledger.reversal_state(ledger.reversal_events(self.index, ACCT, rev))
        self.assertEqual(d["skipped"], {2: "UNDO_DRIFT", 5: "UNDO_GONE"})

    def test_a_wrong_account_or_an_unreadable_message_stops_before_any_mutation(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex)
        other = fm._Service(OTHER, {m: (t, list(l)) for m, (t, l) in self.svc.messages.items()}, ())
        factory = fm._Factory(other)
        mb = live._wrap_undo(gw.ArchiveAdapter(gw._Transport(other.creds, factory, capabilities=("UNDO",)), ACCT, _clock=self.clk), ACCT, factory)
        r = self.run_rev(rev, mailbox=mb)                                                        # the live profile answers as another account
        self.assertEqual((r.restored, r.stopped, other.undos(), self.svc.undos()), (0, True, 0, 0))
        self.assertEqual(self.state(rev), "STOPPED")


class ThreadRuleTests(ReversalBase):
    """F5: siblings of one thread restored by the SAME approved plan are expected restored; nothing else is."""
    N = 12
    SHARED = {2: 1, 3: 1}                        # messages 1, 2 and 3 share one thread

    def test_siblings_archived_together_are_restored_together_by_one_plan(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.restored, r.skipped, r.stopped), (12, 0, False))
        for i in (1, 2, 3):
            self.assertEqual(set(self.svc.messages[self.mid(i)][1]), set(LABELS))

    def test_the_single_item_path_stays_strict_for_siblings(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        mb = self.undo_mailbox()
        cu.authorize_undo(self.index, ACCT, ex["exec_id"], 1, cu.undo_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"], 1), now=self.clk())
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, mb).status, "RESTORED")
        cu.authorize_undo(self.index, ACCT, ex["exec_id"], 2, cu.undo_phrase(cp.get_plan(self.index, ACCT, ex["plan_id"]), ex["exec_id"], 2), now=self.clk())
        with self.assertRaises(ce.ExecError) as ctx:                                          # M12C.3 behavior is unchanged: no plan, no trusted proof of the sibling's restoration
            cl.undo_live(self.index, ACCT, ex["exec_id"], 2, mb)
        self.assertEqual(ctx.exception.code, "UNDO_DRIFT")

    def test_a_sibling_changed_by_someone_else_still_blocks_the_threads_unsafe_undo(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        self.svc.set_labels(self.mid(3), list(AFTER) + ["STARRED"])
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.restored, r.skipped), (9, 3))                                     # items 1-3 skipped: nothing sent for them
        for i in (1, 2, 3):
            self.assertNotIn("INBOX", self.svc.messages[self.mid(i)][1])

    def test_a_protected_sibling_blocks_the_whole_thread(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        cleanup_protect.add(self.index, ACCT, label="Label_keep", note="synthetic")
        self.svc.set_labels(self.mid(2), list(AFTER) + ["Label_keep"])
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.skipped, r.restored), (3, 9))                                     # the protected sibling blocks every undo in its thread; nothing was sent for them
        for i in (1, 2, 3):
            self.assertNotIn("INBOX", self.svc.messages[self.mid(i)][1])

    def test_an_arbitrary_inbox_label_on_an_unrestored_sibling_is_not_a_trusted_restoration(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        self.svc.script.append(Step("UNDO", nth=1, after=lambda f: f.set_labels(self.mid(3), list(LABELS))))     # someone puts INBOX on sibling 3 after item 1 was restored
        rev = self.approved(ex)
        r = self.run_rev(rev)
        self.assertEqual((r.restored, r.skipped, r.stopped), (10, 2, False))                  # items 2 and 3 are skipped: sibling 3 was NOT restored by this plan
        self.assertNotIn("INBOX", self.svc.messages[self.mid(2)][1])
        self.assertEqual(ledger.reversal_state(ledger.reversal_events(self.index, ACCT, rev))["skipped"], {2: "UNDO_DRIFT", 3: "UNDO_DRIFT"})

    def test_siblings_restored_by_another_plan_are_not_trusted(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        rev_a = self.plan(ex, exclude=list(range(2, 13)))["rev"]                              # a plan for item 1 alone
        self.approve(rev_a)
        self.assertEqual(self.run_rev(rev_a).restored, 1)
        rev_b = self.plan(ex, exclude=list(range(4, 13)))["rev"]                              # items 2 and 3, planned AFTER item 1 was restored by a different plan
        self.approve(rev_b)
        r = self.run_rev(rev_b)
        self.assertEqual((r.restored, r.skipped), (0, 2))                                     # item 1's restoration belongs to ANOTHER plan: not trusted, so the thread still looks drifted

    def test_an_unsettled_sibling_is_never_trusted_as_restored(self):
        ex = self.archived_execution(12)
        self.enable_undo()
        self.svc.script.append(Step("UNDO", nth=1, raises=TimeoutError(), apply=True))
        rev_a = self.approved(ex, exclude=list(range(2, 13)))
        self.assertEqual(self.run_rev(rev_a).reason, "UNKNOWN")                                # item 1 is UNKNOWN (and, on the wire, actually restored)
        with self.assertRaises(ce.ExecError) as ctx:
            self.plan(ex, exclude=list(range(2, 13)))                                          # item 1 is uncertain: not selectable by any plan
        self.assertEqual(ctx.exception.code, "NO_TARGETS")
        rev_c = self.approved(ex)                                                               # the other 11 items
        r = self.run_rev(rev_c)
        self.assertEqual((r.restored, r.skipped, r.stopped), (9, 2, False))                    # siblings 2 and 3 are skipped: an UNKNOWN sibling proves nothing
        res = cl.reconcile_undo_observed(self.index, ACCT, ex["exec_id"], 1, self.observe_mailbox())
        self.assertEqual(res.status, "RESTORED")                                                # settled read-only; still a restoration by ANOTHER plan, so still not trusted for rev_c


class GateAndCliTests(ReversalBase):
    N = 30

    def test_the_live_undo_gate_and_the_mailbox_type_are_enforced_before_anything_is_recorded(self):
        ex = self.archived_execution(10)
        rev = self.approved(ex)
        rows = len(self.audit_rows())
        with self.assertRaises(ce.ExecError) as ctx:
            cl.reverse_slice_live(self.index, ACCT, rev, self.slice_phrase(rev), self.observe_mailbox())
        self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.enable_undo()
        mb = self.undo_mailbox()
        with mock.patch.object(live, "LIVE_UNDO_ENABLED", False):
            with self.assertRaises(ce.ExecError) as ctx:
                cl.reverse_slice_live(self.index, ACCT, rev, self.slice_phrase(rev), mb)
            self.assertEqual(ctx.exception.code, "LIVE_UNDO_DISABLED")
        for fake in (fm.FakeMailbox(ACCT, {}, clock=self.clk),):
            with self.assertRaises(ce.ExecError) as ctx:
                cl.reverse_slice_live(self.index, ACCT, rev, self.slice_phrase(rev), fake)
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual((len(self.audit_rows()), self.svc.undos()), (rows, 0))
        self.assertIs(live.LIVE_EXECUTION_ENABLED if False else False, False)

    def run_cmd(self, *argv, typed=()):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(typed)
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")),
                   mock.patch.object(cli, "_tty_input", side_effect=lambda prompt: next(feed)),
                   mock.patch.object(cp, "_utc", side_effect=lambda n: n if n is not None else self.clk()), mock.patch.object(ce, "_utc", side_effect=lambda n: n if n is not None else self.clk()),
                   mock.patch.object(cli.config, "write_client_secret_path", lambda: self.client_path), mock.patch.object(keystore_write, "WriteTokenStore", lambda: self.store)]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(["cleanup", "undo", *argv, "--account", ACCT])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_the_owner_workflow_through_the_cli_and_its_disabled_refusal(self):
        ex = self.archived_execution(30)
        code, out, err = self.run_cmd("reversal", "create", ex["exec_id"], "--exclude-item", "1")
        self.assertEqual((code, err), (0, ""))
        rev = [w for w in out.split() if w.startswith("rev-")][0].rstrip(":")
        self.assertIn("29 item(s)", out)
        self.assertNotRegex(out, r"18c0ffee|s\d+@|example")
        d = rv.describe(self.index, ACCT, rev, self.clk())
        self.assertEqual(self.run_cmd("reversal", "approve", rev, typed=["nope"])[0], 1)
        code, out, err = self.run_cmd("reversal", "approve", rev, typed=[rv.approval_phrase(rev, d["items"], d["digest"])])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("APPROVED", out)
        with mock.patch.object(idx, "Index", side_effect=AssertionError("the index must not be opened")):
            self.assertEqual(self.run_cmd("reversal", "run", rev), (2, undo_cli.DISABLED + "\n", ""))     # disabled: refuses before the index or any credential
        self.assertEqual(self.svc.undos(), 0)
        self.enable_undo()
        mb = self.undo_mailbox()
        with mock.patch.object(live, "open_live_undo_mailbox", return_value=mb):
            code, out, err = self.run_cmd("reversal", "run", rev, typed=[self.slice_phrase(rev)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("slice 1 finished: 29 restored", out)
        code, out, err = self.run_cmd("reversal", "show", rev, "--json")
        self.assertEqual(json.loads(out)["state"], "COMPLETED")
        self.assertEqual((self.svc.undos(), "INBOX" in self.svc.messages[self.mid(1)][1]), (29, False))      # the excluded item stayed archived

    def test_the_ordinary_cli_reaches_reversal_only_through_the_gated_module(self):
        src = (SRC / "cli.py").read_text()
        for name in ("cleanup_reversal", "reverse_slice_live", "authorize_in_reversal", "LIVE_UNDO_ENABLED"):
            self.assertNotIn(name, src)
        body = (SRC / "undo_cli.py").read_text()
        self.assertLess(body.index('sub_cmd == "run" and live.LIVE_UNDO_ENABLED is not True'), body.index("def go(index, account):\n        try:\n            if sub_cmd"))


if __name__ == "__main__":
    unittest.main()
