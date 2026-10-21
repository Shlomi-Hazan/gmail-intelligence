"""M7A: the M4 sync-health guards E1-E5, the D145 handshake and the plan/approval effects of sync (P1-P5, G2). Synthetic; no Gmail.

Three different things are kept apart here (SYNC.md 9.1): a plan becoming STALE (permanent, plan-specific), an immutable APPROVAL RECORD that keeps existing,
and an operation PROHIBITED until sync health is restored (transient, writes nothing).
"""
import contextlib
import inspect
import io
import threading
import time
import unittest
from datetime import timedelta
from unittest import mock

import test_cleanup_exec as TCE
from test_cleanup import ACCT, msg
from test_cleanup_plans import T0

import m7_support
from fake_history import FakeHistoryMailbox
from sync_support import M4_TABLES, fast_limiter, file_digest, table_digest
from gmail_intelligence import classifier, cleanup_audit as audit, cleanup_canary, cleanup_exec as ce, cleanup_executor, cleanup_plans as cp
from gmail_intelligence import cli, gmail, scanner, sync, sync_health, sync_lease
from gmail_intelligence import index as idx

CONDITIONS = ("MISSING", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE", "FULL_SCAN_ACTIVE", "FULL_SCAN_INTERRUPTED", "STALE", "INCONSISTENT")


class GuardBase(TCE.ExecBase):
    def setUp(self):
        super().setUp()
        self.big_ids = None

    # ---- the sync conditions of SYNC.md 9.4, produced directly in the tables ----
    def basis(self):
        return self.index._q("SELECT basis_scan_id FROM sync_state WHERE account=?", ACCT)[0][0]

    def apply(self, cond):
        c = self.index.conn
        with c:
            if cond == "MISSING":
                c.execute("DELETE FROM sync_state")
            elif cond == "IN_PROGRESS":
                c.execute("UPDATE sync_state SET status='IN_PROGRESS'")
                c.execute("INSERT INTO sync_run (account,kind,status,started_at,lease_token,lease_expires_at,heartbeat_at) VALUES (?,?,?,?,?,?,?)",
                          (ACCT, "INCREMENTAL", "running", "2027-01-15T07:00:00Z", "a" * 64, "2099-01-01T00:00:00Z", "2027-01-15T07:00:00Z"))
            elif cond in ("INTERRUPTED", "NEEDS_RECONCILE"):
                c.execute("UPDATE sync_state SET status=?", (cond,))
            elif cond == "FULL_SCAN_ACTIVE":
                c.execute("UPDATE sync_state SET status='IN_PROGRESS'")
                sid = c.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'running', '2027-01-15T07:00:00Z')", (ACCT,)).lastrowid
                c.execute("INSERT INTO sync_run (account,kind,status,started_at,scan_id,lease_token,lease_expires_at,heartbeat_at) VALUES (?,?,?,?,?,?,?,?)",
                          (ACCT, "FULL", "running", "2027-01-15T07:00:00Z", sid, "b" * 64, "2099-01-01T00:00:00Z", "2027-01-15T07:00:00Z"))
            elif cond == "FULL_SCAN_INTERRUPTED":
                c.execute("UPDATE sync_state SET status='INTERRUPTED', reason='FULL_SCAN_INTERRUPTED'")
                c.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'interrupted', '2027-01-15T07:00:00Z')", (ACCT,))
            elif cond == "STALE":
                c.execute("UPDATE sync_state SET advanced_at=?", (m7_support.utc_iso(T0 - timedelta(hours=30)),))
                self._age = [mock.patch.object(sync_health, "SYNC_MAX_AGE", timedelta(hours=24)), mock.patch.object(sync_health, "CLOCK_TOLERANCE", timedelta(minutes=5))]
                for p in self._age:
                    p.start()
            elif cond == "INCONSISTENT":
                c.execute("UPDATE sync_state SET basis_scan_id=basis_scan_id-1")

    def restore(self):
        for p in getattr(self, "_age", []):
            p.stop()
        self._age = []
        with self.index.conn:
            self.index.conn.execute("DELETE FROM sync_run")
            self.index.conn.execute("DELETE FROM scans WHERE status<>'completed'")
        m7_support.seed_healthy_sync(self.index, ACCT, at=T0)
        self.assertEqual(sync_health.problems(self.index, ACCT, T0), [])

    def all_events(self):
        return [r[0] for r in self.index._q("SELECT event_type FROM cleanup_audit WHERE account=? ORDER BY seq", ACCT)]

    def m4_snapshot(self):
        return (table_digest(self.index, M4_TABLES), audit.head(self.index, ACCT), self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0])

    def refused(self, fn):
        before = self.m4_snapshot()
        with self.assertRaises(cp.PlanError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, "SYNC_NOT_HEALTHY")
        self.assertNotIn("Create a new plan", str(ctx.exception))
        self.assertIn("unchanged", str(ctx.exception))
        self.assertEqual(before, self.m4_snapshot())                       # not one byte of plan, approval, execution or audit state changed
        return ctx.exception

    def each_condition(self, make_call):
        for cond in CONDITIONS:
            with self.subTest(condition=cond):
                call = make_call()
                self.apply(cond)
                try:
                    self.assertNotEqual(sync_health.problems(self.index, ACCT, self.t), [], cond)
                    self.refused(call)
                finally:
                    self.restore()


class GuardMatrixTests(GuardBase):
    def test_create_and_revise_are_prohibited(self):
        self.each_condition(lambda: (lambda: cp.create_plan(self.index, ACCT, self.ids[:2], now=self.tick())))
        draft = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        self.each_condition(lambda: (lambda: cp.revise_exclude(self.index, ACCT, draft["plan_id"], [self.ids[0]], now=self.tick())))

    def test_review_is_prohibited(self):
        draft = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        self.each_condition(lambda: (lambda: cp.mark_reviewed(self.index, ACCT, draft["plan_id"], cp.review_phrase(draft), now=self.tick())))

    def test_approval_is_prohibited(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        self.each_condition(lambda: (lambda: cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())))

    def test_reservation_is_prohibited_and_consumes_nothing(self):
        plan = self.approved_plan()
        phrase = ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0])
        self.each_condition(lambda: (lambda: ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=self.tick())))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_the_canary_plan_entry_point_is_prohibited(self):
        self.each_condition(lambda: (lambda: cp._insert_plan(self.index, ACCT, [self.ids[0]], cp.cc.MIN_AGE_DAYS, self.tick(), canary=True)))

    def test_slice_continuation_is_prohibited(self):
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 131)])
        big = [f"m{i}" for i in range(1, 131)]
        plan = self.approved_plan(big)
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        phrase = ce.continuation_phrase(plan, 2, 100)
        self.each_condition(lambda: (lambda: ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, phrase, now=self.tick())))

    def test_refusals_are_neither_audited_nor_counted_towards_the_lockout(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        events = self.events()
        self.apply("NEEDS_RECONCILE")
        for _ in range(cp.MAX_FAILED_ATTEMPTS + 5):                          # far more than the lockout allows
            self.refused(lambda: cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick()))
        self.assertEqual(self.events(), events)
        self.restore()
        approved = cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())   # no LOCKED_OUT
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_stopping_and_inspection_stay_available_in_every_condition(self):
        plan = self.approved_plan()
        for cond in CONDITIONS:
            with self.subTest(condition=cond):
                self.apply(cond)
                self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "APPROVED")
                self.assertTrue(cp.list_plans(self.index, ACCT))
                self.assertTrue(cp.approval_status(self.index, ACCT, plan["plan_id"], self.t))
                problems = cp.verify_approved(self.index, ACCT, plan["plan_id"], self.tick())       # read-only: reports the sync codes, writes nothing
                self.assertTrue(set(problems) & cp.SYNC_CODES)
                self.assertTrue(ce.dry_run(self.index, ACCT, plan["plan_id"], now=self.tick()))
                cp.expire_due(self.index, ACCT, self.t)
                self.restore()
        self.apply("NEEDS_RECONCILE")
        cp.cancel(self.index, ACCT, plan["plan_id"], now=self.tick())                                 # cancelling is always safe
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "CANCELLED")

    def test_an_unhealthy_condition_takes_precedence_over_a_stale_plan(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        with self.index.conn:
            self.index.conn.execute("UPDATE messages SET sender='changed@x.example.test' WHERE id=?", (self.ids[0],))
        self.apply("INTERRUPTED")
        with self.assertRaises(cp.PlanError) as ctx:
            cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
        self.assertEqual(ctx.exception.code, "SYNC_NOT_HEALTHY")      # the prohibition comes first ...
        self.restore()
        with self.assertRaises(cp.PlanError) as ctx:
            cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
        self.assertEqual(ctx.exception.code, "STALE")                   # ... and the plan's own staleness is reported once health is back


class SyncEffectOnPlansTests(GuardBase):
    """P1-P5 with REAL sync runs against a fake mailbox mirroring the fixture index."""

    def setUp(self):
        super().setUp()
        self.mb = FakeHistoryMailbox(ACCT)
        self.mb.hid = 1000                                                     # matches the seeded checkpoint
        for r in self.index._q("SELECT id, thread_id, internal_ms, size, sender FROM messages WHERE account=?", ACCT):
            labels = sorted(x[0] for x in self.index._q("SELECT label_id FROM message_labels WHERE account=? AND message_id=?", ACCT, r["id"]))
            self.mb.msgs[r["id"]] = {"id": r["id"], "thread_id": r["thread_id"], "internal_ms": r["internal_ms"], "size": r["size"], "sender": r["sender"], "label_ids": labels}

    def run_sync(self):
        return sync.run_sync(self.mb, self.index, ACCT, limiter=fast_limiter(), sleep=lambda s: None)

    def valid_problems(self, plan):
        return cp.verify_approved(self.index, ACCT, plan["plan_id"], self.tick())

    def test_p1_a_label_change_makes_the_plan_stale_and_the_approval_unusable_but_untouched(self):
        plan = self.approved_plan()
        self.assertEqual(self.valid_problems(plan), {})
        before = self.m4_snapshot()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.run_sync()
        self.assertEqual(before, self.m4_snapshot())                           # P2: sync never touches plans, approvals, executions or the audit log
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])      # the immutable record still exists ...
        problems = self.valid_problems(plan)
        self.assertIn("ITEM_CHANGED", problems)                                # ... but it can no longer authorize anything
        self.assertFalse(set(problems) & cp.SYNC_CODES)                        # stale, NOT "prohibited until sync health returns"
        phrase = ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0])
        with self.assertRaises(ce.ExecError) as ctx:
            ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=self.tick())
        self.assertEqual(ctx.exception.code, "NOT_EXECUTABLE")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])      # a refused reservation consumed nothing

    def test_p1_a_deleted_item_makes_the_plan_stale(self):
        plan = self.approved_plan()
        self.mb.delete(self.ids[1])
        self.run_sync()
        self.assertIn("ITEM_MISSING", self.valid_problems(plan))
        self.assertEqual(self.index._q("SELECT message_id FROM message_tombstone")[0][0], self.ids[1])

    def test_p1_losing_eligibility_makes_the_plan_stale(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[2], add=("STARRED",))                    # a starred message is not an eligible candidate
        self.run_sync()
        problems = self.valid_problems(plan)
        self.assertTrue({"ITEM_CHANGED", "ITEM_NOT_ELIGIBLE"} & set(problems))

    def test_p1_a_sync_with_no_net_change_leaves_the_plan_valid(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.mb.labels_change(self.ids[0], remove=("STARRED",))
        self.run_sync()
        self.assertEqual(self.valid_problems(plan), {})
        self.mb.add("brand-new", ("INBOX",))                                    # new, unrelated messages do not affect the plan either
        self.run_sync()
        self.assertEqual(self.valid_problems(plan), {})

    def test_p1_a_change_that_is_changed_back_keeps_the_plan_stale(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.run_sync()
        self.mb.labels_change(self.ids[0], remove=("STARRED",))
        self.run_sync()
        self.assertEqual(self.index_labels(self.ids[0]), sorted(self.mb.msgs[self.ids[0]]["label_ids"]))   # the labels are back as they were ...
        self.assertIn("ITEM_CHANGED", self.valid_problems(plan))                                           # ... but the negative scan_id keeps the plan stale

    def index_labels(self, mid):
        return sorted(x[0] for x in self.index._q("SELECT label_id FROM message_labels WHERE account=? AND message_id=?", ACCT, mid))

    def test_p1_a_changed_message_loses_its_current_classification(self):
        self.assertEqual(classifier.counts(self.index, ACCT)["stale"], 0)
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.run_sync()
        self.assertEqual(classifier.counts(self.index, ACCT)["stale"], 1)       # msg_scan_id no longer equals the negative scan_id

    def test_p2_a_stale_approval_never_becomes_valid_again(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.run_sync()
        for _ in range(3):
            self.run_sync()
            self.assertIn("ITEM_CHANGED", self.valid_problems(plan))
        with self.assertRaises(ce.ExecError):
            ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0]), now=self.tick())

    def test_p3_p4_unhealthy_sync_blocks_then_recovery_restores_the_untouched_plan(self):
        plan = self.approved_plan()
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='INTERRUPTED', reason='API_QUOTA'")
        self.refused(lambda: ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0]), now=self.tick()))
        self.run_sync()                                                         # a completed sync restores health
        self.assertEqual((self.index._q("SELECT status FROM sync_state")[0][0], sync_health.problems(self.index, ACCT, self.tick())), ("OK", []))
        self.assertEqual(self.valid_problems(plan), {})                         # the plan was never touched, so it passes again
        ex = ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0]), now=self.tick())
        self.assertEqual(ex["state"], "PREPARED")

    def test_p4_a_touched_plan_stays_stale_after_health_returns(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='INTERRUPTED'")
        self.run_sync()
        self.assertEqual(sync_health.problems(self.index, ACCT, self.tick()), [])
        self.assertIn("ITEM_CHANGED", self.valid_problems(plan))

    def test_p5_the_audit_chain_verifies_after_every_scenario(self):
        plan = self.approved_plan()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.mb.delete(self.ids[3])
        self.run_sync()
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_a_sync_is_refused_while_an_execution_is_active_and_a_reservation_while_a_sync_is_active(self):
        plan = self.approved_plan()
        ex = self.reserve(plan)
        with self.assertRaises(sync_lease.SyncError) as ctx:
            self.run_sync()
        self.assertEqual(ctx.exception.code, "SYNC_EXECUTION_ACTIVE")
        ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        plan2 = self.approved_plan(self.ids[3:5])
        lease = sync_lease.acquire(self.index, ACCT, "INCREMENTAL")
        self.refused(lambda: ce.reserve_execution(self.index, ACCT, plan2["plan_id"], ce.execution_phrase(plan2, 2), now=self.tick()))
        lease.finish("interrupted", "INTERRUPTED", "API_ERROR")


class HandshakeAndInventoryTests(GuardBase):
    """G2 / D145: the first runnable sync/scan path cannot exist without its M4 protections."""

    GUARDED = {"cleanup_plans": {"create_plan", "revise_exclude", "mark_reviewed", "approve"},
               "cleanup_exec": {"reserve_execution", "confirm_slice"}}
    REVALIDATING = {"cleanup_plans": {"revalidate", "verify_approved"}, "cleanup_exec": {"dry_run"}}   # read-only: they REPORT the sync codes
    ALWAYS_ALLOWED = {"cleanup_plans": {"cancel", "expire_due", "get_plan", "list_plans", "approval_status", "approval_phrase", "review_phrase", "short",
                                        "snapshot_of", "valid_id", "integrity_problems", "sync_guard_error", "sync_only", "sync_codes", "require_sync_health"},
                      "cleanup_exec": {"abort_execution", "code_counts", "continuation_blockers", "continuation_phrase", "execution_phrase", "get_execution",
                                       "invariant_problems", "item_counts", "list_executions", "overlap", "plan_slices", "postread_context", "reconcile_context",
                                       "reconcile_item", "recover_interrupted", "slices"}}
    # act only INSIDE an execution that reserve_execution/confirm_slice (both guarded) created; sync cannot run while one exists
    INSIDE_RESERVED_EXECUTION = {"cleanup_exec": {"start_slice", "renew_lease", "record_intent", "record_outcome", "record_skip", "end_slice", "stop_execution"}}

    def public(self, module):
        return {n for n, f in inspect.getmembers(module, inspect.isfunction) if f.__module__ == module.__name__ and not n.startswith("_")}

    def test_every_public_m4_callable_is_classified_so_a_new_one_cannot_slip_past_the_guard(self):
        for module in (cp, ce):
            name = module.__name__.split(".")[-1]
            known = set().union(self.GUARDED.get(name, set()), self.REVALIDATING.get(name, set()), self.ALWAYS_ALLOWED.get(name, set()),
                                self.INSIDE_RESERVED_EXECUTION.get(name, set()))
            self.assertEqual(self.public(module), known, f"{name}: classify every public callable (guarded / always allowed / inside a reserved execution)")

    def test_every_guarded_callable_has_a_refusal_test_in_the_matrix(self):
        """The matrix (GuardMatrixTests) exercises each guarded callable in every sync condition; a guarded name it does not call would fail here."""
        source = inspect.getsource(GuardMatrixTests)
        for module, names in (("cp", self.GUARDED["cleanup_plans"]), ("ce", self.GUARDED["cleanup_exec"])):
            for name in names:
                self.assertIn(f"{module}.{name}(", source, f"{module}.{name} has no refusal test")
        self.assertIn("cp._insert_plan(", source)       # the canary entry point

    def test_mutation_without_the_check_the_guarded_call_would_succeed(self):
        """Proves the refusal comes from sync_health and nothing else: neutralise it and the same call goes through."""
        self.apply("NEEDS_RECONCILE")
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, self.ids[:2], now=self.tick())
        with mock.patch.object(sync_health, "problems", return_value=[]):
            self.assertEqual(cp.create_plan(self.index, ACCT, self.ids[:2], now=self.tick())["state"], "DRAFT")

    def test_the_handshake_refuses_when_the_contract_or_the_gate_is_missing(self):
        sync_lease.guard_ok()
        for target, name, value in ((cp, "SYNC_GUARD_CONTRACT", 0), (ce, "SYNC_GUARD_CONTRACT", 0), (cp, "SYNC_GUARD_CONTRACT", None), (cp, "require_sync_health", None),
                                    (cp, "sync_codes", None)):
            with self.subTest(target.__name__, name=name, value=value), mock.patch.object(target, name, value), self.assertRaises(sync_lease.SyncError) as ctx:
                sync_lease.guard_ok()
            self.assertEqual(ctx.exception.code, "SYNC_GUARD_MISSING")

    def test_without_the_handshake_no_lease_scan_or_sync_can_start_and_nothing_is_touched(self):
        self.index.close()
        before = file_digest(self.index.path)
        mb = FakeHistoryMailbox(ACCT)
        with mock.patch.object(cp, "SYNC_GUARD_CONTRACT", 0):
            fresh = __import__("gmail_intelligence.index", fromlist=["Index"]).Index(self.index.path)
            try:
                for kind in ("INCREMENTAL", "FULL", "LIMITED"):
                    with self.assertRaises(sync_lease.SyncError) as ctx:
                        sync_lease.acquire(fresh, ACCT, kind)
                    self.assertEqual(ctx.exception.code, "SYNC_GUARD_MISSING")
                with self.assertRaises(sync_lease.SyncError):
                    sync.run_sync(mb, fresh, ACCT)
                with self.assertRaises(sync_lease.SyncError):
                    scanner.run_scan(mb, fresh, ACCT, mode="full")
                with self.assertRaises(sync_lease.SyncError):
                    scanner.run_scan(mb, fresh, ACCT, mode="limited", limit=3)
            finally:
                fresh.close()
        self.assertEqual(mb.calls, [])                                        # no Gmail request
        import sqlite3
        c = sqlite3.connect(self.index.path)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sync_run").fetchone()[0], 0)
        c.close()

    def test_the_cli_runs_the_handshake_before_opening_the_index_or_a_reader(self):
        import argparse
        import os
        from sync_support import config
        home = self.tmp / "clihome"
        with mock.patch.dict(os.environ, {config.HOME_ENV: str(home)}), mock.patch.object(cp, "SYNC_GUARD_CONTRACT", 0), \
                mock.patch.object(cli, "_open_reader", side_effect=AssertionError("reader must not be opened")):
            for fn, ns in ((cli.cmd_mailbox_scan, argparse.Namespace(all=True, limit=None, resume=False, max_units_per_minute=1, accept_count_mismatch=False,
                                                                      allow_large_prune=False, account=ACCT)),
                           (cli.cmd_mailbox_sync, argparse.Namespace(status=False, account=ACCT, max_units_per_minute=1))):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(fn(ns), 1)
                self.assertIn("SYNC_GUARD_MISSING", err.getvalue())
            self.assertFalse((home / "index.sqlite3").exists())               # not even an empty index file was created

    def test_m4_modules_keep_no_gmail_or_write_capability_after_the_guard_changes(self):
        for module in (cp, ce):
            text = inspect.getsource(module)
            for banned in ("googleapiclient", "oauth", "keystore", "urllib", "socket", "requests"):
                self.assertNotIn(banned, text, (module.__name__, banned))
        from gmail_intelligence import gmail_write_policy
        self.assertIs(cleanup_executor.live.LIVE_EXECUTION_ENABLED, False)


if __name__ == "__main__":
    unittest.main()


class ExpiryUnderUnhealthySyncTests(GuardBase):
    """Review finding 1: time-driven expiry stays; a REFUSED request itself writes no rejection record and no lockout count, even for an expired plan."""

    def lockout_attempts(self, plan_id, event):
        return audit.recent(self.index, ACCT, plan_id, (event,), cp._iso(self.t - cp.LOCKOUT_WINDOW))

    def setup_plan(self, upto):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        if upto in ("REVIEWED", "APPROVED"):
            plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        if upto == "APPROVED":
            cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
            plan = cp.get_plan(self.index, ACCT, plan["plan_id"])
        return plan

    def immutable_content(self, plan_id):
        plan = self.index._q("SELECT plan_id, version, parent_id, action, plan_hash, snapshot, item_count, created_at, expires_at FROM cleanup_plan WHERE plan_id=?", plan_id)
        appr = self.index._q("SELECT plan_id, nonce, plan_hash, action, item_count, created_at, expires_at FROM cleanup_approval WHERE plan_id=?", plan_id)
        return [tuple(r) for r in plan], [tuple(r) for r in appr]

    def scenario(self, upto, hours_later):
        plan = self.setup_plan(upto)
        return plan, self.immutable_content(plan["plan_id"]), self.t + timedelta(hours=hours_later), self.all_events()

    def test_expired_draft_review_while_unhealthy(self):
        plan, content, later, events = self.scenario("DRAFT", 49)
        self.apply("INTERRUPTED")
        with self.assertRaises(cp.PlanError) as ctx:
            cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=later)
        self.assertEqual(ctx.exception.code, "SYNC_NOT_HEALTHY")
        self.assertEqual(self.all_events()[len(events):], ["PLAN_EXPIRED"])              # the legitimate time-driven expiry, nothing else
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "EXPIRED")
        self.assertEqual(self.lockout_attempts(plan["plan_id"], "REVIEW_REJECTED"), 0)
        self.assertEqual(content, self.immutable_content(plan["plan_id"]))
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_expired_reviewed_plan_approval_while_unhealthy(self):
        plan, content, later, events = self.scenario("REVIEWED", 49)
        self.apply("NEEDS_RECONCILE")
        for _ in range(cp.MAX_FAILED_ATTEMPTS + 3):
            with self.assertRaises(cp.PlanError) as ctx:
                cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=later)
            self.assertEqual(ctx.exception.code, "SYNC_NOT_HEALTHY")                   # never BAD_STATE / LOCKED_OUT while health is the problem
        self.assertEqual(self.all_events()[len(events):], ["PLAN_EXPIRED"])              # expiry is recorded ONCE; refusals add nothing
        self.assertEqual(self.lockout_attempts(plan["plan_id"], "APPROVAL_REJECTED"), 0)
        self.assertEqual(content, self.immutable_content(plan["plan_id"]))
        self.assertEqual(self.approval_status(plan["plan_id"]), [])

    def test_expired_approval_reservation_while_unhealthy(self):
        plan, content, later, events = self.scenario("APPROVED", 25)               # the approval (24 h) is past its term, the plan (48 h) is not
        self.apply("IN_PROGRESS")
        phrase = ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0])
        for _ in range(cp.MAX_FAILED_ATTEMPTS + 3):
            with self.assertRaises(cp.PlanError) as ctx:
                ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=later)
            self.assertEqual(ctx.exception.code, "SYNC_NOT_HEALTHY")
        self.assertEqual(self.all_events()[len(events):], [])                           # reserve never expires anything; the refusals added nothing
        self.assertEqual(self.lockout_attempts(plan["plan_id"], "RESERVATION_REJECTED"), 0)
        self.assertEqual(content, self.immutable_content(plan["plan_id"]))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])              # the immutable approval record is untouched
        self.restore()
        with self.assertRaises(ce.ExecError) as ctx:                                    # once health is back the ordinary reason applies
            ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=later)
        self.assertEqual(ctx.exception.code, "NOT_EXECUTABLE")

    def test_expiry_itself_is_unchanged_when_healthy(self):
        plan, content, later, events = self.scenario("APPROVED", 49)
        cp.expire_due(self.index, ACCT, later)
        self.assertEqual(self.all_events()[len(events):], ["APPROVAL_EXPIRED", "PLAN_EXPIRED"])
        self.assertEqual(self.approval_status(plan["plan_id"]), ["EXPIRED"])
        self.assertEqual(content[0], self.immutable_content(plan["plan_id"])[0])

    def test_expiry_and_cancel_remain_available_while_unhealthy(self):
        plan, content, later, events = self.scenario("APPROVED", 49)
        self.apply("NEEDS_RECONCILE")
        self.assertEqual(cp.expire_due(self.index, ACCT, later), 1)
        self.assertEqual(self.all_events()[len(events):], ["APPROVAL_EXPIRED", "PLAN_EXPIRED"])
        self.assertEqual(self.approval_status(plan["plan_id"]), ["EXPIRED"])
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class GuardMutationTests(GuardBase):
    """Review finding 3: the guard tests must DETECT a bypass of E1-E5. Each mutant removes one layer of the guard (by behaviour, not by editing source) and
    the suite's own checks have to notice. `checks()` runs every guarded entry point in an unhealthy index (including the expired-plan cases of finding 1)."""

    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 131)])
        self.big = [f"m{i}" for i in range(1, 131)]

    def clean_refusal(self, call, before):
        """True only if `call` is refused with SYNC_NOT_HEALTHY, without any rejection record attempt and without changing any M4 state."""
        with mock.patch.object(cp, "_reject", wraps=cp._reject) as rejected:
            try:
                call()
            except cp.PlanError as exc:
                return exc.code == "SYNC_NOT_HEALTHY" and rejected.call_count == 0 and before == self.m4_snapshot()
            return False

    def checks(self):
        out = {}
        # a fresh plan in every lifecycle state, then unhealthy
        draft = cp.create_plan(self.index, ACCT, self.big[:5], now=self.tick())
        p2 = cp.create_plan(self.index, ACCT, self.big[5:10], now=self.tick())
        reviewed = cp.mark_reviewed(self.index, ACCT, p2["plan_id"], cp.review_phrase(p2), now=self.tick())
        approved = self.approved_plan(self.big[10:15])
        far = self.t + timedelta(hours=49)
        self.apply("NEEDS_RECONCILE")
        before = self.m4_snapshot()
        out["create"] = self.clean_refusal(lambda: cp.create_plan(self.index, ACCT, self.big[20:23], now=self.tick()), before)
        out["review"] = self.clean_refusal(lambda: cp.mark_reviewed(self.index, ACCT, draft["plan_id"], cp.review_phrase(draft), now=self.tick()), before)
        out["approve"] = self.clean_refusal(lambda: cp.approve(self.index, ACCT, reviewed["plan_id"], cp.approval_phrase(reviewed), now=self.tick()), before)
        phrase = ce.execution_phrase(approved, ce.plan_slices(approved["item_count"])[0])
        out["reserve"] = self.clean_refusal(lambda: ce.reserve_execution(self.index, ACCT, approved["plan_id"], phrase, now=self.tick()), before)
        out["verify_reports_the_sync_code"] = bool(set(cp.verify_approved(self.index, ACCT, approved["plan_id"], self.tick())) & cp.SYNC_CODES)
        # the expired-plan cases: the prohibition must still come first, and expiry must still be the only write
        cp.expire_due(self.index, ACCT, far)                                    # time-driven expiry (always allowed) so the next calls see expired plans
        before = self.m4_snapshot()
        out["review_expired"] = self.clean_refusal(lambda: cp.mark_reviewed(self.index, ACCT, draft["plan_id"], cp.review_phrase(draft), now=far), before)
        out["approve_expired"] = self.clean_refusal(lambda: cp.approve(self.index, ACCT, reviewed["plan_id"], cp.approval_phrase(reviewed), now=far), before)
        out["reserve_expired"] = self.clean_refusal(lambda: ce.reserve_execution(self.index, ACCT, approved["plan_id"], phrase, now=far), before)
        self.restore()
        return out

    def continuation_check(self):
        plan = self.approved_plan(self.big)
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        phrase = ce.continuation_phrase(plan, 2, 100)
        self.apply("INTERRUPTED")
        before = self.m4_snapshot()
        ok = self.clean_refusal(lambda: ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, phrase, now=self.tick()), before)
        self.restore()
        return ok

    def failing(self):
        return {name for name, held in self.checks().items() if not held}

    def test_the_guard_holds_in_every_check_with_nothing_mutated(self):
        self.assertEqual(self.failing(), set())

    def test_continuation_guard_holds(self):
        self.assertTrue(self.continuation_check())

    def test_mutant_without_any_health_code_is_detected_everywhere(self):
        with mock.patch.object(cp, "sync_codes", return_value=[]):
            self.assertEqual(self.failing(), {"create", "review", "approve", "reserve", "verify_reports_the_sync_code", "review_expired", "approve_expired", "reserve_expired"})

    def test_mutant_without_the_up_front_gate_is_detected_by_create_and_the_expired_plan_cases(self):
        with mock.patch.object(cp, "require_sync_health", lambda *a, **k: None):
            failing = self.failing()
        self.assertTrue({"create", "review_expired", "approve_expired", "reserve_expired"} <= failing, failing)

    def test_mutant_without_gate_and_without_the_fallback_mapping_fails_every_guarded_call(self):
        with mock.patch.object(cp, "require_sync_health", lambda *a, **k: None), mock.patch.object(cp, "sync_only", lambda p: False):
            failing = self.failing()
        self.assertTrue({"create", "review", "approve", "reserve", "review_expired", "approve_expired", "reserve_expired"} <= failing, failing)

    def test_mutant_continuation_without_its_gate_is_detected(self):
        with mock.patch.object(cp, "require_sync_health", lambda *a, **k: None), mock.patch.object(cp, "sync_only", lambda p: False):
            self.assertFalse(self.continuation_check())

    def test_the_rejection_probe_is_sensitive(self):
        """Control for the 'no rejection attempted' assertion: an ordinary refusal (healthy index, wrong state) DOES call _reject."""
        plan = cp.create_plan(self.index, ACCT, self.big[:3], now=self.tick())
        with mock.patch.object(cp, "_reject", wraps=cp._reject) as rejected, self.assertRaises(cp.PlanError):
            cp.approve(self.index, ACCT, plan["plan_id"], "x", now=self.tick())          # BAD_STATE: the plan was never reviewed
        self.assertEqual(rejected.call_count, 1)


class ConcurrencyWithSyncTests(GuardBase):
    """Review finding 4: the health observation and the commit of every guarded M4 operation are ONE `BEGIN IMMEDIATE` transaction, and sync lease acquisition is
    another; SQLite serialises them, so a healthy observation cannot be invalidated before its transaction commits. Proven with two real connections and threads."""

    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 6)])

    def in_thread(self, fn, timeout_ms=150):
        """Run fn(second_index) on its own connection (SQLite connections are per thread) with a short busy timeout; returns a result holder."""
        holder = {}

        def run():
            ix = idx.Index(self.index.path)
            ix.conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
            try:
                holder["value"] = fn(ix)
            except BaseException as exc:  # noqa: BLE001 - recorded for the test
                holder["error"] = exc
            finally:
                ix.close()
        t = threading.Thread(target=run)
        holder["thread"] = t
        return holder

    def hold_inside_the_transaction(self, operation):
        """Run `operation` (an M4 call in THIS thread) and, right after its health observation, let a competing sync acquire run to completion or timeout."""
        competitor = self.in_thread(lambda ix: sync_lease.acquire(ix, ACCT, "INCREMENTAL"))
        real = sync_health.problems
        seen = {"n": 0}

        def observe(index, account, now=None):
            codes = real(index, account, now)
            seen["n"] += 1
            if seen["n"] == 1 and not codes:
                competitor["thread"].start()
                competitor["thread"].join(timeout=10)       # the competitor must NOT get through while we hold the write lock
                competitor["during"] = dict(competitor)
            return codes
        with mock.patch.object(sync_health, "problems", observe):
            result = operation()
        return competitor, result

    def test_a_sync_cannot_take_the_lease_between_an_approvals_health_check_and_its_commit(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        competitor, result = self.hold_inside_the_transaction(lambda: cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick()))
        during = competitor["during"]
        self.assertIsInstance(during.get("error"), sync_lease.SyncError)                  # it could not interleave ...
        self.assertEqual(during["error"].code, "SYNC_BUSY")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])                # ... and the approval, decided on a healthy state, committed intact
        self.assertEqual(sync_health.problems(self.index, ACCT, self.t), [])              # no sync run existed at that commit
        later = idx.Index(self.index.path)                                                # afterwards the sync may proceed; the approved plan then blocks it? no: only an execution does
        try:
            lease = sync_lease.acquire(later, ACCT, "INCREMENTAL")
            lease.finish("interrupted", "INTERRUPTED", "API_ERROR")
        finally:
            later.close()

    def test_a_sync_cannot_take_the_lease_between_a_reservations_health_check_and_its_commit_and_is_then_refused(self):
        plan = self.approved_plan()
        phrase = ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0])
        competitor, ex = self.hold_inside_the_transaction(lambda: ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=self.tick()))
        self.assertEqual(competitor["during"]["error"].code, "SYNC_BUSY")                 # blocked while the reservation transaction was open
        self.assertEqual(ex["state"], "PREPARED")
        retry = idx.Index(self.index.path)
        try:
            with self.assertRaises(sync_lease.SyncError) as ctx:                          # once committed, the execution excludes any sync
                sync_lease.acquire(retry, ACCT, "INCREMENTAL")
            self.assertEqual(ctx.exception.code, "SYNC_EXECUTION_ACTIVE")
        finally:
            retry.close()

    def test_a_plan_creation_is_equally_serialised_with_the_lease(self):
        competitor, plan = self.hold_inside_the_transaction(lambda: cp.create_plan(self.index, ACCT, self.ids[:2], now=self.tick()))
        self.assertEqual(competitor["during"]["error"].code, "SYNC_BUSY")
        self.assertEqual(plan["state"], "DRAFT")

    def test_a_sync_that_committed_first_makes_the_approval_wait_and_then_refuse(self):
        """The reverse order: the lease transaction holds the write lock; the M4 call blocks on its BEGIN IMMEDIATE, then observes the unhealthy state."""
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        events = self.all_events()
        locker = idx.Index(self.index.path)
        self.addCleanup(locker.close)
        locker.conn.execute("BEGIN IMMEDIATE")                                            # the sync's acquire transaction, half way
        locker.conn.execute("UPDATE sync_state SET status='IN_PROGRESS'")
        locker.conn.execute("INSERT INTO sync_run (account,kind,status,started_at,lease_token,lease_expires_at,heartbeat_at) VALUES (?,?,?,?,?,?,?)",
                            (ACCT, "INCREMENTAL", "running", "2027-01-15T07:00:00Z", "c" * 64, "2099-01-01T00:00:00Z", "2027-01-15T07:00:00Z"))
        outcome = self.in_thread(lambda ix: cp.approve(ix, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick()), timeout_ms=8000)
        outcome["thread"].start()
        time.sleep(0.4)
        self.assertTrue(outcome["thread"].is_alive())                                     # blocked on the write lock: it has decided nothing yet
        locker.conn.commit()                                                              # the sync's acquire commits
        outcome["thread"].join(10)
        self.assertEqual(outcome["error"].code, "SYNC_NOT_HEALTHY")                       # the approval then observes the unhealthy state and refuses
        self.assertEqual(self.approval_status(plan["plan_id"]), [])
        self.assertEqual(self.all_events(), events)

    def test_the_approval_retried_after_the_sync_finished_is_refused_for_health_not_committed(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        self.apply("IN_PROGRESS")
        events = self.all_events()
        holder = self.in_thread(lambda ix: cp.approve(ix, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick()))
        holder["thread"].start()
        holder["thread"].join(10)
        self.assertEqual(holder["error"].code, "SYNC_NOT_HEALTHY")
        self.assertEqual(self.all_events(), events)


class SyncAcquireBusyTests(unittest.TestCase):
    def test_a_write_lock_held_by_another_connection_gives_a_clean_busy_refusal(self):
        import sqlite3, tempfile, os
        from sync_support import ACCOUNT
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "i.sqlite3")
            a = idx.Index(path)
            b = idx.Index(path)
            b.conn.execute("PRAGMA busy_timeout = 100")
            a.conn.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaises(sync_lease.SyncError) as ctx:
                    sync_lease.acquire(b, ACCOUNT, "FULL")
                self.assertEqual(ctx.exception.code, "SYNC_BUSY")
            finally:
                a.conn.rollback()
                a.close()
                b.close()
