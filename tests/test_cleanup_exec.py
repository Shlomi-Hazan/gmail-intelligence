"""Offline tests for M4C-A: schema v5, local execution state, approval consumption, concurrency, recovery and dry runs.

Synthetic data only. There is NO Gmail client, OAuth write credential or network access in this milestone; "outcomes" below are
synthetic values fed to the state machine, never real Gmail results. Sockets are blocked and Gmail/Keychain are replaced by bombs.
"""
import ast
import contextlib
import io
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import textwrap
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, OTHER, msg  # noqa: E402
from test_cleanup_plans import PlanBase, T0  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_exec_report, cleanup_plans as cp, cleanup_protect  # noqa: E402
from gmail_intelligence import cli, config  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402


class ExecBase(PlanBase):
    def setUp(self):
        super().setUp()
        self.t = T0

    token = None

    def ev(self, mid, labels=("CATEGORY_PROMOTIONS",), when=None, **kw):
        """Structured, caller-supplied evidence (test-only construction; production has no adapter that could produce authenticated evidence)."""
        return ce.Evidence(kw.get("kind", "LABEL_OBSERVATION"), kw.get("message_id", mid), tuple(labels), when or cp._iso(self.t), kw.get("source", "CALLER_SUPPLIED"))

    def tick(self, seconds=10):
        self.t = self.t + timedelta(seconds=seconds)  # small steps keep the 5-minute execution lease alive across a test
        return self.t

    def approved_plan(self, ids=None):
        ids = ids or self.ids[:3]
        plan = cp.create_plan(self.index, ACCT, ids, now=self.tick())
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())
        return cp.get_plan(self.index, ACCT, plan["plan_id"])

    def reserve(self, plan=None, **kw):
        plan = plan or self.approved_plan()
        phrase = kw.pop("phrase", ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0]))
        return ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=kw.pop("now", None) or self.tick())

    def started(self, plan=None, slice_no=1):
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], slice_no, now=self.tick())
        return ce.get_execution(self.index, ACCT, ex["exec_id"])

    def ids_of(self, exec_id, slice_no=None, state=None):
        sql, p = "SELECT message_id FROM cleanup_exec_item WHERE account=? AND exec_id=?", [ACCT, exec_id]
        if slice_no:
            sql += " AND slice_no=?"
            p.append(slice_no)
        if state:
            sql += " AND state=?"
            p.append(state)
        return [r[0] for r in self.index._q(sql + " ORDER BY seq", *p)]

    def apply_all(self, ex, slice_no=1, outcome="APPLIED"):
        for mid in self.ids_of(ex["exec_id"], slice_no, "PENDING"):
            ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=self.tick())  # a real executor heartbeats like this
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
            if outcome == "APPLIED":
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=self.ev(mid), now=self.tick())
            else:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, outcome, now=self.tick())

    def exec_state(self, exec_id):
        return ce.get_execution(self.index, ACCT, exec_id)["state"]

    def approval_status(self, plan_id):
        return [r[0] for r in self.index._q("SELECT status FROM cleanup_approval WHERE plan_id=?", plan_id)]


class MigrationV5Tests(ExecBase):
    def make_v4(self):
        path = self.tmp / "v4" / "index.sqlite3"
        path.parent.mkdir(mode=0o700, parents=True)
        c = sqlite3.connect(path)
        c.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + idx.SCHEMA_V4 + "PRAGMA user_version = 4;COMMIT;")
        c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", (ACCT, "m1", "t1", 1000, 10, "a@x.example.test", 0, 1))
        c.execute("INSERT INTO protect_rules (account,id,c_domain,enabled,created_at) VALUES (?,?,?,?,?)", (ACCT, "p1", "x.example.test", 1, "t"))
        c.commit()
        c.close()
        return path

    def rows(self, path):
        c = sqlite3.connect(path)
        data = {t: c.execute(f"SELECT * FROM {t} ORDER BY 1,2,3").fetchall() for t in ("messages", "protect_rules", "cleanup_plan", "cleanup_audit")}
        c.close()
        return data

    def test_v4_to_v5_preserves_rows_with_private_verified_backup(self):
        path = self.make_v4()
        before = self.rows(path)
        with idx.Index(str(path)) as index:
            self.assertEqual((index.migrated_from, index.conn.execute("PRAGMA user_version").fetchone()[0]), (4, 5))
            for t in ("cleanup_execution", "cleanup_exec_slice", "cleanup_exec_item"):
                self.assertEqual(index._q(f"SELECT COUNT(*) FROM {t}")[0][0], 0)
            backup = Path(index.backup_path)
        self.assertIn("pre-m4c-backup", backup.name)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(self.rows(path), before)
        b = sqlite3.connect(backup)
        self.assertEqual(b.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(b.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'cleanup_exec%'").fetchone()[0], 0)
        b.close()
        with idx.Index(str(path)) as again:
            self.assertIsNone(again.migrated_from)
        self.assertEqual(len([p for p in path.parent.iterdir() if "backup" in p.name]), 1)

    def test_failed_upgrade_keeps_v4_and_the_verified_backup(self):
        path = self.make_v4()
        before = self.rows(path)
        with mock.patch.object(idx, "SCHEMA_V5", "CREATE TABLE cleanup_execution (x);CREATE TABLE cleanup_execution (x);"):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.Index(str(path))
        self.assertIn("backup was kept", str(cm.exception))
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'cleanup_exec%'").fetchone()[0], 0)
        c.close()
        self.assertEqual(self.rows(path), before)
        (kept,) = [p for p in path.parent.iterdir() if "backup" in p.name]
        self.assertEqual(stat.S_IMODE(os.stat(kept).st_mode), 0o600)

    def test_backup_failure_leaves_no_partial_file_and_v4_untouched(self):
        path = self.make_v4()

        def boom(conn, p, version):
            Path(p).write_bytes(b"partial")
            raise sqlite3.OperationalError("disk full (simulated)")
        with mock.patch.object(idx, "_write_backup", side_effect=boom):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(path))
        self.assertEqual([p for p in path.parent.iterdir() if "backup" in p.name], [])
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 4)
        c.close()


class ReservationTests(ExecBase):
    def test_reservation_consumes_the_approval_and_freezes_the_targets(self):
        plan = self.approved_plan()
        ex = self.reserve(plan)
        self.assertEqual((ex["state"], ex["item_count"], ex["slice_count"], ex["plan_hash"]), ("PREPARED", 3, 1, plan["plan_hash"]))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["CONSUMED"])
        after = cp.get_plan(self.index, ACCT, plan["plan_id"])
        self.assertEqual((after["state"], after["plan_hash"], after["snapshot"]), ("APPROVED", plan["plan_hash"], plan["snapshot"]))  # plan immutable
        self.assertEqual(self.ids_of(ex["exec_id"]), sorted(i["message_id"] for i in plan["items"]))
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"PENDING": 3})
        (sl,) = ce.slices(self.index, ACCT, ex["exec_id"])
        self.assertEqual((sl["state"], sl["size"], bool(sl["confirmation_sha256"])), ("CONFIRMED", 3, True))
        events = self.events()
        self.assertEqual(events[-2:], ["EXECUTION_RESERVED", "SLICE_CONFIRMED"])
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_a_separate_execution_confirmation_is_required(self):
        plan = self.approved_plan()
        wrong = ["", "yes", cp.approval_phrase(plan), "EXECUTE", f"EXECUTE ARCHIVE 4 {plan['plan_hash'][:8]}",
                 f"execute archive 3 {plan['plan_hash'][:8]}", f"EXECUTE ARCHIVE 3 {'0' * 8}", None]
        for phrase in wrong:
            with self.assertRaises(ce.ExecError, msg=phrase) as cm:
                ce.reserve_execution(self.index, ACCT, plan["plan_id"], phrase, now=self.tick())
            self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])  # nothing consumed by any failed attempt
        self.assertEqual(self.count("cleanup_execution"), 0)
        self.assertEqual(self.events().count("RESERVATION_REJECTED"), len(wrong))
        self.assertNotEqual(ce.execution_phrase(plan, 3), cp.approval_phrase(plan))
        self.reserve(plan)

    def test_failed_confirmations_lock_the_plan(self):
        plan = self.approved_plan()
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(ce.ExecError):
                ce.reserve_execution(self.index, ACCT, plan["plan_id"], "no", now=self.tick(0))
        before = self.count("cleanup_audit")
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(plan)  # even the correct phrase is refused while locked out
        self.assertEqual(cm.exception.code, "LOCKED_OUT")
        self.assertEqual(self.count("cleanup_audit"), before)

    def test_only_approved_unexpired_unrevoked_plans_can_be_reserved(self):
        draft = cp.create_plan(self.index, ACCT, ["m4"], now=self.tick())
        reviewed = cp.mark_reviewed(self.index, ACCT, draft["plan_id"], cp.review_phrase(draft), now=self.tick())
        for p, code in ((draft, "NOT_APPROVED"), (reviewed, "NOT_APPROVED")):
            with self.assertRaises(ce.ExecError) as cm:
                ce.reserve_execution(self.index, ACCT, p["plan_id"], "EXECUTE ARCHIVE 1 " + p["plan_hash"][:8], now=self.tick())
            self.assertEqual(cm.exception.code, code)
        cancelled = self.approved_plan(["m5"])
        cp.cancel(self.index, ACCT, cancelled["plan_id"], now=self.tick())
        with self.assertRaises(ce.ExecError):
            ce.reserve_execution(self.index, ACCT, cancelled["plan_id"], ce.execution_phrase(cancelled, 1), now=self.tick())
        self.assertEqual(self.approval_status(cancelled["plan_id"]), ["REVOKED"])
        expiring = self.approved_plan(["m1", "m2"])
        late = self.t + timedelta(hours=25)
        cp.expire_due(self.index, ACCT, late)
        with self.assertRaises(ce.ExecError):
            ce.reserve_execution(self.index, ACCT, expiring["plan_id"], ce.execution_phrase(expiring, 2), now=late)
        self.assertEqual(self.approval_status(expiring["plan_id"]), ["EXPIRED"])
        self.assertEqual(self.count("cleanup_execution"), 0)

    def test_a_stale_plan_is_refused_without_consuming(self):
        plan = self.approved_plan()
        cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(plan)
        self.assertEqual(cm.exception.code, "NOT_EXECUTABLE")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_a_consumed_approval_can_never_be_used_again(self):
        plan = self.approved_plan()
        ex = self.reserve(plan)
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(plan)
        self.assertEqual(cm.exception.code, "PLAN_ALREADY_HAS_EXECUTION")
        ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        with self.assertRaises(ce.ExecError):  # even after the execution is aborted
            self.reserve(plan)
        with self.assertRaises(sqlite3.DatabaseError):
            with self.index.conn:
                self.index.conn.execute("UPDATE cleanup_approval SET status='VALID' WHERE plan_id=?", (plan["plan_id"],))
        self.assertEqual(cp.verify_approved(self.index, ACCT, plan["plan_id"], self.t).get("NO_SINGLE_VALID_APPROVAL"), 1)
        self.assertEqual(self.approval_status(plan["plan_id"]), ["CONSUMED"])

    def test_reservation_is_atomic(self):
        plan = self.approved_plan()
        calls = {"n": 0}
        real = audit.append

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise sqlite3.OperationalError("disk full (simulated)")
            return real(*a, **k)
        with mock.patch.object(audit, "append", side_effect=flaky):
            with self.assertRaises(sqlite3.OperationalError):
                self.reserve(plan)
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])  # consumption rolled back with everything else
        for t in ("cleanup_execution", "cleanup_exec_slice", "cleanup_exec_item"):
            self.assertEqual(self.index._q(f"SELECT COUNT(*) FROM {t}")[0][0], 0)
        self.assertFalse(self.index.conn.in_transaction)
        self.reserve(plan)

    def test_database_refuses_an_execution_without_a_consumed_approval(self):
        plan = self.approved_plan()
        with self.assertRaises(sqlite3.DatabaseError):
            with self.index.conn:
                self.index.conn.execute("INSERT INTO cleanup_execution (account, exec_id, plan_id, plan_hash, approval_nonce, action, state, "
                                        "item_count, slice_count, confirmation_sha256, created_at, state_changed_at) VALUES "
                                        "(?,?,?,?,?,?,?,?,?,?,?,?)", (ACCT, "exec-forged", plan["plan_id"], plan["plan_hash"], "n" * 32, "ARCHIVE",
                                                                      "PREPARED", 3, 1, "x", "t", "t"))
        self.assertEqual(self.count("cleanup_execution"), 0)

    def test_unexpected_database_refusals_are_generic(self):
        plan = self.approved_plan()
        with mock.patch.object(audit, "append", side_effect=sqlite3.IntegrityError("some constraint")):
            with self.assertRaises(ce.ExecError) as cm:
                self.reserve(plan)
        self.assertEqual(cm.exception.code, "DB_CONSTRAINT")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_account_isolation(self):
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 6)], account=OTHER)
        plan = self.approved_plan()
        with self.assertRaises(cp.PlanError):
            ce.reserve_execution(self.index, OTHER, plan["plan_id"], ce.execution_phrase(plan, 3), now=self.tick())
        ex = self.reserve(plan)
        self.assertEqual(ce.list_executions(self.index, OTHER), [])
        with self.assertRaises(ce.ExecError) as cm:
            ce.get_execution(self.index, OTHER, ex["exec_id"])
        self.assertEqual(cm.exception.code, "NO_SUCH_EXECUTION")
        other = cp.create_plan(self.index, OTHER, ["m1"], now=self.tick())
        other = cp.mark_reviewed(self.index, OTHER, other["plan_id"], cp.review_phrase(other), now=self.tick())
        cp.approve(self.index, OTHER, other["plan_id"], cp.approval_phrase(other), now=self.tick())
        ex2 = ce.reserve_execution(self.index, OTHER, other["plan_id"], ce.execution_phrase(other, 1), now=self.tick())  # no clash with ACCT's active run
        self.assertNotEqual(ex["exec_id"], ex2["exec_id"])

    def test_tampered_plan_or_audit_data_blocks_reservation(self):
        plan = self.approved_plan()
        for t in ("cleanup_audit_no_update", "cleanup_audit_no_delete"):
            self.index.conn.execute(f"DROP TRIGGER {t}")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_audit SET at='2000-01-01T00:00:00Z' WHERE seq=1")
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(plan)
        self.assertIn("AUDIT_CHAIN_BROKEN", str(cm.exception))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_tampered_snapshot_blocks_reservation(self):
        plan = self.approved_plan()
        self.index.conn.execute("DROP TRIGGER cleanup_plan_content_immutable")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_plan SET snapshot=snapshot||' ' WHERE plan_id=?", (plan["plan_id"],))
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(plan)
        self.assertIn("HASH_MISMATCH", str(cm.exception))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])


class ConcurrencyAndOverlapTests(ExecBase):
    def test_a_second_execution_for_the_account_fails_closed_and_keeps_its_approval(self):
        a = self.approved_plan(["m1", "m2"])
        b = self.approved_plan(["m3", "m4"])
        self.reserve(a)
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(b)
        self.assertEqual(cm.exception.code, "ACTIVE_EXECUTION_EXISTS")
        self.assertEqual(self.approval_status(b["plan_id"]), ["VALID"])
        self.assertEqual(self.count("cleanup_execution"), 1)

    def test_overlap_with_unresolved_work_is_refused_until_resolved(self):
        a = self.approved_plan(["m1", "m2"])
        b = self.approved_plan(["m2", "m3"])
        ex = self.reserve(a)
        ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        self.reserve(b)  # a was aborted -> its items are NOT_APPLIED, so nothing is unresolved
        c = self.approved_plan(["m3", "m4"])
        exb = self.index._q("SELECT exec_id FROM cleanup_execution WHERE plan_id=?", b["plan_id"])[0][0]
        self.token = ce.start_slice(self.index, ACCT, exb, 1, now=self.tick())
        ce.record_intent(self.index, ACCT, exb, self.token, "m3", ["INBOX"], now=self.tick())
        ce.recover_interrupted(self.index, ACCT, self.t + timedelta(hours=1))  # crash -> m3 UNKNOWN
        with self.assertRaises(ce.ExecError) as cm:
            ce.reserve_execution(self.index, ACCT, c["plan_id"], ce.execution_phrase(c, 2), now=self.t + timedelta(hours=1, minutes=1))
        self.assertIn(cm.exception.code, ("ACTIVE_EXECUTION_EXISTS", "OVERLAP_UNRESOLVED"))
        self.assertEqual(self.approval_status(c["plan_id"]), ["VALID"])

    def test_overlap_with_already_applied_targets_is_pre_skipped_never_repeated(self):
        a = self.approved_plan(["m1", "m2"])
        b = self.approved_plan(["m2", "m3"])
        exa = self.started(a)
        self.apply_all(exa)
        ce.end_slice(self.index, ACCT, exa["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(exa["exec_id"]), "EXECUTED")
        exb = self.reserve(b)
        states = {r["message_id"]: (r["state"], r["error_code"]) for r in self.index._q(
            "SELECT message_id, state, error_code FROM cleanup_exec_item WHERE exec_id=?", exb["exec_id"])}
        self.assertEqual(states["m2"], ("SKIPPED_DRIFT", "OVERLAP_ALREADY_APPLIED"))
        self.assertEqual(states["m3"], ("PENDING", None))
        # fully overlapping plan: nothing to do, nothing consumed
        ce.abort_execution(self.index, ACCT, exb["exec_id"], now=self.tick())
        c = self.approved_plan(["m1", "m2"])
        with self.assertRaises(ce.ExecError) as cm:
            self.reserve(c)
        self.assertEqual(cm.exception.code, "NOTHING_TO_DO")
        self.assertEqual(self.approval_status(c["plan_id"]), ["VALID"])

    def test_executions_never_change_the_plan_or_let_it_be_cancelled_or_expired(self):
        plan = self.approved_plan()
        self.reserve(plan)
        with self.assertRaises(cp.PlanError) as cm:
            cp.cancel(self.index, ACCT, plan["plan_id"], now=self.tick())
        self.assertEqual(cm.exception.code, "HAS_EXECUTION")
        with self.assertRaises(cp.PlanError):
            cp.revise_exclude(self.index, ACCT, plan["plan_id"], ["m1"], now=self.tick())
        self.assertEqual(cp.expire_due(self.index, ACCT, self.t + timedelta(days=30)), 0)  # a plan with an execution never expires
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "APPROVED")
        with self.assertRaises(sqlite3.DatabaseError):
            with self.index.conn:
                self.index.conn.execute("UPDATE cleanup_plan SET state='CANCELLED' WHERE plan_id=?", (plan["plan_id"],))

    def test_real_processes_racing_to_reserve_produce_exactly_one_execution(self):
        child = self.tmp / "race.py"
        child.write_text(textwrap.dedent("""
            import sys, os, time
            sys.path.insert(0, sys.argv[1]); os.environ["GMAIL_INTELLIGENCE_HOME"] = sys.argv[2]
            plan_id, go, acct = sys.argv[3], sys.argv[4], sys.argv[5]
            from gmail_intelligence import index as idx, cleanup_plans as cp, cleanup_exec as ce
            ix = idx.Index(create=False); plan = cp.get_plan(ix, acct, plan_id)
            while not os.path.exists(go): time.sleep(0.001)
            try:
                ce.reserve_execution(ix, acct, plan_id, ce.execution_phrase(plan, plan["item_count"])); print("OK")
            except cp.PlanError as e: print("ERR", e.code)
        """))
        self.index.purge(ACCT)
        ms = int(time.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 4)])
        plan = cp.create_plan(self.index, ACCT, ["m1", "m2"])
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan))
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan))
        self.index.conn.commit()
        go = self.tmp / "go"
        kids = [subprocess.Popen([sys.executable, str(child), str(SRC), os.environ[config.HOME_ENV], plan["plan_id"], str(go), ACCT],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(3)]
        time.sleep(0.6)
        go.write_text("go")
        results = [k.communicate(timeout=90)[0].strip() for k in kids]
        self.assertEqual(results.count("OK"), 1, results)
        self.assertTrue(all(r == "OK" or r.startswith("ERR") for r in results), results)
        self.assertEqual(self.count("cleanup_execution"), 1)
        self.assertEqual(self.approval_status(plan["plan_id"]), ["CONSUMED"])
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class StateMachineTests(ExecBase):
    def test_happy_path_to_executed(self):
        ex = self.started()
        self.assertEqual(ex["state"], "EXECUTING")
        self.apply_all(ex)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        done = ce.get_execution(self.index, ACCT, ex["exec_id"])
        self.assertEqual((done["state"], done["lease_token"]), ("EXECUTED", None))
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"APPLIED": 3})
        row = self.index._q("SELECT * FROM cleanup_exec_item LIMIT 1")[0]
        self.assertEqual(json.loads(row["prev_label_ids"]), ["CATEGORY_PROMOTIONS", "INBOX"])  # recovery metadata for a later undo
        self.assertTrue(row["intent_at"] and row["result_at"])
        self.assertEqual(self.approval_status(self.index._q("SELECT plan_id FROM cleanup_execution")[0][0]), ["CONSUMED"])
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        with self.assertRaises(ce.ExecError):  # a finished execution can never start again
            self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())

    def test_skips_and_known_failures_give_partial_or_failed(self):
        ex = self.started()
        a, b, c = self.ids_of(ex["exec_id"])
        ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, a, "SKIPPED_DRIFT", "LABELS_CHANGED", now=self.tick())
        ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, b, "SKIPPED_GONE", "NOT_FOUND", now=self.tick())
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, c, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, c, "APPLIED", evidence=self.ev(c, ("CATEGORY_PROMOTIONS",)), now=self.tick())
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTED")  # skips are safe non-actions, at least one verified APPLIED
        ex2 = self.started(self.approved_plan(["m4", "m5"]))
        for mid in self.ids_of(ex2["exec_id"]):
            ce.record_intent(self.index, ACCT, ex2["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
            ce.record_outcome(self.index, ACCT, ex2["exec_id"], self.token, mid, "NOT_APPLIED", code="REJECTED", now=self.tick())
        ce.end_slice(self.index, ACCT, ex2["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex2["exec_id"]), "FAILED")

    def test_mixed_applied_and_not_applied_is_a_final_partial(self):
        ex = self.started()
        ids = self.ids_of(ex["exec_id"])
        for mid, out in zip(ids, ("APPLIED", "APPLIED", "NOT_APPLIED")):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
            if out == "APPLIED":
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=self.ev(mid), now=self.tick())
            else:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "NOT_APPLIED", code="REJECTED", now=self.tick())
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_slice WHERE state='PENDING'")[0][0], 0)  # nothing left to continue

    def test_intent_needs_previous_labels_a_live_lease_and_an_active_slice(self):
        ex = self.reserve()
        mid = self.ids_of(ex["exec_id"])[0]
        with self.assertRaises(ce.ExecError):  # nothing started yet: no lease
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
        with self.assertRaises(sqlite3.DatabaseError):  # and the database itself refuses an INTENT outside EXECUTING
            with self.index.conn:
                self.index.conn.execute("UPDATE cleanup_exec_item SET state='INTENT' WHERE message_id=?", (mid,))
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        for bad in ([], None, [""], [1], ["x" * 65], ["a"] * 101, ["CATEGORY_PROMOTIONS"], ["INBOX\u00e9"]):
            with self.assertRaises(ce.ExecError, msg=bad):
                ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, bad, now=self.tick())
        with self.assertRaises(ce.ExecError) as cm:
            ce.record_intent(self.index, ACCT, ex["exec_id"], "someone-else", mid, ["INBOX"], now=self.tick())
        self.assertEqual(cm.exception.code, "BAD_LEASE")  # malformed token
        with self.assertRaises(ce.ExecError) as cm:
            ce.record_intent(self.index, ACCT, ex["exec_id"], "A" * 32, mid, ["INBOX"], now=self.tick())
        self.assertEqual(cm.exception.code, "LEASE_LOST")  # well-formed but not the issued token
        with self.assertRaises(ce.ExecError) as cm:
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.t + ce.LEASE_TTL + timedelta(minutes=1))
        self.assertEqual(cm.exception.code, "LEASE_LOST")
        with self.assertRaises(ce.ExecError):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, "not-a-target", ["INBOX"], now=self.tick())
        ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=self.tick())
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
        with self.assertRaises(ce.ExecError):  # the same item cannot get a second intent
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.tick())

    def test_invalid_transitions_are_refused_by_the_database(self):
        ex = self.started()
        self.apply_all(ex)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        bad = ["UPDATE cleanup_exec_item SET state='PENDING'", "UPDATE cleanup_exec_item SET state='INTENT'", "UPDATE cleanup_exec_item SET state='UNKNOWN'",
               "UPDATE cleanup_execution SET state='EXECUTING'", "UPDATE cleanup_execution SET state='PREPARED'",
               "UPDATE cleanup_exec_slice SET state='ACTIVE'", "UPDATE cleanup_exec_slice SET state='PENDING'",
               "UPDATE cleanup_execution SET plan_hash='" + "0" * 64 + "'", "UPDATE cleanup_execution SET item_count=99",
               "UPDATE cleanup_exec_item SET message_id='zzz'", "UPDATE cleanup_exec_item SET slice_no=9", "UPDATE cleanup_exec_slice SET size=99",
               "DELETE FROM cleanup_execution", "DELETE FROM cleanup_exec_item", "DELETE FROM cleanup_exec_slice"]
        for sql in bad:
            with self.assertRaises(sqlite3.DatabaseError, msg=sql):
                with self.index.conn:
                    self.index.conn.execute(sql)

    def test_targets_cannot_be_added_or_swapped(self):
        plan = self.approved_plan(["m1", "m2"])
        ex = self.reserve(plan)
        for mid in ("m3", "m5", "unknown"):
            with self.assertRaises(sqlite3.DatabaseError, msg=mid):
                with self.index.conn:
                    self.index.conn.execute("INSERT INTO cleanup_exec_item (account, exec_id, message_id, seq, slice_no, state) VALUES (?,?,?,?,?,?)",
                                            (ACCT, ex["exec_id"], mid, 9, 1, "PENDING"))
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        with self.assertRaises(sqlite3.DatabaseError):  # not even a real plan target, once the execution has started
            with self.index.conn:
                self.index.conn.execute("INSERT INTO cleanup_exec_item (account, exec_id, message_id, seq, slice_no, state) VALUES (?,?,?,?,?,?)",
                                        (ACCT, ex["exec_id"], "m1", 9, 1, "PENDING"))
        self.assertEqual(self.ids_of(ex["exec_id"]), ["m1", "m2"])

    def test_abort_only_from_prepared_or_partial_and_never_restores_the_approval(self):
        plan = self.approved_plan()
        ex = self.reserve(plan)
        done = ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        self.assertEqual(done["state"], "ABORTED")
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"NOT_APPLIED": 3})
        self.assertEqual({r[0] for r in self.index._q("SELECT state FROM cleanup_exec_slice")}, {"STOPPED"})
        self.assertEqual(self.approval_status(plan["plan_id"]), ["CONSUMED"])
        with self.assertRaises(ce.ExecError):
            ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        running = self.started(self.approved_plan(["m4", "m5"]))
        with self.assertRaises(ce.ExecError):
            ce.abort_execution(self.index, ACCT, running["exec_id"], now=self.tick())


class SliceTests(ExecBase):
    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 131)])
        self.big = [f"m{i}" for i in range(1, 131)]

    def test_slice_plan_follows_the_canary_policy(self):
        self.assertEqual(ce.plan_slices(1), [1])
        self.assertEqual(ce.plan_slices(100), [100])
        self.assertEqual(ce.plan_slices(101), [25, 76])
        self.assertEqual(ce.plan_slices(130), [25, 100, 5])
        self.assertEqual(ce.plan_slices(500), [25, 100, 100, 100, 100, 75])
        self.assertTrue(all(sum(ce.plan_slices(n)) == n and max(ce.plan_slices(n)) <= 100 for n in range(1, 501)))

    def test_continuation_needs_a_fresh_confirmation_per_slice(self):
        plan = self.approved_plan(self.big)
        ex = self.reserve(plan)
        self.assertEqual([(s["slice_no"], s["size"], s["state"]) for s in ce.slices(self.index, ACCT, ex["exec_id"])],
                         [(1, 25, "CONFIRMED"), (2, 100, "PENDING"), (3, 5, "PENDING")])
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "AWAITING_CONTINUATION")  # waiting for a SEPARATE confirmation, not continuing
        with self.assertRaises(ce.ExecError) as cm:
            self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=self.tick())
        self.assertEqual(cm.exception.code, "SLICE_NOT_CONFIRMED")
        good = ce.continuation_phrase(plan, 2, 100)
        for bad in ("", cp.approval_phrase(plan), ce.execution_phrase(plan, 25), good.replace("slice 2", "slice 3"), good.lower()):
            with self.assertRaises(ce.ExecError):
                ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, bad, now=self.tick())
        with self.assertRaises(ce.ExecError) as cm:
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 3, ce.continuation_phrase(plan, 3, 5), now=self.tick())
        self.assertEqual(cm.exception.code, "SLICE_NOT_NEXT")
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, good, now=self.tick())
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=self.tick())
        self.apply_all(ex, 2)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 2, self.token, now=self.tick())
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], 3, ce.continuation_phrase(plan, 3, 5), now=self.tick())
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 3, now=self.tick())
        self.apply_all(ex, 3)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 3, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTED")
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"APPLIED": 130})

    def test_continuation_rechecks_only_the_remaining_targets_but_protection_rules_stay_plan_wide(self):
        plan = self.approved_plan(self.big)
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        done = self.ids_of(ex["exec_id"], 1)
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        with self.index.conn:  # local facts of an ALREADY EXECUTED target drift (e.g. after Gmail changed): irrelevant for the rest
            self.index.conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCT, done[0], "Label_77"))
        full = cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, plan["plan_id"]), self.tick())
        self.assertIn("ITEM_CHANGED", full)  # a whole-plan check would now fail...
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())  # ...the subset check passes
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=self.tick())
        cleanup_protect.add(self.index, ACCT, sender="nobody@unrelated.example.test")  # any protection change makes the plan stale (fail closed)
        self.apply_all(ex, 2)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 2, self.token, now=self.tick())
        with self.assertRaises(ce.ExecError) as cm:
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 3, ce.continuation_phrase(plan, 3, 5), now=self.tick())
        self.assertEqual(cm.exception.code, "STALE")

    def test_a_protected_remaining_target_blocks_the_continuation(self):
        plan = self.approved_plan(self.big)
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        remaining = self.ids_of(ex["exec_id"], 2)[0]
        cleanup_protect.add(self.index, ACCT, sender=self.index._q("SELECT sender FROM messages WHERE id=?", remaining)[0][0])
        with self.assertRaises(ce.ExecError) as cm:
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())
        self.assertEqual(cm.exception.code, "STALE")
        self.assertEqual(ce.slices(self.index, ACCT, ex["exec_id"])[1]["state"], "PENDING")

    def test_a_stop_ends_the_whole_execution_with_no_further_slices(self):
        plan = self.approved_plan(self.big)
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        first = self.ids_of(ex["exec_id"], 1)
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, first[0], ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, first[0], "APPLIED", evidence=self.ev(first[0]), now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "CIRCUIT_BREAKER", now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")  # nothing ambiguous, some applied, the rest NEVER_ATTEMPTED
        c = ce.item_counts(self.index, ACCT, ex["exec_id"])
        self.assertEqual((c["APPLIED"], c["NOT_APPLIED"]), (1, 129))
        self.assertEqual({s["state"] for s in ce.slices(self.index, ACCT, ex["exec_id"])}, {"STOPPED"})
        with self.assertRaises(ce.ExecError):
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())


class RecoveryTests(ExecBase):
    def test_a_stop_with_an_open_intent_requires_reconciliation(self):
        ex = self.started()
        a, b, c = self.ids_of(ex["exec_id"])
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX"], now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"UNKNOWN": 1, "NOT_APPLIED": 2})
        with self.assertRaises(ce.ExecError):
            self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        with self.assertRaises(ce.ExecError):
            ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())  # unknown work cannot be abandoned
        with self.assertRaises(ce.ExecError):  # and it still blocks the account
            self.reserve(self.approved_plan(["m4", "m5"]))

    def test_a_crash_after_intent_is_found_by_recovery_and_never_resumed(self):
        ex = self.started()
        mid = self.ids_of(ex["exec_id"])[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
        # "crash": the process dies here - no outcome is recorded. A fresh connection plays the restarted application.
        self.index.conn.commit()
        fresh = idx.Index()
        self.addCleanup(fresh.close)
        self.assertEqual(ce.recover_interrupted(fresh, ACCT, self.t + timedelta(minutes=1)), [])  # lease still live: untouched
        self.assertEqual(ce.recover_interrupted(fresh, ACCT, self.t + ce.LEASE_TTL + timedelta(minutes=1)), [ex["exec_id"]])
        got = ce.get_execution(fresh, ACCT, ex["exec_id"])
        self.assertEqual((got["state"], got["lease_token"]), ("RECONCILIATION_REQUIRED", None))
        self.assertEqual(ce.item_counts(fresh, ACCT, ex["exec_id"]), {"UNKNOWN": 1, "NOT_APPLIED": 2})
        later = self.t + ce.LEASE_TTL + timedelta(minutes=2)
        for call in (lambda: ce.start_slice(fresh, ACCT, ex["exec_id"], 1, now=later),
                     lambda: ce.record_intent(fresh, ACCT, ex["exec_id"], self.token, self.ids_of(ex["exec_id"])[1], ["INBOX"], now=later),
                     lambda: ce.record_outcome(fresh, ACCT, ex["exec_id"], self.token, mid, "APPLIED", now=later)):
            with self.assertRaises(ce.ExecError):
                call()
        self.assertIn("EXECUTION_INTERRUPTED", [e["event_type"] for e in audit.events(fresh, ACCT)])
        self.assertEqual(ce.recover_interrupted(fresh, ACCT, later), [])  # idempotent

    def test_a_crash_between_local_transitions_rolls_back_the_unfinished_step(self):
        ex = self.started()
        mid = self.ids_of(ex["exec_id"])[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        with mock.patch.object(audit, "append", side_effect=sqlite3.OperationalError("disk full (simulated)")):
            with self.assertRaises(sqlite3.OperationalError):
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=self.ev(mid), now=self.tick())
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]).get("INTENT"), 1)  # the INTENT is still on record
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTING")

    def test_killing_a_process_mid_transaction_leaves_the_last_committed_state(self):
        child = self.tmp / "kill.py"
        child.write_text(textwrap.dedent("""
            import sys, os, time
            sys.path.insert(0, sys.argv[1]); os.environ["GMAIL_INTELLIGENCE_HOME"] = sys.argv[2]
            exec_id, mid, go, acct, token = sys.argv[3:8]
            from gmail_intelligence import index as idx, cleanup_exec as ce, cleanup_audit as au
            ix = idx.Index(create=False)
            real = au.append
            def slow(*a, **k):
                r = real(*a, **k); open(go + ".inside", "w").close(); time.sleep(60); return r
            au.append = slow
            ce.record_intent(ix, acct, exec_id, token, mid, ["INBOX"])
        """))
        self.index.purge(ACCT)
        ms = int(time.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 4)])
        plan = cp.create_plan(self.index, ACCT, ["m1", "m2"])
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan))
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan))
        ex = ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, 2))
        token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1)
        self.index.conn.commit()
        go = self.tmp / "go"
        kid = subprocess.Popen([sys.executable, str(child), str(SRC), os.environ[config.HOME_ENV], ex["exec_id"], "m1", str(go), ACCT, token],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(600):
            if Path(str(go) + ".inside").exists():
                break
            time.sleep(0.05)
        else:
            kid.kill()
            self.fail("child never reached the transaction")
        os.kill(kid.pid, signal.SIGKILL)
        kid.wait()
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"PENDING": 2})  # the half-finished INTENT was rolled back
        self.assertEqual(self.index._q("PRAGMA integrity_check")[0][0], "ok")
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_reconciliation_derives_the_outcome_from_structured_evidence(self):
        ex = self.started()
        a, b, c = self.ids_of(ex["exec_id"])
        for mid in (a, b, c):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "UNKNOWN", code="TIMEOUT", now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"UNKNOWN": 3})
        before = lambda m: self.ev(m, ("INBOX", "CATEGORY_PROMOTIONS"))  # noqa: E731
        with self.assertRaises(ce.ExecError):  # a bare assertion is not accepted
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, "APPLIED", now=self.tick())
        for bad in (None, self.ev(a, kind="OTHER"), self.ev(a, source="local-guess"), self.ev(b), self.ev(a, ()), self.ev(a, when="2000-01-01T00:00:00Z"),
                    self.ev(a, when="yesterday")):
            with self.assertRaises(ce.ExecError, msg=bad) as cm:
                ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, bad, now=self.tick())
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE")
        ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a), now=self.tick())  # observed archived state -> APPLIED, verified
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")  # two still unknown
        ce.reconcile_item(self.index, ACCT, ex["exec_id"], b, before(b), now=self.tick())  # observed pre-state -> NOT_APPLIED (unmodified)
        done = ce.reconcile_item(self.index, ACCT, ex["exec_id"], c, self.ev(c, ("SOMETHING_ELSE",)), now=self.tick())  # neither -> CONFLICT
        self.assertEqual(done["state"], "PARTIAL")
        rows = {r["message_id"]: (r["state"], r["error_code"], r["evidence_checked"]) for r in self.index._q("SELECT * FROM cleanup_exec_item")}
        self.assertEqual(rows[a], ("APPLIED", "RECONCILED_OBSERVED_ARCHIVED", 1))
        self.assertEqual(rows[b], ("NOT_APPLIED", "RECONCILED_UNMODIFIED", 0))
        self.assertEqual(rows[c], ("CONFLICT", "RECONCILED_CONFLICT", 0))
        with self.assertRaises(ce.ExecError):
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a), now=self.tick())  # only UNKNOWN items, only while reconciling
        with self.assertRaises(ce.ExecError):
            ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())  # a reconciled execution never restarts


class DryRunAndCliTests(ExecBase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), \
                mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")):
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def snapshot_rows(self):
        return {t: [tuple(r) for r in self.index._q(f"SELECT * FROM {t} ORDER BY 1,2,3")]
                for t in ("cleanup_plan", "cleanup_item", "cleanup_approval", "cleanup_audit", "cleanup_execution", "cleanup_exec_item", "cleanup_exec_slice")}

    def test_dry_run_writes_nothing_and_consumes_nothing(self):
        plan = self.approved_plan()
        before, changes = self.snapshot_rows(), self.index.conn.total_changes
        d = ce.dry_run(self.index, ACCT, plan["plan_id"], self.tick())
        self.assertTrue(d["executable_now"])
        self.assertEqual((d["slices"], d["targets"], d["problems"]), ([3], 3, {}))
        self.assertEqual(d["confirmation_phrase"], ce.execution_phrase(plan, 3))
        self.assertEqual(self.index.conn.total_changes, changes)
        self.assertEqual(self.snapshot_rows(), before)
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_dry_run_reports_problems_without_changing_anything(self):
        reviewed = cp.create_plan(self.index, ACCT, ["m4"], now=self.tick())
        reviewed = cp.mark_reviewed(self.index, ACCT, reviewed["plan_id"], cp.review_phrase(reviewed), now=self.tick())
        plan = self.approved_plan()
        cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")
        before = self.snapshot_rows()
        self.assertIn("NOT_APPROVED", ce.dry_run(self.index, ACCT, reviewed["plan_id"], self.tick())["problems"])
        stale = ce.dry_run(self.index, ACCT, plan["plan_id"], self.tick())
        self.assertFalse(stale["executable_now"])
        self.assertIn("PROTECTION_RULES_CHANGED", stale["problems"])
        self.assertEqual(self.snapshot_rows(), before)

    def test_dry_run_on_a_plan_with_an_execution_and_with_an_active_one(self):
        a = self.approved_plan(["m1", "m2"])
        b = self.approved_plan(["m3", "m4"])
        self.reserve(a)
        self.assertEqual(ce.dry_run(self.index, ACCT, a["plan_id"], self.tick())["problems"].get("PLAN_ALREADY_HAS_EXECUTION"), 1)
        self.assertEqual(ce.dry_run(self.index, ACCT, b["plan_id"], self.tick())["problems"].get("ACTIVE_EXECUTION_EXISTS"), 1)
        with self.assertRaises(cp.PlanError):
            ce.dry_run(self.index, ACCT, "plan-nope", self.tick())

    def test_cli_dry_run_is_private_read_only_and_the_only_execute_mode(self):
        import time as _t
        self.index.purge(ACCT)
        ms = int(_t.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 6)])
        plan = cp.create_plan(self.index, ACCT, ["m1", "m2"])
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan))
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan))
        self.index.conn.commit()
        before, changes = self.snapshot_rows(), self.index.conn.total_changes
        code, out, err = self.run_cli("cleanup", "execute", plan["plan_id"], "--dry-run", "--account", ACCT)
        self.assertEqual(code, 0, err)
        for needle in ("DRY RUN", "<account hidden>", "Locally executable", "NO Gmail execution", "EXECUTE ARCHIVE 2"):
            self.assertIn(needle, out)
        for secret in (ACCT, "m1", "shop.example.test"):
            self.assertNotIn(secret, out)
        code, out, err = self.run_cli("cleanup", "execute", plan["plan_id"], "--account", ACCT)
        self.assertEqual(code, 1)
        self.assertIn("not available in this version", err)
        self.assertEqual(self.run_cli("cleanup", "execute", "plan-nope", "--dry-run", "--account", ACCT)[0], 1)
        self.assertEqual(self.snapshot_rows(), before)
        self.assertEqual(self.index.conn.total_changes, changes)
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])
        for argv in (["cleanup", "execute", plan["plan_id"], "--yes", "--account", ACCT], ["cleanup", "exec", "reserve", "x", "--account", ACCT],
                     ["cleanup", "exec", "start", "x", "--account", ACCT], ["cleanup", "exec", "abort", "x", "--account", ACCT]):
            self.assertEqual(self.run_cli(*argv)[0], 2, argv)  # no production path reserves, starts, aborts or confirms

    def test_cli_exec_listing_and_show_are_read_only_and_private(self):
        self.reserve(self.approved_plan(["m1", "m2"]))
        exec_id = ce.list_executions(self.index, ACCT)[0]["exec_id"]
        before, changes = self.snapshot_rows(), self.index.conn.total_changes
        code, out, _ = self.run_cli("cleanup", "exec", "list", "--account", ACCT)
        self.assertEqual(code, 0)
        self.assertIn(exec_id, out)
        self.assertIn("PREPARED", out)
        code, out, _ = self.run_cli("cleanup", "exec", "show", exec_id, "--account", ACCT)
        self.assertEqual(code, 0)
        self.assertIn("PENDING=2", out)
        for secret in (ACCT, "m1", "m2", "shop.example.test"):
            self.assertNotIn(secret, out)
        code, out, _ = self.run_cli("cleanup", "exec", "show", exec_id, "--account", ACCT, "--show-ids")
        self.assertIn("m1 : PENDING", out)
        code, out, err = self.run_cli("cleanup", "exec", "show", "exec-nope", "--account", ACCT)
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", out + err)
        self.assertEqual(self.snapshot_rows(), before)
        self.assertEqual(self.index.conn.total_changes, changes)

    def test_reconciliation_banner_is_shown(self):
        ex = self.started()
        mid = self.ids_of(ex["exec_id"])[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        out = self.run_cli("cleanup", "exec", "show", ex["exec_id"], "--account", ACCT)[1]
        self.assertIn("RECONCILIATION REQUIRED", out)
        self.assertIn("Nothing is retried automatically", out)

    def test_audit_trail_distinguishes_intent_outcome_and_unknown_without_message_ids(self):
        ex = self.started()
        a, b, c = self.ids_of(ex["exec_id"])
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a), now=self.tick())
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, b, ["INBOX"], now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        metas = [json.loads(e["meta"]) for e in audit.events(self.index, ACCT, limit=1000) if e["event_type"] == "ITEM_TRANSITION"]
        transitions = {(m["from"], m["to"]) for m in metas}
        self.assertTrue({("PENDING", "INTENT"), ("INTENT", "APPLIED"), ("INTENT", "UNKNOWN"), ("PENDING", "NOT_APPLIED")} <= transitions, transitions)
        text = json.dumps([e["meta"] for e in audit.events(self.index, ACCT, limit=1000)])
        for mid in (a, b, c):
            self.assertNotIn(f'"{mid}"', text)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

class HardeningTests(ExecBase):
    """Regression tests for the independent M4C-A audit findings."""

    # ---- helpers
    def final_partial(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a, b = self.ids_of(ex["exec_id"])
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a), now=self.tick())
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, b, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, b, "NOT_APPLIED", code="rejected", now=self.tick())  # normalized
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        return ex

    def sql(self, sql, *params):
        try:
            with self.index.conn:
                self.index.conn.execute(sql, params)
            return None
        except sqlite3.DatabaseError as exc:
            return str(exc)

    def refused(self, sql, *params):
        self.assertIsNotNone(self.sql(sql, *params), sql)

    def audit_count(self):
        return self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0]

    # ---- 1. final-state correctness
    def test_abort_is_only_possible_before_the_end_never_for_a_final_state(self):
        ex = self.final_partial()
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        with self.assertRaises(ce.ExecError) as cm:
            ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())
        self.assertEqual(cm.exception.code, "BAD_STATE")
        self.refused("UPDATE cleanup_execution SET state='ABORTED' WHERE exec_id=?", ex["exec_id"])  # not even by direct SQL
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        done = self.started(self.approved_plan(["m3", "m4"]))
        self.apply_all(done)
        ce.end_slice(self.index, ACCT, done["exec_id"], 1, self.token, now=self.tick())
        failed = self.started(self.approved_plan(["m5"]))
        mid = self.ids_of(failed["exec_id"])[0]
        ce.record_skip(self.index, ACCT, failed["exec_id"], self.token, mid, "SKIPPED_GONE", "NOT_FOUND", now=self.tick())
        ce.end_slice(self.index, ACCT, failed["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual((self.exec_state(done["exec_id"]), self.exec_state(failed["exec_id"])), ("EXECUTED", "FAILED"))
        for e in (done, failed):
            with self.assertRaises(ce.ExecError):
                ce.abort_execution(self.index, ACCT, e["exec_id"], now=self.tick())

    def test_abort_is_allowed_from_prepared_and_awaiting_continuation_only(self):
        prepared = self.reserve(self.approved_plan(["m1", "m2"]))
        self.assertEqual(ce.abort_execution(self.index, ACCT, prepared["exec_id"], now=self.tick())["state"], "ABORTED")
        self.assertEqual(ce.code_counts(self.index, ACCT, prepared["exec_id"]), {("NOT_APPLIED", "NEVER_ATTEMPTED"): 2})
        running = self.started(self.approved_plan(["m3", "m4"]))
        with self.assertRaises(ce.ExecError):
            ce.abort_execution(self.index, ACCT, running["exec_id"], now=self.tick())  # EXECUTING: use stop_execution
        ce.stop_execution(self.index, ACCT, running["exec_id"], self.token, "OWNER_REQUEST", now=self.tick())
        self.assertEqual(self.exec_state(running["exec_id"]), "FAILED")

    # ---- 2. closed vocabulary
    def test_codes_are_a_closed_vocabulary_validated_before_any_mutation(self):
        ex = self.started(self.approved_plan(["m1", "m2", "m3"]))
        a, b, c = self.ids_of(ex["exec_id"])
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        before = self.audit_count()
        bad_codes = ["sender@example.test", "x" * 500, "line\nbreak", "\u05e9\u05dc\u05d5\u05dd", "", "DROP TABLE", "reject-ed", "NEVER_ATTEMPTED",
                     "RECONCILED_OBSERVED_ARCHIVED", 5, None.__class__, ["REJECTED"], str(RuntimeError("secret@example.test"))]
        for bad in bad_codes:
            with self.assertRaises(ce.ExecError, msg=repr(bad)) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "NOT_APPLIED", code=bad, now=self.tick())
            self.assertEqual(cm.exception.code, "BAD_CODE")
            self.assertNotIn(str(bad)[:6] if isinstance(bad, str) and len(bad) > 5 else "\x00", str(cm.exception).replace("reason code", ""))
        self.assertEqual((self.audit_count(), ce.item_counts(self.index, ACCT, ex["exec_id"])), (before, {"INTENT": 1, "PENDING": 2}))  # nothing changed
        for pair in (("APPLIED", "REJECTED"), ("NOT_APPLIED", "TIMEOUT"), ("UNKNOWN", "REJECTED")):  # right vocabulary, wrong outcome
            with self.assertRaises(ce.ExecError):
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, pair[0], code=pair[1], evidence=self.ev(a), now=self.tick())
        with self.assertRaises(ce.ExecError):
            ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, b, "SKIPPED_DRIFT", "someone@example.test", now=self.tick())
        with self.assertRaises(ce.ExecError):
            ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "free text reason", now=self.tick())
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"INTENT": 1, "PENDING": 2})
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "NOT_APPLIED", code=" rejected ", now=self.tick())  # normalized
        ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, b, "SKIPPED_DRIFT", "labels_changed", now=self.tick())
        codes = {r["message_id"]: r["error_code"] for r in self.index._q("SELECT message_id, error_code FROM cleanup_exec_item")}
        self.assertEqual((codes[a], codes[b]), ("REJECTED", "LABELS_CHANGED"))

    def test_the_database_itself_rejects_free_text_codes(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        for text in ("sender@example.test", "x" * 300, "REJECTED\n", "never_attempted", "anything"):
            self.refused("UPDATE cleanup_exec_item SET error_code=? WHERE exec_id=?", text, ex["exec_id"])
        for code in idx.EXEC_ITEM_CODES:
            self.assertIsNone(self.sql("UPDATE cleanup_exec_item SET error_code=? WHERE exec_id=? AND message_id='m1'", code, ex["exec_id"]), code)

    def test_not_applied_reasons_distinguish_unattempted_rejected_reconciled_and_interrupted(self):
        ex = self.started(self.approved_plan(["m1", "m2", "m3", "m4"]))
        a, b, c, d = self.ids_of(ex["exec_id"])
        for mid in (a, b, c):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "NOT_APPLIED", now=self.tick(), code="REJECTED")
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, b, "UNKNOWN", code="TIMEOUT", now=self.tick())
        ce.recover_interrupted(self.index, ACCT, self.t + ce.LEASE_TTL + timedelta(minutes=1))  # c: INTENT -> UNKNOWN(INTERRUPTED); d: never attempted
        ce.reconcile_item(self.index, ACCT, ex["exec_id"], b, self.ev(b, ("INBOX", "CATEGORY_PROMOTIONS"), when=cp._iso(self.t + ce.LEASE_TTL + timedelta(minutes=2))),
                          now=self.t + ce.LEASE_TTL + timedelta(minutes=2))
        got = {r["message_id"]: (r["state"], r["error_code"]) for r in self.index._q("SELECT * FROM cleanup_exec_item")}
        self.assertEqual(got[a], ("NOT_APPLIED", "REJECTED"))
        self.assertEqual(got[b], ("NOT_APPLIED", "RECONCILED_UNMODIFIED"))
        self.assertEqual(got[c], ("UNKNOWN", "INTERRUPTED"))
        self.assertEqual(got[d], ("NOT_APPLIED", "NEVER_ATTEMPTED"))
        self.assertEqual(self.index._q("SELECT intent_at IS NOT NULL FROM cleanup_exec_item WHERE message_id=?", d)[0][0], 0)  # unattempted: no intent
        for code in ("NEVER_ATTEMPTED", "REJECTED", "RECONCILED_UNMODIFIED", "INTERRUPTED", "OVERLAP_ALREADY_APPLIED"):
            self.assertIn(code, idx.EXEC_ITEM_CODES)
            self.assertIn(code, ce.CODE_MEANING)

    # ---- 3. lease ownership
    def test_lease_tokens_are_random_library_generated_and_stored_only_as_hashes(self):
        import inspect
        self.assertEqual(list(inspect.signature(ce.start_slice).parameters), ["index", "account", "exec_id", "slice_no", "now"])  # no token parameter
        tokens = set()
        for i in range(1, 6):
            ex = self.reserve(self.approved_plan([f"m{i}"]))
            tok = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
            self.assertGreaterEqual(len(tok), 32)
            self.assertTrue(all(c.isalnum() or c in "-_" for c in tok))
            tokens.add(tok)
            self.assertNotIn(tok, json.dumps([tuple(r) for r in self.index._q("SELECT * FROM cleanup_execution")]))  # only a hash is stored
            self.assertEqual(self.index._q("SELECT length(lease_token) FROM cleanup_execution WHERE exec_id=?", ex["exec_id"])[0][0], 64)
            mid = self.ids_of(ex["exec_id"])[0]
            ce.record_skip(self.index, ACCT, ex["exec_id"], tok, mid, "SKIPPED_GONE", "NOT_FOUND", now=self.tick())
            ce.end_slice(self.index, ACCT, ex["exec_id"], 1, tok, now=self.tick())
        self.assertEqual(len(tokens), 5)  # never repeated
        self.assertEqual(len({sha for sha in (ce.sha256(t) for t in tokens)}), 5)

    def test_short_reused_forged_and_stale_tokens_are_rejected(self):
        first = self.started(self.approved_plan(["m1", "m2"]))
        old = self.token
        mid = self.ids_of(first["exec_id"])[0]
        for bad, code in (("x", "BAD_LEASE"), ("a" * 31, "BAD_LEASE"), ("a" * 65, "BAD_LEASE"), ("\u05d0" * 40, "BAD_LEASE"), ("bad token " + "a" * 30, "BAD_LEASE"),
                          (None, "BAD_LEASE"), (12345, "BAD_LEASE"), ("A" * 32, "LEASE_LOST"), ("A" * 43, "LEASE_LOST"), (old[::-1], "LEASE_LOST")):
            with self.assertRaises(ce.ExecError, msg=repr(bad)) as cm:
                ce.record_intent(self.index, ACCT, first["exec_id"], bad, mid, ["INBOX"], now=self.tick())
            self.assertEqual(cm.exception.code, code, repr(bad))
            with self.assertRaises(ce.ExecError):
                ce.renew_lease(self.index, ACCT, first["exec_id"], bad, now=self.tick())
        self.assertEqual(ce.item_counts(self.index, ACCT, first["exec_id"]), {"PENDING": 2})
        for m in self.ids_of(first["exec_id"]):  # finish it, then try the (now stale) token on the next execution
            ce.record_skip(self.index, ACCT, first["exec_id"], old, m, "SKIPPED_GONE", "NOT_FOUND", now=self.tick())
        ce.end_slice(self.index, ACCT, first["exec_id"], 1, old, now=self.tick())
        second = self.started(self.approved_plan(["m3", "m4"]))
        self.assertNotEqual(self.token, old)
        with self.assertRaises(ce.ExecError) as cm:  # a token from another execution
            ce.record_intent(self.index, ACCT, second["exec_id"], old, self.ids_of(second["exec_id"])[0], ["INBOX"], now=self.tick())
        self.assertEqual(cm.exception.code, "LEASE_LOST")
        with self.assertRaises(ce.ExecError):  # and a finished execution accepts nothing
            ce.record_skip(self.index, ACCT, first["exec_id"], old, mid, "SKIPPED_GONE", "NOT_FOUND", now=self.tick())
        ce.recover_interrupted(self.index, ACCT, self.t + ce.LEASE_TTL + timedelta(minutes=1))  # stale after recovery
        with self.assertRaises(ce.ExecError) as cm:
            ce.renew_lease(self.index, ACCT, second["exec_id"], self.token, now=self.t + ce.LEASE_TTL + timedelta(minutes=2))
        self.assertEqual(cm.exception.code, "LEASE_LOST")

    # ---- 4. one clock policy
    def test_every_mutation_refuses_a_clock_earlier_than_the_last_recorded_event(self):
        plan = self.approved_plan(["m1", "m2", "m3"])
        past = self.t - timedelta(minutes=10)
        with self.assertRaises(cp.PlanError) as cm:
            ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, 3), now=past)
        self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")
        ex = self.reserve(plan)
        past = self.t - timedelta(minutes=10)
        calls = {"start_slice": lambda: ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=past),
                 "abort": lambda: ce.abort_execution(self.index, ACCT, ex["exec_id"], now=past),
                 "recover": lambda: ce.recover_interrupted(self.index, ACCT, now=past)}
        for name, call in calls.items():
            with self.assertRaises(cp.PlanError, msg=name) as cm:
                call()
            self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK", name)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        a = self.ids_of(ex["exec_id"])[0]
        past = self.t - timedelta(minutes=10)
        live = {"intent": lambda: ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX"], now=past),
                "skip": lambda: ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, a, "SKIPPED_GONE", "NOT_FOUND", now=past),
                "renew": lambda: ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=past),
                "end_slice": lambda: ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=past),
                "stop": lambda: ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "OWNER_REQUEST", now=past)}
        for name, call in live.items():
            with self.assertRaises(cp.PlanError, msg=name) as cm:
                call()
            self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK", name)
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["INBOX"], now=self.t)
        with self.assertRaises(cp.PlanError) as cm:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "UNKNOWN", code="TIMEOUT", now=past)
        self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")
        ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=self.t - timedelta(minutes=4))  # small skew is tolerated
        self.assertEqual(ce.item_counts(self.index, ACCT, ex["exec_id"]), {"INTENT": 1, "PENDING": 2})  # nothing changed by refused calls

    # ---- 5. schema invariants against direct invalid SQL
    def test_direct_sql_cannot_create_contradictory_terminal_states(self):
        ex = self.started(self.approved_plan(["m1", "m2", "m3"]))
        E = ex["exec_id"]
        self.refused("UPDATE cleanup_execution SET state='EXECUTED' WHERE exec_id=?", E)  # items still PENDING
        self.refused("UPDATE cleanup_execution SET state='PARTIAL' WHERE exec_id=?", E)
        self.refused("UPDATE cleanup_execution SET state='FAILED' WHERE exec_id=?", E)
        self.refused("UPDATE cleanup_execution SET state='AWAITING_CONTINUATION' WHERE exec_id=?", E)  # no pending slice
        self.refused("UPDATE cleanup_execution SET state='RECONCILIATION_REQUIRED' WHERE exec_id=?", E)  # nothing UNKNOWN
        self.refused("UPDATE cleanup_exec_slice SET state='COMPLETED' WHERE exec_id=?", E)  # open items
        a, b, c = self.ids_of(E)
        self.refused("UPDATE cleanup_exec_item SET state='INTENT' WHERE message_id=?", a)  # no metadata
        self.refused("UPDATE cleanup_exec_item SET state='INTENT', intent_at='2026-01-01T00:00:00.000000Z' WHERE message_id=?", a)
        self.refused("UPDATE cleanup_exec_item SET state='INTENT', intent_at='2026-01-01T00:00:00.000000Z', prev_label_ids='not json' WHERE message_id=?", a)
        self.refused("UPDATE cleanup_exec_item SET state='INTENT', intent_at='2026-01-01T00:00:00.000000Z', prev_label_ids='[]' WHERE message_id=?", a)
        self.assertIsNone(self.sql("UPDATE cleanup_exec_item SET state='INTENT', intent_at='2026-01-01T00:00:00.000000Z', prev_label_ids='[\"INBOX\"]' WHERE message_id=?", a))
        self.refused("UPDATE cleanup_exec_item SET prev_label_ids='[\"OTHER\"]' WHERE message_id=?", a)  # recovery metadata is immutable
        self.refused("UPDATE cleanup_exec_item SET prev_label_ids=NULL WHERE message_id=?", a)
        self.refused("UPDATE cleanup_exec_item SET intent_at='later' WHERE message_id=?", a)
        self.refused("UPDATE cleanup_exec_item SET state='APPLIED' WHERE message_id=?", a)  # no verification / result time
        self.refused("UPDATE cleanup_exec_item SET state='APPLIED', evidence_checked=1 WHERE message_id=?", a)  # no result time
        self.refused("UPDATE cleanup_exec_item SET evidence_checked=1 WHERE message_id=?", b)  # only APPLIED can be verified
        self.refused("UPDATE cleanup_exec_item SET state='APPLIED', result_at='2026-01-01T00:00:00.000000Z', evidence_checked=1 WHERE message_id=?", b)  # b never had an intent
        self.assertIsNone(self.sql("UPDATE cleanup_exec_item SET state='APPLIED', result_at='2026-01-01T00:00:00.000000Z', evidence_checked=1, evidence_source='CALLER_SUPPLIED', evidence_observed_at='2026-01-01T00:00:01.000000Z' WHERE message_id=?", a))
        self.refused("UPDATE cleanup_execution SET state='EXECUTED' WHERE exec_id=?", E)  # b, c still open
        self.assertIsNone(self.sql("UPDATE cleanup_exec_item SET state='NOT_APPLIED', error_code='NEVER_ATTEMPTED' WHERE message_id IN (?,?)", b, c))
        self.refused("UPDATE cleanup_execution SET state='EXECUTED' WHERE exec_id=?", E)  # contains unsuccessful items
        self.refused("UPDATE cleanup_execution SET state='FAILED' WHERE exec_id=?", E)  # something was applied
        self.assertIsNone(self.sql("UPDATE cleanup_exec_slice SET state='COMPLETED' WHERE exec_id=?", E))
        self.assertIsNone(self.sql("UPDATE cleanup_execution SET state='PARTIAL' WHERE exec_id=?", E))
        for stmt in ("UPDATE cleanup_exec_item SET error_code='REJECTED'", "UPDATE cleanup_exec_slice SET finished_at='x'",
                     "UPDATE cleanup_execution SET state='EXECUTING'", "UPDATE cleanup_execution SET state='ABORTED'"):
            self.refused(stmt)  # everything about a finished execution is frozen

    def test_executed_needs_a_verified_applied_item_and_zero_applied_is_failed(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        E = ex["exec_id"]
        a, b = self.ids_of(E)
        self.assertIsNone(self.sql("UPDATE cleanup_exec_item SET state='SKIPPED_GONE', error_code='NOT_FOUND', result_at='2026-01-01T00:00:00.000000Z' WHERE exec_id=?", E))
        self.assertIsNone(self.sql("UPDATE cleanup_exec_slice SET state='COMPLETED' WHERE exec_id=?", E))
        self.refused("UPDATE cleanup_execution SET state='EXECUTED' WHERE exec_id=?", E)  # nothing applied: only FAILED is coherent
        self.assertIsNone(self.sql("UPDATE cleanup_execution SET state='FAILED' WHERE exec_id=?", E))

    def test_related_rows_follow_one_safe_order_items_then_slices_then_execution(self):
        ex = self.reserve(self.approved_plan(["m1", "m2"]))
        self.refused("UPDATE cleanup_execution SET state='ABORTED' WHERE exec_id=?", ex["exec_id"])  # reverse order: items still PENDING
        self.refused("UPDATE cleanup_exec_slice SET state='COMPLETED' WHERE exec_id=?", ex["exec_id"])
        self.assertEqual(ce.abort_execution(self.index, ACCT, ex["exec_id"], now=self.tick())["state"], "ABORTED")  # the library uses the safe order

    def test_lease_column_only_holds_a_sha256(self):
        ex = self.reserve(self.approved_plan(["m1", "m2"]))
        self.refused("UPDATE cleanup_execution SET lease_token='plain-token' WHERE exec_id=?", ex["exec_id"])
        self.assertIsNone(self.sql("UPDATE cleanup_execution SET lease_token=? WHERE exec_id=?", "a" * 64, ex["exec_id"]))

    # ---- 6. AWAITING_CONTINUATION versus a final PARTIAL
    def test_awaiting_continuation_is_distinct_from_a_final_partial_and_only_awaiting_blocks_overlap(self):
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 141)])
        big = self.approved_plan([f"m{i}" for i in range(1, 131)])
        ex = self.reserve(big)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "AWAITING_CONTINUATION")
        self.assertEqual(sum(1 for s in ce.slices(self.index, ACCT, ex["exec_id"]) if s["state"] == "PENDING"), 2)
        self.assertEqual(ce.recover_interrupted(self.index, ACCT, self.t + timedelta(hours=1)), [])  # no lease to expire: untouched
        rest = self.ids_of(ex["exec_id"], 2)[:2]
        later = self.approved_plan(rest)
        with self.assertRaises(ce.ExecError) as cm:  # pending work of an awaiting execution still counts as unresolved overlap
            self.reserve(later)
        self.assertEqual(cm.exception.code, "OVERLAP_UNRESOLVED")
        other = self.approved_plan(["m135", "m136"])
        ex2 = self.reserve(other)  # an AWAITING execution does not occupy the account's single running slot
        with self.assertRaises(ce.ExecError) as cm:  # ...but continuing it while another one runs fails closed
            self.index.conn.execute  # noqa: B018
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(big, 2, 100), now=self.tick())
            ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=self.tick())
        self.assertEqual(cm.exception.code, "ACTIVE_EXECUTION_EXISTS")
        ce.abort_execution(self.index, ACCT, ex2["exec_id"], now=self.tick())
        # a final PARTIAL (no pending slice) never counts as active and cannot be continued
        fin = self.final_partial.__func__(self) if False else None  # noqa: F841
        self.assertEqual(self.exec_state(ex["exec_id"]), "AWAITING_CONTINUATION")

    def test_a_final_partial_does_not_block_the_account_or_continuation(self):
        ex = self.final_partial()
        self.assertEqual(self.exec_state(ex["exec_id"]), "PARTIAL")
        nxt = self.reserve(self.approved_plan(["m3", "m4"]))  # the account is free again
        self.assertEqual(nxt["state"], "PREPARED")
        with self.assertRaises(ce.ExecError):
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 1, "CONTINUE", now=self.tick())
        with self.assertRaises(ce.ExecError):
            ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())

    # ---- 7. no false verification
    def test_applied_requires_matching_live_read_evidence_and_never_a_bare_claim(self):
        ex = self.started(self.approved_plan(["m1", "m2", "m3"]))
        a, b, c = self.ids_of(ex["exec_id"])
        for mid in (a, b, c):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS", "Label_9"], now=self.tick())
        import inspect
        self.assertNotIn("evidence_checked", inspect.signature(ce.record_outcome).parameters)  # callers cannot assert verification
        with self.assertRaises(ce.ExecError) as cm:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", now=self.tick())
        self.assertEqual(cm.exception.code, "BAD_EVIDENCE")
        for labels, expect in ((("INBOX", "CATEGORY_PROMOTIONS", "Label_9"), "EVIDENCE_MISMATCH"), (("CATEGORY_PROMOTIONS",), "EVIDENCE_MISMATCH"),
                               (("CATEGORY_PROMOTIONS", "Label_9", "STARRED"), "EVIDENCE_MISMATCH")):
            with self.assertRaises(ce.ExecError) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, labels), now=self.tick())
            self.assertEqual(cm.exception.code, expect)
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(b, ("CATEGORY_PROMOTIONS", "Label_9")), now=self.tick())
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE evidence_checked=1")[0][0], 0)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, ("Label_9", "CATEGORY_PROMOTIONS")), now=self.tick())
        self.assertEqual(self.index._q("SELECT state, evidence_checked FROM cleanup_exec_item WHERE message_id=?", a)[0][:], ("APPLIED", 1))
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, b, "UNKNOWN", code="NETWORK_ERROR", now=self.tick())
        self.assertEqual(self.index._q("SELECT evidence_checked FROM cleanup_exec_item WHERE message_id=?", b)[0][0], 0)  # unknown is never verified
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")  # unknown work is not "executed"

    def test_reconciliation_is_not_reachable_from_production_code(self):
        text = (SRC / "gmail_intelligence" / "cli.py").read_text()
        for name in ("reconcile_item", "Evidence", "record_outcome", "reserve_execution", "recover_interrupted"):
            self.assertNotIn(name, text)
        doc = (ROOT / "docs" / "CLEANUP.md").read_text()
        self.assertIn("local metadata alone cannot prove", doc.lower().replace("\n", " "))

    # ---- 8. reporting
    def test_reports_show_continuation_only_when_it_exists_and_reasons_without_ids(self):
        def show(exec_id, flags=()):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(["cleanup", "exec", "show", exec_id, "--account", ACCT, *flags]), 0, err.getvalue())
            return out.getvalue()
        partial = self.final_partial()
        text = show(partial["exec_id"])
        self.assertIn("PARTIAL (final)", text)
        self.assertNotIn("AWAITING", text)
        self.assertNotIn("fresh typed confirmation", text)
        self.assertIn("REJECTED", text)
        for mid in ("m1", "m2"):
            self.assertNotIn(mid, text)
        failed = self.started(self.approved_plan(["m3"]))
        ce.stop_execution(self.index, ACCT, failed["exec_id"], self.token, "AUTH_PROBLEM", now=self.tick())
        text = show(failed["exec_id"])
        self.assertIn("FAILED (final)", text)
        self.assertIn("NEVER_ATTEMPTED", text)
        self.assertNotIn("confirmation", text.replace("This version", ""))
        unknown = self.started(self.approved_plan(["m4", "m5"]))
        mid = self.ids_of(unknown["exec_id"])[0]
        ce.record_intent(self.index, ACCT, unknown["exec_id"], self.token, mid, ["INBOX"], now=self.tick())
        ce.stop_execution(self.index, ACCT, unknown["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        text = show(unknown["exec_id"])
        self.assertIn("RECONCILIATION REQUIRED", text)
        self.assertIn("AMBIGUOUS_RESULT", text)
        self.assertIn("uncertain", text)
        self.assertNotIn(mid, text)
        self.assertIn(mid, show(unknown["exec_id"], ["--show-ids"]))

    def test_awaiting_continuation_report_names_the_pending_slices(self):
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 121)])
        ex = self.reserve(self.approved_plan([f"m{i}" for i in range(1, 111)]))
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        self.apply_all(ex, 1)
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["cleanup", "exec", "show", ex["exec_id"], "--account", ACCT])
        self.assertIn("AWAITING CONTINUATION: slice(s) 2", out.getvalue())

    # ---- 9. dry run stays byte-for-byte read-only on a synthetic v5 file
    def test_dry_run_and_listings_leave_the_database_file_byte_identical(self):
        import hashlib
        plan = self.approved_plan(["m1", "m2"])
        ex = self.reserve(self.approved_plan(["m3", "m4"]))
        self.index.conn.commit()
        path = config.index_path()
        digest = lambda: hashlib.sha256(Path(path).read_bytes()).hexdigest()  # noqa: E731
        before = digest()
        for argv in (["cleanup", "execute", plan["plan_id"], "--dry-run"], ["cleanup", "exec", "list"], ["cleanup", "exec", "show", ex["exec_id"], "--show-ids"],
                     ["cleanup", "execute", plan["plan_id"]]):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                cli.main([*argv, "--account", ACCT])
        self.assertEqual(digest(), before)



class FinalMicroCorrectionTests(ExecBase):
    """Strict evidence chronology, honest evidence terminology, evidence/INBOX/invariant hardening and fail-closed continuation."""
    sql = HardeningTests.sql
    refused = HardeningTests.refused

    LABELS = ["INBOX", "CATEGORY_PROMOTIONS", "Label_9", "My Private Label"]
    AFTER = ("CATEGORY_PROMOTIONS", "Label_9", "My Private Label")

    def snapshot(self):
        q = self.index._q
        return ([tuple(r) for r in q("SELECT * FROM cleanup_exec_item ORDER BY message_id")], [tuple(r) for r in q("SELECT * FROM cleanup_execution")],
                [tuple(r) for r in q("SELECT * FROM cleanup_approval")], q("SELECT COUNT(*) FROM cleanup_audit")[0][0])

    def at_micro(self, micro=250000, seconds=10):
        return self.tick(seconds) + timedelta(microseconds=micro)

    def intent(self, ex, mid, when):
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, self.LABELS, now=when)

    def iso(self, dt, frac=True):
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + (dt.strftime(".%f") if frac else "") + "Z"

    # ---- P2: strict chronology
    def test_evidence_may_not_predate_the_intent_not_even_by_a_microsecond(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a, b = self.ids_of(ex["exec_id"])
        intent = self.at_micro()
        self.intent(ex, a, intent)
        now = intent + timedelta(seconds=20)
        before = self.snapshot()
        for label, when in (("4 minutes before", intent - timedelta(minutes=4)), ("1 second before", intent - timedelta(seconds=1)),
                            ("1 microsecond before", intent - timedelta(microseconds=1))):
            with self.assertRaises(ce.ExecError, msg=label) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=self.iso(when)), now=now)
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE", label)
            self.assertEqual(self.snapshot(), before, label)  # item, execution, approval and audit rows are untouched
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=self.iso(intent)), now=now)  # exactly at
        row = self.index._q("SELECT * FROM cleanup_exec_item WHERE message_id=?", a)[0]
        self.assertEqual((row["state"], row["evidence_checked"], row["evidence_source"], row["evidence_observed_at"]),
                         ("APPLIED", 1, "CALLER_SUPPLIED", self.iso(intent)))
        intent_b = self.at_micro(500000)
        self.intent(ex, b, intent_b)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, b, "APPLIED", evidence=self.ev(b, self.AFTER, when=self.iso(intent_b + timedelta(microseconds=1))),
                          now=intent_b + timedelta(seconds=20))  # after

    def test_future_missing_malformed_and_zone_inconsistent_timestamps_are_refused(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a = self.ids_of(ex["exec_id"])[0]
        intent = self.at_micro(0)
        self.intent(ex, a, intent)
        now = intent + timedelta(seconds=20)
        before = self.snapshot()
        base = self.iso(intent, frac=False)[:-1]
        for bad in (self.iso(now + timedelta(minutes=6)), 12345, "yesterday", base, base + "z", base + "+0200", base + "Z+00:00", base + "+25:00",
                    self.iso(intent)[:-1] + "1234567Z", "2027-13-01T00:00:00Z", base + " Z", "\u0661" + base[1:] + "Z"):
            with self.assertRaises(ce.ExecError, msg=bad) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=bad), now=now)
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE", bad)
            self.assertEqual(self.snapshot(), before, bad)
        for missing in (None, ""):  # (the ev() helper substitutes a default for falsy values, so build these directly)
            with self.assertRaises(ce.ExecError) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=ce.Evidence("LABEL_OBSERVATION", a, self.AFTER, missing), now=now)
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)
        # an explicit offset is normalised to UTC: the same instant is accepted, one microsecond earlier is not
        same = (intent + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+02:00"
        early = (intent - timedelta(microseconds=1) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+02:00"
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=early), now=now)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=same), now=now)
        self.assertEqual(self.index._q("SELECT evidence_observed_at FROM cleanup_exec_item WHERE message_id=?", a)[0][0], self.iso(intent))
        # a modestly future observation is still bounded only by the shared clock policy (5 minutes)
        b = self.ids_of(ex["exec_id"])[1]
        self.intent(ex, b, now)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, b, "APPLIED", evidence=self.ev(b, self.AFTER, when=self.iso(now + timedelta(minutes=4))), now=now)

    def test_reconciliation_evidence_may_not_predate_the_unknown_transition(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a, b = self.ids_of(ex["exec_id"])
        i1 = self.at_micro()
        self.intent(ex, a, i1)
        u = i1 + timedelta(seconds=30)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "UNKNOWN", code="TIMEOUT", now=u)
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=u + timedelta(seconds=1))
        unknown_at = self.index._q("SELECT result_at FROM cleanup_exec_item WHERE message_id=?", a)[0][0]
        self.assertEqual(unknown_at, self.iso(u))
        now = u + timedelta(minutes=1)
        before = self.snapshot()
        for label, when in (("before the intent", i1 - timedelta(microseconds=1)), ("at the intent but before UNKNOWN", i1),
                            ("1 microsecond before UNKNOWN", u - timedelta(microseconds=1))):
            with self.assertRaises(ce.ExecError, msg=label) as cm:
                ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a, self.AFTER, when=self.iso(when)), now=now)
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE", label)
            self.assertEqual(self.snapshot(), before, label)
        ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a, self.AFTER, when=self.iso(u)), now=now)  # exactly at UNKNOWN
        self.assertEqual(self.index._q("SELECT state, error_code FROM cleanup_exec_item WHERE message_id=?", a)[0][:], ("APPLIED", "RECONCILED_OBSERVED_ARCHIVED"))

    def test_sql_level_chronology_backstop(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a = self.ids_of(ex["exec_id"])[0]
        intent = self.at_micro()
        self.intent(ex, a, intent)
        upd = "UPDATE cleanup_exec_item SET state='APPLIED', result_at=?, evidence_checked=1, evidence_source='CALLER_SUPPLIED', evidence_observed_at=? WHERE message_id=?"
        self.refused(upd, self.iso(intent), self.iso(intent - timedelta(microseconds=1)), a)
        self.refused(upd, self.iso(intent), "2026-01-01T00:00:00Z", a)  # not the fixed microsecond format
        self.assertIsNone(self.sql(upd, self.iso(intent), self.iso(intent), a))

    # ---- P3: honest terminology and trust boundary
    def test_terminology_columns_codes_and_untrusted_sources(self):
        cols = [r[1] for r in self.index._q("PRAGMA table_info(cleanup_exec_item)")]
        self.assertIn("evidence_checked", cols)
        self.assertNotIn("verified", cols)
        self.assertIn("RECONCILED_OBSERVED_ARCHIVED", idx.EXEC_ITEM_CODES)
        self.assertNotIn("RECONCILED_APPLIED", idx.EXEC_ITEM_CODES)
        self.assertNotIn("RECONCILED_APPLIED", ce.CODE_MEANING)
        self.assertIn("not attributed", ce.CODE_MEANING["RECONCILED_OBSERVED_ARCHIVED"])
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a = self.ids_of(ex["exec_id"])[0]
        intent = self.at_micro()
        self.intent(ex, a, intent)
        now = intent + timedelta(seconds=5)
        before = self.snapshot()
        for src in ("TRUSTED_ADAPTER", "gmail-live-read", "local-guess", None):  # a caller cannot claim to be the trusted Gmail adapter
            with self.assertRaises(ce.ExecError, msg=src) as cm:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=self.iso(intent), source=src), now=now)
            self.assertEqual(cm.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(ce.ACCEPTED_EVIDENCE_SOURCES, ("CALLER_SUPPLIED",))
        self.assertNotIn("attributed", " ".join(cols))

    # ---- S1: accepted evidence cannot be downgraded
    def test_accepted_evidence_cannot_be_downgraded_or_altered_by_direct_sql(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a = self.ids_of(ex["exec_id"])[0]
        intent = self.at_micro()
        self.intent(ex, a, intent)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER, when=self.iso(intent)), now=intent + timedelta(seconds=5))
        before = self.snapshot()
        for stmt, params in (("UPDATE cleanup_exec_item SET evidence_checked=0 WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET evidence_source=NULL WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET evidence_source='TRUSTED_ADAPTER' WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET evidence_observed_at=NULL WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET evidence_observed_at='2030-01-01T00:00:00.000000Z' WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET state='UNKNOWN' WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET state='NOT_APPLIED', evidence_checked=0 WHERE message_id=?", (a,)),
                             ("UPDATE cleanup_exec_item SET evidence_checked=0, evidence_source=NULL, evidence_observed_at=NULL, state='PENDING' WHERE message_id=?", (a,))):
            self.refused(stmt, *params)
            self.assertEqual(self.snapshot(), before, stmt)  # a refused statement rolls back completely
        self.refused("UPDATE cleanup_exec_item SET evidence_checked=1 WHERE message_id<>?", a)  # nor can evidence appear on non-APPLIED items

    def test_executed_requires_every_applied_item_to_have_checked_evidence(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        for mid in self.ids_of(ex["exec_id"]):
            self.intent(ex, mid, self.at_micro())
        # 'APPLIED' without evidence_checked cannot even be written (table CHECK and trigger)
        self.refused("UPDATE cleanup_exec_item SET state='APPLIED', result_at='2030-01-01T00:00:00.000000Z' WHERE exec_id=?", ex["exec_id"])

    # ---- S3: ARCHIVE recovery metadata must include INBOX
    def test_archive_intent_must_include_inbox_in_library_and_sql_and_preserves_other_labels_exactly(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a, b = self.ids_of(ex["exec_id"])
        before = self.snapshot()
        for labels in (["CATEGORY_PROMOTIONS"], ["Label_9", "My Private Label"], ["inbox"], ["INBOX2"], ["XINBOX"], [], None, "INBOX", ["Label\"INBOX\""]):
            with self.assertRaises(ce.ExecError, msg=labels) as cm:
                ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, labels, now=self.tick())
            self.assertEqual(cm.exception.code, "BAD_INPUT")
            self.assertEqual(self.snapshot(), before)
        for bad in ('["CATEGORY_PROMOTIONS"]', '["INBOXX"]', '["inbox"]', '["a\\"INBOX\\"]', '[]', 'INBOX', '{"INBOX":1}'):
            self.refused("UPDATE cleanup_exec_item SET state='INTENT', intent_at='2026-01-01T00:00:00.000000Z', prev_label_ids=? WHERE message_id=?", bad, a)
            self.refused("UPDATE cleanup_exec_item SET prev_label_ids=? WHERE message_id=?", bad, b)  # table CHECK even before an intent
        self.assertEqual(self.snapshot(), before)
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, ["Label_9", "INBOX", "My Private Label", "CATEGORY_PROMOTIONS", "Label_9"], now=self.tick())
        stored = self.index._q("SELECT prev_label_ids FROM cleanup_exec_item WHERE message_id=?", a)[0][0]
        self.assertEqual(stored, json.dumps(sorted({"INBOX", "Label_9", "My Private Label", "CATEGORY_PROMOTIONS"})))
        self.assertEqual(set(json.loads(stored)) - {"INBOX"}, {"Label_9", "My Private Label", "CATEGORY_PROMOTIONS"})  # unrelated labels preserved exactly
        self.refused("UPDATE cleanup_exec_item SET prev_label_ids='[\"INBOX\"]' WHERE message_id=?", a)  # still immutable

    # ---- S2: EXECUTING needs exactly one ACTIVE slice
    def test_executing_invariant_normal_interrupted_recovered_and_corrupted(self):
        ex = self.reserve(self.approved_plan(["m1", "m2"]))
        E = ex["exec_id"]
        self.assertEqual(ce.invariant_problems(self.index, ACCT, E), [])
        self.refused("UPDATE cleanup_execution SET state='EXECUTING' WHERE exec_id=?", E)  # no ACTIVE slice yet: refused at the entry
        self.token = ce.start_slice(self.index, ACCT, E, 1, now=self.tick())  # slice goes ACTIVE first, then the execution
        self.assertEqual(ce.invariant_problems(self.index, ACCT, E), [])
        self.assertEqual([s["state"] for s in ce.slices(self.index, ACCT, E)], ["ACTIVE"])
        a = self.ids_of(E)[0]
        # direct-SQL corruption: the ACTIVE slice disappears under a running execution (cannot be blocked per statement, must be detected)
        self.assertIsNone(self.sql("UPDATE cleanup_exec_slice SET state='STOPPED' WHERE exec_id=?", E))
        self.assertEqual(ce.invariant_problems(self.index, ACCT, E), ["EXECUTING_WITHOUT_ONE_ACTIVE_SLICE_AND_LEASE"])
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as cm:
            ce.record_intent(self.index, ACCT, E, self.token, a, self.LABELS, now=self.tick())
        self.assertEqual(cm.exception.code, "INVARIANT_BROKEN")
        self.assertEqual(self.snapshot(), before)
        recovered = ce.recover_interrupted(self.index, ACCT, self.t + timedelta(minutes=30))  # an expired lease still recovers it, fail closed
        self.assertEqual(recovered, [E])
        self.assertEqual(self.exec_state(E), "FAILED")
        self.assertEqual(ce.invariant_problems(self.index, ACCT, E), [])

    def test_interruption_with_a_normal_active_slice_recovers_cleanly(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        a = self.ids_of(ex["exec_id"])[0]
        self.intent(ex, a, self.at_micro())
        self.assertEqual(ce.recover_interrupted(self.index, ACCT, self.t + timedelta(minutes=30)), [ex["exec_id"]])
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")
        self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])

    def test_a_second_active_slice_or_early_activation_is_refused(self):
        ex = self.started(self.approved_plan(["m1", "m2"]))
        self.refused("UPDATE cleanup_exec_slice SET state='ACTIVE' WHERE exec_id=?", ex["exec_id"])  # already ACTIVE: not a transition
        self.refused("UPDATE cleanup_execution SET state='AWAITING_CONTINUATION' WHERE exec_id=?", ex["exec_id"])

    # ---- C1: fail-closed continuation
    def big(self):
        self.index.purge(ACCT)
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 141)])
        plan = self.approved_plan([f"m{i}" for i in range(1, 131)])
        ex = self.reserve(plan)
        self.token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
        return plan, ex

    def work(self, ex, plan_outcomes):
        """plan_outcomes: list of 'A' applied, 'R' rejected, 'D' skipped (drift), 'G' skipped (gone), 'U' unknown, one per slice-1 item."""
        for mid, o in zip(self.ids_of(ex["exec_id"], 1), plan_outcomes):
            ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=self.tick())
            if o in "DG":
                ce.record_skip(self.index, ACCT, ex["exec_id"], self.token, mid, "SKIPPED_DRIFT" if o == "D" else "SKIPPED_GONE", "LABELS_CHANGED" if o == "D" else "NOT_FOUND", now=self.tick())
                continue
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, ["INBOX", "CATEGORY_PROMOTIONS"], now=self.tick())
            if o == "A":
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=self.ev(mid), now=self.tick())
            elif o == "R":
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "NOT_APPLIED", now=self.tick())
            else:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "UNKNOWN", code="TIMEOUT", now=self.tick())

    def finish_and_check_blocked(self, ex, plan, expect_state):
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), expect_state)
        self.assertEqual([s["state"] for s in ce.slices(self.index, ACCT, ex["exec_id"])], ["COMPLETED", "STOPPED", "STOPPED"])
        c = ce.code_counts(self.index, ACCT, ex["exec_id"])
        self.assertEqual(c.get(("NOT_APPLIED", "NEVER_ATTEMPTED")), 105)  # the 105 remaining targets were never touched
        with self.assertRaises(ce.ExecError) as cm:
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())
        self.assertEqual(cm.exception.code, "BAD_STATE")
        with self.assertRaises(ce.ExecError):
            ce.start_slice(self.index, ACCT, ex["exec_id"], 2, now=self.tick())
        self.assertEqual(ce.invariant_problems(self.index, ACCT, ex["exec_id"]), [])
        self.assertNotEqual(self.exec_state(ex["exec_id"]), "EXECUTED")  # failure is never turned into apparent success

    def test_a_canary_with_zero_applications_never_continues(self):
        plan, ex = self.big()
        self.work(ex, "R" * 25)
        self.finish_and_check_blocked(ex, plan, "FAILED")

    def test_a_canary_of_only_safe_skips_still_applied_nothing_so_it_never_continues(self):
        plan, ex = self.big()
        self.work(ex, "DG" * 12 + "D")
        self.finish_and_check_blocked(ex, plan, "FAILED")

    def test_one_rejected_mutation_stops_an_otherwise_successful_canary(self):
        plan, ex = self.big()
        self.work(ex, "A" * 24 + "R")
        self.finish_and_check_blocked(ex, plan, "PARTIAL")

    def test_unknown_outcomes_and_reconciliation_conflicts_never_continue(self):
        plan, ex = self.big()
        self.work(ex, "A" * 24 + "U")
        with self.assertRaises(ce.ExecError):  # an UNKNOWN item keeps the slice open
            ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")
        unknown = self.ids_of(ex["exec_id"], 1, "UNKNOWN")[0]
        done = ce.reconcile_item(self.index, ACCT, ex["exec_id"], unknown, self.ev(unknown, ("SOMETHING_ELSE",)), now=self.tick())
        self.assertEqual(done["state"], "PARTIAL")
        with self.assertRaises(ce.ExecError):
            ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())

    def test_a_canary_with_applications_and_only_safe_skips_may_continue(self):
        plan, ex = self.big()
        self.work(ex, "A" * 20 + "DDDGG")
        ce.end_slice(self.index, ACCT, ex["exec_id"], 1, self.token, now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "AWAITING_CONTINUATION")
        self.assertEqual(ce.continuation_blockers(self.index, ACCT, ex["exec_id"]), [])
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], 2, ce.continuation_phrase(plan, 2, 100), now=self.tick())
        self.assertEqual([s["state"] for s in ce.slices(self.index, ACCT, ex["exec_id"])], ["COMPLETED", "CONFIRMED", "PENDING"])

    def test_sql_level_refuses_awaiting_continuation_after_an_unsafe_slice(self):
        plan, ex = self.big()
        self.work(ex, "R" * 25)
        self.assertIsNone(self.sql("UPDATE cleanup_exec_slice SET state='COMPLETED' WHERE exec_id=? AND slice_no=1", ex["exec_id"]))
        self.refused("UPDATE cleanup_execution SET state='AWAITING_CONTINUATION' WHERE exec_id=?", ex["exec_id"])
        plan2 = None  # noqa: F841



class SourceGuards(unittest.TestCase):
    MODULES = ("cleanup_exec.py", "cleanup_exec_report.py")

    def test_m4c_a_modules_have_no_gmail_oauth_network_or_keychain_code(self):
        allowed_local = {"cleanup_audit", "cleanup_plans", "cleanup_exec", "cleanup_protect", "index"}
        for name in self.MODULES:
            text = (SRC / "gmail_intelligence" / name).read_text()
            for node in ast.walk(ast.parse(text)):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module] + ([f"gmail_intelligence.{a.name}" for a in node.names] if node.module == "gmail_intelligence" else [])
                for m in mods:
                    top = m.split(".")[0]
                    if top == "gmail_intelligence":
                        self.assertIn(m.split(".")[1] if "." in m else None, allowed_local | {None}, (name, m))
                    else:
                        self.assertIn(top, {"json", "secrets", "sqlite3", "datetime", "hmac", "dataclasses", "re"}, (name, m))
            for banned in ("googleapiclient", "google.", "keystore", "oauth", "urllib", "socket", "subprocess", "requests", "ai_http", "scanner",
                           "gmail_write", "batchModify", ".trash(", ".send(", "untrash", "messages().modify", "gmail.modify", "mail.google.com"):
                self.assertNotIn(banned, text, (name, banned))
            self.assertNotRegex(text, r"\b(eval|exec|compile|__import__)\(")

    def test_schema_v5_has_only_archive_and_no_gmail_vocabulary(self):
        sql = idx.SCHEMA_V5
        self.assertIn("CHECK (action IN ('ARCHIVE'))", sql)
        for word in ("TRASH", "DELETE_FOREVER", "SEND"):
            self.assertNotIn(word, sql)
        self.assertEqual(sorted(__import__("gmail_intelligence.oauth", fromlist=["x"]).EXPECTED_SCOPES), ["https://www.googleapis.com/auth/gmail.readonly"])

    def test_no_module_other_than_the_cli_imports_the_execution_state_module(self):
        importers = []
        for path in (SRC / "gmail_intelligence").glob("*.py"):
            if path.name in ("cleanup_exec.py", "cleanup_exec_report.py"):
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else []
                if isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [f"{node.module}.{a.name}" for a in node.names]
                if any(n.split(".")[-1] in ("cleanup_exec", "cleanup_exec_report") for n in names):
                    importers.append(path.name)
        self.assertEqual(sorted(set(importers)), ["cli.py"])


if __name__ == "__main__":
    unittest.main()
