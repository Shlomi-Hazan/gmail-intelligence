"""M5D: immutable label-change plans, one-time local approvals, audit continuity and the v5 -> v6 migration (issue #15). Synthetic data only; nothing can execute a plan."""
import ast
import json
import os
import sqlite3
import stat
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, OTHER, M5Base, label, mail  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, index as idx, label_model as lm, label_plan_report as rep, label_plans as lp  # noqa: E402
from gmail_intelligence.cleanup_plans import PlanError  # noqa: E402

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
PRIVATE_LABEL = "SentinelPrivateName"


def minutes(n):
    return T0 + timedelta(minutes=n)


class PlanBase(M5Base):
    def setUp(self):
        super().setUp()
        labels = [label("Label_1", "Work"), label("Label_2", "Work/Plans"), label("Label_3", "Receipts"), label("Label_4", "Receipts Old"), label("Label_5", "Travel"),
                  label("Label_6", "Travel"), label("Label_7", PRIVATE_LABEL), label("INBOX", "INBOX", "system"), label("CATEGORY_SOCIAL", "CATEGORY_SOCIAL", "system")]
        self.fixture(labels, [mail(1, ["INBOX", "Label_1", "Label_3", "Label_7"])])
        self.fixture([label("Label_9", "OtherOnly")], [mail(2, ["INBOX", "Label_9"])], account=OTHER)

    def make(self, *specs, now=T0):
        return lp.create_plan(self.index, ACCT, list(specs), now=now)

    def refuse(self, code, *specs):
        before = self.index._q("SELECT COUNT(*) FROM label_plan")[0][0]
        with self.assertRaises(PlanError) as cm:
            self.make(*specs)
        self.assertEqual(cm.exception.code, code, cm.exception)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan")[0][0], before)  # nothing partial
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_op")[0][0], 0 if not before else self.index._q("SELECT COUNT(*) FROM label_plan_op")[0][0])

    def reviewed(self, plan=None, now=T0):
        plan = plan or self.make(("CREATE", "Archive"), now=now)
        return lp.mark_reviewed(self.index, ACCT, plan["plan_id"], lp.review_phrase(plan), now=now)

    def approved(self, now=T0):
        plan = self.reviewed(now=now)
        lp.approve(self.index, ACCT, plan["plan_id"], lp.approval_phrase(plan), now=now)
        return lp.get_plan(self.index, ACCT, plan["plan_id"])


class OperationTests(PlanBase):
    def test_all_four_operation_kinds(self):
        p = self.make(("CREATE", "Archive"), ("CREATE", "Archive/2025"), ("RENAME", "Label_3", "Bills"), ("NEST", "Label_4", "Archive"), ("MERGE", "Label_5", "Label_6"))
        self.assertEqual((p["state"], p["op_count"]), ("DRAFT", 5))
        snap = json.loads(p["snapshot"])
        self.assertEqual([o["op"] for o in snap["ops"]], ["CREATE", "CREATE", "RENAME", "NEST", "MERGE"])
        self.assertEqual((snap["executable"], snap["reversible"], snap["max_depth"]), (False, False, 3))
        self.assertEqual(snap["ops"][2]["new_name"], "Bills")
        self.assertEqual(snap["ops"][3]["new_name"], "Archive/Receipts Old")
        self.assertEqual(snap["ops"][3]["target_id"], "")  # nested under a label created in this plan
        self.assertEqual(lp.integrity_problems(p), [])

    def test_names_resolve_by_id_or_exact_name_and_nest_to_top_level(self):
        p = self.make(("RENAME", "Receipts Old", "Old receipts"), ("NEST", "Label_2", ""))
        ops = json.loads(p["snapshot"])["ops"]
        self.assertEqual((ops[0]["label_id"], ops[0]["new_name"]), ("Label_4", "Old receipts"))
        self.assertEqual((ops[1]["old_name"], ops[1]["new_name"]), ("Work/Plans", "Plans"))

    def test_rename_and_nest_report_affected_children(self):
        ops = json.loads(self.make(("RENAME", "Label_1", "Job"))["snapshot"])["ops"]
        self.assertEqual((ops[0]["new_name"], ops[0]["descendants"]), ("Job", 1))
        text = rep.plan_text(self.index, ACCT, lp.get_plan(self.index, ACCT, self.index._q("SELECT plan_id FROM label_plan")[0][0]), True)
        self.assertIn("changes the full path of 1 child label(s)", text)

    def test_system_labels_are_never_touched(self):
        for ref in ("INBOX", "CATEGORY_SOCIAL"):
            self.refuse("SYSTEM_LABEL", ("RENAME", ref, "x"))
            self.refuse("SYSTEM_LABEL", ("MERGE", "Label_3", ref))
            self.refuse("SYSTEM_LABEL", ("NEST", "Label_3", ref))
        self.refuse("SYSTEM_LABEL", ("MERGE", "TRASH", "Label_3"))

    def test_reserved_invalid_and_duplicate_names(self):
        for name in ("Inbox", "TRASH", "Sent Mail", "CATEGORY_PROMOTIONS", "Inbox/Child"):
            self.refuse("RESERVED_NAME", ("CREATE", name))
        for name in ("", "  ", "a//b", "/lead", "trail/", " pad", "a /b", "x" * 300, "bad\x07name", "é"):
            self.refuse("BAD_NAME", ("CREATE", name))
        for name in ("receipts", "RECEIPTS ", "Receipts", "Ｒeceipts"):
            with self.assertRaises(PlanError) as cm:
                self.make(("CREATE", name))
            self.assertIn(cm.exception.code, ("DUPLICATE_NAME", "BAD_NAME"))
        self.refuse("DUPLICATE_NAME", ("CREATE", "receipts"))
        self.refuse("DUPLICATE_NAME", ("CREATE", "Foo"), ("CREATE", "foo"))
        self.refuse("DUPLICATE_NAME", ("RENAME", "Label_4", "receipts"))
        self.refuse("BAD_NAME", ("RENAME", "Label_4", "a/b"))
        self.refuse("NO_CHANGE", ("RENAME", "Label_4", "Receipts Old"))

    def test_a_case_only_rename_is_allowed(self):
        self.make(("RENAME", "Label_3", "RECEIPTS"))

    def test_nesting_limits_parents_and_cycles(self):
        self.refuse("TOO_DEEP", ("CREATE", "a"), ("CREATE", "a/b"), ("CREATE", "a/b/c"), ("CREATE", "a/b/c/d"))
        self.refuse("PARENT_MISSING", ("CREATE", "Nowhere/Child"))
        self.refuse("NO_SUCH_LABEL", ("NEST", "Label_3", "Nowhere"))
        self.refuse("CYCLE", ("NEST", "Label_1", "Label_2"))
        self.refuse("CYCLE", ("NEST", "Label_1", "Label_1"))
        self.refuse("TOO_DEEP", ("CREATE", "Deep"), ("CREATE", "Deep/Deeper"), ("NEST", "Label_1", "Deep/Deeper"))  # Work/Plans would sit at depth 5
        self.make(("CREATE", "Deep"), ("NEST", "Label_1", "Deep"))  # depth 3 is the maximum
        self.refuse("DUPLICATE_NAME", ("CREATE", "Receipts/x"), ("CREATE", "Work/Plans"))  # existing child path

    def test_ambiguous_missing_and_cross_account_references(self):
        self.refuse("AMBIGUOUS_LABEL", ("MERGE", "Label_3", "Travel"))
        self.make(("MERGE", "Label_3", "Label_5"))
        self.refuse("NO_SUCH_LABEL", ("RENAME", "Label_404", "x"))
        self.refuse("NO_SUCH_LABEL", ("MERGE", "Label_3", "Label_9"))  # the other account's label does not exist here
        self.refuse("NO_SUCH_LABEL", ("RENAME", "OtherOnly", "x"))

    def test_merge_rules(self):
        self.refuse("SAME_LABEL", ("MERGE", "Label_3", "Label_3"))
        self.refuse("HAS_CHILDREN", ("MERGE", "Label_1", "Label_3"))
        self.refuse("CONFLICTING_OPS", ("MERGE", "Label_3", "Label_4"), ("MERGE", "Label_4", "Label_5"))  # chains
        self.refuse("CONFLICTING_OPS", ("MERGE", "Label_3", "Label_4"), ("RENAME", "Label_3", "x"))
        self.refuse("CONFLICTING_OPS", ("MERGE", "Label_3", "Label_4"), ("RENAME", "Label_4", "x"))
        self.refuse("CONFLICTING_OPS", ("RENAME", "Label_3", "x"), ("NEST", "Label_3", "Label_4"))
        self.make(("MERGE", "Label_3", "Label_5"), ("MERGE", "Label_4", "Label_5"))  # several into one target is fine

    def test_empty_oversized_and_unknown_plans(self):
        self.refuse("NO_OPS")
        self.refuse("TOO_MANY_OPS", *[("CREATE", f"L{i}") for i in range(lp.MAX_OPS + 1)])
        self.refuse("BAD_OP", ("DELETE", "Label_3"))

    def test_no_inventory(self):
        with self.assertRaises(PlanError) as cm:
            lp.create_plan(self.index, "nobody@example.invalid", [("CREATE", "x")], now=T0)
        self.assertEqual(cm.exception.code, "NO_INVENTORY")

    def test_account_isolation(self):
        p = self.make(("CREATE", "Archive"))
        self.assertEqual(lp.list_plans(self.index, OTHER), [])
        with self.assertRaises(PlanError) as cm:
            lp.get_plan(self.index, OTHER, p["plan_id"])
        self.assertEqual(cm.exception.code, "NO_SUCH_PLAN")
        for fn in (lambda: lp.mark_reviewed(self.index, OTHER, p["plan_id"], "x", now=T0), lambda: lp.cancel(self.index, OTHER, p["plan_id"], now=T0)):
            with self.assertRaises(PlanError) as cm:
                fn()
            self.assertEqual(cm.exception.code, "NO_SUCH_PLAN")
        self.assertEqual(lp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")


class LifecycleTests(PlanBase):
    def test_review_then_approve(self):
        p = self.make(("CREATE", "Archive"))
        self.assertEqual(lp.review_phrase(p), f"REVIEWED LABEL PLAN 1 {p['plan_hash'][:8]}")
        r = lp.mark_reviewed(self.index, ACCT, p["plan_id"], lp.review_phrase(p), now=minutes(1))
        self.assertEqual((r["state"], r["reviewed_at"] is not None), ("REVIEWED", True))
        st = lp.approve(self.index, ACCT, p["plan_id"], lp.approval_phrase(p), now=minutes(2))
        self.assertEqual((st["plan_state"], [a["status"] for a in st["approvals"]]), ("APPROVED", ["VALID"]))
        self.assertEqual(lp.verify_approved(self.index, ACCT, p["plan_id"], now=minutes(3)), {})

    def test_wrong_phrases_change_nothing_and_are_audited(self):
        p = self.make(("CREATE", "Archive"))
        for bad in ("", "REVIEWED", lp.approval_phrase(p), lp.review_phrase(p) + " ", "reviewed label plan 1 " + p["plan_hash"][:8]):
            if bad.strip() == lp.review_phrase(p):
                continue
            with self.assertRaises(PlanError) as cm:
                lp.mark_reviewed(self.index, ACCT, p["plan_id"], bad, now=minutes(1))
            self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(lp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")
        events = [e["event_type"] for e in audit.events(self.index, ACCT, p["plan_id"])]
        self.assertIn("LABEL_REVIEW_REJECTED", events)
        r = self.reviewed(p, minutes(2))
        with self.assertRaises(PlanError) as cm:
            lp.approve(self.index, ACCT, p["plan_id"], lp.review_phrase(r), now=minutes(3))
        self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_approval")[0][0], 0)

    def test_a_draft_cannot_be_approved_and_an_approved_plan_cannot_be_reviewed(self):
        p = self.make(("CREATE", "Archive"))
        with self.assertRaises(PlanError) as cm:
            lp.approve(self.index, ACCT, p["plan_id"], lp.approval_phrase(p), now=minutes(1))
        self.assertEqual(cm.exception.code, "BAD_STATE")
        a = self.approved(now=minutes(2))
        with self.assertRaises(PlanError) as cm:
            lp.mark_reviewed(self.index, ACCT, a["plan_id"], lp.review_phrase(a), now=minutes(3))
        self.assertEqual(cm.exception.code, "BAD_STATE")

    def test_approval_is_one_time_double_approval_and_replay_are_refused(self):
        a = self.approved()
        for _ in range(2):
            with self.assertRaises(PlanError) as cm:
                lp.approve(self.index, ACCT, a["plan_id"], lp.approval_phrase(a), now=minutes(1))
            self.assertEqual(cm.exception.code, "ALREADY_APPROVED")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_approval")[0][0], 1)
        with self.assertRaises(sqlite3.DatabaseError):  # a second VALID approval row is refused by the database itself
            with self.index.conn:
                self.index.conn.execute("INSERT INTO label_plan_approval VALUES (?,?,?,?,?,?,?,?,?)", (ACCT, a["plan_id"], "n2", a["plan_hash"], 1, "t", "t", "VALID", "t"))

    def test_concurrent_approvals_yield_exactly_one(self):
        p = self.reviewed()
        results, barrier = [], threading.Barrier(2)

        def worker():
            with idx.Index(self.index.path) as other:
                barrier.wait()
                try:
                    lp.approve(other, ACCT, p["plan_id"], lp.approval_phrase(p), now=minutes(1))
                    results.append("ok")
                except PlanError as exc:
                    results.append(exc.code)
        threads = [threading.Thread(target=worker) for _ in range(2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(results), ["ALREADY_APPROVED", "ok"])
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_approval WHERE status='VALID'")[0][0], 1)

    def test_an_interrupted_approval_rolls_back_completely(self):
        p = self.reviewed()
        with mock.patch.object(audit, "append", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                lp.approve(self.index, ACCT, p["plan_id"], lp.approval_phrase(p), now=minutes(1))
        self.assertEqual(lp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_approval")[0][0], 0)
        self.assertFalse(self.index.conn.in_transaction)
        lp.approve(self.index, ACCT, p["plan_id"], lp.approval_phrase(p), now=minutes(2))  # and it still works afterwards

    def test_plan_and_approval_expiry(self):
        p = self.make(("CREATE", "Archive"))
        late = T0 + lp.PLAN_TTL + timedelta(minutes=1)
        self.assertEqual(lp.expire_due(self.index, ACCT, late), 1)
        self.assertEqual(lp.get_plan(self.index, ACCT, p["plan_id"])["state"], "EXPIRED")
        with self.assertRaises(PlanError) as cm:
            lp.mark_reviewed(self.index, ACCT, p["plan_id"], lp.review_phrase(p), now=late)
        self.assertEqual(cm.exception.code, "BAD_STATE")
        a = self.approved(now=late + timedelta(minutes=5))
        later = late + timedelta(minutes=5) + lp.APPROVAL_TTL + timedelta(minutes=1)
        self.assertTrue(lp.verify_approved(self.index, ACCT, a["plan_id"], now=later))
        self.assertEqual(lp.expire_due(self.index, ACCT, later), 1)
        st = lp.approval_status(self.index, ACCT, a["plan_id"])
        self.assertEqual((st["plan_state"], [x["status"] for x in st["approvals"]]), ("EXPIRED", ["EXPIRED"]))
        with self.assertRaises(sqlite3.DatabaseError):  # an expired approval can never become valid again
            with self.index.conn:
                self.index.conn.execute("UPDATE label_plan_approval SET status='VALID' WHERE plan_id=?", (a["plan_id"],))

    def test_cancel_revokes_the_approval_and_is_final(self):
        a = self.approved()
        lp.cancel(self.index, ACCT, a["plan_id"], now=minutes(1))
        st = lp.approval_status(self.index, ACCT, a["plan_id"])
        self.assertEqual((st["plan_state"], [x["status"] for x in st["approvals"]]), ("CANCELLED", ["REVOKED"]))
        with self.assertRaises(PlanError) as cm:
            lp.cancel(self.index, ACCT, a["plan_id"], now=minutes(2))
        self.assertEqual(cm.exception.code, "NOT_ACTIVE")
        with self.assertRaises(PlanError):
            lp.approve(self.index, ACCT, a["plan_id"], lp.approval_phrase(a), now=minutes(3))
        self.assertTrue(lp.verify_approved(self.index, ACCT, a["plan_id"], now=minutes(3)))

    def test_clock_rollback_is_refused(self):
        self.approved(now=minutes(60))
        for fn in (lambda: self.make(("CREATE", "Other"), now=minutes(0)),):
            with self.assertRaises(PlanError) as cm:
                fn()
            self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")
        p = self.make(("CREATE", "Next"), now=minutes(61))
        with self.assertRaises(PlanError) as cm:
            lp.mark_reviewed(self.index, ACCT, p["plan_id"], lp.review_phrase(p), now=minutes(0))
        self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")

    def test_repeated_wrong_confirmations_lock_the_plan_out_without_flooding_the_log(self):
        p = self.make(("CREATE", "Archive"))
        codes = []
        for k in range(lp.MAX_FAILED_ATTEMPTS + 6):
            with self.assertRaises(PlanError) as cm:
                lp.mark_reviewed(self.index, ACCT, p["plan_id"], "nope", now=minutes(1) + timedelta(seconds=k))
            codes.append(cm.exception.code)
        self.assertEqual(codes[:lp.MAX_FAILED_ATTEMPTS], ["BAD_CONFIRMATION"] * lp.MAX_FAILED_ATTEMPTS)
        self.assertEqual(set(codes[lp.MAX_FAILED_ATTEMPTS:]), {"LOCKED_OUT"})
        events = [e["event_type"] for e in audit.events(self.index, ACCT, p["plan_id"], 1000)]
        self.assertEqual(events.count("LABEL_ATTEMPTS_LOCKED_OUT"), 1)
        self.assertEqual(events.count("LABEL_REVIEW_REJECTED"), lp.MAX_FAILED_ATTEMPTS)

    def test_inventory_drift_makes_a_plan_stale(self):
        p = self.make(("RENAME", "Label_3", "Bills"))
        self.index.save_labels(ACCT, [label("Label_1", "Work"), label("Label_2", "Work/Plans"), label("Label_3", "Receipts 2"), label("Label_4", "Receipts Old"),
                                      label("Label_5", "Travel"), label("Label_6", "Travel"), label("Label_7", PRIVATE_LABEL)])
        self.assertIn("INVENTORY_CHANGED", lp.revalidate(self.index, ACCT, p, now=minutes(1)))
        with self.assertRaises(PlanError) as cm:
            lp.mark_reviewed(self.index, ACCT, p["plan_id"], lp.review_phrase(p), now=minutes(1))
        self.assertEqual(cm.exception.code, "STALE")
        self.assertEqual(lp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")

    def test_drift_after_review_blocks_approval(self):
        r = self.reviewed()
        self.index.save_labels(ACCT, [label("Label_1", "Work")])
        with self.assertRaises(PlanError) as cm:
            lp.approve(self.index, ACCT, r["plan_id"], lp.approval_phrase(r), now=minutes(1))
        self.assertEqual(cm.exception.code, "STALE")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM label_plan_approval")[0][0], 0)

    def test_another_accounts_inventory_change_does_not_affect_a_plan(self):
        p = self.make(("CREATE", "Archive"))
        self.index.save_labels(OTHER, [label("Label_9", "Changed")])
        self.assertEqual(lp.revalidate(self.index, ACCT, p, now=minutes(1)), {})


class TamperTests(PlanBase):
    def drop_triggers(self):
        names = [r[0] for r in self.index._q("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'label_plan%'")]
        for n in names:
            self.index.conn.execute(f"DROP TRIGGER {n}")
        self.index.conn.commit()

    def test_triggers_refuse_content_changes_deletes_and_backward_states(self):
        a = self.approved()
        pid = a["plan_id"]
        for sql in ("UPDATE label_plan SET snapshot='{}' WHERE plan_id=?", "UPDATE label_plan SET plan_hash=? WHERE plan_id=?", "UPDATE label_plan SET op_count=9 WHERE plan_id=?",
                    "UPDATE label_plan SET expires_at='2099-01-01T00:00:00Z' WHERE plan_id=?", "UPDATE label_plan SET state='DRAFT' WHERE plan_id=?",
                    "UPDATE label_plan SET state='REVIEWED' WHERE plan_id=?", "DELETE FROM label_plan WHERE plan_id=?", "UPDATE label_plan_op SET new_name='x' WHERE plan_id=?",
                    "DELETE FROM label_plan_op WHERE plan_id=?", "UPDATE label_plan_approval SET expires_at='2099-01-01T00:00:00Z' WHERE plan_id=?",
                    "UPDATE label_plan_approval SET plan_hash=? WHERE plan_id=?", "DELETE FROM label_plan_approval WHERE plan_id=?"):
            params = ("f" * 64, pid) if sql.count("?") == 2 else (pid,)
            with self.assertRaises(sqlite3.DatabaseError, msg=sql):
                with self.index.conn:
                    self.index.conn.execute(sql, params)
        self.assertEqual(lp.verify_approved(self.index, ACCT, pid, now=minutes(1)), {})

    def test_triggers_enforce_the_lifecycle(self):
        p = self.make(("CREATE", "Archive"))
        for sql in ("UPDATE label_plan SET state='APPROVED', reviewed_at='t' WHERE plan_id=?", "UPDATE label_plan SET state='REVIEWED' WHERE plan_id=?"):  # no approval / no timestamp
            with self.assertRaises(sqlite3.DatabaseError):
                with self.index.conn:
                    self.index.conn.execute(sql, (p["plan_id"],))
        with self.assertRaises(sqlite3.DatabaseError):  # approval rows exist only for REVIEWED plans
            with self.index.conn:
                self.index.conn.execute("INSERT INTO label_plan_approval VALUES (?,?,?,?,?,?,?,?,?)", (ACCT, p["plan_id"], "n", p["plan_hash"], 1, "t", "t", "VALID", "t"))
        with self.assertRaises(sqlite3.DatabaseError):  # a plan must start as DRAFT, ops only while drafting
            with self.index.conn:
                self.index.conn.execute("INSERT INTO label_plan (account,plan_id,state,plan_hash,inventory_hash,snapshot,op_count,created_at,expires_at,state_changed_at) "
                                        "VALUES (?,?,?,?,?,?,?,?,?,?)", (ACCT, "x", "APPROVED", "a" * 64, "b" * 64, "{}", 1, "t", "t", "t"))
        self.reviewed(p, minutes(1))
        with self.assertRaises(sqlite3.DatabaseError):
            with self.index.conn:
                self.index.conn.execute("INSERT INTO label_plan_op VALUES (?,?,?,?,?,?,?,?,?)", (ACCT, p["plan_id"], 2, "CREATE", "", "", "", "Late", "c" * 64))

    def test_tampered_snapshot_is_detected_even_when_triggers_are_dropped(self):
        a = self.approved()
        pid = a["plan_id"]
        self.drop_triggers()
        snap = json.loads(a["snapshot"])
        snap["ops"][0]["new_name"] = "Evil"
        self.index.conn.execute("UPDATE label_plan SET snapshot=? WHERE plan_id=?", (audit.canonical(snap), pid))
        self.index.conn.commit()
        self.assertEqual(lp.integrity_problems(lp.get_plan(self.index, ACCT, pid)), ["HASH_MISMATCH"])
        self.assertIn("HASH_MISMATCH", lp.verify_approved(self.index, ACCT, pid, now=minutes(1)))

    def test_a_consistently_rewritten_invalid_plan_still_fails_revalidation(self):
        a = self.approved()
        pid = a["plan_id"]
        self.drop_triggers()
        snap = json.loads(a["snapshot"])
        snap["ops"][0]["new_name"] = "Inbox"  # reserved
        text = audit.canonical(snap)
        digest = audit.sha256(text)
        op = snap["ops"][0]
        self.index.conn.execute("UPDATE label_plan SET snapshot=?, plan_hash=? WHERE plan_id=?", (text, digest, pid))
        self.index.conn.execute("UPDATE label_plan_op SET new_name=?, op_digest=? WHERE plan_id=?", ("Inbox", audit.sha256(audit.canonical(op)), pid))
        self.index.conn.commit()
        self.assertEqual(lp.integrity_problems(lp.get_plan(self.index, ACCT, pid)), [])
        self.assertIn("OP_RESERVED_NAME", lp.revalidate(self.index, ACCT, lp.get_plan(self.index, ACCT, pid), now=minutes(1)))

    def test_flags_and_op_table_tampering(self):
        a = self.approved()
        pid = a["plan_id"]
        self.drop_triggers()
        snap = json.loads(a["snapshot"])
        snap["executable"] = True
        text = audit.canonical(snap)
        self.index.conn.execute("UPDATE label_plan SET snapshot=?, plan_hash=? WHERE plan_id=?", (text, audit.sha256(text), pid))
        self.index.conn.commit()
        self.assertIn("FLAGS_TAMPERED", lp.integrity_problems(lp.get_plan(self.index, ACCT, pid)))
        self.index.conn.execute("UPDATE label_plan_op SET new_name='Zed' WHERE plan_id=?", (pid,))
        self.index.conn.commit()
        self.assertIn("OP_TABLE_MISMATCH", lp.integrity_problems(lp.get_plan(self.index, ACCT, pid)))

    def test_snapshot_mutation_in_memory_does_not_change_the_stored_plan(self):
        a = self.approved()
        a["ops"].clear()
        again = lp.get_plan(self.index, ACCT, a["plan_id"])
        self.assertEqual((len(again["ops"]), lp.integrity_problems(again)), (1, []))

    def test_account_confusion_in_verification(self):
        a = self.approved()
        self.assertEqual(lp.revalidate(self.index, OTHER, a, now=minutes(1)), {"ACCOUNT_MISMATCH": 1})
        self.drop_triggers()
        self.index.conn.execute("UPDATE label_plan_approval SET plan_hash=? WHERE plan_id=?", ("0" * 64, a["plan_id"]))
        self.index.conn.commit()
        self.assertIn("APPROVAL_MISMATCH", lp.verify_approved(self.index, ACCT, a["plan_id"], now=minutes(1)))

    def test_verify_approved_needs_the_audit_trail(self):
        a = self.approved()
        self.drop_triggers()
        self.index.conn.execute("DROP TRIGGER cleanup_audit_no_delete")
        self.index.conn.execute("DELETE FROM cleanup_audit WHERE event_type='LABEL_PLAN_APPROVED'")
        self.index.conn.commit()
        self.assertIn("APPROVAL_NOT_IN_AUDIT", lp.verify_approved(self.index, ACCT, a["plan_id"], now=minutes(1)))


class AuditTests(PlanBase):
    def test_label_events_share_the_m4_chain_and_keep_it_valid(self):
        audit.append(self.index, ACCT, "plan-m4m4m4m4", "PLAN_CREATED", T0.strftime("%Y-%m-%dT%H:%M:%SZ"), {"items": 1})
        self.index.conn.commit()
        a = self.approved(now=minutes(1))
        audit.append(self.index, ACCT, "plan-m4m4m4m4", "PLAN_CANCELLED", minutes(5).strftime("%Y-%m-%dT%H:%M:%SZ"), {})
        self.index.conn.commit()
        lp.cancel(self.index, ACCT, a["plan_id"], now=minutes(6))
        ok, n, bad = audit.verify_chain(self.index, ACCT)
        self.assertEqual((ok, bad), (True, None))
        self.assertGreaterEqual(n, 7)
        kinds = [e["event_type"] for e in audit.events(self.index, ACCT, None, 1000)]
        for want in ("LABEL_PLAN_CREATED", "LABEL_PLAN_REVIEWED", "LABEL_PLAN_APPROVED", "LABEL_APPROVAL_REVOKED", "LABEL_PLAN_CANCELLED", "PLAN_CREATED"):
            self.assertIn(want, kinds)

    def test_the_audit_log_holds_no_label_names_or_ids(self):
        self.make(("RENAME", "Label_7", "Renamed" + PRIVATE_LABEL), ("MERGE", "Label_3", "Label_5"))
        p = self.make(("RENAME", "Label_7", "Other"))
        self.reviewed(p, minutes(1))
        with self.assertRaises(PlanError):
            lp.approve(self.index, ACCT, p["plan_id"], "wrong", now=minutes(2))
        dump = json.dumps([dict(r) for r in self.index._q("SELECT * FROM cleanup_audit")])
        for secret in (PRIVATE_LABEL, "Label_7", "Label_3", "Receipts", "Travel"):
            self.assertNotIn(secret, dump)

    def test_tampering_with_a_label_audit_row_breaks_the_chain(self):
        self.approved()
        self.index.conn.execute("DROP TRIGGER cleanup_audit_no_update")
        self.index.conn.execute("UPDATE cleanup_audit SET meta='{\"ops\":99}' WHERE event_type='LABEL_PLAN_CREATED'")
        self.index.conn.commit()
        self.assertFalse(audit.verify_chain(self.index, ACCT)[0])

    def test_the_audit_vocabulary_is_extended_without_removing_m4_events(self):
        for old in ("PLAN_CREATED", "PLAN_APPROVED", "EXECUTION_RESERVED", "UNDO_RESULT", "CANARY_CONFIRMED"):
            self.assertIn(old, audit.EVENTS)
        self.assertEqual(len([e for e in audit.EVENTS if e.startswith("LABEL_")]), 10)
        self.assertEqual(len(audit.EVENTS), len(set(audit.EVENTS)))


class MigrationTests(M5Base):
    def make_v5(self, name="v5"):
        path = self.tmp / name / "index.sqlite3"
        path.parent.mkdir(mode=0o700, parents=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + idx.SCHEMA_V4 + idx.SCHEMA_V5 + "PRAGMA user_version = 5;COMMIT;")
        conn.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", (ACCT, "m1", "t1", 1000, 10, "a@x.example.test", 1, 1))
        conn.execute("INSERT INTO labels VALUES (?,?,?,?)", (ACCT, "Label_1", "Work", "user"))
        shim = SimpleNamespace(conn=conn, _q=lambda sql, *p: conn.execute(sql, p).fetchall())
        audit.append(shim, ACCT, "plan-aaaaaaaa", "PLAN_CREATED", "2026-01-01T00:00:00Z", {"items": 1})
        audit.append(shim, ACCT, "plan-aaaaaaaa", "PLAN_CANCELLED", "2026-01-01T00:01:00Z", {})
        conn.commit()
        self.tables_before = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        return path

    def snapshot_rows(self, path):
        c = sqlite3.connect(path)
        data = {t: c.execute(f"SELECT * FROM {t} ORDER BY 1,2,3").fetchall() for t in ("messages", "labels", "cleanup_audit")}
        c.close()
        return data

    def test_fresh_database_is_v6_with_the_label_plan_tables(self):
        self.assertEqual(idx.SCHEMA_VERSION, 6)
        self.assertEqual(self.index.conn.execute("PRAGMA user_version").fetchone()[0], 6)
        tables = {r[0] for r in self.index._q("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"label_plan", "label_plan_op", "label_plan_approval", "cleanup_plan", "cleanup_audit"} <= tables)
        self.assertGreaterEqual(self.index._q("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'label_plan%'")[0][0], 12)

    def test_v5_to_v6_is_additive_with_a_private_verified_backup(self):
        path = self.make_v5()
        before = self.snapshot_rows(path)
        with idx.Index(str(path)) as index:
            self.assertEqual((index.migrated_from, index.conn.execute("PRAGMA user_version").fetchone()[0]), (5, 6))
            self.assertEqual(index._q("SELECT COUNT(*) FROM label_plan")[0][0], 0)
            ok = audit.verify_chain(index, ACCT)
            self.assertEqual(ok, (True, 2, None))
            backup = Path(index.backup_path)
            now_tables = {r[0] for r in index._q("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("pre-m5-backup", backup.name)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(now_tables - self.tables_before, {"label_plan", "label_plan_op", "label_plan_approval"})
        self.assertEqual(self.snapshot_rows(path), before)  # M4 rows and the audit chain are byte-for-byte preserved
        b = sqlite3.connect(backup)
        self.assertEqual((b.execute("PRAGMA user_version").fetchone()[0], b.execute("PRAGMA quick_check").fetchone()[0]), (5, "ok"))
        self.assertEqual(b.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'label_plan%'").fetchone()[0], 0)
        b.close()

    def test_migration_is_idempotent_and_the_new_chain_extends_the_old_one(self):
        path = self.make_v5()
        with idx.Index(str(path)):
            pass
        with idx.Index(str(path)) as again:
            self.assertIsNone(again.migrated_from)
            self.assertEqual(again.conn.execute("PRAGMA user_version").fetchone()[0], 6)
            self.assertEqual(len(list(path.parent.glob("*backup*"))), 1)
            again.save_labels(ACCT, [label("Label_1", "Work")])
            scan = again.start_scan(ACCT, "full")
            again.finish_scan(scan, "completed")
            plan = lp.create_plan(again, ACCT, [("CREATE", "New")], now=datetime(2026, 1, 2, tzinfo=timezone.utc))
            self.assertEqual(audit.verify_chain(again, ACCT), (True, 3, None))
            self.assertEqual(plan["state"], "DRAFT")

    def test_a_failed_migration_leaves_the_v5_index_unchanged_and_keeps_the_backup(self):
        path = self.make_v5()
        raw = path.read_bytes()
        with mock.patch.object(idx, "SCHEMA_V6", idx.SCHEMA_V6 + "\nSELECT * FROM table_that_does_not_exist;"):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.Index(str(path))
        self.assertIn("left unchanged", str(cm.exception))
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 5)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'label_plan%'").fetchone()[0], 0)  # no partial migration
        self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        c.close()
        self.assertEqual(len(list(path.parent.glob("*pre-m5-backup*"))), 1)
        with idx.Index(str(path)) as retry:  # a later run migrates cleanly
            self.assertEqual(retry.conn.execute("PRAGMA user_version").fetchone()[0], 6)
        del raw

    def test_a_backup_failure_changes_nothing(self):
        path = self.make_v5()
        with mock.patch.object(idx, "_write_backup", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(path))
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 5)
        c.close()
        self.assertEqual(list(path.parent.glob("*backup*")), [])

    def test_a_corrupt_file_is_refused(self):
        path = self.tmp / "bad" / "index.sqlite3"
        path.parent.mkdir(mode=0o700)
        path.write_bytes(b"this is not a sqlite database" * 100)
        with self.assertRaises(idx.IndexProblem):
            idx.Index(str(path))

    def test_future_versions_are_still_refused(self):
        path = self.make_v5("v7")
        c = sqlite3.connect(path)
        c.execute("PRAGMA user_version = 7")
        c.close()
        with self.assertRaises(idx.IndexProblem):
            idx.Index(str(path))


class CliTests(PlanBase):
    def create(self, *args):
        return self.run_cli("labels", "plan", "create", "--account", ACCT, *args)

    def test_full_workflow(self):
        code, out, err = self.create("--create", "Archive", "--rename", "Label_3=Bills")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("LOCAL ONLY — no Gmail changes performed.", out)
        pid = out.split()[2]
        code, out, _ = self.run_cli("labels", "plan", "list", "--account", ACCT)
        self.assertIn(pid, out)
        code, out, _ = self.run_cli("labels", "plan", "show", pid, "--account", ACCT)
        self.assertEqual(code, 0)
        for hidden in (PRIVATE_LABEL, "Receipts", "Bills", "Archive"):
            self.assertNotIn(hidden, out)
        self.assertIn("(name hidden)", out)
        self.assertIn("nothing in this build can execute", out)
        code, out, _ = self.run_cli("labels", "plan", "show", pid, "--account", ACCT, "--show-names")
        self.assertIn('"Bills"', out)
        plan = lp.get_plan(self.index, ACCT, pid)
        code, out, err = self.run_cli("labels", "plan", "review", pid, "--account", ACCT, inputs=[lp.review_phrase(plan)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("REVIEWED", out)
        code, out, err = self.run_cli("labels", "approve", pid, "--account", ACCT, inputs=[lp.approval_phrase(plan)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Nothing was executed and Gmail was not contacted", out)
        code, out, err = self.run_cli("labels", "approve", pid, "--account", ACCT, inputs=[lp.approval_phrase(plan)])
        self.assertEqual(code, 1)
        self.assertIn("already", err)
        code, out, _ = self.run_cli("labels", "plan", "cancel", pid, "--account", ACCT, inputs=["y"])
        self.assertEqual(code, 0)
        self.assertEqual(lp.get_plan(self.index, ACCT, pid)["state"], "CANCELLED")

    def test_wrong_phrase_and_non_terminal_input_are_refused(self):
        _, out, _ = self.create("--create", "Archive")
        pid = out.split()[2]
        code, out, err = self.run_cli("labels", "plan", "review", pid, "--account", ACCT, inputs=["wrong"])
        self.assertEqual(code, 1)
        self.assertIn("did not match", err)
        code, out, err = self.run_cli("labels", "plan", "review", pid, "--account", ACCT, tty=False)  # the real _tty_input refuses piped input
        self.assertEqual(code, 1)
        self.assertIn("interactive terminal", err)
        code, out, err = self.run_cli("labels", "plan", "cancel", pid, "--account", ACCT, inputs=["n"])
        self.assertEqual(code, 1)
        self.assertEqual(lp.get_plan(self.index, ACCT, pid)["state"], "DRAFT")

    def test_friendly_errors(self):
        for args, needle in ((("--rename", "INBOX=x"), "system labels"), (("--create", "Inbox"), "system label"), (("--merge", "Travel=Label_3"), "share this name"),
                             (("--rename", "noequals"), "LABEL=VALUE"), ((), "no operations"), (("--create", "a/b/c/d"), "deeper")):
            code, out, err = self.create(*args)
            self.assertEqual(code, 1, args)
            self.assertIn(needle, err, args)
            self.assertNotIn("Traceback", err)
        code, _, err = self.run_cli("labels", "plan", "show", "lplan-nope", "--account", ACCT)
        self.assertEqual(code, 1)
        self.assertIn("no such label plan", err)

    def test_nothing_in_the_output_names_the_account(self):
        _, out, _ = self.create("--merge", "Label_3=Label_5")
        pid = out.split()[2]
        _, shown, _ = self.run_cli("labels", "plan", "show", pid, "--account", ACCT, "--show-names")
        self.assertNotIn(ACCT, out + shown)
        self.assertIn("IRREVERSIBLE", shown)

    def test_help_text(self):
        for argv in (("labels", "plan", "--help"), ("labels", "plan", "create", "--help"), ("labels", "approve", "--help")):
            code, out, _ = self.run_cli(*argv)
            self.assertEqual(code, 0)
        self.assertIn("--merge", self.run_cli("labels", "plan", "create", "--help")[1])


class BoundaryTests(unittest.TestCase):
    SRC = ROOT / "src" / "gmail_intelligence"

    def imports(self, name):
        mods = set()
        for n in ast.walk(ast.parse((self.SRC / f"{name}.py").read_text())):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
        return mods

    def test_label_plan_modules_import_nothing_live(self):
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "exec_live_mailbox", "exec_fake_mailbox", "cleanup_exec",
                     "cleanup_executor", "cleanup_undo", "cleanup_canary", "http", "urllib", "socket", "ssl", "requests"}
        for name in ("label_plans", "label_plan_report", "label_model", "label_report", "label_suggest", "filter_suggest", "label_hygiene"):
            self.assertEqual(self.imports(name) & forbidden, set(), name)

    def test_there_is_no_execute_path(self):
        tree = ast.parse((self.SRC / "label_plans.py").read_text())
        names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        for n in names:
            self.assertFalse(any(w in n.lower() for w in ("execute", "apply", "run_", "send", "perform", "commit_plan")), n)
        from gmail_intelligence import exec_live_mailbox
        self.assertIs(exec_live_mailbox.LIVE_EXECUTION_ENABLED, False)

    def test_the_cli_label_commands_use_no_write_or_live_module(self):
        src = (self.SRC / "cli.py").read_text()
        block = src[src.index("def _label_plan_cmd"):src.index("def cmd_labels_report")]
        for word in ("exec_live", "oauth_write", "keystore_write", "gmail_write", "_open_reader", "_store(", "_write_store"):
            self.assertNotIn(word, block)

    def test_model_reserved_names_cover_system_labels(self):
        for name in ("INBOX", "Trash", "SPAM", "Category_Updates", "Sent Mail", "Drafts"):
            self.assertTrue(lm.reserved(name), name)


if __name__ == "__main__":
    unittest.main()
