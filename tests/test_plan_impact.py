"""M7B: `cleanup plan impact` - a READ-ONLY explanation of how the current index state affects stored M4 plans. Synthetic data only.

The central promises tested here: it reports every reason a plan has (not just one), keeps a surviving immutable approval distinct from a stale plan, tells apart a
genuinely stale plan from one merely blocked by an unhealthy sync, and changes NOTHING (the report runs on a database opened read-only, and the M4 write helpers
are replaced by bombs while it runs).
"""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest
from datetime import timedelta
from unittest import mock

import test_cleanup_exec as TCE
from test_cleanup import ACCT, msg
from test_cleanup_plans import T0

import m7_support
from fake_history import FakeHistoryMailbox
from sync_support import HERE, SRC, fast_limiter, file_digest, table_digest
from gmail_intelligence import classifier, cleanup_audit as audit, cleanup_plans as cp, cli, config, plan_impact, scanner, sync, sync_health
from gmail_intelligence import index as idx

ALL_TABLES = ("messages", "message_labels", "labels", "scans", "message_class", "sync_state", "sync_run", "message_tombstone", "cleanup_audit", "cleanup_plan",
              "cleanup_item", "cleanup_approval", "cleanup_execution", "cleanup_exec_slice", "cleanup_exec_item", "protect_rules", "class_rules")


class ImpactBase(TCE.ExecBase):
    def setUp(self):
        super().setUp()
        self.mb = FakeHistoryMailbox(ACCT)
        self.mb.hid = 1000                                               # the seeded checkpoint
        for r in self.index._q("SELECT id, thread_id, internal_ms, size, sender FROM messages WHERE account=?", ACCT):
            labels = sorted(x[0] for x in self.index._q("SELECT label_id FROM message_labels WHERE account=? AND message_id=?", ACCT, r["id"]))
            self.mb.msgs[r["id"]] = {"id": r["id"], "thread_id": r["thread_id"], "internal_ms": r["internal_ms"], "size": r["size"], "sender": r["sender"], "label_ids": labels}

    def sync_now(self):
        return sync.run_sync(self.mb, self.index, ACCT, limiter=fast_limiter(), sleep=lambda s: None)

    def impact(self, now=None, account=ACCT):
        ro = idx.ReadOnlyIndex(self.index.path)
        try:
            return plan_impact.impact_report(ro, account, now=now or self.t)
        finally:
            ro.close()

    def entry(self, plan, **kw):
        return next(e for e in self.impact(**kw)["plans"] if e["plan_id"] == plan["plan_id"])

    def approved(self):
        return self.approved_plan()

    def change_sender(self, mid, addr="renamed@shop.example.test"):
        self.mb.msgs[mid]["sender"] = addr
        self.mb._event("labels", mid)

    def reviewed(self):
        plan = cp.create_plan(self.index, ACCT, self.ids[:3], now=self.tick())
        return cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=self.tick())


class ClassificationTests(ImpactBase):
    def test_a_fresh_approved_plan(self):
        plan = self.approved()
        e = self.entry(plan)
        self.assertEqual((e["headline"], e["reasons"], e["passes_every_local_check"], e["evidence"]), ("FRESH", [], True, "OBSERVED_LOCAL_INDEX"))
        self.assertEqual((e["targets"]["unchanged"], e["targets"]["changed"], e["targets"]["absent_from_index"]), (3, 0, 0))
        self.assertEqual(e["approval_rows"], {"VALID": 1, "CONSUMED": 0, "REVOKED": 0, "EXPIRED": 0})

    def test_a_changed_target_makes_the_plan_stale_but_the_immutable_approval_survives(self):
        plan = self.approved()
        self.change_sender(self.ids[0])                                           # a change that leaves the message eligible: exactly one reason
        self.sync_now()
        e = self.entry(plan)
        self.assertEqual((e["headline"], e["reasons"]), ("STALE", ["TARGET_CHANGED", "CLASSIFICATION_NOT_CURRENT"]))   # changed AND no longer classified as of the new state
        self.assertEqual(e["codes"], {"ITEM_CHANGED": 1, "ITEM_NOT_ELIGIBLE": 1, "REASON_CLASSIFICATION_STALE": 1})
        t = e["targets"]
        self.assertEqual((t["changed"], t["unchanged"], t["changed_by_field"]["sender"]), (1, 2, 1))
        self.assertEqual(e["approval_rows"]["VALID"], 1)                         # the approval row is still there, untouched ...
        self.assertTrue(e["approval_rows_are_retained"])
        self.assertFalse(e["passes_every_local_check"])                          # ... but nothing may rely on it any more
        text = plan_impact.impact_text(self.impact())
        self.assertIn("immutable", text)
        self.assertIn("can no longer authorize anything", text)
        self.assertNotRegex(text.lower(), r"approval[^.\n]*(deleted|removed|revoked)")
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_field_level_evidence_distinguishes_what_changed(self):
        plan = self.approved()
        self.mb.labels_change(self.ids[0], add=("UNREAD",))                      # read state AND labels
        self.mb.msgs[self.ids[1]]["sender"] = "other@sender.example.test"
        self.mb._event("labels", self.ids[1])
        self.sync_now()
        e = self.entry(plan)
        f = e["targets"]["changed_by_field"]
        self.assertEqual((f["labels"], f["read_state"], f["sender"], f["rescan_stamp_only"]), (1, 1, 1, 0))
        self.assertIn("TARGET_CHANGED", e["reasons"])

    def test_a_full_rescan_changes_the_anchor_and_re_stamps_every_target(self):
        plan = self.approved()
        later = lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc) + timedelta(hours=1)   # the anchor keeps second resolution
        row = scanner.run_scan(self.mb, self.index, ACCT, mode="full", limiter=fast_limiter(), sleep=lambda s: None, clock=later, page_size=3)
        self.assertEqual(row["status"], "completed")
        e = self.entry(plan)
        self.assertEqual(e["headline"], "STALE")
        self.assertIn("ANCHOR_CHANGED_BY_FULL_SCAN", e["reasons"])
        self.assertEqual(e["targets"]["changed_by_field"]["rescan_stamp_only"], 3)    # nothing about the messages differs: only the scan stamp
        self.assertEqual(e["approval_rows"]["VALID"], 1)

    def test_a_deleted_target_is_told_apart_by_the_recorded_reason(self):
        plan = self.approved()
        self.mb.delete(self.ids[0])
        self.sync_now()
        with self.index.conn:                                                    # another target vanished without any recorded cause
            self.index.conn.execute("DELETE FROM message_labels WHERE message_id=?", (self.ids[1],))
            self.index.conn.execute("DELETE FROM messages WHERE id=?", (self.ids[1],))
        e = self.entry(plan)
        self.assertIn("TARGET_DELETED_OR_ABSENT", e["reasons"])
        self.assertEqual(e["targets"]["absent_by_recorded_reason"], {"HISTORY_DELETED": 1, "NO_TOMBSTONE": 1})
        self.assertEqual(e["targets"]["absent_from_index"], 2)
        self.assertEqual(e["approval_rows"]["VALID"], 1)

    def test_rule_and_eligibility_changes_are_their_own_reason(self):
        plan = self.approved()
        classifier.add_rule(self.index, ACCT, kind="type", value="PERSONAL", confidence="HIGH", priority=0, domain="shop.example.test")
        e = self.entry(plan)
        self.assertEqual(e["reasons"], ["CLASSIFICATION_NOT_CURRENT"])
        self.assertIn("CLASSIFICATION_RULES_CHANGED", e["codes"])
        self.mb.labels_change(self.ids[2], add=("STARRED",))
        self.sync_now()
        e = self.entry(plan)
        self.assertIn("TARGET_CHANGED", e["reasons"])                                                       # several reasons at once, none hidden
        self.assertIn("CLASSIFICATION_NOT_CURRENT", e["reasons"])
        self.assertGreaterEqual(len(e["reasons"]), 3)
        self.assertIn("ELIGIBILITY_OR_RULES_CHANGED", e["reasons"])                                         # a starred message is no longer an eligible candidate

    def test_an_unhealthy_sync_blocks_a_fresh_plan_without_calling_it_stale(self):
        plan = self.approved()
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='INTERRUPTED', reason='API_QUOTA'")
        rep = self.impact()
        e = next(p for p in rep["plans"] if p["plan_id"] == plan["plan_id"])
        self.assertEqual((e["headline"], e["reasons"], e["evidence"]), ("BLOCKED_BY_SYNC", ["SYNC_NOT_HEALTHY"], "UNCERTAIN_INDEX"))
        self.assertEqual((rep["sync_health"]["healthy"], rep["sync_health"]["codes"]), (False, ["SYNC_INTERRUPTED"]))
        self.assertIn("uncertain freshness", plan_impact.impact_text(rep))

    def test_a_genuinely_stale_plan_is_not_hidden_behind_an_unhealthy_sync(self):
        plan = self.approved()
        self.change_sender(self.ids[0])
        self.sync_now()
        with self.index.conn:
            self.index.conn.execute("UPDATE sync_state SET status='NEEDS_RECONCILE', reason='HISTORY_EXPIRED'")
        e = self.entry(plan)
        self.assertEqual(e["headline"], "STALE_AND_BLOCKED")
        self.assertEqual(sorted(e["reasons"]), ["CLASSIFICATION_NOT_CURRENT", "SYNC_NOT_HEALTHY", "TARGET_CHANGED"])
        self.assertEqual(e["evidence"], "UNCERTAIN_INDEX")

    def test_an_incomplete_full_scan_blocks_rather_than_staling(self):
        plan = self.approved()
        with self.index.conn:
            self.index.conn.execute("INSERT INTO scans (account, mode, status, started_at) VALUES (?, 'full', 'interrupted', '2027-01-15T07:00:00Z')", (ACCT,))
            self.index.conn.execute("UPDATE sync_state SET status='INTERRUPTED', reason='FULL_SCAN_INTERRUPTED'")
        e = self.entry(plan)
        self.assertEqual(e["headline"], "BLOCKED_BY_SYNC")
        self.assertIn("INDEX_INCOMPLETE", e["reasons"])
        self.assertIn("SYNC_NOT_HEALTHY", e["reasons"])

    def test_an_overdue_plan_is_reported_as_expired_without_recording_the_expiry(self):
        plan = self.reviewed()
        events = self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0]
        e = self.entry(plan, now=self.t + timedelta(hours=60))
        self.assertEqual((e["headline"], e["state"], e["expiry_not_yet_recorded"]), ("EXPIRED", "REVIEWED", True))
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "REVIEWED")                 # still stored as it was
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0], events)                    # no PLAN_EXPIRED event was appended
        self.assertIn("this report does not record it", plan_impact.impact_text(self.impact(now=self.t + timedelta(hours=60))))

    def test_an_approval_past_its_term_is_a_non_executable_approval_not_a_stale_plan(self):
        plan = self.approved()
        e = self.entry(plan, now=self.t + timedelta(hours=26))
        self.assertEqual((e["headline"], e["reasons"]), ("NOT_EXECUTABLE_APPROVAL", ["APPROVAL_NOT_USABLE"]))
        self.assertEqual(e["approval_rows"]["VALID"], 1)

    def test_closed_plans_are_listed_but_not_re_checked(self):
        plan = self.reviewed()
        cp.cancel(self.index, ACCT, plan["plan_id"], now=self.tick())
        rep = self.impact()
        self.assertEqual(rep["plans"], [])
        self.assertEqual(rep["closed_plans"], [{"plan_id": plan["plan_id"], "state": "CANCELLED"}])
        self.assertEqual(rep["plans_by_headline"], {"NON_EXECUTABLE": 1})

    def test_a_stored_plan_that_fails_its_integrity_check_is_reported_as_inconsistent(self):
        plan = self.reviewed()
        with self.index.conn:
            self.index.conn.execute("DROP TRIGGER cleanup_item_no_delete")
            self.index.conn.execute("DELETE FROM cleanup_item WHERE plan_id=? AND message_id=?", (plan["plan_id"], self.ids[0]))
        e = self.entry(plan)
        self.assertEqual(e["headline"], "STORED_PLAN_INCONSISTENT")
        self.assertNotIn("targets", e)

    def test_other_accounts_are_never_mixed_in(self):
        plan = self.approved()
        self.assertEqual(self.impact(account=OTHER_ACCT)["plans_total"], 0)
        self.assertEqual(self.impact()["plans_total"], 1)
        self.assertEqual(self.entry(plan)["items"], 3)


OTHER_ACCT = "other@example.invalid"


class ReadOnlyGuaranteeTests(ImpactBase):
    def test_nothing_is_written_not_one_table_not_one_byte(self):
        plan = self.approved()
        self.reviewed()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.sync_now()
        before, digest, mtime = table_digest(self.index, ALL_TABLES), file_digest(self.index.path), os.stat(self.index.path).st_mtime_ns
        for _ in range(2):
            self.impact(now=self.t + timedelta(hours=60))                 # also with every plan overdue (the case where expiry WOULD be written by a normal command)
        self.assertEqual((before, digest, mtime), (table_digest(self.index, ALL_TABLES), file_digest(self.index.path), os.stat(self.index.path).st_mtime_ns))
        self.assertEqual(self.approval_status(plan["plan_id"]), ["VALID"])

    def test_the_m4_write_helpers_are_never_reached(self):
        plan = self.approved()
        bomb = mock.Mock(side_effect=AssertionError("a write helper was called by a read-only report"))
        with mock.patch.object(cp, "expire_due", bomb), mock.patch.object(cp, "_txn", bomb), mock.patch.object(cp, "_reject", bomb), \
                mock.patch.object(cp, "_set_state", bomb), mock.patch.object(cp, "_close_approvals", bomb), mock.patch.object(audit, "append", bomb):
            rep = self.impact(now=self.t + timedelta(hours=60))
            plan_impact.impact_text(rep)
        bomb.assert_not_called()

    def test_it_creates_no_audit_event_and_no_lockout_count(self):
        plan = self.reviewed()
        events = self.index._q("SELECT event_type FROM cleanup_audit ORDER BY seq")
        for _ in range(cp.MAX_FAILED_ATTEMPTS + 2):
            self.impact(now=self.t + timedelta(hours=60))
        self.assertEqual(events, self.index._q("SELECT event_type FROM cleanup_audit ORDER BY seq"))
        self.assertEqual(audit.recent(self.index, ACCT, plan["plan_id"], ("APPROVAL_REJECTED", "REVIEW_REJECTED", "RESERVATION_REJECTED"), "1970-01-01T00:00:00Z"), 0)
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=self.tick())            # an ordinary approval still works afterwards

    def test_the_report_does_not_open_the_database_for_writing(self):
        self.approved()
        with mock.patch.object(idx.Index, "__init__", side_effect=AssertionError("the writable Index class must not be used")):
            ro = idx.ReadOnlyIndex(self.index.path)                       # ReadOnlyIndex has its own constructor
            plan_impact.impact_report(ro, ACCT, now=self.t)
            ro.close()
        ro = idx.ReadOnlyIndex(self.index.path)
        try:
            with self.assertRaises(Exception):
                ro.conn.execute("UPDATE cleanup_plan SET state='CANCELLED'")
        finally:
            ro.close()


class PrivacyAndCliTests(ImpactBase):
    def run_cli(self, argv):
        store = mock.Mock()
        store.load.return_value = {"account": ACCT}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_store", return_value=store), mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail must not be touched")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_default_output_is_aggregate_only(self):
        plan = self.approved()
        self.mb.labels_change(self.ids[0], add=("STARRED",))
        self.mb.delete(self.ids[1])
        self.sync_now()
        rep = self.impact()
        text, raw = plan_impact.impact_text(rep), json.dumps(rep, sort_keys=True)
        for blob in (text, raw):
            for needle in ("owner@example", "shop.example", "Receipts", "m1", "m2", "m3", "m4", "m5", str(self.tmp), str(self.index.path), "snapshot", "plan_hash"):
                self.assertNotIn(needle, blob, needle)
            self.assertIsNone(re.search(r"[0-9a-f]{32,}", blob))
            self.assertIsNone(re.search(r"\bm\d+\b", blob))

    def test_cli_text_and_json_read_only_and_without_gmail(self):
        self.approved()
        before = file_digest(self.index.path)
        code, text, err = self.run_cli(["cleanup", "plan", "impact"])
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)
        self.assertIn("Cleanup plan impact", text)
        code, raw, err = self.run_cli(["cleanup", "plan", "impact", "--json"])
        data = json.loads(raw)
        self.assertEqual((code, data["read_only"], data["gmail_contacted"], data["section"]), (0, True, False, "plan-impact"))
        self.assertEqual(before, file_digest(self.index.path))

    def test_an_old_schema_is_refused_without_changes(self):
        self.approved()
        self.index.close()
        import sqlite3
        c = sqlite3.connect(self.index.path)
        for t in ("sync_state", "sync_run", "message_tombstone"):
            c.execute(f"DROP TABLE {t}")
        c.execute("PRAGMA user_version = 6")
        c.commit()
        c.close()
        before = file_digest(self.index.path)
        code, out, err = self.run_cli(["cleanup", "plan", "impact"])
        self.assertEqual(code, 1)
        self.assertIn("index upgrade", err)
        self.assertEqual(before, file_digest(self.index.path))
        self.index = idx.Index(self.index.path, allow_upgrade=True)
        self.addCleanup(self.index.close)  # the cleanup registered by the base class closes the OLD object


class DeterminismTests(unittest.TestCase):
    def test_the_report_is_identical_under_different_hash_seeds(self):
        digests = set()
        for seed in ("0", "1", "42", "1234"):
            proc = subprocess.run([sys.executable, "-I", str(HERE / "impact_digest.py")], capture_output=True, text=True, timeout=120,
                                  env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")})
            self.assertEqual(proc.returncode, 0, proc.stderr)
            digests.add(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(len(digests), 1)


if __name__ == "__main__":
    unittest.main()
