"""M12C.1: the local, read-only execution recovery status (`cleanup exec recovery`, issue #61; coordinates with #41). Synthetic data only: the executions are produced by the existing fake
mailbox and executor test infrastructure, nothing contacts Gmail, and the status step itself never gets a mailbox at all.

What is proved: known / UNKNOWN / manual-review are reported honestly, ambiguity stays UNKNOWN, nothing is retried, resumed or written, output is privacy-safe and stable, and the CLI cannot reach
the recovery/undo engine."""
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import unittest
from datetime import datetime as dt, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_executor import AFTER, HEX, THREADS  # noqa: E402
from test_cleanup_recovery import RecoveryBase, Step  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_exec_report as rep, cleanup_recovery as cr, cli  # noqa: E402


class Base(RecoveryBase):
    def at(self):
        return self.step_clock.at + ce.LEASE_TTL + timedelta(seconds=11) if hasattr(self, "step_clock") else dt(2000, 1, 1, tzinfo=timezone.utc)

    def data(self, now=None):
        return rep.recovery_data(self.index, ACCT, now or self.at())

    def only(self, now=None):
        (e,) = self.data(now)["executions"]
        return e

    def run_cmd(self, *argv):
        from datetime import datetime
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = self.at()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(rep, "datetime", fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")):
            try:
                code = cli.main(["cleanup", "exec", "recovery", "--account", ACCT, *argv])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


class StatusTests(Base):
    def test_an_interrupted_execution_is_reported_as_unknown_and_needing_the_owner_without_being_touched(self):
        ex, mb = self.crashed_batch()
        before = self.snapshot()
        d = self.data()
        e = self.only()
        self.assertEqual((e["exec_id"], e["state"], d["needs_owner"]), (ex["exec_id"], "EXECUTING", True))
        self.assertEqual((e["unknown"], e["items_needing_owner"]), (1, [2]))
        self.assertEqual((e["known_applied"], e["known_not_applied"], e["pending"]), (1, 0, 2))
        self.assertTrue(any("lease has expired" in n for n in e["notes"]))
        self.assertFalse(any(n.startswith("in progress") for n in e["notes"]))
        self.assertEqual(self.snapshot(), before)                     # nothing was recovered, retried or written
        self.assertEqual(self.exec_state(ex["exec_id"]), "EXECUTING")
        self.assertEqual(self.item(self.mid(2))["state"], "INTENT")   # not even the local recovery transition was made

    def test_a_live_lease_is_in_progress_not_interrupted(self):
        ex = self.batch_execution()
        e = self.only(dt(2000, 1, 1, tzinfo=timezone.utc))  # long before the lease expires
        self.assertTrue(any(n.startswith("in progress") for n in e["notes"]))
        self.assertFalse(any("lease has expired" in n for n in e["notes"]))

    def test_ambiguity_stays_unknown_after_a_failed_observation(self):
        ex, mb = self.crashed_batch()
        cr.recover(self.index, ACCT, self.umb(mb, [Step("GET_MESSAGE", raises=TimeoutError())]))   # the (fake-only) library step; the status step has no mailbox
        before = self.snapshot()
        e = self.only()
        self.assertEqual((e["state"], e["unknown"], e["manual_review"], e["items_needing_owner"]), ("RECONCILIATION_REQUIRED", 1, 0, [2]))
        self.assertTrue(self.data()["needs_owner"])
        self.assertEqual(self.snapshot(), before)

    def test_a_conflicting_observation_is_manual_review(self):
        ex, mb = self.crashed_batch()
        cr.recover(self.index, ACCT, self.umb(mb, [Step("GET_MESSAGE", before=lambda f: f.set_labels(self.mid(2), list(AFTER) + ["STARRED"]))]))
        e = self.only()
        self.assertEqual((e["manual_review"], e["unknown"], e["items_needing_owner"]), (1, 0, [2]))
        self.assertTrue(self.data()["needs_owner"])

    def test_a_reconciled_execution_no_longer_needs_the_owner(self):
        ex, mb = self.crashed_batch()
        cr.recover(self.index, ACCT, self.umb(mb))
        d = self.data()
        self.assertFalse(d["needs_owner"])
        self.assertEqual(d["executions"], [])        # settled and nothing unknown: not listed
        self.assertIn("no open or uncertain executions", rep.recovery_text(d))

    def test_no_executions_and_other_accounts_are_empty_and_isolated(self):
        self.assertEqual(rep.recovery_data(self.index, OTHER, self.at())["executions"], [])
        self.crashed_batch()
        d = rep.recovery_data(self.index, OTHER, self.at())
        self.assertEqual((d["executions"], d["needs_owner"]), ([], False))

    def test_results_are_stable_and_the_audit_history_is_untouched(self):
        self.crashed_batch()
        head = audit.head(self.index, ACCT)
        events = [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")]
        first = json.dumps(self.data(), sort_keys=True)
        self.assertEqual(first, json.dumps(self.data(), sort_keys=True))
        self.assertEqual(audit.head(self.index, ACCT), head)
        self.assertEqual([tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")], events)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class OpenWithoutUnknownTests(Base):
    """A PREPARED or AWAITING_CONTINUATION execution has no UNKNOWN item, yet it is open: the report must not suggest it is settled."""

    def check(self, state, ex):
        d = self.data(dt(2000, 1, 1, tzinfo=timezone.utc))
        (e,) = d["executions"]
        self.assertEqual((e["state"], e["unknown"], e["manual_review"], d["needs_owner"]), (state, 0, 0, True))
        text = rep.recovery_text(d)
        self.assertIn("not settled", text)
        self.assertIn("OWNER ACTION REQUIRED", text)
        self.assertNotIn("nothing needs the owner", text)

    def test_a_prepared_execution_is_open_and_not_settled(self):
        ex = self.reserve(self.approved_plan([self.mid(1)]))
        self.assertEqual(ex["state"], "PREPARED")
        self.check("PREPARED", ex)

    def test_an_execution_awaiting_continuation_is_open_and_not_settled(self):
        import test_cleanup_batch as tb
        from gmail_intelligence import cleanup_executor as cx, exec_fake_mailbox as fm
        from test_cleanup_executor import LABELS
        ids = [f"18c0ffee{i:08x}" for i in range(1, 102)]
        with mock.patch.object(type(self), "messages", create=True, new=lambda self_: [dict(tb.msg(i, sender=f"s{i}@shop.example.test"), id=f"18c0ffee{i:08x}", thread_id=f"28c0ffee{i:08x}") for i in range(1, 102)]):
            self.setUp()
            plan = self.approved_plan(ids)
            ex = self.reserve(plan)
            token = ce.start_slice(self.index, ACCT, ex["exec_id"], 1, now=self.tick())
            mb = fm.FakeMailbox(ACCT, {m: (f"28c0ffee{m[-8:]}", list(LABELS)) for m in ids}, clock=self.clock(), script=())
            self.assertEqual(cx.execute_batch(self.index, ACCT, ex["exec_id"], token, mb).execution_state, "AWAITING_CONTINUATION")
        self.check("AWAITING_CONTINUATION", ex)

    def test_an_execution_in_progress_with_a_live_lease_is_not_called_settled_either(self):
        self.batch_execution()
        d = self.data(dt(2000, 1, 1, tzinfo=timezone.utc))
        text = rep.recovery_text(d)
        self.assertFalse(d["needs_owner"])
        self.assertNotIn("nothing needs the owner", text)
        self.assertIn("remain (see above)", text)


class CommandTests(Base):
    def test_the_command_is_read_only_prints_nothing_private_and_matches_the_library(self):
        ex, mb = self.crashed_batch()
        db = Path(self.index.path)
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        names = sorted(os.listdir(db.parent))
        code, out, err = self.run_cmd()
        self.assertEqual((code, err), (0, ""))
        self.assertIn("UNKNOWN: 1", out)
        self.assertIn("items needing the owner: 2", out)
        self.assertIn("OWNER ACTION REQUIRED", out)
        self.assertIn("Gmail was not contacted and nothing was retried", out)
        code, js, err = self.run_cmd("--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(js), self.data())
        for private in (ACCT, OTHER, "example", "CATEGORY_PROMOTIONS", "INBOX", *HEX, *THREADS, ex["plan_id"]):
            self.assertNotIn(private, out + js)
        self.assertIn(ex["exec_id"], out)   # local execution ids may appear; message ids, the account address and labels never do
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(db.parent)), names)
        self.assertEqual(self.item(self.mid(2))["state"], "INTENT")

    def test_the_cli_cannot_reach_the_recovery_or_undo_engine_or_any_mailbox(self):
        cli_src = (ROOT / "src" / "gmail_intelligence" / "cli.py").read_text()
        for name in ("cleanup_undo", "cleanup_recovery", "reconcile_undo", "recover(", "FakeMailbox", "restore_inbox"):
            self.assertNotIn(name, cli_src)
        src = (ROOT / "src" / "gmail_intelligence" / "cleanup_exec_report.py").read_text()
        self.assertEqual(set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.M)), {"json", "dataclasses", "datetime", "gmail_intelligence"})
        code = "\n".join(l for l in src.split("# ---------------------------------------------------------------- M12C.1", 1)[1].splitlines() if not l.lstrip().startswith("#"))  # the M12C.1 section, without comments
        self.assertIsNone(re.search(r"cleanup_(undo|recovery|executor|live)|gmail_write|socket|urllib|http|INSERT|UPDATE |DELETE |\.recover\b|reconcile_|observe\(", code))
        # the moved helpers are the same objects the recovery engine uses: one implementation
        self.assertIs(cr._execution_report, rep._execution_report)
        self.assertIs(cr.ExecutionReport, rep.ExecutionReport)


if __name__ == "__main__":
    unittest.main()
