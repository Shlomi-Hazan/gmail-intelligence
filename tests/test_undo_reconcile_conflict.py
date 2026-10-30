"""M12C.2: the two undo behaviors the M4D suite does not exercise: reconciling an uncertain undo when Gmail now shows a CONFLICTING label set or a vanished message, and the append-only
guarantee across a whole undo + reconciliation. Fake mailbox only; nothing contacts Gmail, nothing here changes the undo engine or any policy."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT  # noqa: E402
from test_cleanup_executor import LABELS  # noqa: E402
from test_cleanup_recovery import Step, UndoBase  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_undo as cu  # noqa: E402


class ReconcileConflictTests(UndoBase):
    def unknown_undo(self):
        """An undo whose mutation was applied but whose independent post-read failed: UNKNOWN, one mutation, authorization used up."""
        ex, mb = self.archived()
        self.authorize(ex, 1)
        um = self.umb(mb, [Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        res = self.undo(ex, um, 1)
        self.assertEqual((res.status, res.mutations, um.service.undos()), ("UNKNOWN", 1, 1))
        um.service.script.clear()
        return ex, um

    def rows(self):
        return [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")]

    def test_conflicting_labels_found_at_reconciliation_end_in_a_final_conflict_without_any_second_mutation(self):
        ex, um = self.unknown_undo()
        um.service.set_labels(self.mid(1), list(LABELS) + ["STARRED"])        # someone else changed the message after the undo
        before = self.rows()
        res = cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)
        self.assertEqual((res.status, res.mutations, um.service.undos()), ("CONFLICT", 0, 1))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "CONFLICT")
        self.assertEqual(self.rows()[:len(before)], before)                    # append-only: every earlier audit row is byte-identical
        self.assertEqual(len(self.rows()), len(before) + 1)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])
        for call in (lambda: self.undo(ex, um, 1), lambda: self.authorize(ex, 1), lambda: cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)):
            with self.assertRaises(ce.ExecError):                                # CONFLICT is final: no retry, no new authorization, nothing left to reconcile
                call()
        self.assertEqual(um.service.undos(), 1)
        self.assertEqual(cu.open_undos(self.index, ACCT), [])                    # a final conflict is recorded, not an open undo

    def test_a_vanished_message_is_a_final_conflict_never_a_guess(self):
        ex, um = self.unknown_undo()
        um.service.remove_message(self.mid(1))
        res = cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)          # an authoritative "absent" observation: neither restored nor unmodified
        self.assertEqual((res.status, res.mutations, um.service.undos()), ("CONFLICT", 0, 1))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "CONFLICT")
        with self.assertRaises(ce.ExecError):
            self.authorize(ex, 1)

    def test_no_usable_observation_keeps_unknown_as_unknown(self):
        ex, um = self.unknown_undo()
        um.service.script[:] = [Step("GET_MESSAGE", nth=um.service.counts["GET_MESSAGE"] + 1, status=503, body=b"x")]
        with self.assertRaises(ce.ExecError) as ctx:
            cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)
        self.assertEqual(ctx.exception.code, "NO_EVIDENCE")
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "UNKNOWN")   # ambiguity is never resolved by a guess
        self.assertEqual(cu.open_undos(self.index, ACCT), [(ex["exec_id"], 1, "UNKNOWN")])
        self.assertEqual(um.service.undos(), 1)

    def test_the_archive_history_and_earlier_audit_rows_survive_undo_and_reconciliation_unchanged(self):
        ex, mb = self.archived()
        history, rows = self.history(), self.rows()
        self.authorize(ex, 1)
        um = self.umb(mb, [Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        self.undo(ex, um, 1)
        um.service.script.clear()
        cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, um)
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "RESTORED")
        self.assertEqual(self.history(), history)
        self.assertEqual(self.rows()[:len(rows)], rows)
        self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT", "UNDO_RESULT"])  # the UNKNOWN result is kept, not rewritten
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


if __name__ == "__main__":
    unittest.main()
