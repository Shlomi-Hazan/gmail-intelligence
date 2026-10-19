"""M5A: label hygiene analysis and report (issue #12). Synthetic fixtures only; no Gmail, no network, nothing is ever changed."""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, OTHER, M5Base, label, mail  # noqa: E402

from gmail_intelligence import label_hygiene as lh, label_model as lm, label_report  # noqa: E402


def codes(h, code=None):
    return [(f.code, f.variant, f.labels, f.confidence) for f in h.findings if code is None or f.code == code]


class ModelTests(unittest.TestCase):
    def test_normalization_is_small_and_documented(self):
        self.assertEqual(lm.normalize("  Work  /  Plans "), "work/plans")
        self.assertEqual(lm.normalize("Ｗork"), "work")  # NFKC: fullwidth letters
        self.assertEqual(lm.normalize("STRASSE"), lm.normalize("strasse"))
        self.assertNotEqual(lm.normalize("Café"), lm.normalize("Cafe"))  # accents are never folded away
        self.assertNotEqual(lm.normalize("Invoice"), lm.normalize("Invoices"))  # nor plurals
        self.assertEqual(lm.normalize_loose("Work-Plans_2.0"), "work plans 2 0")
        self.assertEqual(lm.normalize(""), "")

    def test_name_problems(self):
        for name, problem in (("", "EMPTY_NAME"), ("   ", "EMPTY_NAME"), ("a//b", "EMPTY_SEGMENT"), ("/a", "EMPTY_SEGMENT"), ("a/", "EMPTY_SEGMENT"), (" a", "OUTER_SPACE"),
                              ("a /b", "SEGMENT_SPACE"), ("a\x07b", "CONTROL_CHARACTER"), ("x" * 300, "TOO_LONG"), ("é", "NOT_NFC")):
            self.assertEqual(lm.name_problem(name), problem, name)
        self.assertIsNone(lm.name_problem("Work/Plans 2026"))
        self.assertIsNone(lm.name_problem("Updates"))  # a user label may legitimately be called this; only PLANS refuse reserved names
        self.assertTrue(lm.reserved("inbox") and lm.reserved("Sent Mail") and lm.reserved("CATEGORY_SOCIAL") and lm.reserved("Inbox/Child"))
        self.assertFalse(lm.reserved("Work"))

    def test_bounded_edit_distance(self):
        self.assertTrue(lm.edit_distance_within("invoices", "invoice"))
        self.assertTrue(lm.edit_distance_within("statement", "statemnet"))  # one transposition
        self.assertFalse(lm.edit_distance_within("statement", "statements!!"))
        self.assertFalse(lm.edit_distance_within("abcdef", "abcxyz"))
        self.assertTrue(lm.edit_distance_within("same", "same"))

    def test_label_kinds_and_repr_do_not_leak_names(self):
        self.assertTrue(lm.Label("INBOX", "INBOX", "system").system)
        self.assertTrue(lm.Label("CATEGORY_PROMOTIONS", "x", None).system)
        self.assertTrue(lm.Label("Label_1", "x", "user").user)
        self.assertTrue(lm.Label("Label_2", "x", None).user)
        self.assertFalse(lm.Label("Label_3", "x", "system").user)
        self.assertNotIn("SecretName", repr(lm.Label("Label_1", "SecretName", "user")))


class HygieneTests(M5Base):
    def analyze(self, labels, messages=(), complete=True, **kw):
        self.fixture(labels, messages, complete, **kw)
        return lh.analyze(self.index, ACCT)

    def test_exact_duplicates(self):
        h = self.analyze([label("Label_1", "Receipts"), label("Label_2", "Receipts"), label("Label_3", "Other")], [mail(1, ["INBOX", "Label_1", "Label_2", "Label_3"])])
        self.assertEqual(codes(h, "EXACT_DUPLICATE"), [("EXACT_DUPLICATE", "", ("Label_1", "Label_2"), "HIGH")])
        self.assertEqual(codes(h, "NEAR_DUPLICATE"), [])

    def test_near_duplicates_by_normalization_punctuation_and_edit_distance(self):
        used = ["INBOX"] + [f"Label_{i}" for i in range(1, 12)]
        h = self.analyze([label("Label_1", "Work Plans"), label("Label_2", "work  plans"), label("Label_3", "Project-Alpha"), label("Label_4", "Project_Alpha"),
                          label("Label_5", "Statement"), label("Label_6", "Statements"), label("Label_7", "Bills"), label("Label_8", "Bill"),
                          label("Label_9", "Cafe Menu"), label("Label_10", "Café Menu"), label("Label_11", "Alpha/Statement")], [mail(1, used)])
        near = codes(h, "NEAR_DUPLICATE")
        self.assertIn(("NEAR_DUPLICATE", "NORMALIZED", ("Label_1", "Label_2"), "HIGH"), near)
        self.assertIn(("NEAR_DUPLICATE", "PUNCTUATION", ("Label_3", "Label_4"), "MEDIUM"), near)
        self.assertIn(("NEAR_DUPLICATE", "SIMILAR", ("Label_5", "Label_6"), "LOW"), near)
        flagged = {i for n in near for i in n[2]}
        self.assertFalse(flagged & {"Label_7", "Label_8"})  # short names produce no edit-distance noise
        self.assertIn(("NEAR_DUPLICATE", "SIMILAR", ("Label_10", "Label_9"), "LOW"), near)  # accents are not folded: only a LOW near-miss, never a HIGH duplicate
        self.assertFalse(flagged & {"Label_11"})  # the same leaf under another parent is not a duplicate
        self.assertEqual(len(near), 4)

    def test_unicode_edge_cases(self):
        h = self.analyze([label("Label_1", "Résume"), label("Label_2", "Résuméx"), label("Label_3", "ＡＢＣ"), label("Label_4", "abc")], [mail(1, ["INBOX", "Label_1", "Label_2", "Label_3", "Label_4"])])
        self.assertIn(("NEAR_DUPLICATE", "NORMALIZED", ("Label_3", "Label_4"), "HIGH"), codes(h, "NEAR_DUPLICATE"))  # NFKC: fullwidth ABC equals abc
        self.assertEqual([c for c in codes(h, "INVALID_NAME")], [("INVALID_NAME", "", ("Label_1",), "HIGH")])  # decomposed text is not NFC

    def test_invalid_and_empty_names(self):
        h = self.analyze([label("Label_1", ""), label("Label_2", "A//B"), label("Label_3", "/Lead"), label("Label_4", "Trail/"), label("Label_5", "Fine")], [mail(1, ["INBOX", "Label_5"])])
        self.assertEqual(sorted(c[2] for c in codes(h, "INVALID_NAME")), [("Label_1",), ("Label_2",), ("Label_3",), ("Label_4",)])

    def test_unused_labels_are_claimed_only_against_a_complete_index(self):
        labs = [label("Label_1", "Used"), label("Label_2", "Idle")]
        msgs = [mail(1, ["INBOX", "Label_1"])]
        h = self.analyze(labs, msgs, complete=True)
        self.assertEqual(codes(h, "UNUSED"), [("UNUSED", "", ("Label_2",), "MEDIUM")])
        self.assertEqual(codes(h, "UNUSED_UNCERTAIN"), [])
        self.setUp()
        h = self.analyze(labs, msgs, complete=False)
        self.assertEqual(codes(h, "UNUSED"), [])
        self.assertEqual(codes(h, "UNUSED_UNCERTAIN"), [("UNUSED_UNCERTAIN", "", ("Label_2",), "LOW")])
        self.assertEqual(h.index_state, "partial")
        self.assertIn("says nothing about the mailbox", h.findings[0].reason)

    def test_an_empty_index_judges_nothing_unused(self):
        h = self.analyze([label("Label_1", "Idle")], [], complete=True)
        self.assertEqual((h.messages_indexed, codes(h, "UNUSED"), codes(h, "UNUSED_UNCERTAIN")), (0, [], []))
        self.assertIn("holds no messages", label_report.hygiene_text(self.index, ACCT, h))

    def test_a_container_label_with_used_children_is_not_unused(self):
        h = self.analyze([label("Label_1", "Work"), label("Label_2", "Work/Plans"), label("Label_3", "Work/Empty")], [mail(1, ["INBOX", "Label_2"])])
        self.assertEqual([c[2] for c in codes(h, "UNUSED")], [("Label_3",)])

    def test_orphaned_parents(self):
        h = self.analyze([label("Label_1", "Work/Plans"), label("Label_2", "Work/Notes"), label("Label_3", "A/B/C"), label("Label_4", "A"), label("Label_5", "Fine")],
                         [mail(1, ["INBOX", "Label_1", "Label_2", "Label_3", "Label_4", "Label_5"])])
        orphans = codes(h, "ORPHANED_PARENT")
        self.assertIn(("ORPHANED_PARENT", "", ("Label_1", "Label_2"), "HIGH"), orphans)  # "Work" has no label of its own
        self.assertIn(("ORPHANED_PARENT", "", ("Label_3",), "HIGH"), orphans)  # "A/B" is missing although "A" exists
        self.assertEqual(len(orphans), 2)

    def test_deep_nesting_uses_the_recommended_maximum(self):
        self.assertEqual(lm.MAX_DEPTH, 3)
        h = self.analyze([label("Label_1", "a/b/c"), label("Label_2", "a/b/c/d"), label("Label_3", "a/b/c/d/e"), label("Label_4", "a"), label("Label_5", "a/b")],
                         [mail(1, ["INBOX", "Label_1", "Label_2", "Label_3", "Label_4", "Label_5"])])
        self.assertEqual([c[2] for c in codes(h, "DEEP_NESTING")], [("Label_2",), ("Label_3",)])
        self.assertEqual(dict(h.findings[[f.labels for f in h.findings].index(("Label_2",))].evidence)["depth"], 4)

    def test_inconsistent_nesting_conventions(self):
        used = ["INBOX"] + [f"Label_{i}" for i in range(1, 9)]
        h = self.analyze([label("Label_1", "Work"), label("Label_2", "Work/Plans"), label("Label_3", "Work - Archive"), label("Label_4", "Home - Archive"),
                          label("Label_5", "Team/Docs"), label("Label_6", "team/Notes"), label("Label_7", "Workshop"), label("Label_8", "Home")], [mail(1, used)])
        inc = codes(h, "INCONSISTENT_NESTING")
        self.assertIn(("INCONSISTENT_NESTING", "FLAT_PREFIX", ("Label_1", "Label_3"), "MEDIUM"), inc)  # "Work - Archive" next to the nested "Work/Plans"
        self.assertIn(("INCONSISTENT_NESTING", "PARENT_SPELLING", ("Label_5", "Label_6"), "MEDIUM"), inc)
        flagged = {i for n in inc for i in n[2]}
        self.assertNotIn("Label_4", flagged)  # "Home" has no nested child, so "Home - Archive" does not contradict a convention
        self.assertNotIn("Label_7", flagged)  # "Workshop" shares letters with "Work" but no delimiter

    def test_system_labels_are_ignored_entirely(self):
        h = self.analyze([label("INBOX", "INBOX", "system"), label("CATEGORY_PROMOTIONS", "CATEGORY_PROMOTIONS", "system"), label("SENT", "SENT", "system"),
                          label("Label_1", "Mine")], [mail(1, ["INBOX", "Label_1"])])
        self.assertEqual((h.system_labels, h.user_labels, list(h.findings)), (3, 1, []))
        self.assertTrue(all(i.startswith("Label_") for f in h.findings for i in f.labels))

    def test_accounts_are_isolated(self):
        self.fixture([label("Label_1", "Receipts"), label("Label_2", "receipts")], [mail(1, ["INBOX", "Label_1", "Label_2"])])
        self.fixture([label("Label_9", "Unique")], [mail(2, ["INBOX", "Label_9"])], account=OTHER)
        self.assertEqual(len(codes(lh.analyze(self.index, ACCT))), 1)
        self.assertEqual(codes(lh.analyze(self.index, OTHER)), [])

    def test_the_analysis_is_deterministic_and_independent_of_insertion_order(self):
        labs = [label(f"Label_{i}", n) for i, n in enumerate(["Work Plans", "work plans", "Idle", "Deep/a/b/c", "Statement", "Statements", "Orphan/Child", "Work - Old"], 1)]
        msgs = [mail(1, ["INBOX", "Label_1", "Label_2", "Label_5", "Label_6"])]
        self.fixture(labs, msgs)
        first = lh.analyze(self.index, ACCT)
        again = lh.analyze(self.index, ACCT)
        self.assertEqual(first, again)
        text1 = label_report.hygiene_text(self.index, ACCT, first, True)
        self.assertEqual(text1, label_report.hygiene_text(self.index, ACCT, again, True))
        self.setUp()
        self.fixture(list(reversed(labs)), msgs)
        self.assertEqual(lh.analyze(self.index, ACCT).findings, first.findings)

    def test_every_finding_has_a_reason_evidence_confidence_and_basis_and_no_names(self):
        labs = [label("Label_1", "SecretAlpha"), label("Label_2", "secretalpha"), label("Label_3", "SecretIdle"), label("Label_4", "SecretOrphan/Child"), label("Label_5", "x/y/z/w")]
        h = self.analyze(labs, [mail(1, ["INBOX", "Label_1", "Label_2", "Label_4", "Label_5"])])
        self.assertTrue(h.findings)
        for f in h.findings:
            self.assertTrue(f.reason and f.evidence and f.confidence in ("LOW", "MEDIUM", "HIGH") and f.basis in ("OBSERVED", "INFERRED"))
            self.assertNotIn("secret", f.reason.lower())
            self.assertNotIn("secret", repr(f.evidence).lower())


class ReportTests(M5Base):
    def setUp(self):
        super().setUp()
        self.fixture([label("Label_1", "PrivateAlpha"), label("Label_2", "privatealpha"), label("Label_3", "Idle\x1b[31mRed")], [mail(1, ["INBOX", "Label_1", "Label_2"])])
        self.h = lh.analyze(self.index, ACCT)

    def test_names_are_hidden_by_default_and_shown_only_on_request(self):
        hidden = label_report.hygiene_text(self.index, ACCT, self.h)
        shown = label_report.hygiene_text(self.index, ACCT, self.h, show_names=True)
        self.assertNotIn("PrivateAlpha", hidden)
        self.assertNotIn("Idle", hidden)
        self.assertIn("names hidden", hidden)
        self.assertIn('"PrivateAlpha"', shown)
        self.assertNotIn(ACCT, hidden + shown)
        self.assertIn(label_report.LOCAL_ONLY, hidden)

    def test_untrusted_names_are_sanitized_before_display(self):
        shown = label_report.hygiene_text(self.index, ACCT, self.h, show_names=True)
        self.assertNotIn("\x1b", shown)
        self.assertIn("Idle?[31mRed", shown)
        self.assertEqual(label_report.safe("a\nb\tc"), "a?b?c")
        self.assertEqual(len(label_report.safe("x" * 500)), 80)

    def test_the_report_states_observed_versus_inferred_and_that_nothing_changed(self):
        text = label_report.hygiene_text(self.index, ACCT, self.h)
        for needle in ("OBSERVED", "evidence:", "why:", "not a probability", "cannot create, rename, merge or delete", "Index: COMPLETE"):
            self.assertIn(needle, text)

    def test_a_partial_index_is_called_out(self):
        M5Base.setUp(self)
        self.fixture([label("Label_1", "Idle")], [mail(1, ["INBOX"])], complete=False)
        text = label_report.hygiene_text(self.index, ACCT, lh.analyze(self.index, ACCT))
        self.assertIn("Index: PARTIAL", text)
        self.assertIn("UNUSED_UNCERTAIN", text)
        self.assertNotIn("[UNUSED]", text)


class CliTests(M5Base):
    def test_labels_report_runs_locally_and_hides_names(self):
        self.fixture([label("Label_1", "PrivateAlpha"), label("Label_2", "privatealpha")], [mail(1, ["INBOX", "Label_1", "Label_2"])])
        code, out, err = self.run_cli("labels", "report", "--account", ACCT)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("LOCAL ONLY", out)
        self.assertNotIn("PrivateAlpha", out)
        code, out, _ = self.run_cli("labels", "report", "--account", ACCT, "--show-names")
        self.assertIn('"PrivateAlpha"', out)

    def test_an_unknown_account_gives_an_empty_friendly_report(self):
        self.fixture([label("Label_1", "A")], [mail(1, ["INBOX", "Label_1"])])
        code, out, err = self.run_cli("labels", "report", "--account", OTHER)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("No findings", out)

    def test_help_documents_the_group(self):
        code, out, _ = self.run_cli("labels", "--help")
        self.assertEqual(code, 0)
        self.assertIn("LOCAL ONLY", out)
        code, out, _ = self.run_cli("labels", "report", "--help")
        self.assertIn("--show-names", out)


class BoundaryTests(unittest.TestCase):
    def test_the_hygiene_modules_import_nothing_live(self):
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "http", "urllib", "socket", "requests", "ssl"}
        for name in ("label_model", "label_hygiene", "label_report"):
            tree = ast.parse((ROOT / "src" / "gmail_intelligence" / f"{name}.py").read_text())
            mods = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    mods |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom):
                    mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
            self.assertEqual(mods & forbidden, set(), name)


if __name__ == "__main__":
    unittest.main()
