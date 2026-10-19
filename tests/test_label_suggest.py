"""M5B recommendations and M5C proposed classification rules (issues #13, #14). Synthetic fixtures only; nothing is applied or saved."""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, M5Base, label, mail  # noqa: E402

from gmail_intelligence import classifier, label_report, label_suggest as ls  # noqa: E402

PROMO = ("INBOX", "CATEGORY_PROMOTIONS")


def many(start, n, sender, labels):
    return [mail(start + k, labels, sender=sender) for k in range(n)]


class TierTests(unittest.TestCase):
    def test_tiers_and_caps(self):
        self.assertIsNone(ls.tier(2, 1.0))
        self.assertIsNone(ls.tier(10, 0.5))
        self.assertEqual(ls.tier(3, 0.7), "LOW")
        self.assertEqual(ls.tier(5, 0.8), "MEDIUM")
        self.assertEqual(ls.tier(20, 0.95), "HIGH")
        self.assertEqual(ls.tier(4, 1.0), "LOW")  # small samples cannot yield more
        self.assertEqual(ls.tier(100, 1.0, complete=False), "MEDIUM")
        self.assertEqual(ls.tier(100, 1.0, inferred=True), "MEDIUM")
        self.assertEqual(ls.tier(100, 1.0, weak=True), "MEDIUM")
        self.assertEqual(ls.tier(3, 1.0, inferred=True), "LOW")


class RecommendTests(M5Base):
    def test_apply_existing_label_from_observed_usage(self):
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@shop.example.test") for k in range(1, 23)] + [mail(100, ("INBOX",), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs)
        s = ls.recommend(self.index, ACCT)
        recs = [r for r in s.items if r.group == ("domain", "shop.example.test")]
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual((r.kind, r.target, r.basis, r.source, r.confidence), ("APPLY_LABEL", "Label_1", "OBSERVED", "label-usage", "HIGH"))
        self.assertEqual(dict(r.evidence)["missing"], 1)
        self.assertFalse([x for x in s.items if x.group[0] == "sender"])  # the sender-level suggestion is redundant with its domain

    def test_a_partial_index_caps_confidence_and_adds_a_caveat(self):
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@shop.example.test") for k in range(1, 23)] + [mail(100, ("INBOX",), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs, complete=False)
        r = ls.recommend(self.index, ACCT).items[0]
        self.assertEqual(r.confidence, "MEDIUM")
        self.assertTrue(r.caveats)

    def test_small_groups_and_full_coverage_produce_nothing(self):
        self.fixture([label("Label_1", "X")], [mail(1, ("INBOX", "Label_1"), sender="a@one.example.test"), mail(2, ("INBOX",), sender="a@one.example.test"),
                                               *[mail(k, ("INBOX", "Label_1"), sender="b@two.example.test") for k in range(10, 16)]])
        self.assertEqual(ls.recommend(self.index, ACCT).items, ())

    def test_protected_groups_are_suppressed_and_counted(self):
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@shop.example.test") for k in range(1, 8)] + [mail(50, ("INBOX", "STARRED"), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs)
        s = ls.recommend(self.index, ACCT)
        self.assertEqual(s.items, ())
        self.assertTrue(any("protected" in why for why, n in s.suppressed))

    def test_a_protection_rule_suppresses(self):
        from gmail_intelligence import cleanup_protect
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@shop.example.test") for k in range(1, 8)] + [mail(50, ("INBOX",), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs)
        cleanup_protect.add(self.index, ACCT, domain="shop.example.test")
        self.assertEqual(ls.recommend(self.index, ACCT).items, ())

    def test_trash_and_spam_are_ignored(self):
        msgs = [mail(k, ("TRASH", "Label_1"), sender="a@shop.example.test") for k in range(1, 8)] + [mail(50, ("INBOX",), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs)
        self.assertEqual(ls.recommend(self.index, ACCT).items, ())

    def test_create_label_is_a_generic_inferred_suggestion_aggregated_by_type(self):
        msgs = []
        for d in range(3):
            msgs += many(d * 10 + 1, 4, f"n@dom{d}.example.test", PROMO)
        self.fixture([], msgs)
        recs = ls.recommend(self.index, ACCT).items
        creates = [r for r in recs if r.kind == "CREATE_LABEL"]
        self.assertEqual(len(creates), 1)
        r = creates[0]
        self.assertEqual((r.target, r.basis, r.confidence, r.source), ("Promotions", "INFERRED", "MEDIUM", "classification-rules"))
        self.assertEqual(dict(r.evidence)["messages"], 12)
        self.assertNotIn("example.test", repr(r.reason))

    def test_create_label_becomes_apply_when_a_matching_label_exists(self):
        msgs = []
        for d in range(3):
            msgs += many(d * 10 + 1, 4, f"n@dom{d}.example.test", PROMO)
        self.fixture([label("Label_7", "promotions")], msgs)
        r = [x for x in ls.recommend(self.index, ACCT).items if x.group == ("type", "PROMOTIONAL")][0]
        self.assertEqual((r.kind, r.target), ("APPLY_LABEL", "Label_7"))

    def test_deterministic_and_account_isolated(self):
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@shop.example.test") for k in range(1, 9)] + [mail(100, ("INBOX",), sender="a@shop.example.test")]
        self.fixture([label("Label_1", "Shopping")], msgs)
        a, b = ls.recommend(self.index, ACCT), ls.recommend(self.index, ACCT)
        self.assertEqual(a, b)
        self.assertEqual(ls.recommend(self.index, "other@example.test").items, ())


class RuleTests(M5Base):
    def seeded(self):
        # 6 promotional-category messages + 2 uncategorised ones from one domain: a rule would classify the 2 as PROMOTIONAL
        msgs = many(1, 6, "deals@promo.example.test", PROMO) + many(20, 2, "deals@promo.example.test", ("INBOX",))
        self.fixture([], msgs)

    def test_proposal_reuses_the_m3_preview_exactly(self):
        self.seeded()
        s = ls.suggest_rules(self.index, ACCT)
        p = [x for x in s.items if x.group == ("domain", "promo.example.test")][0]
        self.assertEqual((p.kind, p.value, p.basis), ("type", "PROMOTIONAL", "INFERRED"))
        self.assertEqual(dict(p.preview), classifier.preview_rule(self.index, ACCT, **dict(p.fields)))
        self.assertGreater(dict(p.preview)["type_changes"], 0)

    def test_nothing_is_saved_and_no_rule_command_runs(self):
        self.seeded()
        before = classifier.rule_rows(self.index, ACCT)
        ls.suggest_rules(self.index, ACCT)
        code, out, err = self.run_cli("labels", "suggest-rules", "--account", ACCT)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(classifier.rule_rows(self.index, ACCT), before)
        self.assertIn("No rule was saved", out)

    def test_an_existing_rule_makes_the_proposal_redundant(self):
        self.seeded()
        classifier.add_rule(self.index, ACCT, kind="type", value="PROMOTIONAL", confidence="HIGH", priority=0, domain="promo.example.test")
        s = ls.suggest_rules(self.index, ACCT)
        self.assertEqual([x for x in s.items if x.group == ("domain", "promo.example.test")], [])
        self.assertTrue(any("already exists" in why for why, n in s.suppressed))

    def test_a_contradicting_rule_is_never_contradicted(self):
        self.seeded()
        classifier.add_rule(self.index, ACCT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, domain="promo.example.test")
        s = ls.suggest_rules(self.index, ACCT)
        self.assertEqual([x for x in s.items if x.group == ("domain", "promo.example.test")], [])

    def test_protected_groups_get_no_proposal(self):
        msgs = many(1, 6, "deals@promo.example.test", PROMO) + many(20, 2, "deals@promo.example.test", ("INBOX", "STARRED"))
        self.fixture([], msgs)
        s = ls.suggest_rules(self.index, ACCT)
        self.assertEqual(s.items, ())
        self.assertTrue(s.suppressed)

    def test_no_effect_proposals_are_dropped(self):
        self.fixture([], many(1, 6, "deals@promo.example.test", PROMO))  # the built-in rule already classifies every message
        s = ls.suggest_rules(self.index, ACCT)
        self.assertEqual(s.items, ())

    def test_small_groups_are_ignored(self):
        self.fixture([], many(1, 2, "deals@promo.example.test", PROMO))
        self.assertEqual(ls.suggest_rules(self.index, ACCT).items, ())


class RenderingAndCliTests(M5Base):
    def setUp(self):
        super().setUp()
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@private-shop.example.test") for k in range(1, 9)] + [mail(100, ("INBOX",), sender="a@private-shop.example.test")]
        msgs += many(200, 6, "deals@promo-secret.example.test", PROMO) + many(220, 2, "deals@promo-secret.example.test", ("INBOX",))
        self.fixture([label("Label_1", "PrivateShopping")], msgs)

    def test_recommend_hides_names_and_senders_by_default(self):
        code, out, err = self.run_cli("labels", "recommend", "--account", ACCT)
        self.assertEqual((code, err), (0, ""))
        for secret in ("PrivateShopping", "private-shop", "a@private"):
            self.assertNotIn(secret, out)
        self.assertIn("LOCAL ONLY", out)
        self.assertIn("Nothing was applied", out)
        self.assertIn("OBSERVED", out)
        code, out, _ = self.run_cli("labels", "recommend", "--account", ACCT, "--show-names", "--show-senders")
        self.assertIn('"PrivateShopping"', out)
        self.assertIn("private-shop.example.test", out)

    def test_suggest_rules_hides_senders_by_default(self):
        code, out, _ = self.run_cli("labels", "suggest-rules", "--account", ACCT)
        self.assertNotIn("promo-secret", out)
        self.assertIn("preview", out)
        code, out, _ = self.run_cli("labels", "suggest-rules", "--account", ACCT, "--show-senders")
        self.assertIn("promo-secret.example.test", out)

    def test_untrusted_label_names_are_sanitized(self):
        self.index.save_labels(ACCT, [label("Label_1", "Evil\x1b[2Jname")])
        _, out, _ = self.run_cli("labels", "recommend", "--account", ACCT, "--show-names")
        self.assertNotIn("\x1b", out)

    def test_help(self):
        _, out, _ = self.run_cli("labels", "--help")
        self.assertIn("recommend", out)
        self.assertIn("suggest-rules", out)


class BoundaryTests(unittest.TestCase):
    def test_no_live_imports(self):
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "exec_live_mailbox", "cleanup_exec", "http", "urllib", "socket", "ssl", "requests"}
        tree = ast.parse((ROOT / "src" / "gmail_intelligence" / "label_suggest.py").read_text())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
        self.assertEqual(mods & forbidden, set())

    def test_no_function_stores_a_rule(self):
        src = (ROOT / "src" / "gmail_intelligence" / "label_suggest.py").read_text()
        for needle in ("add_rule(", "INSERT", "UPDATE", "DELETE", "set_enabled(", "remove_rule("):
            self.assertNotIn(needle, src)


if __name__ == "__main__":
    unittest.main()
