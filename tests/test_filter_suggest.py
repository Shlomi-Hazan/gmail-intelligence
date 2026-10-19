"""M5E: local filter suggestions and the safe-vocabulary validator (issue #16). Nothing is created; no Gmail, no settings scope."""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, M5Base, label, mail  # noqa: E402

from gmail_intelligence import filter_suggest as fs, label_report  # noqa: E402


class ValidatorTests(unittest.TestCase):
    def ok(self, **kw):
        return fs.validate_filter(kw.get("criteria", {"domain": "shop.example.test"}), kw.get("actions", [("apply_label", "Label_1")]))

    def code(self, **kw):
        with self.assertRaises(fs.FilterError) as cm:
            self.ok(**kw)
        return cm.exception.code

    def test_the_safe_filter_is_accepted(self):
        crit, acts = self.ok()
        self.assertEqual((crit, acts), ((("domain", "shop.example.test"),), (("APPLY_LABEL", "Label_1"),)))
        self.assertEqual(self.ok(criteria={"sender": "A@Shop.Example.Test"})[0], (("sender", "a@shop.example.test"),))

    def test_dangerous_actions_are_rejected(self):
        for name in ("forward", "FORWARD_TO", "trash", "delete", "skip_inbox", "archive", "send", "mark_spam", "never_spam", "mark_as_read", "star", "reply"):
            self.assertEqual(self.code(actions=[(name, "x@example.test")]), "FORBIDDEN_ACTION", name)

    def test_unknown_actions_and_empty_inputs_are_rejected(self):
        self.assertEqual(self.code(actions=[("frobnicate", "x")]), "UNSUPPORTED_ACTION")
        self.assertEqual(self.code(actions=[]), "NO_ACTION")
        self.assertEqual(self.code(actions=["bad"]), "UNSUPPORTED_ACTION")
        for crit in ({}, {"subject": "hi"}, {"domain": "*.example.test"}, {"sender": "not-an-address"}, {"domain": "a b.example.test"}, None):
            self.assertEqual(self.code(criteria=crit), "BAD_CRITERIA", crit)

    def test_system_labels_are_never_applied(self):
        for lab in ("INBOX", "TRASH", "SPAM", "STARRED", "CATEGORY_SOCIAL", "Sent Mail", "UNREAD", "Inbox/Child"):
            self.assertEqual(self.code(actions=[("APPLY_LABEL", lab)]), "SYSTEM_LABEL", lab)
        self.assertEqual(self.code(actions=[("APPLY_LABEL", "a//b")]), "BAD_LABEL")


class SuggestionTests(M5Base):
    def setUp(self):
        super().setUp()
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@private-shop.example.test") for k in range(1, 9)] + [mail(100, ("INBOX",), sender="a@private-shop.example.test")]
        self.fixture([label("Label_1", "PrivateShopping")], msgs)

    def test_suggestion_has_criteria_actions_effect_and_warnings(self):
        s = fs.suggest(self.index, ACCT)
        f = s.items[0]
        self.assertEqual(f.criteria, (("domain", "private-shop.example.test"),))
        self.assertEqual(f.actions, (("APPLY_LABEL", "Label_1"),))
        self.assertEqual(dict(f.effect), {"matching_indexed": 9, "already_labeled": 8, "would_gain_label": 1})
        self.assertTrue(any("FUTURE" in w for w in f.warnings))
        for _, acts in [fs.validate_filter(dict(f.criteria), f.actions) for f in s.items]:
            self.assertEqual({a[0] for a in acts}, {"APPLY_LABEL"})

    def test_a_partial_index_warns(self):
        M5Base.setUp(self)
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@private-shop.example.test") for k in range(1, 9)] + [mail(100, ("INBOX",), sender="a@private-shop.example.test")]
        self.fixture([label("Label_1", "PrivateShopping")], msgs, complete=False)
        self.assertTrue(any("partial" in w for w in fs.suggest(self.index, ACCT).items[0].warnings))

    def test_cli_hides_private_values_and_states_nothing_was_applied(self):
        code, out, err = self.run_cli("labels", "suggest-filters", "--account", ACCT)
        self.assertEqual((code, err), (0, ""))
        for secret in ("private-shop", "PrivateShopping"):
            self.assertNotIn(secret, out)
        for needle in ("LOCAL ONLY", fs.NOTHING_APPLIED, "not a classification rule", "forwarding, Trash, delete, skip-Inbox and send are rejected"):
            self.assertIn(needle, out)
        code, out, _ = self.run_cli("labels", "suggest-filters", "--account", ACCT, "--show-names", "--show-senders")
        self.assertIn("domain = private-shop.example.test", out)
        self.assertIn('"PrivateShopping"', out)

    def test_protected_groups_yield_no_filter(self):
        M5Base.setUp(self)
        msgs = [mail(k, ("INBOX", "Label_1"), sender="a@x.example.test") for k in range(1, 9)] + [mail(100, ("INBOX", "STARRED"), sender="a@x.example.test")]
        self.fixture([label("Label_1", "L")], msgs)
        self.assertEqual(fs.suggest(self.index, ACCT).items, ())

    def test_no_suggestion_for_a_new_label_or_a_type_group(self):
        M5Base.setUp(self)
        msgs = []
        for d in range(3):
            msgs += [mail(d * 10 + k, ("INBOX", "CATEGORY_PROMOTIONS"), sender=f"n@dom{d}.example.test") for k in range(1, 5)]
        self.fixture([], msgs)
        self.assertEqual(fs.suggest(self.index, ACCT).items, ())  # filters never reference a label that does not exist yet


class BoundaryTests(unittest.TestCase):
    def test_no_network_or_settings_scope(self):
        src = (ROOT / "src" / "gmail_intelligence" / "filter_suggest.py").read_text()
        self.assertNotIn("settings.basic", src)
        tree = ast.parse(src)
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods |= {(n.module or "").split(".")[0]} | {a.name for a in n.names}
        self.assertEqual(mods & {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "http", "urllib", "socket", "ssl"}, set())

    def test_no_source_file_requests_the_settings_scope(self):
        for p in (ROOT / "src" / "gmail_intelligence").glob("*.py"):
            text = p.read_text()
            self.assertNotIn("auth/gmail.settings", text, p.name)
            self.assertNotIn("googleapis.com/auth/gmail.settings", text, p.name)


if __name__ == "__main__":
    unittest.main()
