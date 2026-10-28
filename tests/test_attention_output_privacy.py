"""M8A-1 privacy blocker fix (F1a, F1b): stored text must never reach the user through an error message or a classification-derived output field.

F1a: only the fixed parameter-error text may be printed by the command; any other ValueError (for example from a stored value) ends in the generic message.
F1b: `types` and `signals[].rule` are validated against the authoritative definitions (classify.TYPES, the rule id contract `u<number>`) and otherwise show
the fixed code UNRECOGNISED, in JSON and in text. Ranking for valid data is unchanged. Synthetic data only.
"""
import json
import unittest
from unittest import mock

import attention_support as S
from attention_support import ACCOUNT, attention, classify
from gmail_intelligence import cli
from test_attention_corrupt_metadata import GENERIC, Case

MARK = "stored-text-marker-4471"
RULE_SQL = ("INSERT INTO class_rules (account,id,kind,value,c_domain,confidence,priority,enabled,note,created_at) "
            "VALUES (?,?,?,?,?,?,0,1,?,'2026-10-21T00:00:00Z')")


def blob(text):
    return text.encode("utf-8")


class ErrorBoundaryTests(Case):
    FINISHED_AT = {
        "plain marker": MARK,
        "terminal escape": "\x1b[31m" + MARK,
        "newline injection": "2026-10-21T11:00:00Z\n" + MARK,
        "trailing text": "2026-10-21T11:00:00Z " + MARK,
        "wrong format": "2026-10-21 11:00:00 " + MARK,
        "bidi control": "‮" + MARK,
        "very long": MARK * 400,
        "as blob": blob(MARK),
        "as integer": 20261021,
    }

    def test_a_malformed_scan_timestamp_gives_only_the_generic_message(self):
        for name, value in self.FINISHED_AT.items():
            with self.subTest(name):
                self.reset()
                self.mb.sql("UPDATE scans SET finished_at=? WHERE account=?", value, ACCOUNT)
                self.before = self.mb.tree()
                for argv in (("--json",), (), ("--json", "--reveal-senders"), ("--json", "--sort", "oldest")):
                    code, out, err, attempts = self.run_checked(*argv)
                    self.assertEqual((code, out, err, attempts), (1, "", GENERIC, []), (name, argv))
                    self.assertNotIn(MARK, out + err)
                    self.assertNotIn("Traceback", err)
                    self.assertNotIn("time data", err)
                self.assertUntouched()

    def test_any_internal_value_error_is_generic_whatever_its_text(self):
        for target in ("attention.compute", "attention._run", "attention._freshness", "classifier.features_for", "classify.evaluate", "analytics._parse"):
            with self.subTest(target):
                module, name = target.split(".")
                owner = {"attention": attention, "classifier": attention.classifier, "classify": attention.classify, "analytics": attention.analytics}[module]
                with mock.patch.object(owner, name, side_effect=ValueError("from the index: " + MARK)):
                    code, out, err, _ = self.run_checked("--json")
                self.assertEqual((code, out, err), (1, "", GENERIC), target)

    def test_other_internal_exception_types_stay_generic(self):
        for exc in (KeyError(MARK), TypeError(MARK), AttributeError(MARK), OverflowError(MARK), UnicodeDecodeError("utf-8", b"\xff", 0, 1, MARK)):
            with self.subTest(type(exc).__name__), mock.patch.object(attention, "_run", side_effect=exc):
                code, out, err, _ = self.run_checked()
                self.assertEqual((code, out, err), (1, "", GENERIC))

    def test_bad_arguments_still_print_their_fixed_text_and_exit_one(self):
        cases = {("--limit", "0"): "--limit must be between 1 and 100", ("--limit", "101"): "--limit must be between 1 and 100",
                 ("--sender-limit", "11"): "--sender-limit must be between 0 and 10", ("--sender-limit", "-1"): "--sender-limit must be between 0 and 10"}
        for argv, text in cases.items():
            code, out, err, _ = self.run_checked(*argv)
            self.assertEqual((code, out, err), (1, "", f"error: {text}\n"), argv)

    def test_parameter_errors_are_a_distinct_value_error_built_from_constants_only(self):
        self.assertTrue(issubclass(attention.ParameterError, ValueError))
        for kw in ({"limit": 0}, {"sort": MARK}, {"signals": (MARK,)}, {"min_tier": MARK}, {"sender_limit": 99}):
            with self.assertRaises(attention.ParameterError) as cm:
                self.mb.compute(**kw)
            self.assertNotIn(MARK, str(cm.exception))
            self.assertNotIn("99", str(cm.exception).replace("--sender-limit must be between 0 and 10", ""))

    def test_a_cursor_error_and_a_snapshot_error_are_still_their_fixed_codes(self):
        code, out, err, _ = self.run_checked("--cursor", MARK)
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: CURSOR_INVALID:"), err)
        self.assertNotIn(MARK, err)


class ClassificationOutputTests(Case):
    def rule(self, rule_id, kind, value, conf="HIGH", note=None):
        self.mb.sql(RULE_SQL, ACCOUNT, rule_id, kind, value, "example.test", conf, note)

    def output(self, *argv):
        code, out, err, _ = self.run_checked(*argv)
        return code, out, err

    def test_every_taxonomy_type_is_shown_unchanged(self):
        for value in classify.TYPES:
            with self.subTest(value):
                self.reset()
                self.rule("u1", "type", value)
                code, out, err = self.output("--json")
                self.assertEqual((code, err), (0, ""))
                self.assertEqual({tuple(i["types"]) for i in json.loads(out)["items"]}, {(value,)})
                self.assertIn(value, self.output()[1])

    def test_a_stored_type_outside_the_taxonomy_is_never_echoed(self):
        hostile = [MARK, "<script>alert(1)</script>", "\x1b[31m" + MARK, "‮" + MARK, "personal", "PERSONAL ", "PERSONAL\n" + MARK, MARK * 500,
                   "'; DROP TABLE messages; --" + MARK, "", "javascript:" + MARK]
        for value in hostile:
            with self.subTest(value[:30]):
                self.reset()
                self.rule("u1", "type", value)
                for argv in (("--json",), (), ("--json", "--reveal-senders"), ("--json", "--no-collapse")):
                    code, out, err = self.output(*argv)
                    self.assertEqual((code, err), (0, ""))
                    self.assertNotIn(MARK, out)
                    self.assertNotIn("<script", out)
                    self.assertNotIn("\x1b", out)
                    self.assertNotIn("‮", out)
                data = json.loads(self.output("--json")[1])
                self.assertEqual({tuple(i["types"]) for i in data["items"]}, {("UNRECOGNISED",)})
                self.assertIn("UNRECOGNISED", self.output()[1])

    def test_a_stored_type_stored_as_a_blob_fails_closed_without_output(self):
        self.reset()
        self.mb.sql(RULE_SQL, ACCOUNT, "u1", "type", blob(MARK), "example.test", "HIGH", None)
        code, out, err = self.output("--json")
        self.assertEqual((code, out, err), (1, "", GENERIC))

    def test_a_valid_and_a_malformed_type_together_show_the_valid_one_and_the_fixed_code(self):
        self.rule("u1", "type", "PERSONAL")
        self.rule("u2", "type", MARK)
        out = self.output("--json")[1]
        self.assertNotIn(MARK, out)
        self.assertEqual({tuple(i["types"]) for i in json.loads(out)["items"]}, {("PERSONAL", "UNRECOGNISED")})

    def test_user_rule_ids_follow_the_contract_or_show_the_fixed_code(self):
        valid = ["u1", "u42", "u123456789"]
        invalid = [MARK, "u", "U1", "u1a", "u1234567890", "u١٢", "u1\n", "builtin.label-starred", "u-1", "", "ｕ1", "u1 " + MARK, "<b>u1</b>", "u1" + MARK]
        for rid in valid + invalid:
            with self.subTest(repr(rid)[:30]):
                self.reset()
                self.rule(rid, "attention", "POTENTIALLY_IMPORTANT", "MEDIUM")
                for argv in (("--json",), ()):
                    code, out, err = self.output(*argv)
                    self.assertEqual((code, err), (0, ""))
                    self.assertNotIn(MARK, out)
                    self.assertNotIn("<b>", out)
                data = json.loads(self.output("--json")[1])
                shown = {s["rule"] for i in data["items"] for s in i["signals"] if s["code"] == "USER_RULE"}
                self.assertEqual(shown, {rid if rid in valid else "UNRECOGNISED"})

    def test_a_rule_id_stored_as_a_blob_is_not_echoed(self):
        self.mb.sql(RULE_SQL, ACCOUNT, blob(MARK), "attention", "POTENTIALLY_IMPORTANT", "example.test", "MEDIUM", None)
        code, out, err = self.output("--json")
        self.assertNotIn(MARK, out + err)
        self.assertIn(code, (0, 1))
        if code == 1:
            self.assertEqual((out, err), ("", GENERIC))

    def test_ranking_is_unchanged_by_the_validation(self):
        self.rule("u1", "attention", "POTENTIALLY_IMPORTANT", "MEDIUM")
        baseline = [(i["score"], i["evidence"], i["components"]) for i in json.loads(self.output("--json")[1])["items"]]
        for rid in ("u7", MARK):
            self.reset()
            self.rule(rid, "attention", "POTENTIALLY_IMPORTANT", "MEDIUM")
            shown = [(i["score"], i["evidence"], i["components"]) for i in json.loads(self.output("--json")[1])["items"]]
            self.assertEqual(shown, baseline, rid)  # a malformed id still counts exactly as before; only its display changes
        self.reset()
        self.rule("u1", "type", "PERSONAL")
        valid = json.loads(self.output("--json")[1])
        self.assertTrue(all(i["types"] == ["PERSONAL"] for i in valid["items"]))

    def test_the_snapshot_still_reflects_the_stored_value(self):
        """Two different malformed values both DISPLAY as UNRECOGNISED, but a change between pages is still detected (the snapshot uses the stored value)."""
        self.rule("u1", "type", MARK + "-a")
        first = self.mb.compute(limit=2)
        self.mb.sql("UPDATE class_rules SET value=? WHERE id='u1'", MARK + "-b")
        second = self.mb.compute(limit=2)
        self.assertNotEqual(first["snapshot"], second["snapshot"])
        self.assertEqual([i["types"] for i in first["items"]], [i["types"] for i in second["items"]])


class ReflectionAuditTests(Case):
    """Every stored text column that can reach the engine carries its own marker; none may appear in any output (the sender address is shown only masked)."""

    FIELDS = ("id", "thread", "label-id", "label-name", "rule-note", "rule-sender", "rule-label", "scan-status", "sync-reason", "sender-domain-free", "rule-domain")

    def plant(self):
        m = {f: f"{MARK}-{f}" for f in self.FIELDS}
        self.mb.add(m["id"], thread=m["thread"], sender="plain@example.test", labels=("INBOX", "STARRED", "UNREAD", m["label-id"]), age_days=3)
        self.mb.sql("INSERT INTO labels VALUES (?,?,?,?)", ACCOUNT, m["label-id"], m["label-name"], "user")
        self.mb.sql("INSERT INTO class_rules (account,id,kind,value,c_sender,c_label,confidence,priority,enabled,note,created_at) VALUES (?,?,?,?,?,?,?,?,1,?,'x')",
                    ACCOUNT, "u5", "attention", "POTENTIALLY_IMPORTANT", m["rule-sender"] + "@example.test", m["rule-label"], "LOW", 0, m["rule-note"])
        self.mb.sql("INSERT INTO class_rules (account,id,kind,value,c_domain,confidence,priority,enabled,note,created_at) VALUES (?,?,?,?,?,?,?,1,?,'x')",
                    ACCOUNT, "u6", "type", "PERSONAL", m["rule-domain"] + ".test", "HIGH", 0, m["rule-note"])
        self.mb.sql("UPDATE scans SET status=? WHERE account=? AND status<>'completed'", m["scan-status"], ACCOUNT)
        self.mb.sql("INSERT INTO sync_state (account,history_id,source,basis_scan_id,established_at,advanced_at,status,reason) VALUES (?,?,?,?,?,?,?,?)",
                    ACCOUNT, "1", "HISTORY_RESPONSE", 1, "2026-10-21T10:00:00Z", "2026-10-21T10:30:00Z", "NEEDS_RECONCILE", m["sync-reason"])
        return m

    def test_no_planted_text_reaches_any_output_field(self):
        planted = self.plant()
        for argv in (("--json",), (), ("--json", "--no-collapse"), ("--json", "--include-low-score", "--sort", "date")):
            code, out, err, _ = self.run_checked(*argv)
            self.assertEqual((code, err), (0, ""), argv)
            self.assertIn("SYNC_NOT_HEALTHY", out if "--json" in argv else out + "SYNC_NOT_HEALTHY")  # the sync state is read, only as a fixed label
            for field, text in planted.items():
                self.assertNotIn(text, out, f"{field} leaked ({argv})")
            self.assertNotIn(MARK, out)

    def test_the_revealed_sender_is_the_only_stored_text_shown_on_request(self):
        planted = self.plant()
        self.mb.sql("UPDATE messages SET sender=? WHERE id=?", f"{MARK}-visible@example.test", planted["id"])
        out = self.run_checked("--json", "--reveal-senders")[1]
        self.assertIn(f"{MARK}-visible@example.test", out)
        for field, text in planted.items():
            self.assertNotIn(text, out, field)
        masked = self.run_checked("--json")[1]
        self.assertNotIn(f"{MARK}-visible", masked)


if __name__ == "__main__":
    unittest.main()
