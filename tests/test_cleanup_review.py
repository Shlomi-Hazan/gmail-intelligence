"""M12B: review of discovery groups and creation of a plan from the reviewed selection (issue #60). Synthetic data only: no Gmail, no Keychain, no network, nothing executes.

The M4B plan, approval and audit semantics are the existing ones; these tests prove the new selection layer only reaches them through `cleanup_plans.create_plan`, never widens a
selection, goes stale when anything it depended on changes, and that approval stays a local record."""
import hashlib
import json
import os
import re
import sqlite3
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from m5_support import ACCT, M5Base  # noqa: E402
from test_cleanup import NOW as NOW_MS, msg  # noqa: E402
from test_cleanup_discovery import PROMO, bulk  # noqa: E402

from gmail_intelligence import cleanup_candidates as cc, cleanup_plans as cp, cleanup_protect, cleanup_review as rv, cli  # noqa: E402

NOW = datetime.fromtimestamp(NOW_MS / 1000, timezone.utc)
MARK = "leakmarker-5521"


class Base(M5Base):
    """big (8) and mid (6) are eligible; starred (3) is protected; unread (4) needs review."""

    def setUp(self):
        super().setUp()
        rows = bulk(1, 8, "big.example.test", size=2000) + bulk(20, 6, "mid.example.test", days=120, size=500) + bulk(60, 3, "starred.example.test", labels=PROMO + ("STARRED",)) \
            + bulk(70, 4, "unread.example.test", labels=PROMO + ("UNREAD",))
        self.seed(rows)
        self.db = Path(self.index.path)

    def sel(self, groups=("big.example.test",), exclude=(), **kw):
        return rv.resolve(self.index, ACCT, groups, exclude, now=NOW, **kw)

    def eligible_ids(self, domain):
        res = cc.evaluate_all(self.index, ACCT, now_ms=NOW_MS)
        return sorted(d.message_id for d in res.decisions if d.outcome == cc.ELIGIBLE and d.sender.endswith("@" + domain))

    def plan(self, groups=("big.example.test",), exclude=()):
        s = self.sel(groups, exclude)
        return rv.create_plan_from_selection(self.index, ACCT, groups, exclude, s.digest, now=NOW)


class SelectionAndPreviewTests(Base):
    def test_group_selection_gives_exact_counts_volume_and_action(self):
        p = rv.preview(self.sel(("big.example.test", "mid.example.test")))
        self.assertEqual(p["totals"], {"messages": 14, "threads": 14, "bytes": 8 * 2000 + 6 * 500, "unknown_size": 0})
        self.assertEqual([(g["group"], g["selected"], g["excluded_by_you"]) for g in p["groups"]], [("big.example.test", 8, 0), ("mid.example.test", 6, 0)])
        self.assertEqual(p["action"], "ARCHIVE")
        self.assertEqual(set(p["unavailable_actions"]), {"TRASH", "PERMANENT_DELETE"})
        self.assertIn("never offered", p["unavailable_actions"]["PERMANENT_DELETE"])
        self.assertTrue(p["read_only"])

    def test_the_preview_lists_exactly_the_eligible_messages_of_the_group(self):
        s = self.sel(("big.example.test",))
        self.assertEqual(list(s.ids), self.eligible_ids("big.example.test"))
        shown = rv.preview(s, show_ids=True, page_size=100)["items"]
        self.assertEqual([r["id"] for r in shown], list(s.ids))
        self.assertTrue(all("id" not in r for r in rv.preview(s)["items"]))  # ids stay hidden unless asked
        self.assertEqual(len(rv.preview(s, page=2, page_size=5)["items"]), 3)

    def test_exclusions_remove_only_those_messages_and_change_the_digest(self):
        base = self.sel(("big.example.test",))
        out = base.ids[:2]
        s = self.sel(("big.example.test",), list(out) + list(out))  # duplicated on purpose
        self.assertEqual((len(s.ids), s.duplicates_ignored), (6, 2))
        self.assertTrue(set(out).isdisjoint(s.ids))
        self.assertNotEqual(s.digest, base.digest)
        self.assertEqual(rv.preview(s)["groups"][0]["excluded_by_you"], 2)

    def test_a_selection_never_expands_beyond_the_eligible_set(self):
        for group in ("starred.example.test", "unread.example.test", "nothing.example.test"):  # protected, needs review, unknown
            with self.assertRaises(rv.ReviewError) as cm:
                self.sel((group,))
            self.assertEqual(cm.exception.code, "NO_SUCH_GROUP")
        self.assertEqual(self.sel(("big.example.test",)).not_eligible_same_domains, 0)
        # a protected id cannot be smuggled in or out of a selection either
        with self.assertRaises(rv.ReviewError) as cm:
            self.sel(("big.example.test",), ["m60"])
        self.assertEqual(cm.exception.code, "EXCLUDE_NOT_IN_SELECTION")

    def test_invalid_empty_and_oversized_input_is_refused_with_fixed_text(self):
        cases = ((dict(groups=()), "NO_GROUP"), (dict(groups=("big.example.test",), exclude=["bad id!"]), "BAD_ID"), (dict(groups=("bad group!",)), "BAD_GROUP"),
                 (dict(groups=("big.example.test",), exclude=["nope"]), "EXCLUDE_NOT_IN_SELECTION"), (dict(groups=("big.example.test",), min_age_days=30), "BAD_AGE"),
                 (dict(groups=("big.example.test",), exclude=self.eligible_ids("big.example.test")), "NO_TARGETS"), (dict(groups=["a%d.example.test" % i for i in range(60)]), "TOO_MANY_GROUPS"))
        for kw, code in cases:
            with self.assertRaises(rv.ReviewError) as cm:
                self.sel(kw.pop("groups"), kw.pop("exclude", ()), **kw)
            self.assertEqual(cm.exception.code, code)
            self.assertNotIn("bad id", str(cm.exception))  # the input is never echoed
        for page, size in ((0, 25), (9, 25), (1, 0), (1, 201)):
            with self.assertRaises(rv.ReviewError):
                rv.preview(self.sel(), page=page, page_size=size)

    def test_only_archive_can_be_planned(self):
        self.assertEqual(rv.check_action(None), "ARCHIVE")
        self.assertEqual(rv.check_action("Archive"), "ARCHIVE")
        for action, code in (("trash", "ACTION_UNAVAILABLE"), ("delete", "ACTION_NEVER"), ("permanent-delete", "ACTION_NEVER"), ("shred", "BAD_ACTION")):
            with self.assertRaises(rv.ReviewError) as cm:
                rv.check_action(action)
            self.assertEqual(cm.exception.code, code)

    def test_preview_changes_nothing(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        rv.preview(self.sel(("big.example.test", "mid.example.test"), ["m1"]), show_ids=True)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)


class PlanCreationTests(Base):
    def test_the_plan_is_exactly_the_reviewed_selection_and_is_an_unchanged_m4b_draft(self):
        s = self.sel(("big.example.test",), ["m1"])
        plan = rv.create_plan_from_selection(self.index, ACCT, ("big.example.test",), ["m1"], s.digest, now=NOW)
        self.assertEqual((plan["state"], plan["action"], plan["item_count"], plan["version"]), ("DRAFT", "ARCHIVE", 7, 1))
        self.assertEqual([i["message_id"] for i in plan["items"]], list(s.ids))
        self.assertNotIn("m1", [i["message_id"] for i in plan["items"]])
        self.assertEqual(cp.integrity_problems(plan), [])
        self.assertEqual(cp.revalidate(self.index, ACCT, plan, now=NOW), {})
        self.assertEqual(cp.approval_status(self.index, ACCT, plan["plan_id"])["approvals"], [])

    def test_the_plan_is_immutable_and_hash_bound(self):
        plan = self.plan()
        with self.assertRaises(sqlite3.DatabaseError):
            with self.index.conn:
                self.index.conn.execute("UPDATE cleanup_plan SET snapshot = 'x' WHERE plan_id=?", (plan["plan_id"],))
        self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["plan_hash"], plan["plan_hash"])

    def test_a_stale_digest_is_refused_when_nothing_or_anything_changed_in_between(self):
        s = self.sel()
        for mutate in (lambda: cleanup_protect.add(self.index, ACCT, domain="mid.example.test", note="synthetic"),   # a protection rule (even for another group)
                       lambda: self.seed([bulk(1, 1, "big.example.test", labels=PROMO + ("STARRED",))[0]])):          # one message becomes starred
            mutate()
            with self.assertRaises(rv.ReviewError) as cm:
                rv.create_plan_from_selection(self.index, ACCT, ("big.example.test",), [], s.digest, now=NOW)
            self.assertEqual(cm.exception.code, "STALE_SELECTION")
            s = self.sel()
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)

    def test_a_different_exclusion_is_a_different_selection(self):
        s = self.sel(("big.example.test",), ["m2"])
        for group, exclude in ((("big.example.test",), []), (("big.example.test",), ["m3"]), (("big.example.test", "mid.example.test"), ["m2"])):
            with self.assertRaises(rv.ReviewError) as cm:
                rv.create_plan_from_selection(self.index, ACCT, group, exclude, s.digest, now=NOW)
            self.assertEqual(cm.exception.code, "STALE_SELECTION")
        for bad in (None, "", "abc", "Z" * 64, "0" * 63):
            with self.assertRaises(rv.ReviewError) as cm:
                rv.create_plan_from_selection(self.index, ACCT, ("big.example.test",), [], bad, now=NOW)
            self.assertEqual(cm.exception.code, "BAD_DIGEST")

    def test_the_plan_size_limit_is_enforced_and_not_changed(self):
        self.assertEqual(cp.MAX_PLAN_ITEMS, 500)
        with mock.patch.object(cp, "MAX_PLAN_ITEMS", 5):
            self.assertTrue(rv.preview(self.sel())["plan_limit"]["exceeded"])
            with self.assertRaises(rv.ReviewError) as cm:
                rv.create_plan_from_selection(self.index, ACCT, ("big.example.test",), [], self.sel().digest, now=NOW)
            self.assertEqual(cm.exception.code, "PLAN_LIMIT")

    def test_approval_is_a_local_record_a_changed_selection_needs_a_new_plan_and_approval(self):
        first = self.plan()
        reviewed = cp.mark_reviewed(self.index, ACCT, first["plan_id"], cp.review_phrase(first), now=NOW)
        cp.approve(self.index, ACCT, first["plan_id"], cp.approval_phrase(reviewed), now=NOW)
        self.assertEqual(cp.approval_status(self.index, ACCT, first["plan_id"])["plan_state"], "APPROVED")
        self.assertFalse(cp._has_execution(self.index, ACCT, first["plan_id"]))  # approval executes nothing
        second = self.plan(exclude=["m1"])                                       # one more exclusion
        self.assertNotEqual((second["plan_id"], second["plan_hash"]), (first["plan_id"], first["plan_hash"]))
        self.assertEqual((second["state"], cp.approval_status(self.index, ACCT, second["plan_id"])["approvals"]), ("DRAFT", []))
        # the existing M4B supersede path still invalidates the old approval
        third = cp.revise_exclude(self.index, ACCT, first["plan_id"], ["m2"], now=NOW)
        self.assertEqual(cp.approval_status(self.index, ACCT, first["plan_id"])["plan_state"], "SUPERSEDED")
        self.assertEqual(cp.approval_status(self.index, ACCT, third["plan_id"])["approvals"], [])
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_execution")[0][0], 0)


class CommandAndSafetyTests(Base):
    def run_cmd(self, *argv, patch_plan_time=False):
        fake = mock.MagicMock(wraps=datetime)
        fake.now.return_value = NOW
        with mock.patch.object(rv, "datetime", fake), mock.patch.object(cp, "_utc", side_effect=lambda n: n if n is not None else NOW):
            return self.run_cli("cleanup", *argv, "--account", ACCT)

    def digest(self, *extra):
        return json.loads(self.run_cmd("preview", "--group", "big.example.test", *extra, "--json")[1])["selection_digest"]

    def test_the_complete_review_workflow_through_the_cli(self):
        code, out, err = self.run_cmd("preview", "--group", "big.example.test", "--exclude-id", "m1")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("7 message(s)", out)
        self.assertIn("ids hidden", out)
        d = self.digest("--exclude-id", "m1")
        code, out, err = self.run_cmd("plan", "create", "--group", "big.example.test", "--exclude-id", "m1", "--selection-digest", d)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("created as DRAFT from the reviewed selection: 7 target(s), action ARCHIVE", out)
        self.assertIn("nothing was approved or executed", out)
        pid = re.search(r"Plan (plan-\w+)", out).group(1)
        code, status, _ = self.run_cmd("approval", "status", pid)
        self.assertEqual(code, 0)
        self.assertIn("DRAFT", status)
        self.assertEqual(self.run_cmd("plan", "create", "--group", "big.example.test", "--selection-digest", d)[0], 1)  # wrong exclusions -> stale

    def test_preview_is_read_only_and_prints_no_identifier_or_address(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        names = sorted(os.listdir(self.db.parent))
        for argv in (("preview", "--group", "big.example.test"), ("preview", "--group", "big.example.test", "--group", "mid.example.test", "--json")):
            code, out, err = self.run_cmd(*argv)  # run_cli forbids Gmail and the Keychain; the test base forbids the network
            self.assertEqual((code, err), (0, ""), argv)
            self.assertNotRegex(out, r"https?://|mailto:|@|\bm[0-9]+\b|\bt[0-9]+\b")
            self.assertNotIn(MARK, out)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(self.db.parent)), names)
        self.assertIn("id=m1", self.run_cmd("preview", "--group", "big.example.test", "--show-ids")[1])

    def test_trash_and_deletion_are_refused_everywhere_and_errors_are_fixed(self):
        for act, text in (("trash", "unavailable"), ("delete", "never offered")):
            for argv in (("preview", "--group", "big.example.test", "--action", act), ("plan", "create", "--message-id", "m1", "--action", act),
                         ("plan", "create", "--group", "big.example.test", "--action", act, "--selection-digest", "0" * 64)):
                code, out, err = self.run_cmd(*argv)
                self.assertEqual((code, out), (1, ""), argv)
                self.assertIn(text, err)
        self.assertEqual(self.run_cmd("preview")[::2], (1, "error: select at least one --group (nothing is selected by default)\n"))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)

    def test_the_module_adds_no_policy_no_execution_and_no_network(self):
        src = (ROOT / "src" / "gmail_intelligence" / "cleanup_review.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bimport (socket|urllib|http|smtplib|requests|subprocess|webbrowser|sqlite3|os)\b|https?://|mailto:|INSERT|UPDATE |DELETE |CREATE |_open_reader|gmail_write|cleanup_exec|LIVE_EXECUTION", src))
        self.assertEqual(len(re.findall(r"cp\.create_plan\(", src)), 1)
        self.assertNotRegex(src, r"cp\.(approve|mark_reviewed|revise_exclude)")
        self.assertIn("cc.evaluate_all", src)


if __name__ == "__main__":
    unittest.main()
