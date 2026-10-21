"""Offline tests for M4B: immutable plans, one-time local approvals, freshness, audit chain, schema v4 and the plan CLI.

Synthetic data only, temporary SQLite files, no Gmail/network/Keychain (sockets blocked; Gmail reader and Keychain replaced
by bombs). Approval confirmations are injected by tests; the production CLI only reads them from a real terminal.
"""
import ast
import contextlib
import io
import json
import os
import sqlite3
import stat
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, DAY, NOW, OTHER, SENDER_SENTINEL, Base, msg  # noqa: E402

from gmail_intelligence import classifier, cleanup_audit as audit, cleanup_candidates as cc, cleanup_plans as cp  # noqa: E402
from gmail_intelligence import cleanup_plan_report, cleanup_protect, cli, config  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

T0 = datetime.fromtimestamp(NOW / 1000, tz=timezone.utc)
H = timedelta(hours=1)


class PlanBase(Base):
    def setUp(self):
        super().setUp()
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 6)])
        self.ids = [f"m{i}" for i in range(1, 6)]

    def plan(self, ids=None, now=T0):
        return cp.create_plan(self.index, ACCT, ids or self.ids[:3], now=now)

    def reviewed(self, plan=None, now=T0):
        plan = plan or self.plan()
        return cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan), now=now)

    def approved(self, now=T0):
        plan = self.reviewed(now=now)
        cp.approve(self.index, ACCT, plan["plan_id"], cp.approval_phrase(plan), now=now)
        return cp.get_plan(self.index, ACCT, plan["plan_id"])

    def count(self, table, account=ACCT):
        return self.index._q(f"SELECT COUNT(*) FROM {table} WHERE account=?", account)[0][0]

    def events(self):
        return [e["event_type"] for e in audit.events(self.index, ACCT)]


class CreationTests(PlanBase):
    def test_nothing_is_selected_by_default(self):
        for ids in ([], None):
            with self.assertRaises(cp.PlanError) as cm:
                cp.create_plan(self.index, ACCT, ids or [], now=T0)
            self.assertEqual(cm.exception.code, "NO_TARGETS")
        self.assertEqual(self.count("cleanup_plan"), 0)

    def test_create_binds_exact_targets_and_hash(self):
        p = self.plan()
        self.assertEqual((p["state"], p["action"], p["item_count"], p["version"]), ("DRAFT", "ARCHIVE", 3, 1))
        self.assertEqual(len(p["plan_hash"]), 64)
        self.assertEqual([i["message_id"] for i in p["items"]], ["m1", "m2", "m3"])
        self.assertEqual(cp.integrity_problems(p), [])
        snap = cp.snapshot_of(p)
        self.assertEqual(audit.canonical(snap), p["snapshot"])
        self.assertEqual(audit.sha256(p["snapshot"]), p["plan_hash"])
        self.assertEqual(snap["account"], ACCT)
        self.assertEqual(snap["policy"]["min_age_days"], 90)
        self.assertEqual(len(snap["protection_digest"]), 64)
        self.assertIn("PLAN_CREATED", self.events())
        self.assertNotIn("shop.example.test", p["snapshot"])  # senders are digested, never stored in clear
        self.assertEqual(p["expires_at"], cp._iso(T0 + cp.PLAN_TTL))

    def test_hash_covers_every_security_relevant_field(self):
        facts = cp._facts(self.index, ACCT, ["m1", "m2"])
        items = [facts["m1"], facts["m2"]]
        base = dict(plan_id="plan-x", version=1, parent=None, account=ACCT, created="2026-01-01T00:00:00Z",
                    expires="2026-01-03T00:00:00Z", min_age_days=90, ruleset="r1", protection="p" * 64,
                    anchor={"completeness": "complete", "last_full_scan": "t"}, items=items)
        h = lambda **kw: audit.sha256(audit.canonical(cp._snapshot(**{**base, **kw})))  # noqa: E731
        ref = h()
        self.assertEqual(ref, h())  # deterministic, independent of item order
        self.assertEqual(ref, h(items=list(reversed(items))))
        changed = {"plan_id": "plan-y", "version": 2, "parent": {"plan_id": "a", "hash": "b"}, "account": OTHER,
                   "created": "2026-01-01T00:00:01Z", "expires": "2026-01-03T00:00:01Z", "min_age_days": 120,
                   "ruleset": "r2", "protection": "q" * 64, "anchor": {"completeness": "complete", "last_full_scan": "u"},
                   "items": [facts["m1"]]}
        for key, value in changed.items():
            self.assertNotEqual(ref, h(**{key: value}), key)
        for field in ("thread_id", "internal_ms", "scan_id", "unread", "sender_sha256", "labels_sha256", "class_sha256"):
            tampered = [dict(items[0], **{field: "x" if isinstance(items[0][field], str) else 12345}), items[1]]
            self.assertNotEqual(ref, h(items=tampered), field)

    def test_duplicates_are_collapsed_and_ids_validated(self):
        p = cp.create_plan(self.index, ACCT, ["m1", "m1", "m2"], now=T0)
        self.assertEqual(p["item_count"], 2)
        for bad in (["m1", "bad id"], ["m1;DROP"], [""], ["x" * 65], ["mé"]):
            with self.assertRaises(cp.PlanError, msg=bad) as cm:
                cp.create_plan(self.index, ACCT, bad, now=T0)
            self.assertEqual(cm.exception.code, "BAD_INPUT")

    def test_size_limit(self):
        with self.assertRaises(cp.PlanError) as cm:
            cp.create_plan(self.index, ACCT, [f"id{i}" for i in range(cp.MAX_PLAN_ITEMS + 1)], now=T0)
        self.assertEqual(cm.exception.code, "TOO_MANY")

    def test_unknown_ids_fail_closed(self):
        with self.assertRaises(cp.PlanError) as cm:
            cp.create_plan(self.index, ACCT, ["m1", "nope"], now=T0)
        self.assertEqual(cm.exception.code, "UNKNOWN_IDS")
        self.assertEqual(self.count("cleanup_plan"), 0)
        self.assertNotIn("nope", str(cm.exception))

    def test_age_floor(self):
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, ["m1"], min_age_days=89, now=T0)

    def test_only_message_level_no_thread_expansion(self):
        self.seed([msg(10, thread="T"), msg(11, thread="T"), msg(12, thread="T")])
        p = cp.create_plan(self.index, ACCT, ["m10"], now=T0)
        self.assertEqual([i["message_id"] for i in p["items"]], ["m10"])

    def test_cross_account_isolation(self):
        self.seed([msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 6)], account=OTHER)
        p = self.plan()
        with self.assertRaises(cp.PlanError) as cm:
            cp.get_plan(self.index, OTHER, p["plan_id"])
        self.assertEqual(cm.exception.code, "NO_SUCH_PLAN")
        self.assertEqual(cp.list_plans(self.index, OTHER), [])
        with self.assertRaises(cp.PlanError):
            cp.approve(self.index, OTHER, p["plan_id"], "ARCHIVE 3 " + cp.short(p["plan_hash"]), now=T0)
        q = cp.create_plan(self.index, OTHER, ["m1"], now=T0)
        self.assertEqual(self.count("cleanup_plan", OTHER), 1)
        self.assertNotEqual(q["plan_hash"], p["plan_hash"])


class IneligibleTests(Base):
    def attempt(self, m, **seed_kw):
        self.index.purge(ACCT)
        self.seed([m], **seed_kw)
        with self.assertRaises(cp.PlanError) as cm:
            cp.create_plan(self.index, ACCT, [m["id"]], now=T0)
        self.assertEqual(cm.exception.code, "NOT_ELIGIBLE", cm.exception)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)  # nothing partial
        return str(cm.exception)

    def test_excluded_and_review_required_messages_are_never_planned(self):
        cases = [msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED")), msg(1, labels=("SENT",)),
                 msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "UNREAD")),
                 msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT")),
                 msg(1, labels=("INBOX", "CATEGORY_FORUMS")), msg(1, labels=("INBOX", "CATEGORY_PERSONAL")),
                 msg(1, labels=("INBOX",)), msg(1, days=5), msg(1, labels=("CATEGORY_PROMOTIONS",)),
                 msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "Label_3"))]
        for m in cases:
            self.attempt(m)

    def test_protected_stale_ai_and_mixed_thread(self):
        self.index.purge(ACCT)
        self.seed([msg(1)])
        cleanup_protect.add(self.index, ACCT, domain="shop.example.test")
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, ["m1"], now=T0)
        self.index.purge(ACCT)
        self.seed([msg(1)], classify=False)
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, ["m1"], now=T0)  # unclassified
        self.index.purge(ACCT)
        self.seed([msg(1)])
        with self.index.conn:
            self.index.conn.execute("UPDATE message_class SET source='ai' WHERE kind='type'")
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, ["m1"], now=T0)
        self.index.purge(ACCT)
        cleanup_protect.remove(self.index, ACCT, "p1")  # protection rules survive a purge by design
        self.seed([msg(1, thread="T"), msg(2, thread="T", labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))])
        msg_text = self.attempt_text(["m1"])
        self.assertIn("MIXED_THREAD", msg_text)

    def attempt_text(self, ids):
        with self.assertRaises(cp.PlanError) as cm:
            cp.create_plan(self.index, ACCT, ids, now=T0)
        return str(cm.exception)

    def test_one_bad_target_rejects_the_whole_plan_no_silent_trimming(self):
        self.seed([msg(1), msg(2), msg(3, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))])
        self.assertIn("1 of 3", self.attempt_text(["m1", "m2", "m3"]))
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)

    def test_partial_index_blocks_planning(self):
        self.seed([msg(1)], complete=False)
        with self.assertRaises(cp.PlanError):
            cp.create_plan(self.index, ACCT, ["m1"], now=T0)

    def test_error_messages_carry_no_ids_or_senders(self):
        self.seed([msg(1, sender=SENDER_SENTINEL, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))])
        text = self.attempt_text(["m1"])
        for secret in ("m1", SENDER_SENTINEL, "sentinel"):
            self.assertNotIn(secret, text)


class LifecycleTests(PlanBase):
    def test_review_requires_exact_phrase(self):
        p = self.plan()
        for phrase in ("", "yes", "REVIEWED", "reviewed 3 " + cp.short(p["plan_hash"]), review_wrong(p), None):
            with self.assertRaises(cp.PlanError, msg=phrase) as cm:
                cp.mark_reviewed(self.index, ACCT, p["plan_id"], phrase, now=T0)
            self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")
        self.assertIn("REVIEW_REJECTED", self.events())
        r = cp.mark_reviewed(self.index, ACCT, p["plan_id"], cp.review_phrase(p), now=T0)
        self.assertEqual((r["state"], bool(r["reviewed_at"])), ("REVIEWED", True))

    def test_cannot_approve_draft(self):
        p = self.plan()
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cm.exception.code, "BAD_STATE")

    def test_approval_needs_exact_phrase_with_action_count_and_hash(self):
        p = self.reviewed()
        good = cp.approval_phrase(p)
        self.assertEqual(good, f"ARCHIVE 3 {p['plan_hash'][:8]}")
        for bad in ("", "yes", "ARCHIVE", f"ARCHIVE 4 {p['plan_hash'][:8]}", f"archive 3 {p['plan_hash'][:8]}",
                    f"ARCHIVE 3 {p['plan_hash'][:7]}", f"ARCHIVE 3 {'0' * 8}", f"TRASH 3 {p['plan_hash'][:8]}", good + " now"):
            with self.assertRaises(cp.PlanError, msg=bad) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], bad, now=T0)
            self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")
        self.assertEqual(self.count("cleanup_approval"), 0)
        self.assertEqual(self.events().count("APPROVAL_REJECTED"), 9)  # every rejected attempt (below the lockout limit) is logged
        st = cp.approve(self.index, ACCT, p["plan_id"], good, now=T0)
        self.assertEqual(st["plan_state"], "APPROVED")
        self.assertEqual([a["status"] for a in st["approvals"]], ["VALID"])

    def test_approval_record_is_bound_random_and_short_lived(self):
        p = self.approved()
        a = self.index._q("SELECT * FROM cleanup_approval")[0]
        self.assertEqual((a["plan_hash"], a["action"], a["item_count"], a["status"]), (p["plan_hash"], "ARCHIVE", 3, "VALID"))
        self.assertEqual(len(a["nonce"]), 32)
        self.assertEqual(a["expires_at"], cp._iso(T0 + cp.APPROVAL_TTL))
        ev = audit.events(self.index, ACCT, p["plan_id"])[-1]
        self.assertNotIn(a["nonce"], ev["meta"])  # only a hash of the nonce is logged
        self.assertEqual(self.events()[-1], "PLAN_APPROVED")

    def test_nonces_are_unique_across_plans(self):
        self.approved()
        p2 = self.plan(["m4", "m5"])
        self.reviewed(p2)
        cp.approve(self.index, ACCT, p2["plan_id"], cp.approval_phrase(p2), now=T0)
        nonces = [r[0] for r in self.index._q("SELECT nonce FROM cleanup_approval")]
        self.assertEqual(len(set(nonces)), 2)

    def test_replay_and_duplicate_approval_are_rejected(self):
        p = self.approved()
        for _ in range(2):
            with self.assertRaises(cp.PlanError) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
            self.assertEqual(cm.exception.code, "ALREADY_APPROVED")
        self.assertEqual(self.count("cleanup_approval"), 1)

    def test_database_allows_only_one_valid_approval_per_plan(self):
        p = self.approved()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.index.conn:  # the plan is APPROVED so the trigger refuses first; either way no second VALID row
                self.index.conn.execute("INSERT INTO cleanup_approval VALUES (?,?,?,?,?,?,?,?,?,?)",
                                        (ACCT, p["plan_id"], "n" * 32, p["plan_hash"], "ARCHIVE", 3, "t", "u", "VALID", "t"))

    def test_approval_expires_after_24_hours_and_plan_with_it(self):
        p = self.approved()
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0 + 23 * H), {})
        self.assertEqual(cp.expire_due(self.index, ACCT, T0 + 25 * H), 1)
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "EXPIRED")
        self.assertEqual(self.index._q("SELECT status FROM cleanup_approval")[0][0], "EXPIRED")
        self.assertIn("PLAN_EXPIRED", self.events())
        self.assertIn("APPROVAL_EXPIRED", self.events())
        with self.assertRaises(cp.PlanError):
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0 + 25 * H)

    def test_unapproved_plans_expire_and_cannot_be_approved_late(self):
        p = self.reviewed()
        late = T0 + cp.PLAN_TTL + H
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=late)
        self.assertEqual(cm.exception.code, "BAD_STATE")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "EXPIRED")
        self.assertEqual(self.count("cleanup_approval"), 0)

    def test_approval_never_outlives_the_plan(self):
        p = self.reviewed()
        near_end = T0 + cp.PLAN_TTL - H
        cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=near_end)
        self.assertEqual(self.index._q("SELECT expires_at FROM cleanup_approval")[0][0], p["expires_at"])

    def test_cancel_revokes_and_terminal_states_are_final(self):
        p = self.approved()
        cp.cancel(self.index, ACCT, p["plan_id"], now=T0)
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "CANCELLED")
        self.assertEqual(self.index._q("SELECT status FROM cleanup_approval")[0][0], "REVOKED")
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0).get("NOT_APPROVED"), 1)
        with self.assertRaises(cp.PlanError):
            cp.cancel(self.index, ACCT, p["plan_id"], now=T0)
        with self.assertRaises(cp.PlanError):
            cp.mark_reviewed(self.index, ACCT, p["plan_id"], "x", now=T0)
        with self.assertRaises(cp.PlanError):
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)

    def test_state_transitions_are_atomic_on_failure(self):
        p = self.reviewed()
        real = audit.append
        with mock.patch.object(audit, "append", side_effect=sqlite3.OperationalError("disk full (simulated)")):
            with self.assertRaises(sqlite3.OperationalError):
                cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")  # rolled back together
        self.assertEqual(self.count("cleanup_approval"), 0)
        self.assertFalse(self.index.conn.in_transaction)
        self.assertIs(audit.append, real)
        cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)

    def test_writers_are_serialized(self):
        p = self.reviewed()
        other = idx.Index()
        self.addCleanup(other.close)
        other.conn.execute("PRAGMA busy_timeout = 50")
        self.index.conn.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(sqlite3.OperationalError):
                cp.approve(other, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        finally:
            self.index.conn.rollback()
        cp.approve(other, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        with self.assertRaises(cp.PlanError):  # the first connection now sees the committed approval
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)


def review_wrong(p):
    return f"REVIEWED {p['item_count'] + 1} {cp.short(p['plan_hash'])}"


class RevisionTests(PlanBase):
    def test_exclusion_creates_new_version_and_supersedes_old_approval(self):
        old = self.approved()
        new = cp.revise_exclude(self.index, ACCT, old["plan_id"], ["m2"], now=T0)
        self.assertEqual((new["version"], new["parent_id"], new["state"], new["item_count"]), (2, old["plan_id"], "DRAFT", 2))
        self.assertNotEqual(new["plan_hash"], old["plan_hash"])
        self.assertEqual([i["message_id"] for i in new["items"]], ["m1", "m3"])
        again = cp.get_plan(self.index, ACCT, old["plan_id"])
        self.assertEqual(again["state"], "SUPERSEDED")
        self.assertEqual(self.index._q("SELECT status FROM cleanup_approval WHERE plan_id=?", old["plan_id"])[0][0], "REVOKED")
        ev = self.events()
        self.assertTrue({"PLAN_SUPERSEDED", "APPROVAL_REVOKED"} <= set(ev))
        with self.assertRaises(cp.PlanError):  # the old approval/phrase cannot authorize the new plan
            cp.approve(self.index, ACCT, new["plan_id"], cp.approval_phrase(old), now=T0)
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, new["plan_id"], cp.approval_phrase(new), now=T0)
        self.assertEqual(cm.exception.code, "BAD_STATE")  # still DRAFT: must be reviewed and approved afresh
        self.assertEqual(self.count("cleanup_approval"), 1)

    def test_exclude_validation(self):
        p = self.plan()
        for ids, code in (([], "BAD_INPUT"), (["m5"], "NOT_IN_PLAN"), (["bad id"], "BAD_INPUT"), (["m1", "m2", "m3"], "NO_TARGETS")):
            with self.assertRaises(cp.PlanError, msg=ids) as cm:
                cp.revise_exclude(self.index, ACCT, p["plan_id"], ids, now=T0)
            self.assertEqual(cm.exception.code, code)
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")
        self.assertEqual(self.count("cleanup_plan"), 1)

    def test_revision_revalidates_remaining_targets_and_fails_closed(self):
        p = self.plan()
        cleanup_protect.add(self.index, ACCT, sender="s3@shop.example.test")
        with self.assertRaises(cp.PlanError) as cm:
            cp.revise_exclude(self.index, ACCT, p["plan_id"], ["m1"], now=T0)
        self.assertEqual(cm.exception.code, "NOT_ELIGIBLE")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "DRAFT")  # parent untouched
        self.assertEqual(self.count("cleanup_plan"), 1)

    def test_terminal_plans_cannot_be_revised(self):
        p = self.plan()
        cp.cancel(self.index, ACCT, p["plan_id"], now=T0)
        with self.assertRaises(cp.PlanError) as cm:
            cp.revise_exclude(self.index, ACCT, p["plan_id"], ["m1"], now=T0)
        self.assertEqual(cm.exception.code, "NOT_ACTIVE")


class FreshnessTests(PlanBase):
    def assert_stale(self, plan, code):
        problems = cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, plan["plan_id"]), T0)
        self.assertIn(code, problems, problems)
        return problems

    def test_fresh_plan_has_no_problems(self):
        self.assertEqual(cp.revalidate(self.index, ACCT, self.plan(), T0), {})

    def test_protection_rule_added_between_creation_and_approval_fails_closed_and_recovers(self):
        p = self.reviewed()
        rid = cleanup_protect.add(self.index, ACCT, sender="s1@shop.example.test")
        self.assert_stale(p, "PROTECTION_RULES_CHANGED")
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cm.exception.code, "STALE")
        after = cp.get_plan(self.index, ACCT, p["plan_id"])
        self.assertEqual((after["state"], after["item_count"]), ("REVIEWED", 3))  # nothing trimmed, nothing approved
        self.assertEqual(self.count("cleanup_approval"), 0)
        cleanup_protect.remove(self.index, ACCT, rid)
        self.assertEqual(cp.revalidate(self.index, ACCT, after, T0), {})  # identical state is fresh again

    def test_classification_rule_change(self):
        p = self.plan()
        classifier.add_rule(self.index, ACCT, kind="type", value="SOCIAL", confidence="HIGH", priority=0, domain="elsewhere.example.test")
        self.assert_stale(p, "CLASSIFICATION_RULES_CHANGED")

    def test_label_change_by_rescan_invalidates(self):
        p = self.plan()
        scan = self.index.start_scan(ACCT, "limited", 1)
        self.index.save_batch(ACCT, scan, [msg(1, sender="s1@shop.example.test", labels=("INBOX", "CATEGORY_PROMOTIONS", "Label_4"))])
        self.index.finish_scan(scan, "completed")
        problems = self.assert_stale(p, "ITEM_CHANGED")
        self.assertEqual(problems["ITEM_CHANGED"], 1)

    def test_item_becoming_ineligible_or_missing(self):
        p = self.plan()
        with self.index.conn:
            self.index.conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCT, "m2", "STARRED"))
        self.assert_stale(p, "ITEM_CHANGED")
        self.assert_stale(p, "ITEM_NOT_ELIGIBLE")
        self.assert_stale(p, "REASON_STARRED")
        q = self.plan(["m4", "m5"])
        with self.index.conn:
            self.index.conn.execute("DELETE FROM messages WHERE id='m4'")
        self.assert_stale(q, "ITEM_MISSING")

    def test_changed_policy_account_or_expiry(self):
        p = self.plan()
        with mock.patch.object(cc, "POLICY_VERSION", 99):
            self.assert_stale(p, "POLICY_CHANGED")
        self.assertIn("PLAN_EXPIRED", cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, p["plan_id"]), T0 + cp.PLAN_TTL))
        self.assertEqual(cp.revalidate(self.index, OTHER, cp.get_plan(self.index, ACCT, p["plan_id"]), T0), {"ACCOUNT_MISMATCH": 1})

    def test_new_full_scan_invalidates(self):
        p = self.plan()
        scan = self.index.start_scan(ACCT, "full")
        self.index.save_batch(ACCT, scan, [msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 6)])
        self.index.finish_scan(scan, "completed", )
        self.assertTrue(cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, p["plan_id"]), T0))

    def test_partial_index_makes_plans_stale(self):
        p = self.plan()
        scan = self.index.start_scan(ACCT, "full")  # a newer full scan that never finishes
        self.index.finish_scan(scan, "failed")
        self.assert_stale(p, "INDEX_NOT_COMPLETE")

    def test_tampered_plan_rows_are_detected(self):
        p = self.plan()
        for stmt in ("DROP TRIGGER cleanup_plan_content_immutable", "DROP TRIGGER cleanup_item_no_update"):
            self.index.conn.execute(stmt)
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_plan SET item_count = 2 WHERE plan_id=?", (p["plan_id"],))
        self.assertIn("COLUMN_MISMATCH", cp.integrity_problems(cp.get_plan(self.index, ACCT, p["plan_id"])))
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_plan SET snapshot = snapshot || ' ' WHERE plan_id=?", (p["plan_id"],))
        self.assertEqual(cp.integrity_problems(cp.get_plan(self.index, ACCT, p["plan_id"])), ["HASH_MISMATCH"])
        with self.assertRaises(cp.PlanError):
            cp.mark_reviewed(self.index, ACCT, p["plan_id"], cp.review_phrase(p), now=T0)

    def test_item_table_swap_is_detected(self):
        p = self.plan()
        self.index.conn.execute("DROP TRIGGER cleanup_item_no_update")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_item SET message_id='m5' WHERE message_id='m1' AND plan_id=?", (p["plan_id"],))
        self.assertIn("ITEM_TABLE_MISMATCH", cp.integrity_problems(cp.get_plan(self.index, ACCT, p["plan_id"])))


class VerifyApprovedTests(PlanBase):
    def test_executor_side_check(self):
        p = self.reviewed()
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0).get("NOT_APPROVED"), 1)
        cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0), {})
        cleanup_protect.add(self.index, ACCT, domain="shop.example.test")
        self.assertIn("PROTECTION_RULES_CHANGED", cp.verify_approved(self.index, ACCT, p["plan_id"], T0))
        self.assertIn("APPROVAL_EXPIRED", cp.verify_approved(self.index, ACCT, p["plan_id"], T0 + 24 * H))

    def test_verification_consumes_nothing(self):
        p = self.approved()
        for _ in range(3):
            cp.verify_approved(self.index, ACCT, p["plan_id"], T0)
        self.assertEqual(self.index._q("SELECT status FROM cleanup_approval")[0][0], "VALID")


class ImmutabilityTests(PlanBase):
    def refuse(self, sql, *params):
        with self.assertRaises(sqlite3.DatabaseError, msg=sql):
            with self.index.conn:
                self.index.conn.execute(sql, params)

    def test_database_refuses_content_changes_and_deletes(self):
        p = self.approved()
        pid = p["plan_id"]
        self.refuse("UPDATE cleanup_plan SET plan_hash = ? WHERE plan_id=?", "0" * 64, pid)
        self.refuse("UPDATE cleanup_plan SET snapshot = 'x' WHERE plan_id=?", pid)
        self.refuse("UPDATE cleanup_plan SET action = 'ARCHIVE', version = 9 WHERE plan_id=?", pid)
        self.refuse("UPDATE cleanup_plan SET expires_at = '2999-01-01T00:00:00Z' WHERE plan_id=?", pid)
        self.refuse("UPDATE cleanup_plan SET account = 'x' WHERE plan_id=?", pid)
        self.refuse("DELETE FROM cleanup_plan WHERE plan_id=?", pid)
        self.refuse("UPDATE cleanup_item SET item_digest = 'x' WHERE plan_id=?", pid)
        self.refuse("DELETE FROM cleanup_item WHERE plan_id=?", pid)
        self.refuse("INSERT INTO cleanup_item VALUES (?,?,?,?,?)", ACCT, pid, "m5", "t5", "d")
        self.refuse("UPDATE cleanup_approval SET plan_hash = ? WHERE plan_id=?", "0" * 64, pid)
        self.refuse("UPDATE cleanup_approval SET expires_at = '2999-01-01T00:00:00Z' WHERE plan_id=?", pid)
        self.refuse("DELETE FROM cleanup_approval WHERE plan_id=?", pid)
        self.refuse("UPDATE cleanup_audit SET event_type = 'PLAN_CANCELLED'")
        self.refuse("DELETE FROM cleanup_audit")

    def test_illegal_state_transitions_are_refused(self):
        p = self.reviewed()
        self.refuse("UPDATE cleanup_plan SET state='DRAFT' WHERE plan_id=?", p["plan_id"])
        self.refuse("UPDATE cleanup_plan SET state='EXECUTING' WHERE plan_id=?", p["plan_id"])  # not even in the CHECK list
        cp.cancel(self.index, ACCT, p["plan_id"], now=T0)
        for state in ("REVIEWED", "APPROVED", "DRAFT"):
            self.refuse("UPDATE cleanup_plan SET state=? WHERE plan_id=?", state, p["plan_id"])

    def test_approvals_cannot_be_resurrected_or_forged(self):
        p = self.approved()
        cp.cancel(self.index, ACCT, p["plan_id"], now=T0)
        self.refuse("UPDATE cleanup_approval SET status='VALID' WHERE plan_id=?", p["plan_id"])
        q = self.plan(["m4", "m5"])  # a DRAFT plan cannot receive an approval row
        self.refuse("INSERT INTO cleanup_approval VALUES (?,?,?,?,?,?,?,?,?,?)",
                    ACCT, q["plan_id"], "f" * 32, q["plan_hash"], "ARCHIVE", 2, "t", "u", "VALID", "t")
        self.refuse("INSERT INTO cleanup_plan (account,plan_id,version,action,state,plan_hash,snapshot,item_count,created_at,"
                    "expires_at,state_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ACCT, "plan-forged", 1, "ARCHIVE", "APPROVED", "0" * 64, "{}", 1, "t", "u", "t")
        self.refuse("INSERT INTO cleanup_plan (account,plan_id,version,action,state,plan_hash,snapshot,item_count,created_at,"
                    "expires_at,state_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ACCT, "plan-trash", 1, "TRASH", "DRAFT", "0" * 64, "{}", 1, "t", "u", "t")

    def test_schema_has_no_execution_states_or_actions(self):
        sql = idx.SCHEMA_V4
        for word in ("EXECUTING", "EXECUTED", "PARTIAL", "FAILED", "'TRASH'", "UNDO"):
            self.assertNotIn(word, sql)

    def test_purge_and_mailbox_commands_keep_plans_and_audit(self):
        self.approved()
        before = [self.count(t) for t in ("cleanup_plan", "cleanup_item", "cleanup_approval", "cleanup_audit")]
        self.index.purge(ACCT)
        self.assertEqual([self.count(t) for t in ("cleanup_plan", "cleanup_item", "cleanup_approval", "cleanup_audit")], before)


class AuditTests(PlanBase):
    def test_chain_links_and_verifies(self):
        self.approved()
        ok, n, bad = audit.verify_chain(self.index, ACCT)
        self.assertEqual((ok, bad), (True, None))
        self.assertEqual(n, 3)  # created, reviewed, approved
        rows = self.index._q("SELECT prev_hash, hash FROM cleanup_audit ORDER BY seq")
        self.assertEqual(rows[0]["prev_hash"], audit.GENESIS)
        self.assertEqual(rows[1]["prev_hash"], rows[0]["hash"])

    def test_chains_are_per_account(self):
        self.seed([msg(1, sender="x@shop.example.test")], account=OTHER)
        cp.create_plan(self.index, OTHER, ["m1"], now=T0)
        self.plan()
        self.assertEqual(audit.verify_chain(self.index, ACCT)[1], 1)
        self.assertEqual(audit.verify_chain(self.index, OTHER)[1], 1)
        first = self.index._q("SELECT prev_hash FROM cleanup_audit WHERE account=?", OTHER)[0][0]
        self.assertEqual(first, audit.GENESIS)

    def test_alteration_and_removal_are_detected_when_triggers_are_bypassed(self):
        self.approved()
        for t in ("cleanup_audit_no_update", "cleanup_audit_no_delete"):
            self.index.conn.execute(f"DROP TRIGGER {t}")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_audit SET at='2000-01-01T00:00:00Z' WHERE seq=2")
        ok, _, bad = audit.verify_chain(self.index, ACCT)
        self.assertEqual((ok, bad), (False, 2))
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_audit SET at=(SELECT at FROM cleanup_audit WHERE seq=1) WHERE seq=2")
            self.index.conn.execute("DELETE FROM cleanup_audit WHERE seq=2")
        self.assertFalse(audit.verify_chain(self.index, ACCT)[0])

    def test_events_hold_no_ids_senders_or_labels(self):
        p = self.approved()
        text = " ".join(f"{e['event_type']} {e['meta']}" for e in audit.events(self.index, ACCT))
        for secret in ("m1", "m2", "m3", "shop.example.test", "Label_", "INBOX"):
            self.assertNotIn(secret, text)
        self.assertIn(p["plan_hash"], text)

    def test_metadata_must_be_flat(self):
        self.index.conn.execute("BEGIN IMMEDIATE")
        try:
            for bad in ({"ids": ["m1"]}, {"x": "a" * 201}, {"d": {"k": ["v"]}}, {1: "a"}):
                with self.assertRaises(ValueError):
                    audit.append(self.index, ACCT, "p", "PLAN_CREATED", "t", bad)
            with self.assertRaises(ValueError):
                audit.append(self.index, ACCT, "p", "NOT_AN_EVENT", "t", {})
        finally:
            self.index.conn.rollback()

    def test_all_lifecycle_events_are_recorded(self):
        p = self.approved()
        new = cp.revise_exclude(self.index, ACCT, p["plan_id"], ["m1"], now=T0)
        cp.cancel(self.index, ACCT, new["plan_id"], now=T0)
        with self.assertRaises(cp.PlanError):
            cp.approve(self.index, ACCT, new["plan_id"], "x", now=T0)
        got = set(self.events())
        self.assertTrue({"PLAN_CREATED", "PLAN_REVIEWED", "PLAN_APPROVED", "PLAN_SUPERSEDED", "APPROVAL_REVOKED", "PLAN_CANCELLED",
                         "APPROVAL_REJECTED"} <= got, got)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])


class MigrationV4Tests(Base):
    def make_v3(self):
        path = self.tmp / "v3" / "index.sqlite3"
        path.parent.mkdir(mode=0o700, parents=True)
        conn = sqlite3.connect(path)
        conn.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + "PRAGMA user_version = 3;COMMIT;")
        conn.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", (ACCT, "m1", "t1", 1000, 10, "a@x.example.test", 0, 1))
        conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCT, "m1", "INBOX"))
        conn.execute("INSERT INTO protect_rules (account,id,c_domain,enabled,created_at) VALUES (?,?,?,?,?)",
                     (ACCT, "p1", "x.example.test", 1, "t"))
        conn.execute("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (ACCT, "m1", "type", "UNKNOWN", "LOW", "rules", "engine.no-match", "x", "h", 1, "t"))
        conn.commit()
        conn.close()
        return path

    def logical(self, path):
        c = sqlite3.connect(path)
        data = {t: c.execute(f"SELECT * FROM {t} ORDER BY 1,2,3").fetchall()
                for t in ("messages", "message_labels", "protect_rules", "message_class")}
        c.close()
        return data

    def test_v3_upgrade_preserves_all_rows_with_private_backup(self):
        path = self.make_v3()
        before = self.logical(path)
        with idx.Index(str(path), allow_upgrade=True) as index:
            self.assertEqual((index.migrated_from, index.conn.execute("PRAGMA user_version").fetchone()[0]), (3, idx.SCHEMA_VERSION))
            for t in ("cleanup_plan", "cleanup_item", "cleanup_approval", "cleanup_audit"):
                self.assertEqual(index._q(f"SELECT COUNT(*) FROM {t}")[0][0], 0)
            backup = Path(index.backup_path)
        self.assertEqual(self.logical(path), before)
        self.assertIn("pre-m4b-backup", backup.name)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        b = sqlite3.connect(backup)
        self.assertEqual(b.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(b.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'cleanup_%'").fetchone()[0], 0)
        b.close()
        self.assertEqual(self.logical(backup), before)
        with idx.Index(str(path), allow_upgrade=True) as again:
            self.assertIsNone(again.migrated_from)
        self.assertEqual(len(list(path.parent.glob("*backup*"))), 1)

    def test_failed_upgrade_leaves_v3_intact(self):
        path = self.make_v3()
        before = self.logical(path)
        with mock.patch.object(idx, "SCHEMA_V4", "CREATE TABLE cleanup_plan (x);CREATE TABLE cleanup_plan (x);"):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(path), allow_upgrade=True)
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'cleanup_%'").fetchone()[0], 0)
        c.close()
        self.assertEqual(self.logical(path), before)

    def test_backup_failure_aborts_before_any_change(self):
        path = self.make_v3()
        real = os.chmod

        def picky(p, mode):
            if "backup" in str(p):
                raise OSError("simulated")
            return real(p, mode)
        with mock.patch.object(idx.os, "chmod", side_effect=picky):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(path), allow_upgrade=True)
        c = sqlite3.connect(path)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 3)
        c.close()

    def test_v1_and_v2_chains_reach_the_latest_schema(self):
        for version in (1, 2):
            path = self.tmp / f"chain{version}" / "index.sqlite3"
            path.parent.mkdir(mode=0o700, parents=True)
            c = sqlite3.connect(path)
            c.executescript("BEGIN;" + idx.SCHEMA + (idx.SCHEMA_V2 if version == 2 else "") + f"PRAGMA user_version = {version};COMMIT;")
            c.close()
            with idx.Index(str(path), allow_upgrade=True) as index:
                self.assertEqual(index.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
                self.assertEqual(index._q("SELECT COUNT(*) FROM cleanup_plan")[0][0], 0)

    def test_foreign_keys_are_enforced(self):
        with idx.Index() as index:
            with self.assertRaises(sqlite3.IntegrityError):
                with index.conn:
                    index.conn.execute("INSERT INTO cleanup_item VALUES (?,?,?,?,?)", (ACCT, "plan-none", "m1", "t", "d"))


class CliTests(PlanBase):
    def run_cli(self, *argv, inputs=None, tty=True):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(inputs or [])

        def fake(prompt):
            try:
                return next(feed)
            except StopIteration:
                raise EOFError from None
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")),
                   mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used"))]
        if tty:
            patches.append(mock.patch.object(cli, "_tty_input", side_effect=fake))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        super().setUp()
        self.a = ("--account", ACCT)

    def create(self, *ids):
        # real wall-clock: the CLI uses the current time, so seed messages relative to now
        return self.run_cli("cleanup", "plan", "create", *self.a, *[x for i in ids for x in ("--message-id", i)])

    def reseed_now(self, n=5):
        self.index.purge(ACCT)
        import time
        ms = int(time.time() * 1000) - 200 * DAY
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, n + 1)])

    def test_create_show_review_approve_end_to_end(self):
        self.reseed_now(30)
        ids = [f"m{i}" for i in range(1, 29)]
        code, out, _ = self.create(*ids)
        self.assertEqual(code, 0, out)
        pid = out.split()[1]
        self.assertIn("Nothing was approved or executed", out)
        code, out, _ = self.run_cli("cleanup", "plan", "list", *self.a)
        self.assertIn(pid, out)
        self.assertIn("DRAFT", out)
        code, out, _ = self.run_cli("cleanup", "plan", "show", pid, *self.a)
        self.assertEqual(code, 0, out)
        for needle in ("<account hidden>", "fresh against the LOCAL index", "LOCAL record only"):
            self.assertIn(needle, out)
        self.assertNotIn("m1", out.replace("targets by", ""))
        self.assertNotIn(ACCT, out)
        self.assertNotIn("shop.example.test", out)
        code, out, _ = self.run_cli("cleanup", "plan", "show", pid, "--page", "2", "--page-size", "10", *self.a)
        self.assertIn("page 2/3", out)
        self.assertIn("(id hidden", out)
        self.assertIn("m19", self.run_cli("cleanup", "plan", "show", pid, "--page", "2", "--page-size", "10", "--show-ids", *self.a)[1])
        plan = cp.get_plan(self.index, ACCT, pid)
        # review needs the typed phrase after paging through every page (28 targets = 2 pages)
        code, out, err = self.run_cli("cleanup", "plan", "review", pid, *self.a, inputs=["", cp.review_phrase(plan)])
        self.assertEqual(code, 0, err)
        for i in ids:
            self.assertIn(i + "\n", out)
        self.assertEqual(cp.get_plan(self.index, ACCT, pid)["state"], "REVIEWED")
        # approval: wrong, then right
        code, _, err = self.run_cli("cleanup", "approve", pid, *self.a, inputs=["yes"])
        self.assertEqual(code, 1)
        self.assertEqual(cp.get_plan(self.index, ACCT, pid)["state"], "REVIEWED")
        code, out, _ = self.run_cli("cleanup", "approve", pid, *self.a, inputs=[cp.approval_phrase(plan)])
        self.assertEqual(code, 0, out)
        self.assertIn("APPROVED locally", out)
        self.assertIn("Nothing was executed", out)
        st = self.run_cli("cleanup", "approval", "status", pid, *self.a)[1]
        self.assertIn("VALID", st)
        self.assertIn("does not authorize Gmail", st)
        again = self.run_cli("cleanup", "approve", pid, *self.a, inputs=[cp.approval_phrase(plan)])
        self.assertEqual(again[0], 1)
        self.assertIn("already has an approval", again[2])

    def test_approval_is_impossible_without_a_real_terminal_or_with_flags(self):
        self.reseed_now()
        pid = self.create("m1", "m2")[1].split()[1]
        plan = cp.get_plan(self.index, ACCT, pid)
        cp.mark_reviewed(self.index, ACCT, pid, cp.review_phrase(plan))
        self.assertEqual(self.run_cli("cleanup", "approve", pid, *self.a, "--yes")[0], 2)
        self.assertEqual(self.run_cli("cleanup", "approve", pid, *self.a, "--phrase", cp.approval_phrase(plan))[0], 2)
        # piped (non-tty) stdin must fail closed even when it contains the correct phrase
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(cp.approval_phrase(plan) + "\n")):
            self.assertEqual(cli.main(["cleanup", "approve", pid, *self.a]), 1)
        self.assertIn("interactive terminal", err.getvalue())
        self.assertEqual(cp.get_plan(self.index, ACCT, pid)["state"], "REVIEWED")
        self.assertEqual(self.run_cli("cleanup", "approve", pid, *self.a, inputs=[])[0], 1)  # EOF -> no approval
        self.assertEqual(self.count("cleanup_approval"), 0)

    def test_cancel_exclude_and_errors(self):
        self.reseed_now()
        pid = self.create("m1", "m2", "m3")[1].split()[1]
        code, out, _ = self.run_cli("cleanup", "plan", "exclude", pid, "--message-id", "m2", *self.a)
        self.assertEqual(code, 0, out)
        self.assertIn("SUPERSEDED", out)
        new = out.split()[1]
        self.assertEqual(self.run_cli("cleanup", "plan", "cancel", new, *self.a, inputs=["n"])[0], 1)
        self.assertEqual(cp.get_plan(self.index, ACCT, new)["state"], "DRAFT")
        self.assertEqual(self.run_cli("cleanup", "plan", "cancel", new, *self.a, inputs=["y"])[0], 0)
        self.assertEqual(self.run_cli("cleanup", "plan", "cancel", new, *self.a, inputs=["y"])[0], 1)
        self.assertEqual(self.run_cli("cleanup", "plan", "show", "plan-nope", *self.a)[0], 1)
        self.assertEqual(self.run_cli("cleanup", "plan", "create", *self.a)[0], 1)
        self.assertEqual(self.create("m1", "zzz")[0], 1)
        self.assertEqual(self.run_cli("cleanup", "plan", "show", pid, "--page-size", "0", *self.a)[0], 1)

    def test_ids_file_and_export_ids(self):
        self.reseed_now()
        target = self.tmp / "ids.txt"
        code, out, _ = self.run_cli("cleanup", "candidates", *self.a, "--limit", "3", "--export-ids", str(target))
        self.assertEqual(code, 0, out)
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        lines = [l for l in target.read_text().splitlines() if not l.startswith("#")]
        self.assertEqual(len(lines), 3)
        self.assertNotIn("m1", out.split("Wrote")[-1])  # ids are written to the private file, not echoed to the terminal
        self.assertEqual(self.run_cli("cleanup", "candidates", *self.a, "--limit", "3", "--export-ids", str(target))[0], 1)  # exists
        inside = ROOT / "should-not-exist.txt"
        self.assertEqual(self.run_cli("cleanup", "candidates", *self.a, "--limit", "3", "--export-ids", str(inside))[0], 1)
        self.assertFalse(inside.exists())
        self.assertEqual(self.run_cli("cleanup", "candidates", *self.a, "--limit", "0", "--export-ids", str(self.tmp / "z"))[0], 1)
        code, out, _ = self.run_cli("cleanup", "plan", "create", *self.a, "--ids-file", str(target))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.run_cli("cleanup", "plan", "create", *self.a, "--ids-file", str(self.tmp / "missing"))[0], 1)

    def test_audit_commands(self):
        self.reseed_now()
        self.create("m1")
        code, out, _ = self.run_cli("cleanup", "audit", "verify", *self.a)
        self.assertEqual(code, 0)
        self.assertIn("consistent", out)
        log = self.run_cli("cleanup", "audit", "log", *self.a)[1]
        self.assertIn("PLAN_CREATED", log)
        self.assertNotIn("m1", log)
        self.index.conn.execute("DROP TRIGGER cleanup_audit_no_update")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_audit SET at='2000-01-01T00:00:00Z'")
        self.assertEqual(self.run_cli("cleanup", "audit", "verify", *self.a)[0], 1)

    def test_no_default_account_leak_and_expiry_is_applied_on_use(self):
        self.reseed_now()
        pid = self.create("m1")[1].split()[1]
        with mock.patch.object(cp, "_utc", return_value=datetime.now(timezone.utc) + timedelta(days=3)):
            out = self.run_cli("cleanup", "plan", "list", *self.a)[1]
        self.assertIn("EXPIRED", out)
        self.assertEqual(cp.get_plan(self.index, ACCT, pid)["state"], "EXPIRED")


class SourceGuards(unittest.TestCase):
    MODULES = ("cleanup_plans.py", "cleanup_audit.py", "cleanup_plan_report.py")
    ALLOWED_LOCAL = {"classifier", "cleanup_audit", "cleanup_candidates", "cleanup_protect", "cleanup_plans", "report", "classify", "sync_health",
                     "index", "config"}

    def test_m4b_modules_perform_no_gmail_network_or_execution(self):
        for name in self.MODULES:
            path = SRC / "gmail_intelligence" / name
            text = path.read_text()
            for node in ast.walk(ast.parse(text)):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module] + [f"gmail_intelligence.{a.name}" for a in node.names] if node.module == "gmail_intelligence" \
                        else [node.module]
                for m in mods:
                    top = m.split(".")[0]
                    if top == "gmail_intelligence":
                        leaf = m.split(".")[1] if "." in m else None
                        self.assertIn(leaf, self.ALLOWED_LOCAL | {None}, (name, m))
                    else:
                        self.assertIn(top, {"contextlib", "json", "secrets", "sqlite3", "hashlib", "datetime"}, (name, m))
            for banned in ("googleapiclient", "google.", "keystore", "oauth", "urllib", "socket", "subprocess", "requests",
                           "batchModify", "gmail.modify", ".trash(", ".send(", "untrash", "ai_http", "scanner"):
                self.assertNotIn(banned, text, (name, banned))
            self.assertNotRegex(text, r"\b(eval|exec|compile|__import__)\(")
            self.assertNotRegex(text, r"execute\(\s*f[\"'][^\"']*(account|plan_id)")  # SQL values are always parameters

    def test_cli_has_no_unattended_approval_path(self):
        text = (SRC / "gmail_intelligence" / "cli.py").read_text()
        approve = text[text.index("def cmd_cleanup_approve"):text.index("def cmd_cleanup_approval_status")]
        self.assertNotIn("args.yes", approve)
        self.assertNotIn("args.phrase", approve)
        self.assertIn("_tty_input", approve)
        self.assertIn("isatty()", text[text.index("def _tty_input"):text.index("def _plan_cmd")])

    def test_report_text_states_local_only(self):
        self.assertIn("LOCAL record only", cleanup_plan_report.NOT_AN_AUTH)
        self.assertIn("grants no Gmail permission", cleanup_plan_report.NOT_AN_AUTH)


if __name__ == "__main__":
    unittest.main()
