"""M8A-1: the attention pipeline end to end on synthetic mailboxes (complete results, order, thread collapse, sender diversity, pagination, snapshot, privacy)."""
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta

import attention_support as S
from attention_support import ACCOUNT, NOW, OTHER, MailboxCase, attention, classifier, classify, idx, ms_ago

LEAK = "marker-leak-7741"


def ids(res):
    return [i["rank"] for i in res["items"]]


def scores(res):
    return [i["score"] for i in res["items"]]


class CompleteProcessingTests(MailboxCase):
    def test_the_oldest_item_is_shown_first_when_it_has_the_highest_priority(self):
        for k in range(30):
            self.mb.add(labels=("INBOX", "UNREAD"), age_days=5 + k % 5)
        oldest = self.mb.add("00ffffff", labels=("INBOX", "STARRED", "IMPORTANT"), age_days=3000)
        res = self.mb.compute(limit=100)
        self.assertEqual(res["totals"]["total"], 31)
        self.assertEqual(res["items"][0]["score"], 70)
        self.assertEqual(res["items"][0]["date"], min(i["date"] for i in res["items"]))  # the oldest message of the mailbox, ranked first
        self.assertEqual(oldest, "00ffffff")

    def test_nothing_is_dropped_because_of_the_size_of_the_mailbox(self):
        for k in range(70):
            self.mb.add(labels=("INBOX", "STARRED"), age_days=k)
        res = self.mb.compute(limit=100, sender_limit=0)
        self.assertEqual((res["totals"]["total"], len(res["items"])), (70, 70))

    def test_over_budget_fails_explicitly_with_no_items_independent_of_row_order(self):
        for k in range(6):
            self.mb.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k)
        for budget in (5, 1):
            with self.assertRaises(attention.AttentionError) as cm:
                self.mb.compute(budget=budget)
            self.assertEqual(cm.exception.code, "RESULT_INCOMPLETE")
        other = S.Mailbox()
        self.addCleanup(other.close)
        for k in reversed(range(6)):
            other.add(f"{k:08x}", labels=("INBOX", "STARRED"), age_days=k)
        with self.assertRaises(attention.AttentionError) as cm:
            other.compute(budget=5)
        self.assertEqual(cm.exception.code, "RESULT_INCOMPLETE")
        self.assertEqual(self.mb.compute(budget=6)["totals"]["total"], 6)  # exactly the budget is complete

    def test_collapsed_duplicates_do_not_count_against_the_budget(self):
        for k in range(8):
            self.mb.add(f"{k:08x}", thread="same", labels=("INBOX", "STARRED"))
        self.assertEqual(self.mb.compute(budget=1)["totals"]["threads"], 1)

    def test_the_message_error_texts_contain_only_the_code_and_fixed_words(self):
        for code in attention.ERRORS:
            self.assertEqual(str(attention.AttentionError(code)), code)
            self.assertNotRegex(attention.AttentionError(code).message, r"[0-9a-f]{8,}|@|/")


class EligibilityTests(MailboxCase):
    def test_sent_draft_trash_spam_and_chat_are_excluded_even_when_starred(self):
        for lab in ("SENT", "DRAFT", "TRASH", "SPAM", "CHAT"):
            self.mb.add(labels=("INBOX", "STARRED", lab))
        keep = self.mb.add(labels=("INBOX", "STARRED"))
        res = self.mb.compute()
        self.assertEqual((res["totals"]["total"], res["totals"]["excluded"]), (1, 5))
        self.assertEqual(len(res["items"]), 1)
        self.assertIsNotNone(keep)

    def test_archived_starred_mail_is_included_and_flagged(self):
        self.mb.add(labels=("STARRED",))
        res = self.mb.compute()
        self.assertEqual(res["items"][0]["flags"], ["NOT_IN_INBOX"])
        self.assertEqual(res["items"][0]["evidence"], "OWNER_ASSERTED")

    def test_low_scores_appear_only_when_explicitly_requested_and_zero_never(self):
        self.mb.add(labels=("INBOX", "UNREAD"), age_days=0.5)    # 10
        self.mb.add(labels=("INBOX", "UNREAD"), age_days=200)    # 0
        self.assertEqual(self.mb.compute()["items"], [])
        res = self.mb.compute(include_low_score=True)
        self.assertEqual(scores(res), [10])
        self.assertEqual(res["items"][0]["tier"], "MINIMAL")

    def test_filters(self):
        a = self.mb.add(labels=("INBOX", "STARRED"))
        b = self.mb.add(labels=("INBOX", "IMPORTANT"))
        c = self.mb.add(labels=("INBOX", "UNREAD"), age_days=5)
        self.assertEqual(self.mb.compute(signals=("starred",))["totals"]["total"], 1)
        self.assertEqual(self.mb.compute(signals=("important", "unread"))["totals"]["total"], 2)
        self.assertEqual(self.mb.compute(signals=("rule",))["totals"]["total"], 0)
        self.assertEqual(self.mb.compute(min_tier="medium")["totals"]["total"], 1)
        self.assertEqual(self.mb.compute(min_tier="low")["totals"]["total"], 3)
        self.assertEqual(self.mb.compute(min_tier="high")["totals"]["total"], 0)
        self.assertEqual(len({a, b, c}), 3)

    def test_a_user_attention_rule_finds_messages_that_carry_none_of_the_three_labels(self):
        plain = self.mb.add(sender="boss@vip.example.test", labels=("INBOX",))
        self.mb.add(sender="x@other.example.test", labels=("INBOX",))
        self.mb.add_rule(kind="attention", value="POTENTIALLY_IMPORTANT", confidence="MEDIUM", domain="vip.example.test")
        res = self.mb.compute()
        self.assertEqual((res["totals"]["total"], res["items"][0]["evidence"], res["items"][0]["signals"][0]["code"]), (1, "OWNER_ASSERTED", "USER_RULE"))
        self.assertEqual(self.mb.compute(signals=("rule",))["totals"]["total"], 1)
        self.assertEqual(self.mb.compute(signals=("starred",))["totals"]["total"], 0)
        self.assertIsNotNone(plain)


class CollapseDiversityOrderTests(MailboxCase):
    def test_a_thread_is_represented_by_its_best_message_and_counted(self):
        self.mb.add("00000001", thread="T", labels=("INBOX", "UNREAD"), age_days=5)
        self.mb.add("00000002", thread="T", labels=("INBOX", "STARRED"), age_days=9)
        self.mb.add("00000003", thread="T", labels=("INBOX", "IMPORTANT"), age_days=1)
        res = self.mb.compute()
        self.assertEqual((len(res["items"]), res["items"][0]["score"], res["items"][0]["thread_messages"]), (1, 50, 3))
        self.assertEqual(res["totals"]["collapsed_messages"], 2)
        flat = self.mb.compute(collapse=False)
        self.assertEqual(len(flat["items"]), 3)
        self.assertTrue(all(i["thread_messages"] == 1 for i in flat["items"]))

    def test_a_message_without_a_thread_id_is_its_own_thread(self):
        self.mb.add("00000001", thread=None, labels=("INBOX", "STARRED"))
        self.mb.add("00000002", thread="", labels=("INBOX", "STARRED"))
        self.assertEqual(self.mb.compute()["totals"]["threads"], 2)

    def test_the_sender_limit_keeps_the_best_items_and_reports_the_rest(self):
        for k in range(5):
            self.mb.add(f"{k:08x}", sender="spam@bulk.example.test", labels=("INBOX", "IMPORTANT") if k % 2 else ("INBOX", "STARRED"), age_days=k + 1)
        self.mb.add("000000aa", sender="other@example.test", labels=("INBOX", "IMPORTANT"))
        res = self.mb.compute()
        self.assertEqual((res["totals"]["suppressed_by_sender_limit"], res["totals"]["total"]), (2, 4))
        kept = [i["score"] for i in res["items"]]
        self.assertEqual(sorted(kept, reverse=True), [50, 50, 50, 20])
        self.assertEqual(self.mb.compute(sender_limit=0)["totals"]["total"], 6)
        self.assertEqual(self.mb.compute(sender_limit=1)["totals"]["total"], 2)

    def test_the_sender_limit_is_decided_by_priority_not_by_the_requested_sort(self):
        for k in range(4):
            self.mb.add(f"{k:08x}", sender="a@bulk.example.test", labels=("INBOX", "STARRED"), age_days=10 - k)
        self.mb.add("000000ff", sender="a@bulk.example.test", labels=("INBOX", "IMPORTANT"), age_days=0.1)  # newest but lowest priority
        by_priority = self.mb.compute(sort="priority", limit=100)
        by_date = self.mb.compute(sort="date", limit=100)
        self.assertEqual(sorted(scores(by_priority)), sorted(scores(by_date)))
        self.assertNotIn(20, scores(by_date))

    def test_the_order_key_is_a_total_order_with_documented_tie_breakers(self):
        self.mb.add("00000003", labels=("INBOX", "STARRED"), age_days=3, sender="a@x.test")
        self.mb.add("00000001", labels=("INBOX", "STARRED"), age_days=3, sender="b@x.test")
        self.mb.add("00000002", labels=("INBOX", "STARRED"), age_days=1, sender="c@x.test")
        self.mb.add("00000004", labels=("INBOX", "IMPORTANT", "UNREAD"), age_days=4, sender="d@x.test")  # score 20+15 = 35
        res = self.mb.compute(sender_limit=0)
        self.assertEqual(scores(res), [50, 50, 50, 35])
        first, second, third = (i["date"] for i in res["items"][:3])
        self.assertEqual(first, (S.NOW - timedelta(days=1)).date().isoformat())  # newest first among equal scores ...
        self.assertEqual(second, third)  # ... and equal dates end in the message id (checked by the insertion-order determinism test)

    def test_sorts(self):
        self.mb.add(labels=("INBOX", "STARRED"), age_days=5)
        self.mb.add(labels=("INBOX", "IMPORTANT"), age_days=1)
        self.mb.add(labels=("INBOX", "UNREAD", "IMPORTANT"), age_days=9)
        by = {s: [i["date"] for i in self.mb.compute(sort=s, sender_limit=0)["items"]] for s in attention.SORTS}
        self.assertEqual(by["date"], sorted(by["date"], reverse=True))
        self.assertEqual(by["oldest"], sorted(by["oldest"]))
        self.assertEqual(scores(self.mb.compute(sender_limit=0)), sorted(scores(self.mb.compute(sender_limit=0)), reverse=True))

    def test_messages_without_a_date_sort_last_by_date_and_oldest(self):
        self.mb.add("00000001", labels=("INBOX", "STARRED"), ms=None)
        self.mb.add("00000002", labels=("INBOX", "STARRED"), age_days=2)
        for s in ("date", "oldest"):
            res = self.mb.compute(sort=s, sender_limit=0)
            self.assertIsNone(res["items"][-1]["date"], s)
            self.assertIn("DATE_MISSING", res["items"][-1]["flags"])


class PaginationTests(MailboxCase):
    def setUp(self):
        super().setUp()
        rnd = random.Random(5)
        for k in range(57):
            labels = ["INBOX"] + [l for l in ("STARRED", "IMPORTANT", "UNREAD") if rnd.random() < 0.5]
            self.mb.add(f"{k:08x}", sender=f"s{k % 11}@example.test", labels=tuple(labels), age_days=rnd.randint(0, 80))

    def pages(self, limit, **kw):
        out, cursor = [], None
        while True:
            res = self.mb.compute(limit=limit, cursor=cursor, **kw)
            out.append(res)
            cursor = res["next_cursor"]
            if cursor is None:
                return out

    def test_pages_together_equal_the_full_list_without_overlap_or_gap(self):
        for sort in attention.SORTS:
            full = self.mb.compute(limit=100, sort=sort, sender_limit=0, include_low_score=True)
            for size in (1, 7, 25, 100):
                got = [i for page in self.pages(size, sort=sort, sender_limit=0, include_low_score=True) for i in page["items"]]
                self.assertEqual(got, full["items"], (sort, size))
                self.assertEqual([i["rank"] for i in got], list(range(1, len(got) + 1)))

    def test_the_page_size_does_not_invalidate_a_cursor(self):
        first = self.mb.compute(limit=5)
        self.assertEqual(len(self.mb.compute(limit=20, cursor=first["next_cursor"])["items"]), 20)

    def test_the_last_page_has_no_cursor_and_default_and_maximum_sizes_hold(self):
        self.assertEqual(len(self.mb.compute()["items"]), 25)
        self.assertEqual(len(self.mb.compute(limit=100)["items"]), self.mb.compute(limit=100)["totals"]["total"])
        for bad in (0, 101, -1, True, "5", None):
            with self.assertRaises(ValueError):
                self.mb.compute(limit=bad)

    def test_invalid_parameters_are_rejected_with_fixed_text(self):
        for kw in ({"sort": "x"}, {"signals": ("x",)}, {"min_tier": "x"}, {"sender_limit": 11}, {"sender_limit": -1}):
            with self.assertRaises(ValueError):
                self.mb.compute(**kw)


class CursorTests(MailboxCase):
    def setUp(self):
        super().setUp()
        for k in range(30):
            self.mb.add(f"{k:08x}", sender=f"s{k}@example.test", labels=("INBOX", "STARRED"), age_days=k)
        self.first = self.mb.compute(limit=10)
        self.cursor = self.first["next_cursor"]

    def fails(self, code, **kw):
        with self.assertRaises(attention.AttentionError) as cm:
            self.mb.compute(**kw)
        self.assertEqual(cm.exception.code, code)

    def test_the_cursor_is_opaque_and_carries_no_identifier_or_text(self):
        self.assertRegex(self.cursor, r"^a1\.\d{8}\.[0-9a-f]{64}\.\d{1,7}\.[0-9a-f]{16}$")
        for forbidden in (ACCOUNT, "example", "s1@", "00000009", "owner", "friend"):
            self.assertNotIn(forbidden, self.cursor)

    def test_malformed_cursors_are_invalid(self):
        for bad in ("", "x", self.cursor + "0", self.cursor.upper(), self.cursor.replace("a1.", "a2."), self.cursor[:-1], "a1.20261021." + "0" * 64 + ".0." + "0" * 16,
                    "a1.20261399." + "0" * 64 + ".1." + "0" * 16, self.cursor + " ", "a1." * 60, None.__class__.__name__):
            self.fails("CURSOR_INVALID", cursor=bad)
        self.fails("CURSOR_INVALID", cursor=12345)

    def test_a_mutated_position_or_key_is_invalid_and_a_mutated_snapshot_has_changed(self):
        day, snap, n, key = self.cursor.split(".")[1:]
        self.fails("CURSOR_INVALID", cursor=f"a1.{day}.{snap}.{int(n) + 1}.{key}")
        self.fails("CURSOR_INVALID", cursor=f"a1.{day}.{snap}.{n}.{'0' * 16}")
        self.fails("CURSOR_INVALID", cursor=f"a1.{day}.{snap}.9999999.{key}")
        flipped = ("1" if snap[0] == "0" else "0") + snap[1:]
        self.fails("SNAPSHOT_CHANGED", cursor=f"a1.{day}.{flipped}.{n}.{key}")

    def test_a_cursor_of_another_account_or_other_parameters_has_changed(self):
        self.mb.add("00000fff", account=OTHER, labels=("INBOX", "STARRED"))
        self.mb.scan(OTHER)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, account=OTHER)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, sort="date")
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, signals=("starred",))
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, collapse=False)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, sender_limit=2)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, include_low_score=True)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, min_tier="medium")
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, reveal_senders=True)

    def test_data_and_rule_changes_fail_with_no_items(self):
        self.mb.set_labels("00000003", ("INBOX",))
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor)

    def test_a_rule_change_fails(self):
        self.mb.add_rule(kind="type", value="PERSONAL", confidence="HIGH", domain="example.test")
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor)

    def test_the_reference_day_may_be_today_or_yesterday_only(self):
        tomorrow = NOW + timedelta(days=1)
        res = self.mb.compute(limit=10, cursor=self.cursor, now=tomorrow)  # still the day the cursor was issued for
        self.assertEqual(res["reference_day"], NOW.date().isoformat())
        self.assertEqual(len(res["items"]), 10)
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, now=NOW + timedelta(days=2))
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor, now=NOW - timedelta(days=1))  # a cursor from the future

    def test_a_new_message_between_pages_changes_the_snapshot(self):
        self.mb.add("00000aaa", labels=("INBOX", "IMPORTANT"))
        self.fails("SNAPSHOT_CHANGED", cursor=self.cursor)

    def test_warnings_and_as_of_are_not_part_of_the_snapshot(self):
        before = self.mb.compute(limit=10, cursor=self.cursor)
        self.mb.scan(ACCOUNT, finished="2026-10-21T11:30:00Z")  # a newer completed scan changes only freshness text
        again = self.mb.compute(limit=10, cursor=self.cursor)
        self.assertEqual(before["items"], again["items"])

    def test_valid_cursor_chain_reaches_the_end(self):
        got, cursor = [], None
        while True:
            res = self.mb.compute(limit=10, cursor=cursor)
            got += res["items"]
            cursor = res["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(got), 30)


class SnapshotSensitivityTests(MailboxCase):
    def setUp(self):
        super().setUp()
        self.target = self.mb.add("00000001", thread="T1", sender="a@example.test", labels=("INBOX", "STARRED", "UNREAD"), age_days=4)
        self.mb.add("00000002", thread="T2", sender="b@example.test", labels=("INBOX", "IMPORTANT"), age_days=2)
        self.base = self.mb.compute()["snapshot"]

    def snap(self, **kw):
        return self.mb.compute(**kw)["snapshot"]

    def test_every_visible_field_changes_the_snapshot(self):
        def changed(label, fn, restore):
            fn()
            self.assertNotEqual(self.snap(), self.base, label)
            restore()
            self.assertEqual(self.snap(), self.base, label + " (restored)")
        sql = self.mb.sql
        changed("labels", lambda: self.mb.set_labels(self.target, ("INBOX", "STARRED")), lambda: self.mb.set_labels(self.target, ("INBOX", "STARRED", "UNREAD")))
        changed("date", lambda: sql("UPDATE messages SET internal_ms=internal_ms-86400000*2 WHERE id=?", self.target),
                lambda: sql("UPDATE messages SET internal_ms=internal_ms+86400000*2 WHERE id=?", self.target))
        changed("sender", lambda: sql("UPDATE messages SET sender='z@example.test' WHERE id=?", self.target), lambda: sql("UPDATE messages SET sender='a@example.test' WHERE id=?", self.target))
        changed("thread", lambda: sql("UPDATE messages SET thread_id='T9' WHERE id=?", self.target), lambda: sql("UPDATE messages SET thread_id='T1' WHERE id=?", self.target))
        changed("extra message", lambda: self.mb.add("00000003", labels=("INBOX", "STARRED")),
                lambda: (sql("DELETE FROM message_labels WHERE message_id='00000003'"), sql("DELETE FROM messages WHERE id='00000003'")))
        changed("rule", lambda: self.mb.add_rule(kind="type", value="PERSONAL", confidence="HIGH", domain="example.test"), lambda: sql("DELETE FROM class_rules"))

    def test_the_time_of_day_does_not_but_the_reference_day_does(self):
        self.assertEqual(self.snap(now=NOW + timedelta(hours=5)), self.base)
        self.assertNotEqual(self.snap(now=NOW + timedelta(days=1)), self.base)

    def test_page_size_does_not_change_it(self):
        self.assertEqual(self.snap(limit=1), self.base)

    def test_accounts_have_different_snapshots_for_identical_data(self):
        for mid, labels in (("00000001", ("INBOX", "STARRED", "UNREAD")), ("00000002", ("INBOX", "IMPORTANT"))):
            self.mb.add(mid, account=OTHER, thread="T1" if mid.endswith("1") else "T2", sender="a@example.test" if mid.endswith("1") else "b@example.test", labels=labels, age_days=4 if mid.endswith("1") else 2)
        self.mb.scan(OTHER)
        self.assertNotEqual(self.snap(account=OTHER), self.base)


class OracleTests(unittest.TestCase):
    """A brute-force reference written from the specification: scan everything, score everything, apply the steps in the documented order."""

    def oracle(self, ro, account, rules, ref_day, collapse, sender_limit, sort, signals, threshold):
        ids_ = [r["id"] for r in ro.conn.execute("SELECT id FROM messages WHERE account=? ORDER BY id", (account,)).fetchall()]
        rows = ro.conn.execute("SELECT id, sender, unread, thread_id, internal_ms FROM messages WHERE account=? ORDER BY id", (account,)).fetchall()
        feats = classifier.features_for(ro, account, rows)
        user = frozenset(r.id for r in rules)
        recs = []
        for row in rows:
            f = feats[row["id"]]
            if f.label_ids & attention.EXCLUDED_LABELS:
                continue
            rec = attention.score_message(f, classify.evaluate(f, rules), row["internal_ms"], ref_day, user)
            if signals and not (("starred" in signals and rec.star) or ("important" in signals and rec.imp) or ("unread" in signals and rec.unread) or ("rule" in signals and rec.rule_pts)):
                continue
            if rec.score < threshold:
                continue
            key = (row["thread_id"] or "m:" + row["id"]) if collapse else "m:" + row["id"]
            recs.append(rec._replace(id=row["id"], thread=key))
        best = {}
        for r in recs:
            best.setdefault(r.thread, []).append(r)
        reps = sorted((min(g, key=attention._pkey) for g in best.values()), key=attention._pkey)
        if sender_limit:
            seen, kept = {}, []
            for r in reps:
                seen[r.sender or ""] = seen.get(r.sender or "", 0) + 1
                if seen[r.sender or ""] <= sender_limit:
                    kept.append(r)
            reps = kept
        reps.sort(key=attention._SORT_KEYS[sort])
        return [(r.score, r.thread if False else r.id, len(best[r.thread])) for r in reps], ids_

    def build(self, seed):
        mb = S.Mailbox()
        self.addCleanup(mb.close)
        rnd = random.Random(seed)
        pool = ("STARRED", "IMPORTANT", "UNREAD", "INBOX", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "SENT", "TRASH")
        for k in range(160):
            labels = tuple(l for l in pool if rnd.random() < (0.9 if l == "INBOX" else 0.3))
            mb.add(f"{rnd.getrandbits(32):08x}", thread=rnd.choice([None, ""] + [f"t{i}" for i in range(40)]),
                   sender=rnd.choice(["", "noreply@bulk.test", "a@example.test", "b@example.test", "c@vip.test", "d@vip.test", f"s{rnd.randint(0, 9)}@x.test"]),
                   labels=labels, age_days=rnd.choice([0, 1, 2, 3, 10, 14, 15, 40, 60, 61, 300]), ms=None if rnd.random() < 0.03 else "auto")
        return mb, rnd

    def test_the_pipeline_equals_the_reference_for_many_mailboxes_and_parameter_sets(self):
        for seed in range(6):
            mb, rnd = self.build(seed)
            rules = ()
            if seed % 2:
                mb.add_rule(kind="attention", value="POTENTIALLY_IMPORTANT", confidence=rnd.choice(("LOW", "MEDIUM", "HIGH")), domain="vip.test")
                mb.add_rule(kind="type", value="PERSONAL", confidence="HIGH", sender="a@example.test")
            ro = mb.readonly()
            self.addCleanup(ro.close)
            rules = classifier.active_rules(ro, ACCOUNT)
            for collapse in (True, False):
                for sender_limit in (0, 1, 3):
                    for sort in attention.SORTS:
                        for signals in ((), ("starred",), ("unread", "important"), ("rule",)):
                            for low in (False, True):
                                threshold = 1 if low else 15
                                want, _ = self.oracle(ro, ACCOUNT, rules, S.TODAY, collapse, sender_limit, sort, set(signals), threshold)
                                got = []
                                cursor = None
                                while True:
                                    res = attention.compute(ro, ACCOUNT, limit=100, cursor=cursor, sort=sort, signals=signals, sender_limit=sender_limit, collapse=collapse,
                                                            include_low_score=low, now=NOW)
                                    got += res["items"]
                                    cursor = res["next_cursor"]
                                    if not cursor:
                                        break
                                self.assertEqual([(i["score"], i["thread_messages"]) for i in got], [(w[0], w[2]) for w in want], (seed, collapse, sender_limit, sort, signals, low))


class ClassificationIndependenceTests(MailboxCase):
    def test_persisted_and_ai_classification_never_influence_the_ranking_and_is_never_read(self):
        a = self.mb.add(sender="x@bulk.example.test", labels=("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT", "UNREAD"), age_days=3)
        before = self.mb.compute()
        self.mb.conn.execute("INSERT INTO message_class (account,message_id,kind,value,confidence,source,rule_id,explanation,ruleset_hash,msg_scan_id,classified_at) "
                             "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (ACCOUNT, a, "type", "PERSONAL", "HIGH", "ai", "ai.local", "x", "stale", 99, "2026-01-01T00:00:00Z"))
        self.mb.conn.execute("INSERT INTO message_class (account,message_id,kind,value,confidence,source,rule_id,explanation,ruleset_hash,msg_scan_id,classified_at) "
                             "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (ACCOUNT, a, "attention", "POTENTIALLY_IMPORTANT", "HIGH", "rules", "u9", "x", "stale", 1, "2026-01-01T00:00:00Z"))
        self.mb.conn.commit()
        ro = self.mb.readonly()
        statements = []
        ro.conn.set_trace_callback(statements.append)
        after = attention.compute(ro, ACCOUNT, now=NOW)
        ro.close()
        self.assertEqual(before["items"], after["items"])
        self.assertEqual(before["snapshot"], after["snapshot"])
        self.assertFalse([s for s in statements if "message_class" in s])

    def test_only_reads_are_issued_and_the_engine_requires_a_read_only_index(self):
        self.mb.add(labels=("INBOX", "STARRED"))
        ro = self.mb.readonly()
        statements = []
        ro.conn.set_trace_callback(statements.append)
        attention.compute(ro, ACCOUNT, now=NOW)
        ro.close()
        verbs = {s.strip().split()[0].upper() for s in statements if s.strip()}
        self.assertLessEqual(verbs, {"SELECT", "PRAGMA", "WITH"})
        writable = idx.Index(self.mb.path)
        self.addCleanup(writable.close)
        with self.assertRaises(TypeError):
            attention.compute(writable, ACCOUNT, now=NOW)


class ReadOnlyTests(MailboxCase):
    def test_files_modes_mtimes_and_the_directory_are_untouched_and_no_temp_files_appear(self):
        for k in range(40):
            self.mb.add(labels=("INBOX", "STARRED", "UNREAD"), age_days=k)
        self.mb.conn.close()
        before = self.mb.tree()
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, TMPDIR=tmp, SQLITE_TMPDIR=tmp)
            code = ("import sys; sys.path[:0]=[%r,%r]\nimport attention_support as S\nro=S.idx.ReadOnlyIndex(%r)\nS.attention.compute(ro, S.ACCOUNT, now=S.NOW, limit=100)\nro.close()" %
                    (str(S.SRC), str(S.HERE), self.mb.path))
            subprocess.run([sys.executable, "-I", "-c", code], check=True, env=env, cwd=str(S.HERE))
            self.assertEqual(os.listdir(tmp), [])
        self.assertEqual(os.listdir(self.mb.dir), ["index.sqlite3"])  # no journal, WAL or SHM
        self.assertEqual(self.mb.tree(), before)
        self.mb.conn = sqlite3.connect(self.mb.path)


class IsolationAndPrivacyTests(MailboxCase):
    def test_the_same_ids_in_two_accounts_never_mix(self):
        self.mb.add("00000001", labels=("INBOX", "STARRED"), sender="a@example.test")
        self.mb.add("00000001", account=OTHER, labels=("INBOX", "IMPORTANT"), sender="o@other.test")
        self.mb.scan(OTHER)
        mine, theirs = self.mb.compute(), self.mb.compute(account=OTHER)
        self.assertEqual(([i["score"] for i in mine["items"]], mine["items"][0]["sender"]["domain"]), ([50], "example.test"))
        self.assertEqual(([i["score"] for i in theirs["items"]], theirs["items"][0]["sender"]["domain"]), ([20], "other.test"))
        self.assertNotEqual(mine["snapshot"], theirs["snapshot"])
        self.assertEqual(self.mb.compute(account="nobody@example.test")["items"], [])

    def test_senders_are_masked_by_default_and_hostile_strings_are_inert(self):
        hostile = ["a‮b@evil.test", "<script>alert(1)</script>@evil.test", "javascript:alert(1)@evil.test", "ctrl\x07char@evil.test", "idn@exämple.test"]
        for k, sender in enumerate(hostile):
            self.mb.add(f"{k + 1:08x}", sender=sender, labels=("INBOX", "STARRED"), age_days=k)
        res = self.mb.compute(sender_limit=0)
        blob = json.dumps(res)
        for s in hostile:
            self.assertNotIn(s.split("@")[0], blob)
        self.assertTrue(all(i["sender"]["masked"] for i in res["items"]))
        self.assertIn("NON_ASCII_DOMAIN", [f for i in res["items"] for f in i["flags"]])
        shown = json.dumps(self.mb.compute(sender_limit=0, reveal_senders=True))
        self.assertNotRegex(shown, "[‮\x07]")
        self.assertNotIn("\\u202e", shown)

    def test_stored_marker_strings_and_identifiers_never_appear_in_any_output(self):
        for k in range(12):
            self.mb.add(f"abc{k:05x}", thread=f"deadbeef{k:04x}", sender=f"{LEAK}{k}@bulk.example.test", labels=("INBOX", "STARRED", "UNREAD"), age_days=k)
        res = self.mb.compute(limit=5, sender_limit=0)
        text = attention.render_text(res)
        out = json.dumps(res) + text
        for needle in (LEAK, "abc0000", "deadbeef", ACCOUNT, "owner@", "http", "mail.google"):
            self.assertNotIn(needle, out, needle)
        self.assertNotIn(LEAK, res["next_cursor"])
        self.assertTrue(all(i["link"] == {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"} for i in res["items"]))
        self.assertTrue(all(i["sender"]["domain"] == "bulk.example.test" for i in res["items"]))  # the domain is shown by design, the address is masked

    def test_the_output_shape_is_closed(self):
        self.mb.add(labels=("INBOX", "STARRED"))
        item = self.mb.compute()["items"][0]
        self.assertEqual(sorted(item), ["components", "date", "evidence", "flags", "link", "rank", "score", "sender", "signals", "thread_messages", "tier", "types", "unread_days"])


class WarningTests(MailboxCase):
    def test_warnings_warn_and_never_block(self):
        self.mb.add(labels=("INBOX", "STARRED"))
        res = self.mb.compute()
        self.assertIn("SYNC_NOT_HEALTHY", res["warnings"])  # no checkpoint in this synthetic index
        self.assertEqual(len(res["items"]), 1)
        stale = self.mb.compute(now=NOW + timedelta(days=9))
        self.assertIn("SCAN_STALE", stale["warnings"])
        self.assertEqual(len(stale["items"]), 1)

    def test_an_index_without_any_scan_is_reported_empty(self):
        other = S.Mailbox()
        self.addCleanup(other.close)
        other.conn.execute("DELETE FROM scans")
        other.conn.commit()
        res = other.compute()
        self.assertIn("INDEX_EMPTY", res["warnings"])
        self.assertEqual(res["items"], [])


class DeterminismTests(MailboxCase):
    def test_identical_results_under_different_hash_seeds_and_insertion_orders(self):
        rnd = random.Random(21)
        rows = []
        for k in range(120):
            rows.append((f"{k:08x}", f"t{k % 37}", f"s{k % 13}@example.test", tuple(l for l in ("INBOX", "STARRED", "IMPORTANT", "UNREAD") if rnd.random() < 0.5), rnd.randint(0, 90)))
        outputs = set()
        for order in (rows, list(reversed(rows)), random.Random(1).sample(rows, len(rows))):
            mb = S.Mailbox()
            self.addCleanup(mb.close)
            for mid, thread, sender, labels, age in order:
                mb.add(mid, thread=thread, sender=sender, labels=labels, age_days=age)
            outputs.add(json.dumps(mb.compute(limit=100), sort_keys=True))
        self.assertEqual(len(outputs), 1)
        snapshots = set()
        code = ("import sys; sys.path[:0]=[%r,%r]\nimport attention_support as S\nro=S.idx.ReadOnlyIndex(%r)\nr=S.attention.compute(ro, S.ACCOUNT, now=S.NOW, limit=100)\nprint(S.attention.as_json(r))" %
                (str(S.SRC), str(S.HERE), self.mb.path))
        mb = S.Mailbox()
        self.addCleanup(mb.close)
        for mid, thread, sender, labels, age in rows:
            mb.add(mid, thread=thread, sender=sender, labels=labels, age_days=age)
        mb.conn.close()
        code = code.replace(self.mb.path, mb.path)
        for seed in ("0", "1", "2", "7", "1234", "99"):
            out = subprocess.run([sys.executable, "-I", "-c", code], check=True, capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED=seed), cwd=str(S.HERE)).stdout
            snapshots.add(out)
        self.assertEqual(len(snapshots), 1)
        mb.conn = sqlite3.connect(mb.path)


class BoundaryTests(unittest.TestCase):
    FORBIDDEN = ("gmail_intelligence.gmail_write", "gmail_intelligence.gmail", "gmail_intelligence.oauth", "gmail_intelligence.keystore", "gmail_intelligence.exec_live_mailbox",
                 "gmail_intelligence.cleanup_exec", "gmail_intelligence.cleanup_plans", "gmail_intelligence.dashboard_server", "googleapiclient", "google", "keyring", "socket",
                 "urllib.request", "http.client", "subprocess", "httplib2")

    def test_importing_the_engine_pulls_in_no_gmail_oauth_keychain_write_or_network_module(self):
        code = ("import sys; sys.path[:0]=[%r]\nimport gmail_intelligence.attention, gmail_intelligence.cli\n"
                "print(sorted(m for m in sys.modules if m in %r or m.split('.')[0] in ('googleapiclient','google','keyring','httplib2')))" % (str(S.SRC), self.FORBIDDEN))
        # the attention module itself, without the CLI (which lazily imports other commands only when they run)
        code_engine = code.replace("import gmail_intelligence.attention, gmail_intelligence.cli", "import gmail_intelligence.attention")
        out = subprocess.run([sys.executable, "-I", "-c", code_engine], check=True, capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "[]")

    def test_the_source_contains_no_url_and_no_link_building(self):
        source = open(S.SRC / "gmail_intelligence" / "attention.py", encoding="utf-8").read()
        for needle in ("http://", "https://", "mail.google", "/u/0", "href", "urlopen", "requests", "INSERT", "UPDATE ", "DELETE ", "CREATE "):
            self.assertNotIn(needle, source, needle)


if __name__ == "__main__":
    unittest.main()
