"""M8A-1: the pure scoring function (no database). Weights are PROVISIONAL; these tests pin the arithmetic and the invariants, not the product value."""
import random
import unittest

import attention_support as S
from attention_support import attention, classify

REF = S.TODAY
SENDER = "friend@example.test"


def feats(labels, sender=SENDER, unread=None, names=()):
    labels = frozenset(labels)
    return classify.Features(sender, ("UNREAD" in labels) if unread is None else unread, labels, frozenset(names))


def rec(labels=("INBOX",), age=1.0, sender=SENDER, rules=(), unread=None, ms="auto", weights=attention.DEFAULT_WEIGHTS):
    f = feats(labels, sender, unread)
    when = S.ms_ago(age) if ms == "auto" else ms
    return attention.score_message(f, classify.evaluate(f, rules), when, REF, frozenset(r.id for r in rules), weights)


def user_rule(rid, kind, value, conf, priority=0, **cond):
    return classify.Rule(rid, kind, value, conf, "user rule", tier=classify.TIER_USER, priority=priority, **cond)


class SignalTests(unittest.TestCase):
    def test_star_alone_is_fifty_medium_owner_asserted(self):
        r = rec(("INBOX", "STARRED"))
        self.assertEqual((r.score, r.owner, r.ev, attention.tier_of(r.score)), (50, 50, 2, "MEDIUM"))

    def test_important_alone_is_twenty_low_gmail_heuristic(self):
        r = rec(("INBOX", "IMPORTANT"))
        self.assertEqual((r.score, r.ev, attention.tier_of(r.score)), (20, 1, "LOW"))

    def test_unread_age_buckets_and_their_boundaries(self):
        for age, pts in ((0, 10), (2, 10), (3, 15), (14, 15), (15, 5), (60, 5), (61, 0), (400, 0)):
            self.assertEqual(rec(("INBOX", "UNREAD"), age=age).age_pts, pts, age)

    def test_age_is_counted_in_utc_days_and_a_future_date_counts_as_today(self):
        self.assertEqual(rec(("INBOX", "UNREAD"), age=-3).age_pts, 10)

    def test_read_mail_gets_no_age_points(self):
        self.assertEqual(rec(("INBOX",), age=5).score, 0)

    def test_fresh_unread_alone_is_below_the_default_threshold(self):
        r = rec(("INBOX", "UNREAD"), age=0.5)
        self.assertEqual(r.score, 10)
        self.assertLess(r.score, attention.DEFAULT_WEIGHTS.min_score)

    def test_important_unread_three_days_is_medium(self):
        r = rec(("INBOX", "UNREAD", "IMPORTANT"), age=3)
        self.assertEqual((r.score, attention.tier_of(r.score)), (35, "MEDIUM"))


class CapTests(unittest.TestCase):
    def test_owner_points_are_capped_at_seventy(self):
        r = rec(("INBOX", "STARRED"), rules=(user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", "HIGH", domain="example.test"),))
        self.assertEqual((r.owner, r.score), (70, 70))

    def test_inferred_points_are_capped_at_forty(self):
        personal = user_rule("u1", "type", "PERSONAL", "HIGH", domain="example.test")
        r = rec(("INBOX", "IMPORTANT", "UNREAD"), age=5, rules=(personal,))
        self.assertEqual((r.imp, r.age_pts, r.pers, r.score), (20, 15, 10, 40))

    def test_primary_tab_alone_is_not_a_personal_bonus(self):
        self.assertEqual(rec(("INBOX", "CATEGORY_PERSONAL", "IMPORTANT")).pers, 0)

    def test_the_score_never_exceeds_one_hundred(self):
        r = rec(("INBOX", "STARRED", "IMPORTANT", "UNREAD"), age=5, rules=(user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", "HIGH", domain="example.test"),
                                                                           user_rule("u2", "type", "PERSONAL", "HIGH", domain="example.test")))
        self.assertLessEqual(r.score, 100)


class PenaltyTests(unittest.TestCase):
    def test_promotions_tab_removes_inferred_points_but_not_owner_points(self):
        self.assertEqual(rec(("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT", "UNREAD"), age=3).score, 5)
        starred = rec(("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT", "UNREAD", "STARRED"), age=3)
        self.assertEqual((starred.owner, starred.pen, starred.score), (50, 30, 55))

    def test_a_starred_promotion_scores_exactly_fifty_and_never_below(self):
        r = rec(("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))
        self.assertEqual((r.score, attention.tier_of(r.score)), (50, "MEDIUM"))

    def test_the_automated_sender_penalty_is_fifteen_and_one_penalty_is_never_summed(self):
        auto = rec(("INBOX", "IMPORTANT"), sender="noreply@example.test")
        self.assertEqual((auto.pen, auto.pen_type), (15, "AUTOMATED_NOTIFICATION"))
        both = rec(("INBOX", "IMPORTANT", "CATEGORY_PROMOTIONS"), sender="noreply@example.test")
        self.assertEqual(both.pen, 30)

    def test_low_confidence_types_do_not_penalise_updates_and_forums(self):
        self.assertEqual(rec(("INBOX", "CATEGORY_UPDATES", "IMPORTANT")).pen, 0)
        self.assertEqual(rec(("INBOX", "CATEGORY_FORUMS", "IMPORTANT")).pen, 0)

    def test_transactional_and_financial_are_never_penalised(self):
        tx = user_rule("u1", "type", "TRANSACTIONAL", "HIGH", domain="example.test")
        self.assertEqual(rec(("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT"), rules=(tx,)).pen, 0)
        # both types present (an equal-precedence conflict): the exemption still holds and the conflict is only a flag
        promo = user_rule("u2", "type", "PROMOTIONAL", "HIGH", domain="example.test")
        r = rec(("INBOX", "IMPORTANT"), rules=(tx, promo))
        self.assertEqual(r.pen, 0)
        self.assertIn("TYPE_CONFLICT", r.flags)
        fin = user_rule("u3", "type", "FINANCIAL", "MEDIUM", domain="example.test")
        self.assertEqual(rec(("INBOX", "IMPORTANT"), sender="noreply@example.test", rules=(fin,)).pen, 0)

    def test_a_user_type_rule_outranks_the_builtin_penalty(self):
        personal = user_rule("u1", "type", "PERSONAL", "HIGH", domain="example.test")
        self.assertEqual(rec(("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT"), rules=(personal,)).pen, 0)


class ClassificationConsistencyTests(unittest.TestCase):
    def test_a_user_rule_masks_the_builtin_star_in_the_outcome_but_not_in_the_score(self):
        rule = user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", "LOW", domain="example.test")
        f = feats(("INBOX", "STARRED"))
        outcome = classify.evaluate(f, (rule,))
        self.assertEqual([r.rule_id for r in outcome.results if r.kind == "attention"], ["u1"])  # the built-in star rule is gone from the outcome
        r = rec(("INBOX", "STARRED"), rules=(rule,))
        self.assertEqual((r.star, r.rule_pts, r.owner, r.score), (50, 20, 70, 70))
        self.assertGreaterEqual(r.score, rec(("INBOX", "STARRED")).score)

    def test_user_rule_weights_follow_confidence(self):
        for conf, pts in (("LOW", 20), ("MEDIUM", 40), ("HIGH", 60)):
            r = rec(("INBOX",), rules=(user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", conf, domain="example.test"),))
            self.assertEqual((r.rule_pts, r.rule_conf, r.rule_id), (pts, conf, "u1"))

    def test_evidence_follows_the_source_not_the_points(self):
        low = rec(("INBOX",), rules=(user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", "LOW", domain="example.test"),))
        med = rec(("INBOX",), rules=(user_rule("u1", "attention", "POTENTIALLY_IMPORTANT", "MEDIUM", domain="example.test"),))
        self.assertEqual((rec(("INBOX", "UNREAD"), age=5).ev, low.ev, med.ev, rec(("INBOX", "STARRED")).ev), (0, 1, 2, 2))

    def test_a_user_review_rule_is_only_a_flag(self):
        flagged = rec(("INBOX",), rules=(user_rule("u1", "attention", "REVIEW_NEEDED", "LOW", domain="example.test"),))
        self.assertEqual((flagged.score, flagged.flags), (0, ("REVIEW_FLAGGED",)))


class FlagTests(unittest.TestCase):
    def test_flags_never_change_the_score(self):
        base = rec(("INBOX", "STARRED"))
        for kw in ({"sender": ""}, {"sender": "bücher@exämple.test"}, {"ms": None}):
            self.assertEqual(rec(("INBOX", "STARRED"), **kw).score, base.score)
        self.assertEqual(rec(("STARRED",)).score, base.score)

    def test_each_flag(self):
        self.assertIn("SENDER_MISSING", rec(("INBOX",), sender="").flags)
        self.assertIn("SENDER_MISSING", rec(("INBOX",), sender="no-at-sign").flags)
        self.assertIn("NON_ASCII_DOMAIN", rec(("INBOX",), sender="a@exämple.test").flags)
        self.assertIn("NOT_IN_INBOX", rec(("STARRED",)).flags)
        self.assertIn("DATE_MISSING", rec(("INBOX",), ms=None).flags)
        self.assertIn("UNREAD_MISMATCH", rec(("INBOX", "UNREAD"), unread=False).flags)
        self.assertEqual(rec(("INBOX", "UNREAD"), unread=True).flags, ())

    def test_tiers(self):
        self.assertEqual([attention.tier_of(s) for s in (0, 14, 15, 34, 35, 59, 60, 100)], ["MINIMAL", "MINIMAL", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"])


class PropertyTests(unittest.TestCase):
    LABELS = ("INBOX", "STARRED", "IMPORTANT", "UNREAD", "CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL", "CATEGORY_UPDATES", "CATEGORY_PERSONAL", "CATEGORY_FORUMS")
    SENDERS = (SENDER, "noreply@example.test", "", "x@other.test")

    def samples(self, seed=7, n=400):
        rnd = random.Random(seed)
        rules = (user_rule("u1", "type", "PERSONAL", "HIGH", domain="other.test"), user_rule("u2", "type", "TRANSACTIONAL", "MEDIUM", sender="x@other.test"),
                 user_rule("u3", "attention", "POTENTIALLY_IMPORTANT", "MEDIUM", domain="example.test"))
        for _ in range(n):
            labels = tuple(l for l in self.LABELS if rnd.random() < 0.4)
            yield labels, rnd.choice(self.SENDERS), rnd.choice((0, 1, 3, 10, 30, 100)), rnd.choice((rules[:0], rules[:1], rules[1:], rules))

    def test_bounds_and_the_star_floor(self):
        for labels, sender, age, rules in self.samples():
            r = rec(labels, age=age, sender=sender, rules=rules)
            self.assertTrue(0 <= r.score <= 100)
            if "STARRED" in labels:
                self.assertGreaterEqual(r.score, 50)

    def test_adding_a_positive_signal_never_lowers_the_score(self):
        for labels, sender, age, rules in self.samples(seed=11):
            base = rec(labels, age=age, sender=sender, rules=rules).score
            for extra in ("STARRED", "IMPORTANT", "UNREAD"):
                self.assertGreaterEqual(rec(tuple(set(labels) | {extra}), age=age, sender=sender, rules=rules).score, base, (labels, extra))

    def test_a_penalty_never_raises_the_score(self):
        for labels, sender, age, rules in self.samples(seed=13):
            base = rec(labels, age=age, sender=sender, rules=rules).score
            for extra in ("CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"):
                if not rules:  # without user type rules the added tab can only add a penalty
                    self.assertLessEqual(rec(tuple(set(labels) | {extra}), age=age, sender=sender, rules=rules).score, base, (labels, extra))

    def test_the_same_input_always_gives_the_same_record(self):
        for labels, sender, age, rules in self.samples(seed=3, n=50):
            self.assertEqual(rec(labels, age=age, sender=sender, rules=rules), rec(tuple(reversed(labels)), age=age, sender=sender, rules=rules))


class WeightsTests(unittest.TestCase):
    def test_weights_are_labelled_provisional(self):
        self.assertEqual(attention.WEIGHTS_STATUS, "PROVISIONAL")
        self.assertEqual(attention.ALGORITHM_VERSION, 1)

    def test_weights_are_injectable_for_sensitivity_analysis(self):
        heavier = attention.Weights(star=60)
        self.assertEqual(rec(("INBOX", "STARRED"), weights=heavier).score, 60)


if __name__ == "__main__":
    unittest.main()
