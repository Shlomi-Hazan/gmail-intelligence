"""Deterministic tie-breaking of the Organization recommendations (M5/M6 follow-up). Synthetic data only; no wall-clock assertions.

The bug: a group's dominant type was chosen with `Counter.most_common(1)`, and the counter was filled by iterating a SET of type names. Two compatible types carried by the same messages
(for example NEWSLETTER and EDUCATIONAL) are always tied, and the winner followed the set's iteration order, which changes with PYTHONHASHSEED: different processes recommended
different labels and proposed different rules for the same index. The contract now: the highest count wins; among exactly equal counts the alphabetically first type identifier wins
(`label_suggest.dominant_type`, the same tie rule the dashboard already used for a sender's dominant type).
"""
import ast
import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import organization_bench as ob  # noqa: E402

from gmail_intelligence import analytics, classifier, filter_suggest, label_suggest as ls  # noqa: E402

SEEDS = ("0", "1", "2", "3", "5", "7", "42", "1234")


class Base(unittest.TestCase):
    def ties(self, accounts=(ob.ACCOUNT,)):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        index = None
        for account in accounts:
            if index is not None:
                index.close()  # one connection per account; only the last one is kept open for the test
            index = ob.build_ties(Path(tmp.name) / "t.sqlite3", account)
        self.addCleanup(index.close)
        return index


class DominantTypeTests(unittest.TestCase):
    def test_the_highest_count_wins(self):
        self.assertEqual(ls.dominant_type(Counter({"SOCIAL": 3, "NEWSLETTER": 9, "PERSONAL": 1})), ("NEWSLETTER", 9))
        self.assertEqual(ls.dominant_type(Counter({"ZETA": 5})), ("ZETA", 5))

    def test_exact_ties_pick_the_alphabetically_first_type(self):
        self.assertEqual(ls.dominant_type(Counter({"NEWSLETTER": 4, "EDUCATIONAL": 4})), ("EDUCATIONAL", 4))
        self.assertEqual(ls.dominant_type(Counter({"TRANSACTIONAL": 7, "FINANCIAL": 7})), ("FINANCIAL", 7))

    def test_three_or_more_tied_types(self):
        self.assertEqual(ls.dominant_type(Counter({"PROMOTIONAL": 6, "NEWSLETTER": 6, "EDUCATIONAL": 6})), ("EDUCATIONAL", 6))
        self.assertEqual(ls.dominant_type(Counter({"TRANSACTIONAL": 2, "PROMOTIONAL": 2, "NEWSLETTER": 2, "FINANCIAL": 2, "SOCIAL": 1})), ("FINANCIAL", 2))

    def test_the_result_never_depends_on_insertion_order(self):
        items = [("PROMOTIONAL", 6), ("NEWSLETTER", 6), ("EDUCATIONAL", 6), ("SOCIAL", 2)]
        results = {ls.dominant_type(Counter(dict(order))) for order in itertools.permutations(items)}
        self.assertEqual(results, {("EDUCATIONAL", 6)})
        counter = Counter()  # incremental filling in different orders, as the group collector does
        for t in ("NEWSLETTER", "EDUCATIONAL"):
            counter[t] += 1
        other = Counter()
        for t in ("EDUCATIONAL", "NEWSLETTER"):
            other[t] += 1
        self.assertEqual(ls.dominant_type(counter), ls.dominant_type(other))

    def test_a_tie_only_counts_at_the_top(self):
        self.assertEqual(ls.dominant_type(Counter({"ZETA": 1, "ALPHA": 1, "MIDDLE": 5})), ("MIDDLE", 5))  # lower tied counts never influence the winner


class FixtureContractTests(Base):
    def groups(self, index, account=ob.ACCOUNT):
        return ls._gather(index, account)

    def test_tied_groups_get_the_alphabetical_winner(self):
        g = self.groups(self.ties())
        expect = {("domain", "a.example.test"): ("EDUCATIONAL", 12), ("domain", "b.example.test"): ("FINANCIAL", 12), ("domain", "c.example.test"): ("NEWSLETTER", 12),
                  ("domain", "j.example.test"): ("EDUCATIONAL", 10), ("sender", "one@k.example.test"): ("EDUCATIONAL", 8), ("sender", "other@d.example.test"): ("EDUCATIONAL", 7)}
        for key, want in expect.items():
            self.assertEqual(ls.dominant_type(g[key].types), want, key)
        self.assertEqual(dict(g[("domain", "a.example.test")].types), {"NEWSLETTER": 12, "EDUCATIONAL": 12})  # evidence counts are untouched: both tied types keep their full counts

    def test_three_way_ties_are_protected_and_unknown_is_excluded(self):
        g = self.groups(self.ties())
        e = g[("domain", "e.example.test")]
        self.assertEqual(dict(e.types), {"NEWSLETTER": 12, "EDUCATIONAL": 12, "PROMOTIONAL": 12})
        self.assertEqual(ls.dominant_type(e.types), ("EDUCATIONAL", 12))
        self.assertEqual(e.protected, 12)  # conflicting equal-precedence types mark the group for review: it is never recommended
        self.assertEqual(dict(g[("domain", "g.example.test")].types), {})  # no rule matches there: UNKNOWN only, and UNKNOWN is never counted as a type
        self.assertFalse(any("UNKNOWN" in grp.types for grp in g.values()))

    def test_non_tied_groups_keep_their_dominant_type_and_counts(self):
        g = self.groups(self.ties())
        self.assertEqual(ls.dominant_type(g[("domain", "d.example.test")].types), ("NEWSLETTER", 12))
        self.assertEqual(dict(g[("domain", "d.example.test")].types), {"NEWSLETTER": 12, "EDUCATIONAL": 7})
        self.assertEqual(ls.dominant_type(g[("domain", "h.example.test")].types), ("PROMOTIONAL", 12))  # decided by a higher-priority user rule, not by a tie
        self.assertEqual(ls.dominant_type(g[("sender", "lead@d.example.test")].types), ("NEWSLETTER", 5))

    def test_recommendations_and_rule_proposals_follow_the_contract(self):
        index = self.ties()
        rec, rules = ls.recommend(index, ob.ACCOUNT), ls.suggest_rules(index, ob.ACCOUNT)
        self.assertEqual([(r.kind, r.target, r.group, dict(r.evidence)["messages"], r.confidence) for r in rec.items],
                         [("CREATE_LABEL", "Learning", ("type", "EDUCATIONAL"), 39, "MEDIUM"), ("CREATE_LABEL", "Newsletters", ("type", "NEWSLETTER"), 24, "MEDIUM"),
                          ("CREATE_LABEL", "Finance", ("type", "FINANCIAL"), 12, "MEDIUM"), ("CREATE_LABEL", "Promotions", ("type", "PROMOTIONAL"), 12, "MEDIUM")])
        self.assertEqual([(p.group, p.value, p.confidence, dict(p.preview)["matched"]) for p in rules.items],
                         [(("domain", "k.example.test"), "EDUCATIONAL", "MEDIUM", 15), (("domain", "j.example.test"), "EDUCATIONAL", "MEDIUM", 12)])
        self.assertEqual(rules.suppressed, (("an enabled rule already exists for this group (never duplicated or contradicted)", 2), ("no effect: current classification already agrees", 15),
                                            ("protected or potentially important mail in the group", 4), ("the domain-level proposal already covers this sender", 2)))
        self.assertEqual(rec.suppressed, (("protected or potentially important mail in the group", 4),))

    def test_every_proposal_value_is_the_groups_dominant_type(self):
        index = self.ties()
        groups = ls._gather(index, ob.ACCOUNT)
        for p in ls.suggest_rules(index, ob.ACCOUNT).items:
            self.assertEqual(p.value, ls.dominant_type(groups[p.group].types)[0], p.group)

    def test_label_recommendations_match_an_independent_aggregation(self):
        index = self.ties()
        groups = ls._gather(index, ob.ACCOUNT)
        total = Counter()
        for (kind, key), g in groups.items():
            if kind != "domain" or g.n < ls.MIN_GROUP or g.protected or g.user_labels or not g.types or g.stale:
                continue
            t, n = ls.dominant_type(g.types)
            if t in ls.TYPE_LABEL_NAMES and n / g.n >= 0.8:
                total[t] += g.n
        got = {r.group[1]: dict(r.evidence)["messages"] for r in ls.recommend(index, ob.ACCOUNT).items if r.kind == "CREATE_LABEL"}
        self.assertEqual(got, {t: n for t, n in total.items() if n >= ls.CREATE_MIN_MESSAGES})

    def test_filter_suggestions_remain_consistent(self):
        index = self.ties()
        rec = ls.recommend(index, ob.ACCOUNT)
        self.assertEqual(filter_suggest.suggest(index, ob.ACCOUNT), filter_suggest.suggest(index, ob.ACCOUNT, recommendation=rec))
        self.assertEqual(filter_suggest.suggest(index, ob.ACCOUNT).items, ())

    def test_protection_decisions_are_unchanged(self):
        index = self.ties()
        g = self.groups(index)
        self.assertEqual({k[1] for k, grp in g.items() if k[0] == "domain" and grp.protected}, {"e.example.test", "f.example.test"})  # the 3-way conflict and the starred message
        targets = {r.group[1] for r in ls.recommend(index, ob.ACCOUNT).items}
        self.assertNotIn("PERSONAL", targets)

    def test_the_organization_payload_has_the_same_structure(self):
        data = analytics.Analytics(self.ties(), ob.ACCOUNT, now=ob.NOW).organization()
        self.assertEqual(sorted(data["data"]), ["filter_suggestions", "hygiene", "label_plans", "labels", "names_revealed", "read_only", "recommendations", "rule_proposals"])
        self.assertEqual(data["data"]["recommendations"]["by_kind"], {"CREATE_LABEL": 4})
        self.assertEqual(data["data"]["rule_proposals"]["total"], 2)

    def test_the_index_is_never_modified(self):
        index = self.ties()
        before = [tuple(r) for r in index._q("SELECT account, message_id, kind, value, confidence, rule_id FROM message_class ORDER BY 1,2,3,4")]
        rules_before = [tuple(r) for r in index._q("SELECT id, kind, value, c_domain, c_label, enabled FROM class_rules ORDER BY id")]
        analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()
        self.assertEqual([tuple(r) for r in index._q("SELECT account, message_id, kind, value, confidence, rule_id FROM message_class ORDER BY 1,2,3,4")], before)
        self.assertEqual([tuple(r) for r in index._q("SELECT id, kind, value, c_domain, c_label, enabled FROM class_rules ORDER BY id")], rules_before)

    def test_accounts_stay_isolated_and_agree_with_each_other(self):
        index = self.ties((ob.ACCOUNT, ob.SECOND))
        a, b = ob.digest(index, ob.ACCOUNT), ob.digest(index, ob.SECOND)
        self.assertEqual(a, b)  # the same synthetic data under another account gives exactly the same result
        for account in (ob.ACCOUNT, ob.SECOND):
            groups = ls._gather(index, account)
            self.assertEqual(sum(g.n for (kind, _), g in groups.items() if kind == "domain"), index._q("SELECT COUNT(*) FROM messages WHERE account=?", account)[0][0])
        single = self.ties()
        self.assertEqual(ob.digest(single, ob.ACCOUNT), a)


class CrossProcessTests(unittest.TestCase):
    CODE = ("import json, sys, tempfile; sys.path.insert(0, %r); sys.path.insert(0, %r); import organization_bench as ob; from pathlib import Path; "
            "t = tempfile.TemporaryDirectory(); out = {}\n"
            "i = ob.build_ties(Path(t.name) / 'a.sqlite3'); out['ties'] = ob.digest(i); out['ties_parts'] = ob.parts_digest(i); i.close()\n"
            "j = ob.build_case(Path(t.name) / 'b.sqlite3', 'plain-300'); out['plain'] = ob.digest(j); j.close()\n"
            "print(json.dumps(out, sort_keys=True))")

    def run_seed(self, seed):
        out = subprocess.run([sys.executable, "-I", "-c", self.CODE % (str(ROOT / "src"), str(ROOT / "tests"))], capture_output=True, text=True, timeout=120,
                             env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"})
        self.assertEqual(out.returncode, 0, out.stderr[-500:])
        return json.loads(out.stdout)

    def test_the_complete_organization_output_is_identical_in_independent_processes(self):
        results = {seed: self.run_seed(seed) for seed in SEEDS}
        first = results[SEEDS[0]]
        for seed, r in results.items():
            self.assertEqual(r, first, f"PYTHONHASHSEED={seed}")
        self.assertEqual(len({r["ties"] for r in results.values()}), 1)
        self.assertEqual(set(first["ties_parts"]), {"hygiene", "recommendations", "rules", "filters", "organization"})  # every component was compared, not only the summary

    def test_a_reintroduced_set_iteration_order_dependence_would_be_detected(self):
        # the mutation that reproduces the original bug: the old tie rule (first-inserted wins) over an iteration order that follows the hash seed
        code = ("import sys, json; from collections import Counter; names = ['NEWSLETTER', 'EDUCATIONAL', 'PROMOTIONAL', 'TRANSACTIONAL', 'FINANCIAL', 'SOCIAL', 'PERSONAL']; "
                "c = Counter(); [c.__setitem__(t, c[t] + 1) for t in set(names)]; print(c.most_common(1)[0][0])")
        winners = {subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env={"PYTHONHASHSEED": s, "PATH": "/usr/bin:/bin"}).stdout.strip() for s in SEEDS}
        self.assertGreater(len(winners), 1)  # the original rule really is seed dependent, so the cross-process test above is capable of failing


class StaticGuardTests(unittest.TestCase):
    def test_no_group_winner_is_chosen_with_most_common_any_more(self):
        src = (ROOT / "src" / "gmail_intelligence" / "label_suggest.py").read_text()
        self.assertNotIn("most_common", src)
        self.assertEqual(src.count("dominant_type(g.types)"), 2)  # recommendations and rule proposals use the single tie rule
        tree = ast.parse(src)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "dominant_type")
        self.assertIn("min(", ast.unparse(fn))

    def test_the_organization_optimization_is_still_in_place(self):
        index = ob.build_ties(Path(tempfile.mkdtemp()) / "p.sqlite3")
        try:
            calls = {"gather": 0, "features": 0}
            real_gather, real_features = ls._gather, classifier.features_for

            def gather(*a, **k):
                calls["gather"] += 1
                return real_gather(*a, **k)

            def features(*a, **k):
                calls["features"] += 1
                return real_features(*a, **k)
            ls._gather, classifier.features_for = gather, features
            try:
                analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()
            finally:
                ls._gather, classifier.features_for = real_gather, real_features
            self.assertEqual(calls["gather"], 1)
            self.assertLessEqual(calls["features"], 1)
        finally:
            index.close()


if __name__ == "__main__":
    unittest.main()
