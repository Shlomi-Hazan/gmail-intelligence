"""M6 hotfix: Organization cold-load performance. Exact-equivalence and call-count regression tests on deterministic SYNTHETIC data (no real data, no wall-clock assertions).

The golden digests were produced by the ORIGINAL implementation (before the optimization) on the fixtures of `organization_bench.py`; each digest covers the full hygiene result, every
recommendation, rule proposal and filter suggestion in order with all evidence, confidence tiers, reasons and previews, and the whole Organization API payload (only the injected clock is fixed).
They guard the exact semantics: if one changes, so did a result.
"""
import ast
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import organization_bench as ob  # noqa: E402

from gmail_intelligence import analytics, classifier, classify, filter_suggest, index as idx, label_suggest  # noqa: E402

GOLDEN = {
    "empty|nobody": "17550f7c6130318b02b72537125fc7ea74752718d4c8f8973cd44b192720652a",
    "norules-1000|bench": "3afdfec4676e7cfda82bc96c3038c5905efe01782c0de74bf3289e4fa2edbfa0",
    "partial-1000|bench": "1dcb6cd605c020d5e925bdca5bd7401912cc01013a1575f19711726a6f91001d",
    "plain-1000|bench": "74c065e87fb7118279132be5c8dad96a128093c8230d5cb84d6c82cbe2da3d29",
    "plain-3000|bench": "4b4f61ad29cf9409701ff77fec2a5401b7328111d980088f7033f7c279f1d07c",
    "plain-300|bench": "e0ed97dd7c0f57e018f76fe92fffa79724906d1e6574d03a3c89313686bf4502",
    "stale-1000|bench": "b0b0cd1d6d0475e588f46f500f09b49853bc7deb3c4e2b837e21d052d7bb0ec3",
    "tiny-20|bench": "dc6608420068b5cc790614d2fa1fba05868c1a4a86a12ea2d4fc8b4d7cf57e40",
    "twoaccounts-600|bench": "0e7a0517de022eb31d28eb8be44c95c660ebd3c37297814806a5cbe9d4efe1fd",
    "twoaccounts-600|second": "0ba53b2bb84bcc35ed7b457bd8e60f0c08177a6a5792626fe61c7ebd5b0d4edc",
}


def reference_preview_rule(index, account, **fields):
    """The ORIGINAL preview_rule, verbatim (full scan of every message, features re-read per batch): the oracle the optimized preview must equal exactly."""
    v = classify.validate_new_rule(**fields)
    cand = classifier.Rule("preview", v["kind"], v["value"], v["confidence"], v["note"] or "candidate rule", priority=v["priority"], sender=v.get("sender"), domain=v.get("domain"),
                           label=v.get("label"), unread=v.get("unread"))
    user = classifier.active_rules(index, account)
    rows = index._q("SELECT id, sender, unread FROM messages WHERE account=?", account)
    out = {"messages": len(rows), "matched": 0, "type_changes": 0, "now_unknown": 0}
    for k in range(0, len(rows), classifier.BATCH):
        chunk = rows[k:k + classifier.BATCH]
        feats = classifier.features_for(index, account, chunk)
        for r in chunk:
            f = feats[r["id"]]
            if not cand.matches(f):
                continue
            out["matched"] += 1
            before, after = classify.evaluate(f, user), classify.evaluate(f, [*user, cand])
            out["now_unknown"] += before.values() == ["UNKNOWN"]
            out["type_changes"] += (sorted(before.values()), sorted(before.values("attention"))) != (sorted(after.values()), sorted(after.values("attention")))
    return out


class Base(unittest.TestCase):
    def build(self, name):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        index = ob.build_case(Path(tmp.name) / "x.sqlite3", name)
        self.addCleanup(index.close)
        return index


class GoldenEquivalenceTests(Base):
    def test_every_case_matches_the_digest_of_the_original_implementation(self):
        for name in list(ob.CASES) + ["twoaccounts-600"]:
            index = self.build(name)
            accounts = [ob.ACCOUNT, ob.SECOND] if name.startswith("twoaccounts") else [ob.ACCOUNT]
            for account in accounts:
                key = f"{name}|{account.split('.')[0]}"
                self.assertEqual(ob.digest(index, account), GOLDEN[key], key)

    def test_an_empty_index_matches_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = idx.Index(str(Path(tmp) / "e.sqlite3"))
            try:
                self.assertEqual(ob.digest(index, "nobody@example.invalid"), GOLDEN["empty|nobody"])
            finally:
                index.close()


class PreviewEquivalenceTests(Base):
    CANDIDATES = (dict(domain="d0000.example.test"), dict(domain="D0001.EXAMPLE.TEST"), dict(domain="d0007.example.test", unread=True), dict(domain="d0007.example.test", unread=False),
                  dict(label="CATEGORY_PROMOTIONS"), dict(label="Label_3"), dict(label="receipts"), dict(label="STARRED", unread=True), dict(domain="nowhere.example.test"),
                  dict(sender="nobody@nowhere.example.test"), dict(sender="newsletter0@d0002.example.test"), dict(sender="noreply1@d0003.example.test", domain="d0003.example.test"),
                  dict(sender="x@d0004.example.test", domain="d0005.example.test"), dict(domain="d0009.example.test", label="INBOX"))

    def check_all(self, index, account=ob.ACCOUNT):
        count = 0
        for kind, value in (("type", "NEWSLETTER"), ("type", "PROMOTIONAL"), ("type", "PERSONAL"), ("attention", "REVIEW_NEEDED")):
            for conf in ("LOW", "HIGH"):
                for cond in self.CANDIDATES:
                    fields = dict(kind=kind, value=value, confidence=conf, priority=0, **cond)
                    try:
                        want = reference_preview_rule(index, account, **fields)
                    except classify.RuleError:
                        with self.assertRaises(classify.RuleError):
                            classifier.preview_rule(index, account, **fields)
                        continue
                    self.assertEqual(classifier.preview_rule(index, account, **fields), want, fields)
                    count += 1
        return count

    def test_preview_rule_equals_the_original_for_many_candidates(self):
        index = self.build("plain-1000")
        self.assertGreater(self.check_all(index), 60)

    def test_one_context_gives_the_same_answers_as_one_call_each(self):
        index = self.build("plain-1000")
        ctx = classifier.PreviewContext(index, ob.ACCOUNT)
        for cond in self.CANDIDATES:
            fields = dict(kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, **cond)
            self.assertEqual(ctx.preview(**fields), reference_preview_rule(index, ob.ACCOUNT, **fields), fields)
            self.assertEqual(ctx.preview(**fields), ctx.preview(**fields))  # previews do not influence each other

    def test_conflicting_disabled_and_priority_rules(self):
        index = self.build("plain-300")
        rid = classifier.add_rule(index, ob.ACCOUNT, kind="type", value="SOCIAL", confidence="HIGH", priority=50, domain="d0001.example.test")
        classifier.add_rule(index, ob.ACCOUNT, kind="type", value="PERSONAL", confidence="LOW", priority=-5, label="CATEGORY_PROMOTIONS")
        classifier.set_enabled(index, ob.ACCOUNT, rid, False)
        self.assertGreater(self.check_all(index), 40)
        classifier.set_enabled(index, ob.ACCOUNT, rid, True)
        self.assertGreater(self.check_all(index), 40)

    def test_partial_stale_and_unruled_indexes(self):
        for name in ("partial-1000", "stale-1000", "norules-1000", "tiny-20"):
            self.assertGreater(self.check_all(self.build(name)), 20, name)

    def test_accounts_never_mix(self):
        index = self.build("twoaccounts-600")
        for account in (ob.ACCOUNT, ob.SECOND):
            ctx = classifier.PreviewContext(index, account)
            self.assertEqual(ctx.total, index._q("SELECT COUNT(*) FROM messages WHERE account=?", account)[0][0])
            fields = dict(kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, label="CATEGORY_PROMOTIONS")
            self.assertEqual(ctx.preview(**fields), reference_preview_rule(index, account, **fields))
        a = classifier.preview_rule(index, ob.ACCOUNT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, label="CATEGORY_PROMOTIONS")
        b = classifier.preview_rule(index, ob.SECOND, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, label="CATEGORY_PROMOTIONS")
        self.assertNotEqual(a, b)

    def test_every_rule_proposal_preview_is_the_original_preview(self):
        index = self.build("plain-3000")
        proposals = label_suggest.suggest_rules(index, ob.ACCOUNT).items
        self.assertGreater(len(proposals), 3)
        for p in proposals:
            self.assertEqual(dict(p.preview), reference_preview_rule(index, ob.ACCOUNT, **dict(p.fields)))


class CallCountRegressionTests(Base):
    """Detect the reintroduction of the repeated full-index work that made the first Organization request slow (counts, never wall-clock time)."""

    def test_the_index_is_read_a_bounded_number_of_times_however_many_previews_run(self):
        index = self.build("plain-3000")
        calls = {"features_for": 0, "gather": 0, "context": 0, "evaluate": 0, "recommend": 0}
        real = dict(features_for=classifier.features_for, gather=label_suggest._gather, context=classifier.PreviewContext.__init__, evaluate=classify.evaluate, recommend=label_suggest.recommend)

        def wrap(name):
            def inner(*a, **k):
                calls[name] += 1
                return real[name](*a, **k)
            return inner
        previewed = []
        real_preview = classifier.PreviewContext.preview

        def spy(self, **fields):
            r = real_preview(self, **fields)
            previewed.append(r["matched"])
            return r
        with mock.patch.object(classifier, "features_for", wrap("features_for")), mock.patch.object(label_suggest, "_gather", wrap("gather")), \
                mock.patch.object(classifier.PreviewContext, "__init__", lambda self, *a, **k: (calls.__setitem__("context", calls["context"] + 1), real["context"](self, *a, **k))[1]), \
                mock.patch.object(classify, "evaluate", wrap("evaluate")), mock.patch.object(label_suggest, "recommend", wrap("recommend")), mock.patch.object(classifier.PreviewContext, "preview", spy):
            analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()
        self.assertGreater(len(previewed), 5)  # there really were many previews
        self.assertEqual(calls["gather"], 1)  # recommendations, rule proposals and filter suggestions share ONE read of the per-group facts
        self.assertEqual(calls["recommend"], 1)  # filter suggestions reuse the recommendations instead of computing them again
        self.assertEqual(calls["context"], 1)  # message features are loaded once for all previews
        self.assertLessEqual(calls["features_for"], 1)
        self.assertLessEqual(calls["evaluate"], 2 * sum(previewed))  # only matching messages are ever evaluated: no per-preview full scan

    def test_standalone_functions_still_work_without_shared_state(self):
        index = self.build("plain-1000")
        groups = label_suggest.gather(index, ob.ACCOUNT)
        self.assertEqual(label_suggest.recommend(index, ob.ACCOUNT), label_suggest.recommend(index, ob.ACCOUNT, groups=groups))
        self.assertEqual(label_suggest.suggest_rules(index, ob.ACCOUNT), label_suggest.suggest_rules(index, ob.ACCOUNT, groups=groups, context=classifier.PreviewContext(index, ob.ACCOUNT)))
        rec = label_suggest.recommend(index, ob.ACCOUNT)
        self.assertEqual(filter_suggest.suggest(index, ob.ACCOUNT), filter_suggest.suggest(index, ob.ACCOUNT, recommendation=rec))

    def test_nothing_is_cached_between_requests(self):
        index = self.build("plain-300")
        before = analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()["data"]
        classifier.add_rule(index, ob.ACCOUNT, kind="type", value="SOCIAL", confidence="HIGH", priority=0, domain="d0002.example.test")
        index.save_labels(ob.ACCOUNT, [{"id": "Label_1", "name": "Only", "type": "user"}])
        after = analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()["data"]
        self.assertNotEqual(before, after)
        self.assertEqual(after["labels"]["user"], 1)
        for module in (analytics, label_suggest, filter_suggest, classifier):
            tree = ast.parse(Path(module.__file__).read_text())
            module_level_dicts = [n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, (ast.Dict, ast.List, ast.Set)) and any(getattr(t, "id", "").lower().endswith(("cache", "memo")) for t in n.targets)]
            self.assertEqual(module_level_dicts, [], module.__name__)

    def test_organization_via_the_read_only_index_is_identical_and_leaves_the_file_unchanged(self):
        index = self.build("plain-1000")
        normal = analytics.Analytics(index, ob.ACCOUNT, now=ob.NOW).organization()
        before = hashlib.sha256(Path(index.path).read_bytes()).hexdigest()
        ro = idx.ReadOnlyIndex(index.path)
        try:
            self.assertEqual(analytics.Analytics(ro, ob.ACCOUNT, now=ob.NOW).organization(), normal)
        finally:
            ro.close()
        self.assertEqual(hashlib.sha256(Path(index.path).read_bytes()).hexdigest(), before)

    def test_the_api_payload_shape_is_unchanged(self):
        data = analytics.Analytics(self.build("plain-300"), ob.ACCOUNT, now=ob.NOW).organization()
        self.assertEqual(sorted(data), ["as_of", "basis", "data", "explain", "index", "section"])
        self.assertEqual(sorted(data["data"]), ["filter_suggestions", "hygiene", "label_plans", "labels", "names_revealed", "read_only", "recommendations", "rule_proposals"])
        self.assertEqual(sorted(data["data"]["rule_proposals"]), ["by_confidence", "suppressed_groups", "total"])
        self.assertEqual(sorted(data["data"]["hygiene"]), ["by_code", "by_confidence", "findings", "top"])

    def test_no_new_imports_in_the_touched_modules(self):
        expected = {"classifier": {"gmail_intelligence"}, "label_suggest": {"collections", "dataclasses", "gmail_intelligence"}, "filter_suggest": {"dataclasses", "gmail_intelligence"}}
        forbidden = {"gmail", "oauth", "oauth_write", "keystore", "keystore_write", "scanner", "gmail_write", "gmail_write_policy", "exec_live_mailbox", "cleanup_exec", "socket", "http", "urllib", "ssl",
                     "requests", "subprocess", "threading", "multiprocessing", "concurrent", "sched", "asyncio"}
        for name, top in expected.items():
            tree = ast.parse((ROOT / "src" / "gmail_intelligence" / f"{name}.py").read_text())
            mods, names = set(), set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    mods |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom):
                    mods.add((n.module or "").split(".")[0])
                    names |= {a.name for a in n.names}
            self.assertEqual(mods - {""}, top, name)
            self.assertEqual((mods | names) & forbidden, set(), name)


if __name__ == "__main__":
    unittest.main()
