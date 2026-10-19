"""Deterministic SYNTHETIC index builder and benchmark for the dashboard's Organization section (M6 hotfix). No real data of any kind: invented example.test domains, invented label names.

    python tests/organization_bench.py [--sizes 1000 5000 17000] [--profile] [--digest]

`--digest` prints a SHA-256 of the canonical Organization output (every list, order and number, only the injected clock normalized) so a change of results is detectable.
Timings are for reporting only; correctness tests never assert on wall-clock time.
"""
import argparse
import cProfile
import hashlib
import json
import pstats
import random
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path

import os  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.environ.get("GI_SRC") or str(ROOT / "src"))  # GI_SRC: benchmark another checkout of the source tree (for before/after comparisons)

from gmail_intelligence import analytics, classifier, cleanup_protect, filter_suggest, index as idx, label_hygiene, label_suggest  # noqa: E402

ACCOUNT = "bench.owner@example.invalid"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
LOCALPARTS = ("noreply", "newsletter", "info", "support", "billing", "team", "hello", "alerts", "news", "orders", "no-reply", "digest")
USER_LABELS = ["Receipts", "receipts", "Work", "Work/Plans", "Work/Plans/2026", "Travel", "Travel/2025", "travel 2025", "Finance", "Finance-Old", "Statements", "Statement", "Newsletters",
               "Newsletter", "Family", "School", "Shopping", "Shopping/Deals", "Archive 2024", "Archive_2024", "Health", "Home", "Projects", "Projects/Alpha", "Misc", "Old", "Tax", "Bills",
               "Bills/Utilities", "Events"]


def build(path, messages, seed=11, extra_rules=True, complete=True, stale=False, account=ACCOUNT, wide=False):
    """Create the synthetic index at `path` (deterministic for a seed) and return the open Index."""
    rnd = random.Random(seed)
    index = idx.Index(str(path))
    domains = max(32, messages // (12 if wide else 40))  # `wide`: many mid-sized sender groups, i.e. many rule candidates to preview
    doms = [f"d{i:04d}.example.test" for i in range(domains)]
    weights = [1.0 / (i + 1) ** (0.35 if wide else 0.8) for i in range(domains)]
    senders = {d: [f"{rnd.choice(LOCALPARTS)}{k}@{d}" for k in range(rnd.randint(1, 5))] for d in doms}
    label_of = {d: f"Label_{rnd.randint(1, len(USER_LABELS))}" for d in doms if rnd.random() < 0.3}
    if extra_rules:
        for d in doms[:8]:
            classifier.add_rule(index, account, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, domain=d)
        for d in doms[8:11]:
            classifier.add_rule(index, account, kind="type", value="FINANCIAL", confidence="HIGH", priority=0, domain=d)
        for d in doms[11:13]:
            classifier.add_rule(index, account, kind="type", value="EDUCATIONAL", confidence="MEDIUM", priority=0, domain=d)
        classifier.add_rule(index, account, kind="attention", value="POTENTIALLY_IMPORTANT", confidence="MEDIUM", priority=0, sender=senders[doms[20]][0])
        cleanup_protect.add(index, account, domain=doms[14])
        cleanup_protect.add(index, account, sender=senders[doms[3]][0])
    start = NOW - timedelta(days=1100)
    span = int((NOW - start).total_seconds()) - 86400
    rows = []
    for i in range(messages):
        dom = rnd.choices(doms, weights)[0]
        labels = []
        r = rnd.random()
        if r < 0.9:
            labels.append("INBOX")
        tab = rnd.random()
        labels += ["CATEGORY_PROMOTIONS"] if tab < 0.25 else ["CATEGORY_UPDATES"] if tab < 0.45 else ["CATEGORY_SOCIAL"] if tab < 0.53 else ["CATEGORY_FORUMS"] if tab < 0.56 else []
        if dom in label_of and rnd.random() < 0.6:
            labels.append(label_of[dom])
        if rnd.random() < 0.02:
            labels.append("Label_" + str(rnd.randint(1, len(USER_LABELS))))
        for lab, p in (("STARRED", 0.015), ("IMPORTANT", 0.03), ("UNREAD", 0.2), ("TRASH", 0.01)):
            if rnd.random() < p:
                labels.append(lab)
        when = start + timedelta(seconds=rnd.randrange(span))
        rows.append({"id": f"m{i:06d}", "thread_id": f"t{i:06d}", "internal_ms": int(when.timestamp() * 1000), "size": rnd.randrange(2000, 90000), "sender": rnd.choice(senders[dom]), "label_ids": labels})
    scan = index.start_scan(account, "full" if complete else "limited", None if complete else 5)
    index.save_batch(account, scan, rows)
    index.save_labels(account, [{"id": f"Label_{i + 1}", "name": nm, "type": "user"} for i, nm in enumerate(USER_LABELS)] + [{"id": "INBOX", "name": "INBOX", "type": "system"}])
    index.finish_scan(scan, "completed")
    with index.conn:  # scan times are fixed so that every digest is reproducible (the only other clock, `now`, is injected)
        index.conn.execute("UPDATE scans SET started_at='2026-10-18T09:00:00Z', finished_at='2026-10-18T09:30:00Z' WHERE id=?", (scan,))
    classifier.run(index, account, persist=True)
    if stale:  # a rule added after classification makes every stored result stale
        classifier.add_rule(index, account, kind="type", value="SOCIAL", confidence="HIGH", priority=0, domain=doms[30 % len(doms)])
    return index


CASES = {"tiny-20": dict(messages=20), "plain-300": dict(messages=300), "plain-1000": dict(messages=1000), "plain-3000": dict(messages=3000, seed=5), "norules-1000": dict(messages=1000, seed=3, extra_rules=False),
         "partial-1000": dict(messages=1000, seed=4, complete=False), "stale-1000": dict(messages=1000, seed=6, stale=True)}


SECOND = "second.owner@example.invalid"


def build_case(path, name):
    """One of the named deterministic synthetic cases. 'twoaccounts-600' puts two different accounts (different data) into the same database file."""
    if name == "twoaccounts-600":
        build(path, 600, seed=21).close()
        return build(path, 600, seed=22, account=SECOND)
    return build(path, **CASES[name])


def canonical(index, account=ACCOUNT, reveal_names=True):
    """Everything the Organization screen is built from, in full and in order, as a JSON-serializable structure (clock fixed)."""
    h = label_hygiene.analyze(index, account)
    rec = label_suggest.recommend(index, account)
    rules = label_suggest.suggest_rules(index, account)
    filt = filter_suggest.suggest(index, account)
    org = analytics.Analytics(index, account, now=NOW, reveal_names=reveal_names).organization()
    return json.loads(json.dumps({"hygiene": repr(h), "recommendations": repr(rec), "rules": repr(rules), "filters": repr(filt), "organization": org}, default=repr, sort_keys=True))


def digest(index, account=ACCOUNT):
    return hashlib.sha256(json.dumps(canonical(index, account), sort_keys=True).encode()).hexdigest()


def cold_organization(index, account=ACCOUNT):
    t = time.perf_counter()
    result = analytics.Analytics(index, account, now=NOW).organization()
    return round((time.perf_counter() - t) * 1000, 1), result


def parts(index, account=ACCOUNT):
    out = {}
    for name, fn in (("hygiene", lambda: label_hygiene.analyze(index, account)), ("recommend", lambda: label_suggest.recommend(index, account)),
                     ("suggest_rules", lambda: label_suggest.suggest_rules(index, account)), ("suggest_filters", lambda: filter_suggest.suggest(index, account))):
        t = time.perf_counter()
        fn()
        out[name] = round((time.perf_counter() - t) * 1000, 1)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sizes", type=int, nargs="+", default=[1000, 5000, 17000])
    p.add_argument("--profile", action="store_true")
    p.add_argument("--wide", action="store_true", help="many mid-sized sender groups (a preview-heavy mailbox)")
    p.add_argument("--digest", action="store_true")
    a = p.parse_args()
    for size in a.sizes:
        with tempfile.TemporaryDirectory() as tmp:
            t = time.perf_counter()
            index = build(Path(tmp) / "bench.sqlite3", size, wide=a.wide)
            built = round(time.perf_counter() - t, 1)
            ms, res = cold_organization(index)  # the first call after build: nothing cached in this process except SQLite's page cache
            ms2, _ = cold_organization(index)
            calls = {"preview_rule": 0}
            real = classifier.preview_rule

            def counting(*args, **kw):
                calls["preview_rule"] += 1
                return real(*args, **kw)
            classifier.preview_rule = counting
            tracemalloc.start()
            cold_organization(index)
            peak = round(tracemalloc.get_traced_memory()[1] / 1e6, 1)
            tracemalloc.stop()
            classifier.preview_rule = real
            row = {"messages": size, "wide": a.wide, "build_s": built, "organization_ms_first": ms, "organization_ms_second": ms2, "preview_rule_calls": calls["preview_rule"], "peak_py_mem_mb": peak,
                   "rule_proposals": res["data"]["rule_proposals"]["total"], "recommendations": res["data"]["recommendations"]["total"]}
            if a.digest:
                row["digest"] = digest(index)
            print(json.dumps(row), flush=True)
            if a.profile and size == a.sizes[-1]:
                pr = cProfile.Profile()
                pr.enable()
                cold_organization(index)
                pr.disable()
                pstats.Stats(pr).sort_stats("cumulative").print_stats(14)
            index.close()


if __name__ == "__main__":
    main()
