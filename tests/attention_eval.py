"""M8A-1 synthetic evaluation of the PROVISIONAL ranking weights (not a unit test; run by hand, prints markdown).

    .venv/bin/python -I tests/attention_eval.py

What it can show: internal consistency (bounds, monotonicity, the star floor), whether the documented intent is respected, how stable the order is when
each weight moves by +/-20%, and how a flood of look-alike mail behaves. What it cannot show: that the ranking is useful for a real mailbox. Synthetic data only.
"""
import dataclasses
import itertools
import random
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE)]

import attention_support as S  # noqa: E402
from attention_support import attention, classify  # noqa: E402

REF = S.TODAY
W0 = attention.DEFAULT_WEIGHTS


def rule(rid, kind, value, conf, **cond):
    return classify.Rule(rid, kind, value, conf, "bench", tier=classify.TIER_USER, **cond)


RULES = (rule("u1", "type", "PERSONAL", "HIGH", domain="close.test"), rule("u2", "type", "TRANSACTIONAL", "MEDIUM", domain="bank.test"))
# name, labels, sender, age (days), intended level 0-4 (what the design means to say, written BEFORE looking at any score)
ARCHETYPES = (
    ("starred, personal, unread, recent", ("INBOX", "STARRED", "UNREAD"), "a@close.test", 2, 4),
    ("starred, read, very old", ("INBOX", "STARRED"), "a@x.test", 500, 3),
    ("starred promotion", ("INBOX", "STARRED", "CATEGORY_PROMOTIONS"), "a@promo.test", 30, 3),
    ("important + unread, personal sender", ("INBOX", "IMPORTANT", "UNREAD"), "a@close.test", 5, 3),
    ("important + unread, unknown sender", ("INBOX", "IMPORTANT", "UNREAD"), "a@x.test", 5, 2),
    ("important + unread, transactional (user rule)", ("INBOX", "IMPORTANT", "UNREAD"), "alerts@bank.test", 5, 2),
    ("important, read", ("INBOX", "IMPORTANT"), "a@x.test", 20, 1),
    ("unread, 3-14 days", ("INBOX", "UNREAD"), "a@x.test", 7, 1),
    ("promotion + important + unread", ("INBOX", "IMPORTANT", "UNREAD", "CATEGORY_PROMOTIONS"), "a@promo.test", 5, 0),
    ("noreply notification, unread", ("INBOX", "UNREAD"), "noreply@x.test", 5, 0),
    ("unread, very old", ("INBOX", "UNREAD"), "a@x.test", 300, 0),
)


def score(weights, labels, sender, age):
    f = classify.Features(sender, "UNREAD" in labels, frozenset(labels), frozenset())
    return attention.score_message(f, classify.evaluate(f, RULES), S.ms_ago(age), REF, frozenset(r.id for r in RULES), weights)


def intent(weights):
    rows = [(n, score(weights, l, s, a), lv) for n, l, s, a, lv in ARCHETYPES]
    pairs = [(a, b) for a in rows for b in rows if a[2] > b[2]]
    ok = sum(1 for a, b in pairs if a[1].score > b[1].score)
    return rows, ok, len(pairs)


def corpus(n=600, seed=3):
    rnd = random.Random(seed)
    items = []
    for k in range(n):
        name, labels, sender, age, lv = rnd.choice(ARCHETYPES)
        items.append((f"{k:06d}", labels, sender, max(0, int(age * rnd.uniform(0.5, 1.5)))))
    return items


def order(weights, items):
    recs = []
    for mid, labels, sender, age in items:
        r = score(weights, labels, sender, age)
        recs.append(r._replace(id=mid))
    return [r.id for r in sorted(recs, key=attention._pkey)], {r.id: r.score for r in recs}


def tau(a, b):
    pos = {x: i for i, x in enumerate(b)}
    seq = [pos[x] for x in a]
    conc = disc = 0
    for i in range(len(seq)):
        for j in range(i + 1, len(seq)):
            conc += seq[i] < seq[j]
            disc += seq[i] > seq[j]
    return (conc - disc) / max(1, conc + disc)


def scaled(pairs, f):
    return tuple((k, max(0, round(v * f))) for k, v in pairs)


def perturbations():
    out = []
    for f in (0.8, 1.2):
        out += [(f"star x{f}", dataclasses.replace(W0, star=round(W0.star * f))), (f"owner_cap x{f}", dataclasses.replace(W0, owner_cap=round(W0.owner_cap * f))),
                (f"user rule weights x{f}", dataclasses.replace(W0, rule=scaled(W0.rule, f))), (f"important x{f}", dataclasses.replace(W0, important=round(W0.important * f))),
                (f"age points x{f}", dataclasses.replace(W0, age=tuple((d, round(p * f)) for d, p in W0.age))), (f"personal bonus x{f}", dataclasses.replace(W0, personal=scaled(W0.personal, f))),
                (f"inferred cap x{f}", dataclasses.replace(W0, gmail_cap=round(W0.gmail_cap * f))), (f"penalties x{f}", dataclasses.replace(W0, penalty=scaled(W0.penalty, f)))]
    return out


def properties(samples=20_000, seed=9):
    labels_pool = ("INBOX", "STARRED", "IMPORTANT", "UNREAD", "CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL", "CATEGORY_UPDATES", "CATEGORY_PERSONAL")
    senders = ("a@close.test", "noreply@x.test", "", "alerts@bank.test", "a@x.test")
    rnd = random.Random(seed)
    bad = {"bounds": 0, "star_floor": 0, "positive_monotone": 0, "penalty_monotone": 0}
    for _ in range(samples):
        labels = tuple(l for l in labels_pool if rnd.random() < 0.4)
        sender, age = rnd.choice(senders), rnd.choice((0, 1, 3, 10, 30, 100))
        base = score(W0, labels, sender, age).score
        bad["bounds"] += not 0 <= base <= 100
        bad["star_floor"] += "STARRED" in labels and base < 50
        for extra in ("STARRED", "IMPORTANT", "UNREAD"):
            bad["positive_monotone"] += score(W0, tuple(set(labels) | {extra}), sender, age).score < base
        bad["penalty_monotone"] += "CATEGORY_PROMOTIONS" not in labels and sender != "alerts@bank.test" and score(W0, tuple(set(labels) | {"CATEGORY_PROMOTIONS"}), sender, age).score > base
    return samples, bad


def flood():
    out = []
    mb = S.Mailbox()
    try:
        for k in range(25):
            mb.add(f"{k:08x}", sender=f"friend{k}@close.test", labels=("INBOX", "STARRED"), age_days=10 + k)
        for k in range(10_000):
            mb.add(f"f{k:07x}", thread=f"ft{k}", sender="spoof@close.test", labels=("INBOX", "UNREAD"), age_days=4 + k % 10)
        for limit in (3, 0):
            res = mb.compute(limit=100, sender_limit=limit)
            starred = sum(1 for i in res["items"] if any(s["code"] == "STARRED" for s in i["signals"]))
            out.append((f"10,000 look-alike unread mails from ONE sender among 25 starred (sender limit {limit or 'off'})", len(res["items"]), starred, res["totals"]["total"]))
        mb2 = S.Mailbox()
        try:
            for k in range(25):
                mb2.add(f"{k:08x}", sender=f"friend{k}@close.test", labels=("INBOX", "STARRED"), age_days=10 + k)
            for k in range(5_000):
                mb2.add(f"g{k:07x}", sender=f"spoof{k}@close.test", labels=("INBOX", "UNREAD", "IMPORTANT"), age_days=4)
            res = mb2.compute(limit=100, sender_limit=3)
            top = [i["score"] for i in res["items"]]
            out.append(("5,000 look-alikes from 5,000 senders, each Gmail-IMPORTANT + unread (score 35) among 25 starred", len(top), sum(1 for s in top if s >= 50), res["totals"]["total"]))
        finally:
            mb2.close()
    finally:
        mb.close()
    return out


def main():
    print("# Synthetic evaluation (generated by tests/attention_eval.py)\n")
    rows, ok, total = intent(W0)
    print("## 1. Documented intent (11 archetypes, written before scoring)\n\n| archetype | intended level | score | tier |\n|---|---|---|---|")
    for n, r, lv in rows:
        print(f"| {n} | {lv} | {r.score} | {attention.tier_of(r.score)} |")
    print(f"\nPairs with a higher intended level that score strictly higher: **{ok}/{total}**.\n")
    n, bad = properties()
    print(f"## 2. Invariants over {n:,} random label/sender/age combinations\n")
    for k, v in bad.items():
        print(f"- {k}: {v} violation(s)")
    items = corpus()
    base_order, base_scores = order(W0, items)
    print("\n## 3. Sensitivity: each weight moved by +/-20% (corpus of 600 mixed messages)\n\n| change | Kendall tau vs baseline | top-25 overlap | intent pairs kept |\n|---|---|---|---|")
    worst = (1.0, 25, total)
    for name, w in perturbations():
        o, _ = order(w, items)
        t, ov = tau(o, base_order), len(set(o[:25]) & set(base_order[:25]))
        _, ok2, _ = intent(w)
        worst = (min(worst[0], t), min(worst[1], ov), min(worst[2], ok2))
        print(f"| {name} | {t:.3f} | {ov}/25 | {ok2}/{total} |")
    print(f"\nWorst case: tau {worst[0]:.3f}, top-25 overlap {worst[1]}/25, intent pairs kept {worst[2]}/{total}.\n")
    print("## 4. Flood scenarios (through the full pipeline)\n\n| scenario | items listed | starred among them | total after filters |\n|---|---|---|---|")
    for name, listed, starred, tot in flood():
        print(f"| {name} | {listed} | {starred} | {tot} |")


if __name__ == "__main__":
    main()
