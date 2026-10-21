"""M8A-1 benchmark: wall time and peak RSS of the complete attention computation on large SYNTHETIC mailboxes (not a unit test; run by hand).

    .venv/bin/python -I tests/attention_bench.py [--json]

Every scenario builds its synthetic index in a temporary directory, then measures in a FRESH child process so the numbers cover only the engine: candidate streaming,
classification, scoring, thread collapse, sender diversity, sorting, the full snapshot hash and the cursor page (a second complete computation).
Peak RSS is the process high-water mark after minus before (`ru_maxrss`); nothing here touches Gmail, the Keychain or a personal index.
"""
import json
import os
import random
import resource
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
ACCOUNT = "owner@example.test"
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
DAY_MS = 86_400_000
NOW_MS = int(NOW.timestamp() * 1000)


def build(path, n, kind, seed=1):
    sys.path.insert(0, str(SRC))
    from gmail_intelligence import index as idx
    with idx.Index(path):
        pass
    rnd = random.Random(seed)
    conn = sqlite3.connect(path)
    senders = [f"s{i}@example{i % 300}.test" for i in range(3000)]
    msgs, labels = [], []
    for k in range(n):
        mid = f"{k:010x}"
        if kind == "dense":      # every message is a candidate that survives the threshold: unread 3-14 days, own thread, many senders
            labs = ["INBOX", "UNREAD"]
            age = rnd.uniform(3, 14)
            thread = f"t{k}"
        elif kind == "many-unread":   # 90% unread over all ages: most are NOT retained (fresh or old), a large share is
            labs = ["INBOX"] + (["UNREAD"] if rnd.random() < 0.9 else []) + (["CATEGORY_PROMOTIONS"] if rnd.random() < 0.3 else [])
            age = rnd.uniform(0, 400)
            thread = f"t{rnd.randrange(max(1, n // 3))}"
        else:                    # balanced: a typical mailbox
            labs = ["INBOX"] if rnd.random() < 0.7 else []
            for lab, p in (("STARRED", 0.01), ("IMPORTANT", 0.10), ("UNREAD", 0.25), ("CATEGORY_PROMOTIONS", 0.3), ("CATEGORY_UPDATES", 0.2)):
                if rnd.random() < p:
                    labs.append(lab)
            age = rnd.uniform(0, 1500)
            thread = f"t{rnd.randrange(max(1, n // 3))}"
        msgs.append((ACCOUNT, mid, thread, int(NOW_MS - age * DAY_MS), 1000, rnd.choice(senders), 1 if "UNREAD" in labs else 0, 1))
        labels.extend((ACCOUNT, mid, lab) for lab in labs)
    conn.executemany("INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) VALUES (?,?,?,?,?,?,?,?)", msgs)
    conn.executemany("INSERT INTO message_labels VALUES (?,?,?)", labels)
    if kind == "rule":
        pass
    conn.execute("INSERT INTO scans (account, mode, status, started_at, finished_at) VALUES (?, 'full', 'completed', '2026-10-21T10:00:00Z', '2026-10-21T11:00:00Z')", (ACCOUNT,))
    conn.commit()
    conn.close()


def add_attention_rule(path):
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO class_rules (account,id,kind,value,c_domain,confidence,priority,enabled,note,created_at) VALUES (?,?,?,?,?,?,?,1,'bench','2026-10-21T00:00:00Z')",
                 (ACCOUNT, "u1", "attention", "POTENTIALLY_IMPORTANT", "example7.test", "MEDIUM", 0))
    conn.commit()
    conn.close()


def rss_bytes():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == "darwin" else value * 1024


CHILD = r"""
import json, resource, sys, time
sys.path[:0] = [%(src)r]
from datetime import datetime, timezone
from gmail_intelligence import attention, index as idx
def rss():
    v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return v if sys.platform == "darwin" else v * 1024
ro = idx.ReadOnlyIndex(%(path)r)
now = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
before = rss()
t0 = time.perf_counter()
try:
    first = attention.compute(ro, %(account)r, now=now, limit=25, budget=%(budget)d, sender_limit=%(sender_limit)d)
    t1 = time.perf_counter()
    second = attention.compute(ro, %(account)r, now=now, limit=100, cursor=first["next_cursor"], budget=%(budget)d, sender_limit=%(sender_limit)d) if first["next_cursor"] else first
    t2 = time.perf_counter()
    out = {"ok": True, "totals": first["totals"], "first_s": round(t1 - t0, 2), "cursor_page_s": round(t2 - t1, 2), "second_items": len(second["items"])}
except attention.AttentionError as exc:
    out = {"ok": False, "code": exc.code, "first_s": round(time.perf_counter() - t0, 2)}
out["peak_rss_before_mb"] = round(before / 1048576, 1)
out["peak_rss_after_mb"] = round(rss() / 1048576, 1)
out["delta_mb"] = round((rss() - before) / 1048576, 1)
print(json.dumps(out))
"""


def measure(path, budget, sender_limit=3):
    code = CHILD % {"src": str(SRC), "path": path, "account": ACCOUNT, "budget": budget, "sender_limit": sender_limit}
    return json.loads(subprocess.run([sys.executable, "-I", "-c", code], check=True, capture_output=True, text=True).stdout)


def main(argv):
    scenarios = [("balanced", 200_000, False), ("many-unread", 200_000, False), ("balanced + user attention rule (full scan)", 200_000, True),
                 ("dense 100k retained", 100_000, False), ("dense 200k retained", 200_000, False), ("dense 400k retained", 400_000, False),
                 ("dense 500k retained, budget 500k (complete)", 500_000, False, 500_000), ("dense 600k retained, budget 500k (RESULT_INCOMPLETE)", 600_000, False, 500_000)]
    only = argv[argv.index("--only") + 1] if "--only" in argv else ""
    results = []
    for name, n, rule, *extra in scenarios:
        if only not in name:
            continue
        kind = "dense" if name.startswith("dense") else "many-unread" if name.startswith("many") else "balanced"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "index.sqlite3")
            t0 = time.perf_counter()
            build(path, n, kind)
            if rule:
                add_attention_rule(path)
            built = round(time.perf_counter() - t0, 1)
            res = measure(path, budget=extra[0] if extra else 10_000_000, sender_limit=0 if name.startswith("dense") else 3)
        res.update(scenario=name, messages=n, build_s=built)
        results.append(res)
        print(json.dumps(res) if "--json" in argv else f"{name:45s} n={n:>7} {res}", flush=True)
    return results


if __name__ == "__main__":
    main(sys.argv[1:])
