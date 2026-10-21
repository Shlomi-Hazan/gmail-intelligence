"""Builds a small synthetic index with several plans in different conditions and prints a digest of the plan-impact report (used to compare PYTHONHASHSEED values)."""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

with tempfile.TemporaryDirectory() as tmp:
    os.environ["GMAIL_INTELLIGENCE_HOME"] = tmp
    from gmail_intelligence import classifier, cleanup_plans as cp, index as idx, plan_impact
    import m7_support
    from test_cleanup import ACCT, NOW, msg

    m7_support_pin = None
    index = idx.Index()
    from gmail_intelligence import sync_health
    from datetime import timedelta as td
    sync_health.SYNC_MAX_AGE = td(days=36500)
    sync_health.CLOCK_TOLERANCE = td(days=36500)
    scan = index.start_scan(ACCT, "full")
    index.save_batch(ACCT, scan, [msg(i, sender=f"s{i}@shop.example.test") for i in range(1, 9)])
    index.finish_scan(scan, "completed")
    m7_support.seed_healthy_sync(index, ACCT)
    classifier.run(index, ACCT, persist=True)
    t = datetime.fromtimestamp(NOW / 1000, tz=timezone.utc)
    ids = [f"m{i}" for i in range(1, 9)]
    plans = []
    for k, chunk in enumerate((ids[:2], ids[2:5], ids[5:8])):
        t += timedelta(seconds=10)
        p = cp.create_plan(index, ACCT, chunk, now=t)
        if k < 2:
            p = cp.mark_reviewed(index, ACCT, p["plan_id"], cp.review_phrase(p), now=t + timedelta(seconds=1))
        if k == 0:
            cp.approve(index, ACCT, p["plan_id"], cp.approval_phrase(p), now=t + timedelta(seconds=2))
        plans.append(p)
    with index.conn:
        index.conn.execute("UPDATE message_labels SET label_id='STARRED' WHERE message_id='m3' AND label_id='CATEGORY_PROMOTIONS'")
        index.conn.execute("DELETE FROM message_labels WHERE message_id='m1'")
        index.conn.execute("DELETE FROM messages WHERE id='m6'")
    ro = idx.ReadOnlyIndex(index.path)
    rep = plan_impact.impact_report(ro, ACCT, now=t + timedelta(hours=30))
    for e in rep["plans"]:
        e["plan_id"] = "p"
        e.pop("created_at"), e.pop("expires_at")
    print(hashlib.sha256(json.dumps(rep, sort_keys=True).encode()).hexdigest())
