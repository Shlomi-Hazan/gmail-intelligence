"""A SYNTHETIC index for the dashboard: invented domains (reserved example.test), invented label names, no real data of any kind.

Used by the tests and for local visual checks:
    python tests/dashboard_fixture.py --serve        # builds a temporary synthetic index and serves it on 127.0.0.1 with a fixed demo token
It never touches the owner's real index, Gmail, the Keychain or the network.
"""
import argparse
import random
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gmail_intelligence import classifier, cleanup_plans as cp, index as idx, label_plans as lp  # noqa: E402

ACCOUNT = "demo.owner@example.invalid"
DEMO_TOKEN = "demo-token-synthetic-0123456789abcdef"
HOSTILE_SENDER = '"><img src=x onerror=alert(1)>@evil.example.test'
HOSTILE_LABEL = "<script>alert(1)</script> \u202eevil"
SENDERS = [  # (address, labels, weight)
    ("deals@shop-deals.example.test", ("INBOX", "CATEGORY_PROMOTIONS"), 9), ("weekly@news-weekly.example.test", ("INBOX",), 6), ("noreply@alerts.example.test", ("INBOX",), 8),
    ("updates@social-hub.example.test", ("INBOX", "CATEGORY_SOCIAL"), 5), ("statements@bank.example.test", ("INBOX",), 3), ("friend@mail.example.test", ("INBOX",), 3),
    ("team@course.example.test", ("INBOX",), 2), ("offers@travel.example.test", ("INBOX", "CATEGORY_PROMOTIONS"), 4), ("digest@forum.example.test", ("INBOX", "CATEGORY_FORUMS"), 2),
    (HOSTILE_SENDER, ("INBOX",), 1)]


def build(path, messages=900, seed=7, now=None):
    """Create the synthetic index at `path`. Deterministic for a given seed. Returns the Index (open)."""
    rnd = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    index = idx.Index(str(path))
    classifier.add_rule(index, ACCOUNT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, domain="news-weekly.example.test")
    classifier.add_rule(index, ACCOUNT, kind="type", value="FINANCIAL", confidence="HIGH", priority=0, domain="bank.example.test")
    classifier.add_rule(index, ACCOUNT, kind="type", value="EDUCATIONAL", confidence="MEDIUM", priority=0, domain="course.example.test")
    classifier.add_rule(index, ACCOUNT, kind="attention", value="POTENTIALLY_IMPORTANT", confidence="MEDIUM", priority=0, sender="friend@mail.example.test")
    rows, start = [], now - timedelta(days=31 * 30)
    weights = [w for _, _, w in SENDERS]
    for i in range(messages):
        addr, labels, _ = rnd.choices(SENDERS, weights)[0]
        when = start + timedelta(seconds=rnd.randrange(int((now - start).total_seconds()) - 3 * 86400))
        label_ids = list(labels) + (["UNREAD"] if rnd.random() < 0.18 else []) + (["Label_1"] if "shop-deals" in addr and rnd.random() < 0.7 else [])
        rows.append({"id": f"m{i:05d}", "thread_id": f"t{i:05d}", "internal_ms": int(when.timestamp() * 1000), "size": rnd.randrange(3000, 90000), "sender": addr, "label_ids": label_ids})
    scan = index.start_scan(ACCOUNT, "full")
    index.save_batch(ACCOUNT, scan, rows)
    index.save_labels(ACCOUNT, [{"id": "Label_1", "name": "Receipts", "type": "user"}, {"id": "Label_2", "name": "receipts", "type": "user"}, {"id": "Label_3", "name": "Travel/2025", "type": "user"},
                                {"id": "Label_4", "name": HOSTILE_LABEL, "type": "user"}, {"id": "Label_5", "name": "Archive Old", "type": "user"}, {"id": "INBOX", "name": "INBOX", "type": "system"}])
    index.finish_scan(scan, "completed")
    import m7_support  # M7A: the synthetic demo plans need a healthy synthetic sync state
    m7_support.seed_healthy_sync(index, ACCOUNT, at=now)
    classifier.run(index, ACCOUNT, persist=True)
    return index


def add_history(index, now=None):
    """A reviewed and approved cleanup plan plus a label plan, so the Cleanup and Organization screens have something to show."""
    from gmail_intelligence import cleanup_candidates as cc
    now = now or datetime.now(timezone.utc)
    res = cc.evaluate_all(index, ACCOUNT, now_ms=int(now.timestamp() * 1000))
    ids = [d.message_id for d in res.decisions if d.outcome == cc.ELIGIBLE][:5]
    if ids:
        plan = cp.create_plan(index, ACCOUNT, ids, now=now)
        cp.mark_reviewed(index, ACCOUNT, plan["plan_id"], cp.review_phrase(plan), now=now + timedelta(minutes=1))
        cp.approve(index, ACCOUNT, plan["plan_id"], cp.approval_phrase(plan), now=now + timedelta(minutes=2))
    lp.create_plan(index, ACCOUNT, [("CREATE", "Archive 2026")], now=now + timedelta(minutes=3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--reveal", action="store_true", help="show sender addresses and label names")
    args = parser.parse_args()
    from gmail_intelligence import dashboard_server as ds
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "index.sqlite3"
    index = build(path)
    add_history(index)
    index.close()
    if args.serve:
        server = ds.DashboardServer(str(path), ACCOUNT, DEMO_TOKEN, port=args.port, reveal_senders=args.reveal, reveal_names=args.reveal, reload_static=True)
        print("SYNTHETIC demo data only. Open:", server.url(), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
