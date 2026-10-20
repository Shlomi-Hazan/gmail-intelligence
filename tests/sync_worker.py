"""Subprocess driver for the real-process concurrency/crash tests (synthetic only; never contacts Gmail).

    sync_worker.py --db PATH --mode sync|scan-all|scan-resume|scan-limit --script JSON --n N [--offset SECONDS]
                   [--pause-at POINT --paused-file F --release-file F] [--crash-at POINT]
It rebuilds the same deterministic fake mailbox as the parent (n messages, then the JSON `script` of changes), runs the operation and prints one JSON line.
`--crash-at` ends the process with os._exit (no clean-up, like kill -9) when the named durable boundary is reached; `--pause-at` stops there until released.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from fake_history import ACCOUNT, standard_mailbox  # noqa: E402
from gmail_intelligence import index as idx, scanner, sync, sync_lease  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--script", default="[]")
    ap.add_argument("--offset", type=float, default=0.0)
    ap.add_argument("--pause-at")
    ap.add_argument("--paused-file")
    ap.add_argument("--release-file")
    ap.add_argument("--crash-at")
    ap.add_argument("--chunk", type=int, default=50)
    args = ap.parse_args()
    mailbox = standard_mailbox(args.n)
    mailbox.script(json.loads(args.script))
    clock = lambda: datetime.now(timezone.utc) + timedelta(seconds=args.offset)  # noqa: E731

    def hook(point):
        if args.crash_at == point:
            os._exit(9)
        if args.pause_at == point:
            Path(args.paused_file).write_text("paused")
            while not os.path.exists(args.release_file):
                time.sleep(0.02)

    fast = scanner.RateLimiter(10 ** 9, clock=lambda: 0.0, sleep=lambda s: None)
    try:
        with idx.Index(args.db, create=False) as index:
            if args.mode == "e2e":  # deterministic end-to-end digest (used to compare PYTHONHASHSEED values)
                import hashlib
                base = standard_mailbox(args.n)
                scanner.run_scan(base, index, ACCOUNT, mode="full", limiter=fast, sleep=lambda s: None, clock=clock, page_size=3)
                base.script(json.loads(args.script))
                sync.run_sync(base, index, ACCOUNT, limiter=fast, sleep=lambda s: None, clock=clock, page_size=2, chunk=3)
                rows = [tuple(r) for r in index.conn.execute("SELECT id,thread_id,internal_ms,size,sender,unread,scan_id FROM messages ORDER BY id")]
                labs = [tuple(r) for r in index.conn.execute("SELECT * FROM message_labels ORDER BY 1,2,3")]
                tomb = [tuple(r)[:2] + tuple(r)[3:] for r in index.conn.execute("SELECT * FROM message_tombstone ORDER BY 1,2")]
                out = {"digest": hashlib.sha256(repr((rows, labs, tomb)).encode()).hexdigest()}
            elif args.mode == "sync":
                out = sync.run_sync(mailbox, index, ACCOUNT, limiter=fast, sleep=lambda s: None, clock=clock, hook=hook, chunk=args.chunk)
            else:
                mode = {"scan-all": dict(mode="full"), "scan-resume": dict(mode="full", resume=True), "scan-limit": dict(mode="limited", limit=5)}[args.mode]
                mailbox.hooks[("get_profile", 1)] = lambda: hook("acquired")  # the first profile call happens right after the lease is acquired
                mailbox.hooks[("list_message_ids", 2)] = lambda: hook("page2")
                out = scanner.run_scan(mailbox, index, ACCOUNT, limiter=fast, sleep=lambda s: None, clock=clock, page_size=3, **mode)
                out = {"status": out["status"]}
    except sync_lease.SyncError as exc:
        print(json.dumps({"error": exc.code}))
        return 3
    except scanner.ScanInterrupted as exc:
        print(json.dumps({"error": "SCAN_INTERRUPTED"}))
        return 4
    print(json.dumps({"ok": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
