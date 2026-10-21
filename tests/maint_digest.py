"""Builds a synthetic index with anomalies and backups in a temp dir and prints a digest of the maintenance report (used to compare PYTHONHASHSEED values)."""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from fake_history import ACCOUNT, standard_mailbox  # noqa: E402
from gmail_intelligence import index as idx, maintenance, scanner, sync  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    db = os.path.join(tmp, "index.sqlite3")
    index = idx.Index(db)
    fast = scanner.RateLimiter(10 ** 9, clock=(lambda it=__import__("itertools").count(): next(it) * 1000.0), sleep=lambda s: None)
    mb = standard_mailbox(12)
    t0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
    scanner.run_scan(mb, index, ACCOUNT, mode="full", limiter=fast, sleep=lambda s: None, clock=lambda: t0, page_size=3)
    mb.add("n1")
    mb.delete("m002")
    sync.run_sync(mb, index, ACCOUNT, limiter=fast, sleep=lambda s: None, clock=lambda: t0 + timedelta(minutes=5), page_size=2)
    with index.conn:
        index.conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCOUNT, "ghost", "INBOX"))
        index.conn.execute("UPDATE messages SET scan_id=9999 WHERE id='m003'")
    index.close()
    for i, mode in enumerate((0o600, 0o644)):
        path = f"{db}.pre-m7-backup-2026102011000{i}Z"
        src, dest = sqlite3.connect(db), sqlite3.connect(path)
        src.backup(dest)
        dest.close()
        src.close()
        os.chmod(path, mode)
    rep = maintenance.run(db, ACCOUNT, deep=True, now=t0 + timedelta(hours=30))
    print(hashlib.sha256((json.dumps(rep, sort_keys=True) + maintenance.render_text(rep)).encode()).hexdigest())
