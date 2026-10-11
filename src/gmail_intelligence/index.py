"""Local SQLite metadata index (stdlib only). Stores no bodies, snippets, subjects or credentials.

All data is keyed by account, so one account's rows are never mixed with another's. Schema version is
kept in `PRAGMA user_version`; there is no migration framework (version 1 only).
"""
import os
import sqlite3
from datetime import datetime, timezone

from gmail_intelligence import config

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE messages (
  account TEXT NOT NULL, id TEXT NOT NULL, thread_id TEXT, internal_ms INTEGER, size INTEGER,
  sender TEXT, unread INTEGER NOT NULL DEFAULT 0, scan_id INTEGER NOT NULL,
  PRIMARY KEY (account, id)) WITHOUT ROWID;
CREATE INDEX messages_sender ON messages (account, sender);
CREATE INDEX messages_date ON messages (account, internal_ms);
CREATE TABLE message_labels (
  account TEXT NOT NULL, message_id TEXT NOT NULL, label_id TEXT NOT NULL,
  PRIMARY KEY (account, message_id, label_id)) WITHOUT ROWID;
CREATE INDEX message_labels_label ON message_labels (account, label_id);
CREATE TABLE labels (
  account TEXT NOT NULL, id TEXT NOT NULL, name TEXT, type TEXT, PRIMARY KEY (account, id)) WITHOUT ROWID;
CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, mode TEXT NOT NULL, limit_n INTEGER,
  status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, page_token TEXT,
  listed INTEGER NOT NULL DEFAULT 0, indexed INTEGER NOT NULL DEFAULT 0, vanished INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0, pruned INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE INDEX scans_account ON scans (account, id);
"""


class IndexProblem(Exception):
    """Index problem with a user-facing message."""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Index:
    def __init__(self, path=None, create=True):
        self.path = path if path is not None else config.index_path()
        parent = os.path.dirname(self.path) or "."
        if not os.path.exists(self.path) and not create:
            raise IndexProblem("no local index yet; run `mailbox scan --limit 100` first")
        os.makedirs(parent, mode=0o700, exist_ok=True)
        os.chmod(parent, 0o700)
        self.conn = sqlite3.connect(self.path)
        os.chmod(self.path, 0o600)
        self.conn.row_factory = sqlite3.Row
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            with self.conn:
                self.conn.executescript("BEGIN;" + SCHEMA + f"PRAGMA user_version = {SCHEMA_VERSION};COMMIT;")
        elif version != SCHEMA_VERSION:
            self.conn.close()
            raise IndexProblem(f"unsupported index schema version {version} (expected {SCHEMA_VERSION})")

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _q(self, sql, *params):
        return self.conn.execute(sql, params).fetchall()

    # ---- scans ----
    def start_scan(self, account, mode, limit=None):
        with self.conn:  # an old 'running' scan of this account can only be a crashed one
            self.conn.execute("UPDATE scans SET status='interrupted' WHERE account=? AND status='running'", (account,))
            cur = self.conn.execute("INSERT INTO scans (account, mode, limit_n, status, started_at) VALUES (?,?,?,?,?)",
                                    (account, mode, limit, "running", _now()))
        return cur.lastrowid

    def find_resumable(self, account):
        """Latest unfinished scan of this account (interrupted/running/incomplete after a stop), or None."""
        rows = self._q("SELECT * FROM scans WHERE account=? ORDER BY id DESC LIMIT 1", account)
        if rows and rows[0]["status"] in ("interrupted", "running", "failed"):
            return dict(rows[0])
        return None

    def reopen_scan(self, scan_id):
        with self.conn:
            self.conn.execute("UPDATE scans SET status='running', error=NULL, finished_at=NULL WHERE id=?", (scan_id,))

    def set_page_token(self, scan_id, token):
        with self.conn:
            self.conn.execute("UPDATE scans SET page_token=? WHERE id=?", (token, scan_id))

    def finish_scan(self, scan_id, status, error=None, **counters):
        with self.conn:
            self.conn.execute("UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                              (status, _now(), error, scan_id))
            for key, val in counters.items():
                assert key in ("listed", "indexed", "vanished", "failed", "pruned")
                self.conn.execute(f"UPDATE scans SET {key}=? WHERE id=?", (val, scan_id))

    def add_counters(self, scan_id, listed=0, indexed=0, vanished=0, failed=0):
        self.conn.execute("UPDATE scans SET listed=listed+?, indexed=indexed+?, vanished=vanished+?, failed=failed+? "
                          "WHERE id=?", (listed, indexed, vanished, failed, scan_id))

    def scan(self, scan_id):
        rows = self._q("SELECT * FROM scans WHERE id=?", scan_id)
        return dict(rows[0]) if rows else None

    def recent_scans(self, account, n=5):
        return [dict(r) for r in self._q("SELECT * FROM scans WHERE account=? ORDER BY id DESC LIMIT ?", account, n)]

    # ---- messages ----
    def done_ids(self, account, scan_id, ids):
        """Ids from `ids` already fetched during this scan (stamped with its id)."""
        if not ids:
            return set()
        marks = ",".join("?" * len(ids))
        rows = self._q(f"SELECT id FROM messages WHERE account=? AND scan_id=? AND id IN ({marks})",
                       account, scan_id, *ids)
        return {r["id"] for r in rows}

    def set_listed(self, scan_id, listed):
        with self.conn:
            self.conn.execute("UPDATE scans SET listed=? WHERE id=?", (listed, scan_id))

    def save_batch(self, account, scan_id, rows, vanished=0, failed=0):
        """Upsert message rows (dicts from the adapter) and bump counters in ONE transaction."""
        with self.conn:
            for r in rows:
                labels = r["label_ids"]
                self.conn.execute(
                    "INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) "
                    "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(account,id) DO UPDATE SET thread_id=excluded.thread_id, "
                    "internal_ms=excluded.internal_ms, size=excluded.size, sender=excluded.sender, "
                    "unread=excluded.unread, scan_id=excluded.scan_id",
                    (account, r["id"], r["thread_id"], r["internal_ms"], r["size"], r["sender"],
                     1 if "UNREAD" in labels else 0, scan_id))
                self.conn.execute("DELETE FROM message_labels WHERE account=? AND message_id=?", (account, r["id"]))
                self.conn.executemany("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)",
                                      [(account, r["id"], lab) for lab in labels])
            self.add_counters(scan_id, indexed=len(rows), vanished=vanished, failed=failed)

    def save_labels(self, account, labels):
        with self.conn:
            self.conn.execute("DELETE FROM labels WHERE account=?", (account,))
            self.conn.executemany("INSERT OR IGNORE INTO labels VALUES (?,?,?,?)",
                                  [(account, x["id"], x["name"], x["type"]) for x in labels if x.get("id")])

    def prune_unseen(self, account, scan_id):
        """After a COMPLETE full scan only: drop rows the scan did not see (no longer in Gmail)."""
        with self.conn:
            self.conn.execute("DELETE FROM message_labels WHERE account=? AND message_id IN "
                              "(SELECT id FROM messages WHERE account=? AND scan_id<>?)", (account, account, scan_id))
            cur = self.conn.execute("DELETE FROM messages WHERE account=? AND scan_id<>?", (account, scan_id))
        return cur.rowcount

    def purge(self, account):
        with self.conn:
            for table in ("message_labels", "messages", "labels", "scans"):
                self.conn.execute(f"DELETE FROM {table} WHERE account=?", (account,))

    def accounts(self):
        return [r[0] for r in self._q("SELECT DISTINCT account FROM scans UNION SELECT DISTINCT account FROM messages")]

    # ---- reporting queries (local only) ----
    def overview(self, account):
        r = self._q("SELECT COUNT(*) n, COUNT(DISTINCT thread_id) t, COALESCE(SUM(unread),0) u, "
                    "COALESCE(SUM(size),0) sz, MIN(internal_ms) lo, MAX(internal_ms) hi FROM messages WHERE account=?",
                    account)[0]
        return dict(r)

    def label_counts(self, account):
        return [dict(r) for r in self._q(
            "SELECT ml.label_id id, l.name name, l.type type, COUNT(*) n FROM message_labels ml "
            "LEFT JOIN labels l ON l.account=ml.account AND l.id=ml.label_id WHERE ml.account=? "
            "GROUP BY ml.label_id ORDER BY n DESC, ml.label_id", account)]

    def by_period(self, account, fmt):
        assert fmt in ("%Y", "%Y-%m")
        return [(r[0], r[1]) for r in self._q(
            f"SELECT strftime('{fmt}', internal_ms/1000, 'unixepoch') p, COUNT(*) FROM messages "
            "WHERE account=? AND internal_ms IS NOT NULL GROUP BY p ORDER BY p", account)]

    def top_senders(self, account, limit=20, unread_only=False, domains=False):
        key = "COALESCE(substr(sender, instr(sender,'@')+1), '(unknown)')" if domains else "COALESCE(sender,'(unknown)')"
        where = "AND unread=1" if unread_only else ""
        return [dict(r) for r in self._q(
            f"SELECT {key} who, COUNT(*) n, COALESCE(SUM(unread),0) unread, COALESCE(SUM(size),0) size "
            f"FROM messages WHERE account=? {where} GROUP BY who ORDER BY n DESC, who LIMIT ?", account, limit)]
