"""Local, user-triggered, READ-ONLY maintenance report (M7C, docs/SYNC.md section 10 and 18).

`run(index_path, account, deep, now)` returns a report dict; `render_text(report)` renders it. It reads the local index and the backup files next to it and
nothing else: it never contacts Gmail, never writes, never repairs, rescans, migrates, restores, chmods or deletes, never expires a plan, consumes an approval,
reserves an execution or appends an audit event. It does not use the writable `Index` class: the index is opened with SQLite `mode=ro` + `query_only`, backups with
`mode=ro&immutable=1`, and a database is not opened at all when an auxiliary journal/WAL file is present (opening could require recovery, which writes).

Four separate properties are reported and must not be confused: a healthy LOCAL DATABASE, a FRESH MAILBOX INDEX (judged from local sync records only; Gmail itself is
never verified), a VALID BACKUP, and whether M4 PLAN OPERATIONS are allowed by index freshness (this is not the safety of any single plan: see `cleanup plan impact`).

Everything stored is untrusted: findings use fixed, static texts plus integer counts; no value read from the database (no id, address, label, path, error message or
free text) is ever placed in the output.
"""
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from gmail_intelligence import cleanup_audit, sync_health

SEVERITIES = ("CRITICAL", "ERROR", "WARN", "INFO")
CERTAINTIES = ("OBSERVED", "INFERRED", "UNKNOWN")
CURRENT_SCHEMA = 7
EXPECTED_BACKUP_VERSION = {"pre-m3": 1, "pre-m4a": 2, "pre-m4b": 3, "pre-m4c": 4, "pre-m5": 5, "pre-m7": 6}   # the version the backup was taken FROM
KNOWN_TABLES = frozenset({"messages", "message_labels", "labels", "scans", "class_rules", "message_class", "protect_rules", "cleanup_plan", "cleanup_item", "cleanup_approval",
                          "cleanup_audit", "cleanup_execution", "cleanup_exec_slice", "cleanup_exec_item", "label_plan", "label_plan_op", "label_plan_approval", "sync_state",
                          "sync_run", "message_tombstone"})
OPEN_EXECUTION_STATES = ("PREPARED", "EXECUTING", "AWAITING_CONTINUATION")
CHECKPOINT_MAY_EXPIRE_DAYS, CHECKPOINT_LIKELY_EXPIRED_DAYS = 5, 7   # Gmail documents "typically at least a week", sometimes much less: both are INFERRED
AUX_SUFFIXES = ("-journal", "-wal", "-shm")

# code -> (category, explanation, recommendation). Static text only (see the module docstring).
TEXT = {
    # A. SQLite
    "INDEX_MISSING": ("A", "No local index file was found.", "Nothing to check. Create one with `mailbox scan --limit 100` when you want to (this contacts Gmail read-only and needs your own go-ahead)."),
    "INDEX_NOT_READABLE": ("A", "The local index file exists but this account cannot read it.", "Check the file's owner and permissions yourself; this command changed nothing."),
    "INDEX_UNREADABLE_OR_CORRUPT": ("A", "SQLite could not read the local index file (it may be corrupt or not a database).", "Stop using the tool on this file, keep a copy of it, and consider restoring a verified backup after review. Nothing was changed."),
    "INDEX_AUX_FILES_PRESENT": ("A", "A journal/WAL file exists next to the index: another process may be writing, or a write was interrupted. The index was NOT opened, because opening could need recovery, which writes.", "Wait for any running sync/scan to finish and run this again. If it persists, keep a copy of the files before doing anything else."),
    "INDEX_SCHEMA_OLD": ("A", "The local index uses an older schema than this version expects; row-level checks were skipped.", "Run `gmail-intelligence index upgrade` (it makes a verified private backup first)."),
    "INDEX_SCHEMA_NEWER": ("A", "The local index uses a newer schema than this version understands; row-level checks were skipped.", "Use the newer version of the tool for this index."),
    "INDEX_PERMISSIONS_TOO_OPEN": ("A", "The index file is readable by other accounts (expected owner-only).", "Restrict it yourself, for example `chmod 600` on the index file. This command does not change permissions."),
    "SQLITE_INTEGRITY_FAILED": ("A", "SQLite's integrity check reported problems with the index file.", "Keep a copy of the file, do not run cleanup operations, and consider restoring a verified backup after review. No repair was attempted."),
    "FOREIGN_KEY_VIOLATIONS": ("A", "Rows reference parent rows that do not exist.", "Keep a copy of the file and consider restoring a verified backup after review. No repair was attempted."),
    # B. rows
    "ORPHAN_MESSAGE_LABELS": ("B", "Label assignments exist for messages that are not in the index.", "A full scan rebuilds them (`mailbox scan --all`, contacts Gmail read-only, needs your own go-ahead)."),
    "ORPHAN_CLASSIFICATIONS": ("B", "Classification rows exist for messages that are not in the index.", "They are harmless to read but indicate an inconsistent write; a full scan prunes unseen rows. Consider `classify clear` followed by `classify run`."),
    "LABEL_REFERENCES_UNKNOWN_LABEL": ("B", "Some messages carry label ids that are not in the label list. Possible causes: a label deleted in Gmail (deletions are not reported by history) or a stale label list.", "Run `mailbox sync` (it refreshes the label list) and look again."),
    "INVALID_SCAN_REFERENCE_POSITIVE": ("B", "Some messages point to a scan record that does not exist.", "Keep a copy of the file; a full scan (`mailbox scan --all`) re-stamps every message."),
    "INVALID_SCAN_REFERENCE_NEGATIVE": ("B", "Some messages were stamped by a sync run that is not recorded.", "Keep a copy of the file; a full scan (`mailbox scan --all`) re-stamps every message."),
    "INVALID_SCAN_REFERENCE_ZERO": ("B", "Some messages carry the scan stamp 0, which no scan or sync run produces.", "Keep a copy of the file; a full scan (`mailbox scan --all`) re-stamps every message."),
    "CLASSIFICATION_REFERENCES_MISSING_SCAN": ("B", "Some classifications refer to a scan or sync record that does not exist.", "Run `classify run` after the index is fresh; they are treated as not current anyway."),
    "TOMBSTONE_MESSAGE_CONTRADICTION": ("B", "Messages are present although a deletion record exists for the same id. Gmail does not reuse message ids, so a deletion may have been recorded wrongly (possible false deletion) or the message came back.", "Run a full scan (`mailbox scan --all`) to re-establish the truth from Gmail."),
    "TOMBSTONE_RUN_MISSING": ("B", "Some deletion records name a sync/scan run that is not recorded.", "Informational for audit trails; a full scan does not change it."),
    "CHECKPOINT_BASELINE_MISSING": ("B", "The sync checkpoint refers to a baseline scan that does not exist.", "Run `mailbox scan --all` to establish a new checkpoint."),
    "CHECKPOINT_BASELINE_NOT_COMPLETED_FULL": ("B", "The sync checkpoint's baseline is not a completed full scan.", "Run `mailbox scan --all` to establish a new checkpoint."),
    "SYNC_RUN_SCAN_MISSING": ("B", "Some scan runs refer to a scan record that does not exist.", "Informational; a new full scan records a consistent run."),
    "PLAN_ITEMS_REFERENCE_REMOVED_MESSAGES": ("B", "Stored cleanup plans list messages that are no longer in the index. This is EXPECTED: plans are immutable history and simply become stale; it is not corruption.", "Use `cleanup plan impact` to see how each plan is affected. Nothing needs repair."),
    "NO_DATA_FOR_ACCOUNT": ("B", "No messages, scans or sync records exist for this account in the index.", "Nothing to check for this account."),
    "ACCOUNT_UNKNOWN": ("B", "No account was given and none is stored, so only file-level checks ran.", "Pass `--account EMAIL` to include the row-level checks."),
    # C. scans and sync
    "NO_BASELINE_SCAN": ("C", "No completed full scan exists for this account.", "Run `mailbox scan --all` (contacts Gmail read-only; needs your own go-ahead). Cleanup plan operations stay blocked until then."),
    "CHECKPOINT_MISSING": ("C", "Full scans exist but there is no sync checkpoint (they predate sync support).", "Run `mailbox scan --all` once to establish a checkpoint. Cleanup plan operations stay blocked until then."),
    "FULL_SCAN_UNFINISHED": ("C", "A full or limited scan is unfinished (running, interrupted, failed or incomplete).", "Resume it with `mailbox scan --resume`, or start `mailbox scan --all`."),
    "SCAN_FAILED_REFRESHES": ("C", "Some scans counted messages that could not be indexed.", "A completed full scan sets no checkpoint when messages fail; run `mailbox scan --all` again."),
    "SYNC_RUN_FAILED_REFRESHES": ("C", "Some sync runs counted messages that could not be refreshed.", "Run `mailbox sync` again; the checkpoint does not advance past a failed refresh."),
    "LATEST_RUN_NOT_COMPLETED": ("C", "The most recent sync or scan run did not complete.", "Run `mailbox sync` (or `mailbox scan --resume` for a scan); see `mailbox changes` for what it applied."),
    "SYNC_RUN_ACTIVE": ("C", "A sync or scan run currently holds a valid lease. Maintenance did not interrupt it.", "Wait for it to finish."),
    "SYNC_LEASE_EXPIRED": ("C", "A run is marked running and its lease has expired. That alone does not prove the process stopped (it may be suspended or very slow). The next sync or scan can take over only once the lease is expired and the run is truly idle.", "Wait a little, then run `mailbox sync` (or `mailbox scan --resume`); it refuses while the lease is active."),
    "SYNC_INTERRUPTED": ("C", "The last sync was interrupted; the checkpoint did not move.", "Run `mailbox sync`; it replays from the saved checkpoint."),
    "SYNC_NEEDS_RECONCILE": ("C", "The saved checkpoint can no longer be used for an incremental sync.", "Run `mailbox scan --all` to reconcile (contacts Gmail read-only; needs your own go-ahead)."),
    "SYNC_STATE_INCONSISTENT": ("C", "The sync records contradict each other (state flag, runs, scans or timestamps).", "Run `mailbox scan --all`, which re-establishes a consistent state. Nothing was repaired automatically."),
    "CHECKPOINT_STALE": ("C", "The last successful sync is older than 24 hours, so the index may be behind Gmail and cleanup plan operations are blocked.", "Run `mailbox sync`."),
    "CHECKPOINT_MAY_EXPIRE": ("C", "The checkpoint is several days old. Gmail's history window is not guaranteed and can be shorter than a week, so the next sync might need a full scan. This is a possibility, not a fact.", "Run `mailbox sync` soon."),
    "CHECKPOINT_LIKELY_EXPIRED": ("C", "The checkpoint is about a week old or older. Gmail's history may no longer cover it. Not verified: only Gmail can tell.", "Run `mailbox sync`; if it reports that history expired, run `mailbox scan --all`."),
    "HISTORY_RETENTION_UNCERTAIN": ("C", "Gmail does not guarantee how long it keeps history, so how far back an incremental sync can reach is not known in advance.", "Sync regularly (this tool never schedules anything for you)."),
    # D. backups
    "NO_BACKUPS_FOUND": ("D", "No backup files were found next to the index. That is not a fault: backups are made before schema upgrades, and copies you keep elsewhere cannot be seen from here.", "Nothing to do. Keep your own copies if you want extra safety."),
    "BACKUPS_VERIFIED": ("D", "The listed backups passed SQLite's checks, have the expected schema version and owner-only permissions. This says nothing about how recent they are or whether they match Gmail.", "None."),
    "BACKUP_PERMISSIONS_TOO_OPEN": ("D", "Some backups are readable by other accounts (expected owner-only).", "Restrict them yourself (`chmod 600`). This command does not change permissions."),
    "BACKUP_SCHEMA_VERSION_MISMATCH": ("D", "Some backups do not have the schema version their name says they were taken from.", "Do not rely on them for restoring until you have inspected them."),
    "BACKUP_CORRUPT": ("D", "SQLite's integrity check failed on some backups.", "Do not restore from them. Nothing was deleted."),
    "BACKUP_INVALID": ("D", "Some backup files are not SQLite databases.", "Do not restore from them. Nothing was deleted."),
    "BACKUP_UNREADABLE": ("D", "Some backups could not be read; whether they are valid is not verified.", "Check their owner and permissions yourself."),
    "BACKUP_NOT_VERIFIED_AUX_FILES": ("D", "Some backups have a journal/WAL file next to them; they were not opened, because opening could modify them.", "Inspect those files yourself; nothing was touched."),
    "BACKUP_NOT_REGULAR_FILE": ("D", "Some backup names are not regular files (for example links); they were not followed.", "Inspect them yourself."),
    # E. audit and executions
    "AUDIT_CHAIN_BROKEN": ("E", "The cleanup audit chain does not verify: an entry was altered, removed or reordered.", "Stop using cleanup plans on this index, keep a copy of the file, and consider restoring a verified backup after review. Nothing was repaired."),
    "AUDIT_TAIL_NOT_VERIFIABLE": ("E", "The audit chain proves internal continuity only. Deleting the newest entries cannot be detected without an external checkpoint of its head.", "If this matters to you, note the head hash from time to time outside this computer."),
    "EXECUTION_RECONCILIATION_REQUIRED": ("E", "A cleanup execution is waiting for reconciliation of uncertain results.", "Review it with `cleanup exec show` and the recovery steps in docs/CLEANUP.md. Syncs are blocked while an execution is open."),
    "EXECUTION_OPEN": ("E", "A cleanup execution is open (prepared, running or waiting for continuation). Syncs are blocked while it is open.", "Finish or abort it deliberately; this command never does."),
    "EXECUTION_STATE_INCONSISTENT": ("E", "A finished execution still has open items.", "Keep a copy of the file and review the execution with `cleanup exec show`."),
    "APPROVAL_CONSUMED_WITHOUT_EXECUTION": ("E", "An approval is marked consumed but no execution exists for its plan.", "Keep a copy of the file and review the plan with `cleanup plan show`. Nothing was changed."),
    "PLANS_PAST_EXPIRY_NOT_RECORDED": ("E", "Some plans are past their expiry time but still stored as active; expiry is recorded only when a plan operation runs.", "Nothing to do; they cannot be used. This report does not record the expiry."),
}
_PLACEHOLDER = ("?", "An unrecognised finding.", "None.")
_AGE = re.compile(r"(?P<stamp>[0-9]{8}T[0-9]{6}Z)(?:-(?P<n>[0-9]{1,2}))?")


def _utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)


class _Q:
    """The one read helper the shared checks (sync_health, cleanup_audit) need: `_q` on a read-only connection."""

    def __init__(self, conn):
        self.conn = conn

    def _q(self, sql, *params):
        return self.conn.execute(sql, params).fetchall()


class _Findings:
    def __init__(self):
        self.items = {}

    def add(self, code, severity, certainty, count=None, detail=None):
        assert severity in SEVERITIES and certainty in CERTAINTIES, (code, severity, certainty)
        category, explanation, recommendation = TEXT.get(code, _PLACEHOLDER)
        item = {"code": code, "severity": severity, "certainty": certainty, "category": category, "explanation": explanation, "recommendation": recommendation}
        if count is not None:
            item["count"] = int(count)
        if detail:
            item["detail"] = {str(k): int(v) for k, v in sorted(detail.items())}
        self.items[code] = item

    def sorted(self):
        return sorted(self.items.values(), key=lambda f: (SEVERITIES.index(f["severity"]), f["code"]))


def _connect(path, immutable=False):
    uri = Path(os.path.abspath(path)).as_uri() + "?mode=ro" + ("&immutable=1" if immutable else "")
    conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _aux_present(path):
    return [s for s in AUX_SUFFIXES if os.path.lexists(path + s)]


def _pragma_problems(conn, name):
    """(ok, problem_count) of quick_check / integrity_check; raises sqlite3.DatabaseError when the file cannot even be read."""
    rows = [str(r[0]) for r in conn.execute(f"PRAGMA {name}").fetchall()]
    if rows == ["ok"]:
        return True, 0
    return False, len(rows)


def _count(conn, sql, *params):
    return conn.execute(sql, params).fetchone()[0]


# ---------------------------------------------------------------- A / B / C / E on the main index
def _file_checks(path, deep, f, out):
    out["local_database"] = {"status": "NOT_VERIFIED", "mode": "deep" if deep else "quick", "schema_version": None}
    if not os.path.lexists(path):
        f.add("INDEX_MISSING", "WARN", "OBSERVED")
        return None
    if not os.access(path, os.R_OK):
        f.add("INDEX_NOT_READABLE", "ERROR", "OBSERVED")
        return None
    try:
        if os.stat(path).st_mode & 0o077:
            f.add("INDEX_PERMISSIONS_TOO_OPEN", "WARN", "OBSERVED")
    except OSError:
        pass
    aux = _aux_present(path)
    if aux:
        f.add("INDEX_AUX_FILES_PRESENT", "WARN", "UNKNOWN", count=len(aux))
        return None
    try:
        conn = _connect(path)
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
    except sqlite3.Error:
        f.add("INDEX_UNREADABLE_OR_CORRUPT", "CRITICAL", "OBSERVED")
        out["local_database"]["status"] = "PROBLEMS_DETECTED"
        return None
    out["local_database"]["schema_version"] = version if isinstance(version, int) else None
    problems = 0
    try:
        ok, n = _pragma_problems(conn, "integrity_check" if deep else "quick_check")
        if not ok:
            problems += 1
            f.add("SQLITE_INTEGRITY_FAILED", "CRITICAL", "OBSERVED", count=n)
        fk = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk:
            problems += 1
            by = {}
            for r in fk:
                child = r[0] if r[0] in KNOWN_TABLES else "other"
                by[child] = by.get(child, 0) + 1
            f.add("FOREIGN_KEY_VIOLATIONS", "ERROR", "OBSERVED", count=len(fk), detail=by)
    except sqlite3.Error:
        f.add("INDEX_UNREADABLE_OR_CORRUPT", "CRITICAL", "OBSERVED")
        out["local_database"]["status"] = "PROBLEMS_DETECTED"
        conn.close()
        return None
    if version == 0:
        out["local_database"]["status"] = "PROBLEMS_DETECTED" if problems else "HEALTHY"
        conn.close()
        return None
    if version < CURRENT_SCHEMA:
        f.add("INDEX_SCHEMA_OLD", "WARN", "OBSERVED")
        out["local_database"]["status"] = "PROBLEMS_DETECTED" if problems else "HEALTHY"
        conn.close()
        return None
    if version > CURRENT_SCHEMA:
        f.add("INDEX_SCHEMA_NEWER", "ERROR", "OBSERVED")
        conn.close()
        return None
    out["local_database"]["status"] = "PROBLEMS_DETECTED" if problems else "HEALTHY"
    return conn


def _row_checks(conn, account, f, out):
    c = lambda sql, *p: _count(conn, sql, account, *p)  # noqa: E731
    present = _count(conn, "SELECT (SELECT COUNT(*) FROM messages WHERE account=?) + (SELECT COUNT(*) FROM scans WHERE account=?) + (SELECT COUNT(*) FROM sync_run WHERE account=?)",
                     account, account, account)
    if present == 0:
        f.add("NO_DATA_FOR_ACCOUNT", "INFO", "OBSERVED")
    n = c("SELECT COUNT(*) FROM message_labels ml WHERE ml.account=? AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.account=ml.account AND m.id=ml.message_id)")
    if n:
        f.add("ORPHAN_MESSAGE_LABELS", "ERROR", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM message_class mc WHERE mc.account=? AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.account=mc.account AND m.id=mc.message_id)")
    if n:
        f.add("ORPHAN_CLASSIFICATIONS", "ERROR", "OBSERVED", count=n)
    n = c("SELECT COUNT(DISTINCT ml.label_id) FROM message_labels ml WHERE ml.account=? AND NOT EXISTS (SELECT 1 FROM labels l WHERE l.account=ml.account AND l.id=ml.label_id) "
          "AND EXISTS (SELECT 1 FROM labels l2 WHERE l2.account=ml.account)")
    if n:
        f.add("LABEL_REFERENCES_UNKNOWN_LABEL", "WARN", "INFERRED", count=n)
    n = c("SELECT COUNT(*) FROM messages m WHERE m.account=? AND m.scan_id>0 AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.id=m.scan_id AND s.account=m.account)")
    if n:
        f.add("INVALID_SCAN_REFERENCE_POSITIVE", "ERROR", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM messages m WHERE m.account=? AND m.scan_id<0 AND NOT EXISTS (SELECT 1 FROM sync_run r WHERE r.id=-m.scan_id AND r.account=m.account)")
    if n:
        f.add("INVALID_SCAN_REFERENCE_NEGATIVE", "ERROR", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM messages m WHERE m.account=? AND m.scan_id=0")
    if n:
        f.add("INVALID_SCAN_REFERENCE_ZERO", "ERROR", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM message_class mc WHERE mc.account=? AND ((mc.msg_scan_id>0 AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.id=mc.msg_scan_id AND s.account=mc.account)) "
          "OR (mc.msg_scan_id<0 AND NOT EXISTS (SELECT 1 FROM sync_run r WHERE r.id=-mc.msg_scan_id AND r.account=mc.account)))")
    if n:
        f.add("CLASSIFICATION_REFERENCES_MISSING_SCAN", "WARN", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM messages m WHERE m.account=? AND EXISTS (SELECT 1 FROM message_tombstone t WHERE t.account=m.account AND t.message_id=m.id)")
    if n:
        f.add("TOMBSTONE_MESSAGE_CONTRADICTION", "WARN", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM message_tombstone t WHERE t.account=? AND t.run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sync_run r WHERE r.id=t.run_id AND r.account=t.account)")
    if n:
        f.add("TOMBSTONE_RUN_MISSING", "WARN", "OBSERVED", count=n)
    n = c("SELECT COUNT(*) FROM sync_run r WHERE r.account=? AND r.scan_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.id=r.scan_id AND s.account=r.account)")
    if n:
        f.add("SYNC_RUN_SCAN_MISSING", "WARN", "OBSERVED", count=n)
    # expected history, NOT corruption: immutable plan items whose message has since left the index
    gone = c("SELECT COUNT(*) FROM cleanup_item ci WHERE ci.account=? AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.account=ci.account AND m.id=ci.message_id)")
    if gone:
        tomb = c("SELECT COUNT(*) FROM cleanup_item ci WHERE ci.account=? AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.account=ci.account AND m.id=ci.message_id) "
                 "AND EXISTS (SELECT 1 FROM message_tombstone t WHERE t.account=ci.account AND t.message_id=ci.message_id)")
        f.add("PLAN_ITEMS_REFERENCE_REMOVED_MESSAGES", "INFO", "OBSERVED", count=gone, detail={"with_deletion_record": tomb, "without_deletion_record": gone - tomb})
    state = conn.execute("SELECT * FROM sync_state WHERE account=?", (account,)).fetchone()
    if state is not None:
        scan = conn.execute("SELECT mode, status FROM scans WHERE account=? AND id=?", (account, state["basis_scan_id"])).fetchone()
        if scan is None:
            f.add("CHECKPOINT_BASELINE_MISSING", "ERROR", "OBSERVED")
        elif scan["mode"] != "full" or scan["status"] != "completed":
            f.add("CHECKPOINT_BASELINE_NOT_COMPLETED_FULL", "ERROR", "OBSERVED")


def _sync_checks(conn, account, now, f, out):
    q = _Q(conn)
    codes = sync_health.problems(q, account, now)
    out["mailbox_index_freshness"] = {"status": "FRESH" if not codes else "NOT_FRESH", "codes": codes,
                                      "note": "judged from local sync records only; Gmail itself is not verified"}
    out["m4_plan_operations"] = {"status": "ALLOWED_BY_INDEX_FRESHNESS" if not codes else "BLOCKED_BY_INDEX_FRESHNESS",
                                 "note": "this is about index freshness only, not the safety of any single plan: use `cleanup plan impact`"}
    state = sync_health.state_row(q, account)
    completed_full = _count(conn, "SELECT COUNT(*) FROM scans WHERE account=? AND mode='full' AND status='completed'", account)
    if "SYNC_CHECKPOINT_MISSING" in codes:
        f.add("CHECKPOINT_MISSING" if completed_full else "NO_BASELINE_SCAN", "WARN", "OBSERVED")
    if "SYNC_INTERRUPTED" in codes and state is not None and state["status"] == "INTERRUPTED":
        f.add("SYNC_INTERRUPTED", "WARN", "OBSERVED")
    if "SYNC_NEEDS_RECONCILE" in codes:
        f.add("SYNC_NEEDS_RECONCILE", "WARN", "OBSERVED")
    if "SYNC_FULL_SCAN_INCOMPLETE" in codes:
        f.add("FULL_SCAN_UNFINISHED", "WARN", "OBSERVED")
    if "SYNC_STALE" in codes:
        f.add("CHECKPOINT_STALE", "WARN", "OBSERVED")
    if "SYNC_STATE_INCONSISTENT" in codes:
        f.add("SYNC_STATE_INCONSISTENT", "ERROR", "OBSERVED")
    if state is not None:
        f.add("HISTORY_RETENTION_UNCERTAIN", "INFO", "UNKNOWN")
        try:
            age = now - sync_health.parse(state["advanced_at"])
            if age > timedelta(days=CHECKPOINT_LIKELY_EXPIRED_DAYS):
                f.add("CHECKPOINT_LIKELY_EXPIRED", "ERROR", "INFERRED")
            elif age > timedelta(days=CHECKPOINT_MAY_EXPIRE_DAYS):
                f.add("CHECKPOINT_MAY_EXPIRE", "WARN", "INFERRED")
        except (ValueError, TypeError):
            pass
    active = expired = 0
    for r in conn.execute("SELECT lease_expires_at FROM sync_run WHERE account=? AND status='running'", (account,)):
        try:
            alive = sync_health.parse(r[0]) > now
        except (ValueError, TypeError):
            alive = None
        if alive:
            active += 1
        else:
            expired += 1  # an unparseable lease is treated as not provably active, never as proof of a dead process
    if active:
        f.add("SYNC_RUN_ACTIVE", "INFO", "OBSERVED", count=active)
    if expired:
        f.add("SYNC_LEASE_EXPIRED", "WARN", "INFERRED", count=expired)
    latest = conn.execute("SELECT status FROM sync_run WHERE account=? ORDER BY id DESC LIMIT 1", (account,)).fetchone()
    if latest is not None and latest["status"] in ("interrupted", "failed", "needs_reconcile"):
        f.add("LATEST_RUN_NOT_COMPLETED", "WARN", "OBSERVED")
    n = _count(conn, "SELECT COUNT(*) FROM sync_run WHERE account=? AND kind='INCREMENTAL' AND failed>0 AND id>(SELECT COALESCE(MAX(id),0)-20 FROM sync_run WHERE account=?)", account, account)
    if n:
        f.add("SYNC_RUN_FAILED_REFRESHES", "WARN", "OBSERVED", count=n)
    n = _count(conn, "SELECT COUNT(*) FROM scans WHERE account=? AND failed>0 AND id>(SELECT COALESCE(MAX(id),0)-20 FROM scans WHERE account=?)", account, account)
    if n:
        f.add("SCAN_FAILED_REFRESHES", "WARN", "OBSERVED", count=n)


def _audit_checks(conn, account, now, f, out):
    q = _Q(conn)
    ok, events, _bad = cleanup_audit.verify_chain(q, account)
    out["audit_chain"] = {"status": "NO_EVENTS" if events == 0 and ok else "CONTINUOUS" if ok else "BROKEN", "events": events,
                          "note": "internal continuity only; removal of the newest entries cannot be detected without an external checkpoint"}
    if not ok:
        f.add("AUDIT_CHAIN_BROKEN", "CRITICAL", "OBSERVED")
    if events:
        f.add("AUDIT_TAIL_NOT_VERIFIABLE", "INFO", "UNKNOWN", count=events)
    n = _count(conn, "SELECT COUNT(*) FROM cleanup_execution WHERE account=? AND state='RECONCILIATION_REQUIRED'", account)
    if n:
        f.add("EXECUTION_RECONCILIATION_REQUIRED", "WARN", "OBSERVED", count=n)
    marks = ",".join("?" * len(OPEN_EXECUTION_STATES))
    n = _count(conn, f"SELECT COUNT(*) FROM cleanup_execution WHERE account=? AND state IN ({marks})", account, *OPEN_EXECUTION_STATES)
    if n:
        f.add("EXECUTION_OPEN", "WARN", "OBSERVED", count=n)
    n = _count(conn, "SELECT COUNT(DISTINCT e.exec_id) FROM cleanup_execution e JOIN cleanup_exec_item i ON i.account=e.account AND i.exec_id=e.exec_id "
                     "WHERE e.account=? AND e.state IN ('EXECUTED','PARTIAL','FAILED','ABORTED') AND i.state IN ('PENDING','INTENT','UNKNOWN')", account)
    if n:
        f.add("EXECUTION_STATE_INCONSISTENT", "ERROR", "OBSERVED", count=n)
    n = _count(conn, "SELECT COUNT(*) FROM cleanup_approval a WHERE a.account=? AND a.status='CONSUMED' AND NOT EXISTS (SELECT 1 FROM cleanup_execution e WHERE e.account=a.account AND e.plan_id=a.plan_id)", account)
    if n:
        f.add("APPROVAL_CONSUMED_WITHOUT_EXECUTION", "ERROR", "OBSERVED", count=n)
    n = _count(conn, "SELECT COUNT(*) FROM cleanup_plan WHERE account=? AND state IN ('DRAFT','REVIEWED','APPROVED') AND expires_at<=?",
               account, now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    if n:
        f.add("PLANS_PAST_EXPIRY_NOT_RECORDED", "INFO", "OBSERVED", count=n)


# ---------------------------------------------------------------- D. backups
def _backups(index_path, deep, now, f, out):
    base = os.path.basename(index_path)
    directory = os.path.dirname(os.path.abspath(index_path))
    pattern = re.compile(re.escape(base) + r"\.(?P<tag>pre-m[0-9]+[a-z]?)-backup-" + _AGE.pattern + r"\Z")
    found = []
    try:
        with os.scandir(directory) as it:
            for entry in it:
                m = pattern.match(entry.name)
                if m:
                    found.append((m.group("stamp"), int(m.group("n") or 0), m.group("tag"), os.path.join(directory, entry.name)))
    except OSError:
        pass
    found.sort()
    items, problems = [], {}

    def bad(code):
        problems[code] = problems.get(code, 0) + 1

    for stamp, n, tag, path in found:
        try:
            age = round((now - datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)).total_seconds() / 3600, 1)
        except ValueError:
            age = None
        item = {"tag": tag if tag in EXPECTED_BACKUP_VERSION else "other", "age_hours": age, "status": "NOT_VERIFIED", "schema_version": None,
                "expected_schema_version": EXPECTED_BACKUP_VERSION.get(tag), "permissions_ok": None}
        items.append(item)
        try:
            st = os.lstat(path)
        except OSError:
            item["status"] = "UNREADABLE"
            bad("BACKUP_UNREADABLE")
            continue
        import stat as stat_mod
        if not stat_mod.S_ISREG(st.st_mode):
            item["status"] = "NOT_REGULAR_FILE"
            bad("BACKUP_NOT_REGULAR_FILE")
            continue
        item["permissions_ok"] = not (st.st_mode & 0o077)
        if not item["permissions_ok"]:
            bad("BACKUP_PERMISSIONS_TOO_OPEN")
        if _aux_present(path):
            item["status"] = "NOT_VERIFIED_AUX_FILES"
            bad("BACKUP_NOT_VERIFIED_AUX_FILES")
            continue
        if not os.access(path, os.R_OK):
            item["status"] = "UNREADABLE"
            bad("BACKUP_UNREADABLE")
            continue
        try:
            conn = _connect(path, immutable=True)
        except sqlite3.Error:
            item["status"] = "UNREADABLE"
            bad("BACKUP_UNREADABLE")
            continue
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            item["schema_version"] = version
            ok, _n = _pragma_problems(conn, "integrity_check" if deep else "quick_check")
            if not ok:
                item["status"] = "CORRUPT"
                bad("BACKUP_CORRUPT")
            elif item["expected_schema_version"] is not None and version != item["expected_schema_version"]:
                item["status"] = "SCHEMA_VERSION_MISMATCH"
                bad("BACKUP_SCHEMA_VERSION_MISMATCH")
            else:
                item["status"] = "VERIFIED"
        except sqlite3.DatabaseError:
            item["status"] = "INVALID"
            bad("BACKUP_INVALID")
        except sqlite3.Error:
            item["status"] = "UNREADABLE"
            bad("BACKUP_UNREADABLE")
        finally:
            conn.close()
    verified = sum(1 for i in items if i["status"] == "VERIFIED" and i["permissions_ok"])
    if not items:
        f.add("NO_BACKUPS_FOUND", "INFO", "OBSERVED")
    for code, count in problems.items():
        sev, cert = {"BACKUP_PERMISSIONS_TOO_OPEN": ("WARN", "OBSERVED"), "BACKUP_SCHEMA_VERSION_MISMATCH": ("ERROR", "OBSERVED"), "BACKUP_CORRUPT": ("ERROR", "OBSERVED"),
                     "BACKUP_INVALID": ("ERROR", "OBSERVED"), "BACKUP_UNREADABLE": ("WARN", "UNKNOWN"), "BACKUP_NOT_VERIFIED_AUX_FILES": ("WARN", "UNKNOWN"),
                     "BACKUP_NOT_REGULAR_FILE": ("WARN", "OBSERVED")}[code]
        f.add(code, sev, cert, count=count)
    if verified:
        f.add("BACKUPS_VERIFIED", "INFO", "OBSERVED", count=verified)
    status = "NONE_FOUND" if not items else "ALL_VERIFIED" if verified == len(items) else "PROBLEMS_DETECTED" if any(
        i["status"] in ("CORRUPT", "INVALID", "SCHEMA_VERSION_MISMATCH") for i in items) else "NOT_FULLY_VERIFIED"
    out["backups"] = {"status": status, "found": len(items), "verified": verified, "items": items,
                      "note": "a valid backup says nothing about how recent it is or whether it matches Gmail; nothing was restored, changed or deleted"}


# ---------------------------------------------------------------- the report
def run(index_path, account=None, deep=False, now=None):
    now = _utc(now)
    index_path = os.fspath(index_path)
    f, out = _Findings(), {}
    conn = _file_checks(index_path, deep, f, out)
    out.setdefault("mailbox_index_freshness", {"status": "UNKNOWN", "codes": [], "note": "not verified: the index could not be fully read or has no sync records"})
    out.setdefault("m4_plan_operations", {"status": "UNKNOWN", "note": "not verified: the index could not be fully read"})
    out.setdefault("audit_chain", {"status": "NOT_VERIFIED", "events": None, "note": "not verified: the index could not be fully read"})
    if conn is not None:
        try:
            if account:
                _row_checks(conn, account, f, out)
                _sync_checks(conn, account, now, f, out)
                _audit_checks(conn, account, now, f, out)
            else:
                f.add("ACCOUNT_UNKNOWN", "INFO", "OBSERVED")
        except sqlite3.Error:
            f.add("INDEX_UNREADABLE_OR_CORRUPT", "CRITICAL", "OBSERVED")
            out["local_database"]["status"] = "PROBLEMS_DETECTED"
        finally:
            conn.close()
    _backups(index_path, deep, now, f, out)
    findings = f.sorted()
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITIES}
    return {"section": "maintenance", "read_only": True, "gmail_contacted": False, "mode": "deep" if deep else "quick",
            "properties": {"local_database": out["local_database"], "mailbox_index_freshness": out["mailbox_index_freshness"], "backups": out["backups"],
                           "m4_plan_operations": out["m4_plan_operations"], "audit_chain": out["audit_chain"]},
            "findings": findings, "summary": counts, "overall": next((s for s in SEVERITIES if counts[s]), "NONE"),
            "limits": ["Gmail itself was not contacted or verified: a clean report is not proof that the mailbox is unchanged or that the index matches it",
                       "a healthy local database, a fresh mailbox index, a valid backup and plan operations being allowed are four separate properties",
                       "advisory only: nothing was repaired, rescanned, migrated, restored, expired, consumed or recorded; every recommended action is yours to run"]}


def render_text(rep):
    p = rep["properties"]
    out = [f"Maintenance report ({rep['mode']} checks; local only, read-only; Gmail was not contacted)"]
    db, fr, bk, m4, au = p["local_database"], p["mailbox_index_freshness"], p["backups"], p["m4_plan_operations"], p["audit_chain"]
    out += ["", "Properties (separate things):",
            f"  local database:        {db['status']}" + (f" (schema v{db['schema_version']})" if db.get("schema_version") is not None else ""),
            f"  mailbox index fresh:   {fr['status']}" + (" (" + ", ".join(fr["codes"]) + ")" if fr["codes"] else "") + " - judged from local sync records; Gmail is not verified",
            f"  backups:               {bk['status']} ({bk['verified']} verified of {bk['found']} found)",
            f"  cleanup plan operations: {m4['status'].replace('_', ' ').lower()} - index freshness only; see `cleanup plan impact` for individual plans",
            f"  audit chain:           {au['status']}" + (f" ({au['events']} events)" if au.get("events") else "")]
    s = rep["summary"]
    out += ["", "Findings: " + ", ".join(f"{k} {s[k]}" for k in SEVERITIES) + (" - nothing to report" if rep["overall"] == "NONE" else "")]
    for x in rep["findings"]:
        count = f" (count {x['count']:,})" if "count" in x else ""
        detail = " " + ", ".join(f"{k.replace('_', ' ')} {v:,}" for k, v in x["detail"].items()) if x.get("detail") else ""
        out.append(f"  [{x['severity']}/{x['certainty']}] {x['code']}{count}{detail}")
        out.append(f"      {x['explanation']}")
        out.append(f"      Suggested (manual): {x['recommendation']}")
    out += ["", "Limits:"] + [f"  - {t}" for t in rep["limits"]]
    return "\n".join(out)
