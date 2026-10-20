"""Read-only judgement of whether the local index is fresh enough for M4 plan operations (M7A, docs/SYNC.md section 9).

`problems()` returns a sorted list of closed-vocabulary codes; an empty list means healthy. It only reads the local index (never Gmail, never a write) and
imports nothing from the M4 modules, so the M4 modules can import it without a cycle. The status flag in `sync_state` is NOT trusted alone: the answer is
also derived from the `scans` and `sync_run` tables, so a wrong or forgotten flag still cannot produce a healthy result.
"""
from datetime import datetime, timedelta, timezone

CODES = ("SYNC_CHECKPOINT_MISSING", "SYNC_IN_PROGRESS", "SYNC_INTERRUPTED", "SYNC_NEEDS_RECONCILE", "SYNC_FULL_SCAN_INCOMPLETE",
         "SYNC_STALE", "SYNC_STATE_INCONSISTENT")
SYNC_MAX_AGE = timedelta(hours=24)       # a sync (or full scan) is needed within this age before plan operations (D143)
CLOCK_TOLERANCE = timedelta(minutes=5)   # how far a recorded time may lie in the future
UNFINISHED_SCAN = ("running", "interrupted", "failed", "incomplete")


def _utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)


def parse(ts):
    """Parse a stored UTC timestamp (with or without fractional seconds); raises ValueError."""
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(timezone.utc)


def state_row(index, account):
    rows = index._q("SELECT * FROM sync_state WHERE account=?", account)
    return dict(rows[0]) if rows else None


def unfinished_full_scan(index, account, basis_scan_id=None):
    """True if a FULL or LIMITED scan of this account is unfinished and newer than the checkpoint's basis scan (all of them while no checkpoint exists)."""
    marks = ",".join("?" * len(UNFINISHED_SCAN))
    sql = f"SELECT 1 FROM scans WHERE account=? AND mode IN ('full','limited') AND status IN ({marks})"
    params = [account, *UNFINISHED_SCAN]
    if basis_scan_id is not None:
        sql += " AND id>?"
        params.append(basis_scan_id)
    return bool(index._q(sql + " LIMIT 1", *params))


def running_runs(index, account):
    return index._q("SELECT id, kind FROM sync_run WHERE account=? AND status='running'", account)


def problems(index, account, now=None):
    now = _utc(now)
    out = set()
    state = state_row(index, account)
    running = running_runs(index, account)
    if state is None:
        out.add("SYNC_CHECKPOINT_MISSING")
        if running or unfinished_full_scan(index, account):
            out.add("SYNC_FULL_SCAN_INCOMPLETE")
        return sorted(out)
    status = state["status"]
    if status == "IN_PROGRESS":
        out.add("SYNC_IN_PROGRESS")
        if not running:
            out.add("SYNC_STATE_INCONSISTENT")  # an in-progress flag without any live run record
    elif status == "INTERRUPTED":
        out.add("SYNC_INTERRUPTED")
    elif status == "NEEDS_RECONCILE":
        out.add("SYNC_NEEDS_RECONCILE")
    if running:
        out.add("SYNC_IN_PROGRESS")
        if status == "OK":
            out.add("SYNC_STATE_INCONSISTENT")  # a run is active but the flag says healthy
    if unfinished_full_scan(index, account, state["basis_scan_id"]):
        out.add("SYNC_FULL_SCAN_INCOMPLETE")
    newest = index._q("SELECT MAX(id) AS n FROM scans WHERE account=? AND mode='full' AND status='completed'", account)[0]["n"]
    if newest is None or state["basis_scan_id"] != newest:
        out.add("SYNC_STATE_INCONSISTENT")  # the checkpoint does not descend from the newest completed full scan
    try:
        advanced = parse(state["advanced_at"])
        if advanced > now + CLOCK_TOLERANCE:
            out.add("SYNC_STATE_INCONSISTENT")
        elif now - advanced > SYNC_MAX_AGE:
            out.add("SYNC_STALE")
    except (ValueError, TypeError):
        out.add("SYNC_STATE_INCONSISTENT")
    return sorted(out)


def describe(codes):
    return ", ".join(codes)
