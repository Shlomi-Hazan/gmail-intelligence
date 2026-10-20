"""Single-writer lease and fencing for every writer of Gmail-derived index rows (M7A, docs/SYNC.md section 5).

One `sync_run` row per account may be `running` (a partial unique index enforces it in SQLite). The owner of that row holds the lease:
* an ACTIVE lease is never taken over; an EXPIRED one only by a compare-and-swap in a `BEGIN IMMEDIATE` transaction, and not if the clock moved backwards;
* every write transaction of a run starts with the FENCE (the run is still `running` with this run's random token), so a stalled former owner that was
  superseded cannot commit anything; the fence also renews the lease (heartbeat) but never touches the history checkpoint;
* the process id is never trusted.
Nothing here contacts Gmail.
"""
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from gmail_intelligence import sync_health

LEASE_TTL = timedelta(minutes=5)
HEARTBEAT_EVERY = timedelta(seconds=60)
SLEEP_SLICE = 30.0                       # a long backoff sleep is cut into slices so the lease is renewed meanwhile
GUARD_CONTRACT = 1                       # D145: the M4 modules must declare this exact contract version before any run may start
ACTIVE_EXEC_STATES = ("PREPARED", "EXECUTING", "AWAITING_CONTINUATION", "RECONCILIATION_REQUIRED")
FULL_SCAN_REASONS = ("FULL_SCAN_INTERRUPTED", "FULL_SCAN_INCOMPLETE", "COUNT_MISMATCH")


class SyncError(Exception):
    """A refusal or stop with a stable code and a privacy-safe message (counts and codes only)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class LeaseLost(SyncError):
    def __init__(self, message="the sync lease was lost to another run; nothing further was written"):
        super().__init__("SYNC_LEASE_LOST", message)


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def guard_ok():
    """D145 handshake: refuse before touching the database or Gmail unless the M4 sync-health guards (E1-E5) are present."""
    import inspect

    from gmail_intelligence import cleanup_exec as ce, cleanup_plans as cp
    try:
        ok = (cp.SYNC_GUARD_CONTRACT == GUARD_CONTRACT and ce.SYNC_GUARD_CONTRACT == GUARD_CONTRACT
              and "sync_health" in inspect.getsource(cp.revalidate) and "sync_health" in inspect.getsource(cp._insert_plan)
              and "SYNC_NOT_HEALTHY" in inspect.getsource(ce.reserve_execution) and "SYNC_NOT_HEALTHY" in inspect.getsource(ce.confirm_slice))
    except (AttributeError, OSError, TypeError):
        ok = False
    if not ok:
        raise SyncError("SYNC_GUARD_MISSING", "the M4 sync-health guards are not present in this build; synchronization and scanning are disabled")


def active_execution(index, account):
    marks = ",".join("?" * len(ACTIVE_EXEC_STATES))
    return bool(index._q(f"SELECT 1 FROM cleanup_execution WHERE account=? AND state IN ({marks}) LIMIT 1", account, *ACTIVE_EXEC_STATES))


class Lease:
    def __init__(self, index, account, run_id, kind, token, clock):
        self.index, self.account, self.run_id, self.kind, self.token, self.clock = index, account, run_id, kind, token, clock
        self.last_beat = clock()

    @contextmanager
    def fence_txn(self):
        """BEGIN IMMEDIATE + fence + lease renewal. Raises LeaseLost (nothing written) when this run no longer owns the lease."""
        conn = self.index.conn
        if conn.in_transaction:
            raise RuntimeError("nested sync transaction")
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT heartbeat_at FROM sync_run WHERE id=? AND status='running' AND lease_token=?", (self.run_id, self.token)).fetchone()
            if row is None:
                raise LeaseLost()
            now = self.clock()
            beat = max(sync_health.parse(row[0]), now)  # the stored heartbeat never moves backwards
            conn.execute("UPDATE sync_run SET heartbeat_at=?, lease_expires_at=? WHERE id=?", (iso(beat), iso(max(beat, now) + LEASE_TTL), self.run_id))
            self.last_beat = now
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def heartbeat(self):
        """Renew the lease through the same fence. Never advances the checkpoint and never revives a lost lease."""
        with self.fence_txn():
            pass

    def beat_if_due(self):
        if self.clock() - self.last_beat >= HEARTBEAT_EVERY:
            self.heartbeat()

    def sleep(self, seconds, real_sleep=time.sleep):
        """Sleep in slices, renewing the lease between them (rate-limit backoff can be long)."""
        remaining = float(seconds)
        while remaining > 0:
            step = min(SLEEP_SLICE, remaining)
            real_sleep(step)
            remaining -= step
            self.beat_if_due()

    def set_state(self, status, reason=None):
        """Inside an open fenced transaction: move the account's sync_state row (if any). Only run-completion code may pass 'OK'."""
        self.index.conn.execute("UPDATE sync_state SET status=?, reason=? WHERE account=?", (status, reason, self.account))

    def mark_run(self, status, error=None):
        """Inside an open fenced transaction: end this run's row (the fence of the NEXT transaction then fails, as intended)."""
        self.index.conn.execute("UPDATE sync_run SET status=?, finished_at=?, error=? WHERE id=?", (status, iso(self.clock()), error, self.run_id))

    def add_counters(self, **counts):
        cols = ("pages", "records", "affected", "refreshed", "unchanged", "tombstoned", "vanished", "failed")
        for key, val in counts.items():
            assert key in cols
            self.index.conn.execute(f"UPDATE sync_run SET {key}={key}+? WHERE id=?", (val, self.run_id))

    def finish(self, run_status, state_status=None, state_reason=None, error=None):
        """Best-effort terminal marking. Swallows LeaseLost (a superseded run must not write anything)."""
        try:
            with self.fence_txn():
                self.mark_run(run_status, error)
                if state_status is not None:
                    self.set_state(state_status, state_reason)
        except LeaseLost:
            pass


def _reap(index, account, now):
    """Take over an EXPIRED run (compare-and-swap). Returns True if a run was reaped. Raises SYNC_BUSY / SYNC_CLOCK_UNCERTAIN otherwise."""
    conn = index.conn
    row = conn.execute("SELECT * FROM sync_run WHERE account=? AND status='running'", (account,)).fetchone()
    if row is None:
        # legacy rows: a scan marked running without any live run can only come from code that predates v7 and cannot be live
        conn.execute("UPDATE scans SET status='interrupted', error='interrupted', finished_at=? WHERE account=? AND status='running'", (iso(now), account))
        return False
    expires, beat = sync_health.parse(row["lease_expires_at"]), sync_health.parse(row["heartbeat_at"])
    if expires > now:
        raise SyncError("SYNC_BUSY", "another sync or scan is active for this account; try again after it finishes or its lease expires")
    if now < beat:
        raise SyncError("SYNC_CLOCK_UNCERTAIN", "the system clock moved backwards; an expired run cannot be proven abandoned, nothing was changed")
    cur = conn.execute("UPDATE sync_run SET status='interrupted', error='LEASE_EXPIRED', finished_at=? WHERE id=? AND status='running' AND lease_token=?",
                       (iso(now), row["id"], row["lease_token"]))
    if cur.rowcount != 1:
        raise SyncError("SYNC_BUSY", "another process took over the expired run first; nothing was changed")
    if row["scan_id"] is not None:
        conn.execute("UPDATE scans SET status='interrupted', error='LEASE_EXPIRED', finished_at=? WHERE id=? AND status='running'", (iso(now), row["scan_id"]))
    reason = "LEASE_EXPIRED" if row["kind"] == "INCREMENTAL" else "FULL_SCAN_INTERRUPTED"
    conn.execute("UPDATE sync_state SET status='INTERRUPTED', reason=? WHERE account=?", (reason, account))
    return True


def _admission_error(index, account, kind):
    """The refusal (SyncError) for this requester on the post-reap state, or None when it may start."""
    state = sync_health.state_row(index, account)
    if kind == "INCREMENTAL":
        if state is None:
            return SyncError("SYNC_CHECKPOINT_MISSING", "there is no sync checkpoint yet; run a full scan first (mailbox scan --all)")
        if state["status"] == "NEEDS_RECONCILE":
            return SyncError("SYNC_NEEDS_RECONCILE", "the checkpoint can no longer be used; run a full scan (mailbox scan --all) to reconcile")
        if state["status"] == "IN_PROGRESS":
            return SyncError("SYNC_STATE_INCONSISTENT", "the sync state says a run is active but none is; run a full scan (mailbox scan --all) to repair")
        if sync_health.unfinished_full_scan(index, account, state["basis_scan_id"]) or (
                state["status"] == "INTERRUPTED" and state["reason"] in FULL_SCAN_REASONS):
            return SyncError("SYNC_FULL_SCAN_UNFINISHED", "a full scan did not finish; resume or restart it (mailbox scan --all / --resume) before syncing")
    elif kind == "LIMITED" and state is not None:
        return SyncError("SYNC_LIMITED_REFUSED", "a sync checkpoint exists; use `mailbox sync` or a full scan (`mailbox scan --all`) instead of --limit")
    if active_execution(index, account):
        return SyncError("SYNC_EXECUTION_ACTIVE", "a cleanup execution is active for this account; finish or abort it first")
    return None


def acquire(index, account, kind, *, clock=utc_now):
    """Become the single writer for `account`. Returns a Lease (also attached to the index) or raises SyncError."""
    assert kind in ("INCREMENTAL", "FULL", "LIMITED")
    guard_ok()
    conn = index.conn
    if conn.in_transaction:
        raise RuntimeError("nested sync transaction")
    now = clock()
    conn.execute("BEGIN IMMEDIATE")
    committed = False
    try:
        reaped = _reap(index, account, now)
        err = _admission_error(index, account, kind)
        if err is not None:
            if reaped:  # the clean-up is a fail-closed fact; keep it even though this requester is refused
                conn.commit()
                committed = True
            raise err
        token = secrets.token_hex(32)
        cur = conn.execute("INSERT INTO sync_run (account, kind, status, started_at, lease_token, lease_expires_at, heartbeat_at) "
                           "VALUES (?,?,?,?,?,?,?)", (account, kind, "running", iso(now), token, iso(now + LEASE_TTL), iso(now)))
        conn.execute("UPDATE sync_state SET status='IN_PROGRESS', reason=NULL WHERE account=?", (account,))
        conn.commit()
        committed = True
    except BaseException:
        if not committed:
            conn.rollback()
        raise
    lease = Lease(index, account, cur.lastrowid, kind, token, clock)
    index.lease = lease
    return lease


def release(index):
    index.lease = None


# ---- FULL / LIMITED scan records (the baseline is persisted atomically with the scan and run rows) ----
def begin_scan(index, lease, mode, limit, baseline_history_id):
    with lease.fence_txn() as conn:
        scan_id = conn.execute("INSERT INTO scans (account, mode, limit_n, status, started_at) VALUES (?,?,?,?,?)",
                               (lease.account, mode, limit, "running", iso(lease.clock()))).lastrowid
        conn.execute("UPDATE sync_run SET scan_id=?, first_history_id=? WHERE id=?", (scan_id, baseline_history_id, lease.run_id))
    return scan_id


def resume_scan(index, lease, scan):
    """Reopen an interrupted scan under this lease. Returns its ORIGINAL baseline history id (None for a scan from before v7)."""
    with lease.fence_txn() as conn:
        conn.execute("UPDATE scans SET status='running', error=NULL, finished_at=NULL WHERE id=?", (scan["id"],))
        row = conn.execute("SELECT first_history_id FROM sync_run WHERE account=? AND scan_id=? AND first_history_id IS NOT NULL ORDER BY id DESC LIMIT 1",
                           (lease.account, scan["id"])).fetchone()
        baseline = row[0] if row else None
        conn.execute("UPDATE sync_run SET scan_id=?, first_history_id=? WHERE id=?", (scan["id"], baseline, lease.run_id))
    return baseline
