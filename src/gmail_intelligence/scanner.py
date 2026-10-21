"""Read-only, resumable mailbox scan: list message ids (paginated), fetch metadata, store locally.

Since M7A every scan owns the single-writer lease (sync_lease); a completed FULL scan is the only way a history checkpoint is established (docs/SYNC.md section 6).

Gmail is the source of truth. Rows are only removed after a COMPLETE full scan, never because a scan
failed or stopped early. The reader is any object with the GmailReader read methods (tests use fakes).
"""
import math
import time

from gmail_intelligence import sync_lease
from gmail_intelligence.gmail import GmailApiError, GmailAuthError, GmailNotFoundError, GmailRateLimitError

LIST_COST, GET_COST = 5, 20          # Gmail quota units per call (documented quota page)
DEFAULT_UNITS_PER_MINUTE = 4500      # 75% of the documented 6,000 units/min per-user budget
PAGE_SIZE = 500                      # documented maximum for messages.list
BATCH = 50                           # commit every N fetched messages (checkpoint granularity)
MAX_ATTEMPTS, BACKOFF_BASE, BACKOFF_CAP = 5, 2.0, 60.0
PROFILE_COST = 1                     # users.getProfile
COUNT_TOLERANCE_MIN, COUNT_TOLERANCE_FRACTION = 50, 0.01   # D137: listed ids versus the profile estimate
LARGE_PRUNE_FRACTION, LARGE_PRUNE_MIN_ROWS = 0.20, 100     # D137: a prune above this share needs an explicit flag (not applied to tiny indexes)


class ScanInterrupted(Exception):
    """Scan stopped (Ctrl+C or a transient failure); progress is saved and can be resumed."""


class ScanError(Exception):
    """Scan cannot proceed (user-facing message)."""


class RateLimiter:
    """Spreads requests evenly under a units-per-minute budget. Clock and sleep are injectable for tests."""

    def __init__(self, units_per_minute=DEFAULT_UNITS_PER_MINUTE, clock=time.monotonic, sleep=time.sleep):
        if units_per_minute <= 0:
            raise ValueError("units_per_minute must be positive")
        self.per_unit = 60.0 / units_per_minute
        self.clock, self.sleep = clock, sleep
        self.next_free = clock()

    def acquire(self, cost):
        now = self.clock()
        if self.next_free > now:
            self.sleep(self.next_free - now)
            now = self.next_free
        self.next_free = max(now, self.next_free) + cost * self.per_unit


def _transient(exc):
    if isinstance(exc, (GmailAuthError, GmailNotFoundError)):
        return False
    return isinstance(exc, GmailRateLimitError) or exc.status is None or exc.status >= 500


def with_backoff(fn, sleep):
    """Run fn, retrying transient failures with exponential backoff (bounded). Permanent errors raise at once."""
    for attempt in range(MAX_ATTEMPTS):
        try:
            return fn()
        except GmailApiError as exc:
            if not _transient(exc) or attempt == MAX_ATTEMPTS - 1:
                raise
            sleep(min(BACKOFF_CAP, BACKOFF_BASE * 2 ** attempt))


def count_check(listed, total):
    """(ok, detail) comparing the distinct listed ids with the profile's messagesTotal estimate. A missing estimate cannot confirm anything: not ok."""
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        return False, "no usable message count estimate from Gmail"
    tolerance = max(COUNT_TOLERANCE_MIN, math.ceil(COUNT_TOLERANCE_FRACTION * total))
    return abs(listed - total) <= tolerance, f"listed {listed:,} vs estimate {total:,} (tolerance {tolerance:,})"


def run_scan(reader, index, account, *, mode, limit=None, resume=False, limiter=None, sleep=time.sleep,
             progress=lambda msg: None, stop=lambda: False, page_size=PAGE_SIZE, clock=sync_lease.utc_now,
             accept_count_mismatch=False, allow_large_prune=False):
    """Run a scan under the writer lease. Returns the final scan row (dict).

    Raises ScanInterrupted / ScanError / GmailAuthError, or sync_lease.SyncError when the run may not start (busy, limited scan refused, ...).
    """
    if resume:
        prev = index.find_resumable(account)
        if prev is None:
            raise ScanError("no interrupted scan to resume for this account; start one with --limit or --all")
        mode = prev["mode"]
    lease = sync_lease.acquire(index, account, "FULL" if mode == "full" else "LIMITED", clock=clock)
    try:
        return _run_locked(reader, index, account, lease, mode=mode, limit=limit, resume=resume, limiter=limiter, sleep=sleep, progress=progress,
                           stop=stop, page_size=page_size, accept_count_mismatch=accept_count_mismatch, allow_large_prune=allow_large_prune)
    finally:
        sync_lease.release(index)


def _end(index, lease, scan_id, scan_status, error, run_status, state_status, reason, pruned=None):
    """One fenced transaction that ends the scan row, the run row and (if it exists) the sync state. A lost lease writes nothing."""
    try:
        with lease.fence_txn() as conn:
            conn.execute("UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?", (scan_status, sync_lease.iso(lease.clock()), error, scan_id))
            lease.mark_run(run_status, error)
            lease.set_state(state_status, reason)
    except sync_lease.LeaseLost:
        pass


def _run_locked(reader, index, account, lease, *, mode, limit, resume, limiter, sleep, progress, stop, page_size, accept_count_mismatch, allow_large_prune):
    lease_sleep = lambda seconds: lease.sleep(seconds, sleep)  # noqa: E731 - backoff and pacing sleeps keep the lease alive
    limiter = limiter or RateLimiter(sleep=lease_sleep)

    def call(cost, fn):
        def attempt():
            lease.beat_if_due()
            lease.pace(limiter, cost, sleep)  # a caller-supplied limiter's own sleep must not outlast the lease
            return fn()
        return with_backoff(attempt, lease_sleep)

    state_reason_interrupted = "FULL_SCAN_INTERRUPTED"
    scan_id = None
    try:
        if resume:
            prev = index.find_resumable(account)
            if prev is None:
                lease.finish("failed", error="nothing to resume")
                raise ScanError("no interrupted scan to resume for this account; start one with --limit or --all")
            scan_id, mode, limit, token = prev["id"], prev["mode"], prev["limit_n"], prev["page_token"]
            baseline = sync_lease.resume_scan(index, lease, prev)
            progress(f"resuming scan {scan_id} ({mode}); {prev['indexed']} messages already indexed")
        else:
            profile = call(PROFILE_COST, reader.get_profile)  # the history baseline is read BEFORE the first listing
            baseline = profile.get("historyId") if mode == "full" else None
            scan_id, token = sync_lease.begin_scan(index, lease, mode, limit, profile.get("historyId")), None
        index.save_labels(account, call(LIST_COST, reader.list_label_details))
        listed = index.scan(scan_id)["listed"]
        restarted = False
        while True:
            want = page_size if limit is None else min(page_size, limit - listed)
            try:
                ids, next_token = call(LIST_COST, lambda: reader.list_message_ids(token, want))
            except GmailApiError as exc:
                if token is not None and exc.status == 400 and not restarted:  # expired/invalid page token
                    restarted = True  # restart safely, once
                    progress("saved page token is no longer valid; re-listing from the start (indexed messages are kept)")
                    token, listed = None, 0
                    index.set_page_token(scan_id, None)
                    index.set_listed(scan_id, 0)
                    continue
                raise
            ids = list(dict.fromkeys(ids))[:want]  # drop duplicates within the page
            done = index.done_ids(account, scan_id, ids)
            todo, rows, vanished, failed = [i for i in ids if i not in done], [], 0, 0
            for n, mid in enumerate(todo, 1):
                if stop():
                    raise KeyboardInterrupt
                try:
                    rows.append(call(GET_COST, lambda mid=mid: reader.get_message_metadata(mid)))
                except GmailNotFoundError:
                    vanished += 1  # deleted between list and get
                except GmailAuthError:
                    raise
                except GmailApiError as exc:
                    if _transient(exc):
                        raise  # retries exhausted: stop and let the user resume
                    failed += 1  # permanent per-message problem: counted, scan can never be 'complete'
                if n % BATCH == 0:
                    index.save_batch(account, scan_id, rows, vanished=vanished, failed=failed)
                    rows, vanished, failed = [], 0, 0
                    progress(f"  fetched {index.scan(scan_id)['indexed']} messages")
            index.save_batch(account, scan_id, rows, vanished=vanished, failed=failed)
            listed += len(ids)
            index.set_listed(scan_id, listed)
            progress(f"page done: {listed} listed, {index.scan(scan_id)['indexed']} indexed")
            if next_token is None or (limit is not None and listed >= limit):
                break
            token = next_token
            index.set_page_token(scan_id, token)

        row = index.scan(scan_id)
        if mode != "full":
            with lease.fence_txn() as conn:
                conn.execute("UPDATE scans SET status='completed', finished_at=?, error=NULL WHERE id=?", (sync_lease.iso(lease.clock()), scan_id))
                lease.mark_run("completed")
            return index.scan(scan_id)
        if row["failed"] != 0:
            _end(index, lease, scan_id, "incomplete", f"{row['failed']} messages could not be indexed", "needs_reconcile", "NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE")
            return index.scan(scan_id)
        # ---- validation before anything is pruned or any checkpoint is established (docs/SYNC.md 6.4)
        total = call(PROFILE_COST, reader.get_profile).get("messagesTotal")
        ok, detail = count_check(row["listed"], total)
        if not ok and not accept_count_mismatch:
            progress("count check failed: " + detail)
            _end(index, lease, scan_id, "incomplete", "COUNT_MISMATCH", "needs_reconcile", "NEEDS_RECONCILE", "COUNT_MISMATCH")
            return index.scan(scan_id)
        existing = index._q("SELECT COUNT(*) AS n FROM messages WHERE account=?", account)[0]["n"]
        doomed = index._q("SELECT COUNT(*) AS n FROM messages WHERE account=? AND scan_id<>?", account, scan_id)[0]["n"]
        if existing >= LARGE_PRUNE_MIN_ROWS and doomed > LARGE_PRUNE_FRACTION * existing and not allow_large_prune:
            progress(f"large prune refused: {doomed:,} of {existing:,} indexed messages were not seen")
            _end(index, lease, scan_id, "incomplete", "LARGE_PRUNE", "needs_reconcile", "NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE")
            return index.scan(scan_id)
        # ---- ONE transaction: prune + tombstones + scan completion + checkpoint + run completion (nothing partial can remain)
        with lease.fence_txn() as conn:
            pruned = index._prune_unseen(account, scan_id, lease.run_id)
            conn.execute("UPDATE scans SET status='completed', finished_at=?, error=NULL, pruned=? WHERE id=?",
                         (sync_lease.iso(lease.clock()), pruned, scan_id))
            now = sync_lease.iso(lease.clock())
            if baseline is not None:
                conn.execute("INSERT INTO sync_state (account, history_id, source, basis_scan_id, established_at, advanced_at, status, reason) "
                             "VALUES (?,?,'PROFILE_BEFORE_FULL_LIST',?,?,?,'OK',NULL) ON CONFLICT(account) DO UPDATE SET history_id=excluded.history_id, "
                             "source=excluded.source, basis_scan_id=excluded.basis_scan_id, established_at=excluded.established_at, "
                             "advanced_at=excluded.advanced_at, status='OK', reason=NULL", (account, str(baseline), scan_id, now, now))
            else:
                lease.set_state("NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE")  # a scan from before v7 has no baseline: it cannot establish a checkpoint
            lease.mark_run("completed", None if baseline is not None else "NO_BASELINE")
        return index.scan(scan_id)
    except sync_lease.SyncError:
        raise
    except KeyboardInterrupt:
        _abort(index, lease, scan_id, "interrupted", "interrupted by user", "INTERRUPTED", state_reason_interrupted)
        raise ScanInterrupted("scan interrupted; progress is saved. Resume with: mailbox scan --resume") from None
    except GmailAuthError:
        _abort(index, lease, scan_id, "failed", "authorization failed", "NEEDS_RECONCILE", "FULL_SCAN_INCOMPLETE")
        raise
    except GmailApiError as exc:
        _abort(index, lease, scan_id, "interrupted", f"API error (HTTP {exc.status})", "INTERRUPTED", state_reason_interrupted)
        raise ScanInterrupted(f"scan stopped after repeated API errors ({exc}); progress is saved. "
                              "Resume later with: mailbox scan --resume") from None
    except ScanError:
        raise
    except Exception:
        _abort(index, lease, scan_id, "interrupted", "unexpected error", "INTERRUPTED", state_reason_interrupted)
        raise


def _abort(index, lease, scan_id, status, error, state_status, reason):
    """Roll back the open transaction and end the run cleanly (the scan row too, once it exists). A crash skips this; the lease then simply expires."""
    index.conn.rollback()
    if scan_id is not None:
        _end(index, lease, scan_id, status, error, "failed" if status == "failed" else "interrupted", state_status, reason)
    else:
        lease.finish("failed" if status == "failed" else "interrupted", state_status, reason, error)
