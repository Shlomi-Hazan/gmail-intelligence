"""Read-only, resumable mailbox scan: list message ids (paginated), fetch metadata, store locally.

Gmail is the source of truth. Rows are only removed after a COMPLETE full scan, never because a scan
failed or stopped early. The reader is any object with the GmailReader read methods (tests use fakes).
"""
import time

from gmail_intelligence.gmail import GmailApiError, GmailAuthError, GmailNotFoundError, GmailRateLimitError

LIST_COST, GET_COST = 5, 20          # Gmail quota units per call (documented quota page)
DEFAULT_UNITS_PER_MINUTE = 4500      # 75% of the documented 6,000 units/min per-user budget
PAGE_SIZE = 500                      # documented maximum for messages.list
BATCH = 50                           # commit every N fetched messages (checkpoint granularity)
MAX_ATTEMPTS, BACKOFF_BASE, BACKOFF_CAP = 5, 2.0, 60.0


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


def run_scan(reader, index, account, *, mode, limit=None, resume=False, limiter=None, sleep=time.sleep,
             progress=lambda msg: None, stop=lambda: False, page_size=PAGE_SIZE):
    """Run a scan. Returns the final scan row (dict). Raises ScanInterrupted / ScanError / GmailAuthError."""
    limiter = limiter or RateLimiter(sleep=sleep)
    if resume:
        prev = index.find_resumable(account)
        if prev is None:
            raise ScanError("no interrupted scan to resume for this account; start one with --limit or --all")
        scan_id, mode, limit = prev["id"], prev["mode"], prev["limit_n"]
        token = prev["page_token"]
        index.reopen_scan(scan_id)
        progress(f"resuming scan {scan_id} ({mode}); {prev['indexed']} messages already indexed")
    else:
        scan_id, token = index.start_scan(account, mode, limit), None

    def call(cost, fn):
        def attempt():
            limiter.acquire(cost)
            return fn()
        return with_backoff(attempt, sleep)

    try:
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
    except KeyboardInterrupt:
        index.conn.rollback()
        index.finish_scan(scan_id, "interrupted", error="interrupted by user")
        raise ScanInterrupted("scan interrupted; progress is saved. Resume with: mailbox scan --resume") from None
    except GmailAuthError:
        index.conn.rollback()
        index.finish_scan(scan_id, "failed", error="authorization failed")
        raise
    except GmailApiError as exc:
        index.conn.rollback()
        index.finish_scan(scan_id, "interrupted", error=f"API error (HTTP {exc.status})")
        raise ScanInterrupted(f"scan stopped after repeated API errors ({exc}); progress is saved. "
                              "Resume later with: mailbox scan --resume") from None

    row = index.scan(scan_id)
    if mode == "full":
        if row["failed"] == 0:
            pruned = index.prune_unseen(account, scan_id)
            index.finish_scan(scan_id, "completed", pruned=pruned)
        else:
            index.finish_scan(scan_id, "incomplete", error=f"{row['failed']} messages could not be indexed")
    else:
        index.finish_scan(scan_id, "completed")
    return index.scan(scan_id)
