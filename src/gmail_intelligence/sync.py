"""Replay-based incremental sync from Gmail history (M7A, docs/SYNC.md section 7). Read-only against Gmail; metadata only.

Events are HINTS: the ids they name are collected into a SET (order, duplicates and overlap are irrelevant), nothing is applied until the whole range
from the committed checkpoint H0 has been collected, the truth of each message comes from a fresh metadata read, and the checkpoint moves exactly once,
in the final fenced transaction. Any interruption replays from H0. There is deliberately NO per-page watermark. The reader is any object with the
GmailReader read methods (tests use fakes).
"""
import time

from gmail_intelligence import sync_health, sync_lease
from gmail_intelligence.gmail import (GmailApiError, GmailAuthError, GmailHistoryNotFoundError, GmailNotFoundError, GmailRateLimitError)
from gmail_intelligence.scanner import GET_COST, LIST_COST, PROFILE_COST, RateLimiter, _transient, with_backoff

HISTORY_COST = 2            # users.history.list (documented quota units)
HISTORY_PAGE = 100
CHUNK = 50                  # messages fetched and applied per fenced transaction
MAX_RANGE_IDS = 5000        # D143: a larger range is reconciled by a full scan instead of being replayed
MAX_PAGES = 5000            # bounds an endless pagination
TOKEN_RESTARTS = 2


class SyncStopped(sync_lease.SyncError):
    """The run ended without completing (progress is safe; the checkpoint did not move)."""


def _num(value):
    return int(value) if isinstance(value, str) and value.isdigit() else None


def metadata_row(index, account, message_id):
    row = index._q("SELECT thread_id, internal_ms, size, sender, unread FROM messages WHERE account=? AND id=?", account, message_id)
    if not row:
        return None
    labels = sorted(r[0] for r in index._q("SELECT label_id FROM message_labels WHERE account=? AND message_id=?", account, message_id))
    r = row[0]
    return (r["thread_id"], r["internal_ms"], r["size"], r["sender"], r["unread"], tuple(labels))


def _fetched_tuple(m):
    labels = sorted(set(m["label_ids"]))
    return (m["thread_id"], m["internal_ms"], m["size"], m["sender"], 1 if "UNREAD" in labels else 0, tuple(labels))


def apply_chunk(index, lease, fetched, gone):
    """One fenced transaction: upsert changed/new messages (scan_id = -run id), true no-op for unchanged ones, delete + tombstone the gone ones."""
    account, run_id = lease.account, lease.run_id
    refreshed = unchanged = tombstoned = vanished = 0
    with lease.fence_txn() as conn:
        now = sync_lease.iso(lease.clock())
        for m in fetched:
            if metadata_row(index, account, m["id"]) == _fetched_tuple(m):
                unchanged += 1
                continue
            conn.execute("INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) VALUES (?,?,?,?,?,?,?,?) "
                         "ON CONFLICT(account,id) DO UPDATE SET thread_id=excluded.thread_id, internal_ms=excluded.internal_ms, size=excluded.size, "
                         "sender=excluded.sender, unread=excluded.unread, scan_id=excluded.scan_id",
                         (account, m["id"], m["thread_id"], m["internal_ms"], m["size"], m["sender"], 1 if "UNREAD" in m["label_ids"] else 0, -run_id))
            conn.execute("DELETE FROM message_labels WHERE account=? AND message_id=?", (account, m["id"]))
            conn.executemany("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)", [(account, m["id"], lab) for lab in m["label_ids"]])
            refreshed += 1
        for mid in gone:
            if conn.execute("SELECT 1 FROM messages WHERE account=? AND id=?", (account, mid)).fetchone() is None:
                vanished += 1  # never indexed (or already removed): counted, no tombstone
                continue
            conn.execute("INSERT OR IGNORE INTO message_tombstone (account, message_id, detected_at, reason, run_id) VALUES (?,?,?,?,?)",
                         (account, mid, now, "HISTORY_DELETED" if mid in lease_deleted_hint(lease) else "NOT_FOUND_ON_REFRESH", run_id))
            for table in ("message_labels", "message_class", "messages"):
                col = "id" if table == "messages" else "message_id"
                conn.execute(f"DELETE FROM {table} WHERE account=? AND {col}=?", (account, mid))
            tombstoned += 1
        lease.add_counters(refreshed=refreshed, unchanged=unchanged, tombstoned=tombstoned, vanished=vanished)
    return refreshed, unchanged, tombstoned, vanished


def lease_deleted_hint(lease):
    return getattr(lease, "deleted_hint", frozenset())


def run_sync(reader, index, account, *, limiter=None, sleep=time.sleep, clock=sync_lease.utc_now, progress=lambda msg: None, stop=lambda: False,
             page_size=HISTORY_PAGE, chunk=CHUNK, max_range_ids=MAX_RANGE_IDS, hook=lambda point: None):
    """Run one incremental sync. Returns a dict of aggregate counters. Raises sync_lease.SyncError (refused / stopped) or GmailAuthError.

    `hook(point)` is a test seam called at every durable boundary so tests can crash the process there.
    """
    lease = sync_lease.acquire(index, account, "INCREMENTAL", clock=clock)
    try:
        return _run_locked(reader, index, account, lease, limiter, sleep, progress, stop, page_size, chunk, max_range_ids, hook)
    finally:
        sync_lease.release(index)


def _needs_reconcile(index, lease, reason, run_status="needs_reconcile"):
    lease.finish(run_status, "NEEDS_RECONCILE", reason, reason)
    return SyncStopped("SYNC_NEEDS_RECONCILE", f"the history checkpoint can no longer be used ({reason}); run a full scan (mailbox scan --all) to reconcile")


def _run_locked(reader, index, account, lease, limiter, sleep, progress, stop, page_size, chunk, max_range_ids, hook):
    lease_sleep = lambda seconds: lease.sleep(seconds, sleep)  # noqa: E731
    limiter = limiter or RateLimiter(sleep=lease_sleep)

    def call(cost, fn):
        def attempt():
            lease.beat_if_due()
            lease.pace(limiter, cost, sleep)  # a caller-supplied limiter's own sleep must not outlast the lease
            return fn()
        return with_backoff(attempt, lease_sleep)

    try:
        hook("acquired")
        state = sync_health.state_row(index, account)
        h0 = state["history_id"]
        profile = call(PROFILE_COST, reader.get_profile)
        if str(profile.get("emailAddress", "")).lower() != account.lower():
            raise _needs_reconcile(index, lease, "ACCOUNT_MISMATCH")
        now_id, base_id = _num(str(profile.get("historyId"))), _num(str(h0))
        if now_id is not None and base_id is not None and now_id < base_id:
            raise _needs_reconcile(index, lease, "ID_REGRESSION")  # tripwire only: it can only make the run more cautious
        with lease.fence_txn() as conn:
            conn.execute("UPDATE sync_run SET start_history_id=? WHERE id=?", (str(h0), lease.run_id))

        # ---- 1. collect the whole range into a set; nothing is written
        affected, deleted_hint, first_id, restarts = set(), set(), None, 0
        token, pages, records = None, 0, 0
        while True:
            try:
                page = call(HISTORY_COST, lambda t=token: reader.list_history(h0, t, page_size))
            except GmailHistoryNotFoundError:
                if token is None:
                    raise _needs_reconcile(index, lease, "HISTORY_EXPIRED") from None
                restarts += 1  # a page token expired mid-collection: collect again from H0
                if restarts > TOKEN_RESTARTS:
                    raise
                affected, deleted_hint, first_id, token, pages, records = set(), set(), None, None, 0, 0
                progress("history page token expired; collecting again from the checkpoint")
                continue
            except GmailApiError as exc:
                if exc.status == 400 and token is None:
                    raise _needs_reconcile(index, lease, "HISTORY_INVALID") from None
                if exc.status == 400 and restarts < TOKEN_RESTARTS:
                    restarts += 1
                    affected, deleted_hint, first_id, token, pages, records = set(), set(), None, None, 0, 0
                    continue
                raise
            pages += 1
            if first_id is None and page.get("history_id") is not None:
                first_id = str(page["history_id"])  # the conservative upper bound: the FIRST response's id
            for rec in page.get("records") or []:
                records += 1
                affected.update(rec.get("added") or [])
                affected.update(rec.get("labels") or [])
                dels = rec.get("deleted") or []
                affected.update(dels)
                deleted_hint.update(dels)
            if len(affected) > max_range_ids or pages > MAX_PAGES:
                raise _needs_reconcile(index, lease, "RANGE_TOO_LARGE")
            token = page.get("next")
            if not token:
                break
            if stop():
                raise KeyboardInterrupt
        lease.deleted_hint = frozenset(deleted_hint)
        with lease.fence_txn():
            lease.add_counters(pages=pages, records=records, affected=len(affected))
        hook("collected")

        # ---- 2. labels (their changes are not part of history)
        index.save_labels(account, call(LIST_COST, reader.list_label_details))
        hook("labels_saved")

        # ---- 3. apply in bounded fenced chunks (idempotent; the checkpoint does not move here)
        ids, failed_total, k = sorted(affected), 0, 0
        for start in range(0, len(ids), chunk):
            fetched, gone, failed = [], [], 0
            for mid in ids[start:start + chunk]:
                if stop():
                    raise KeyboardInterrupt
                try:
                    fetched.append(call(GET_COST, lambda mid=mid: reader.get_message_metadata(mid)))
                except GmailNotFoundError:
                    gone.append(mid)
                except GmailAuthError:
                    raise
                except GmailApiError as exc:
                    if _transient(exc):
                        raise
                    failed += 1
            apply_chunk(index, lease, fetched, gone)
            if failed:
                with lease.fence_txn():
                    lease.add_counters(failed=failed)
            failed_total += failed
            k += 1
            hook(f"chunk:{k}")
        if failed_total:
            lease.finish("failed", "INTERRUPTED", "API_ERROR", f"{failed_total} messages could not be refreshed")
            raise SyncStopped("SYNC_INCOMPLETE", f"{failed_total} messages could not be refreshed; the checkpoint did not move. Run `mailbox sync` again")

        # ---- 4. the one and only checkpoint move
        hook("before_end")
        with lease.fence_txn() as conn:
            now = sync_lease.iso(lease.clock())
            new_id = first_id if first_id is not None else str(h0)
            cur = conn.execute("UPDATE sync_state SET history_id=?, source='HISTORY_RESPONSE', advanced_at=?, status='OK', reason=NULL "
                               "WHERE account=? AND history_id=? AND status='IN_PROGRESS'", (new_id, now, account, str(h0)))
            if cur.rowcount != 1:
                raise sync_lease.SyncError("SYNC_STATE_INCONSISTENT", "the sync state changed during the run; nothing was advanced")
            lease.mark_run("completed", None if first_id is not None else "NO_HISTORY_ID")
            conn.execute("UPDATE sync_run SET first_history_id=? WHERE id=?", (first_id, lease.run_id))
        hook("after_end")
        return dict(index._q("SELECT pages, records, affected, refreshed, unchanged, tombstoned, vanished, failed FROM sync_run WHERE id=?", lease.run_id)[0])
    except sync_lease.SyncError:
        raise
    except KeyboardInterrupt:
        index.conn.rollback()
        lease.finish("interrupted", "INTERRUPTED", None, "interrupted by user")
        raise SyncStopped("SYNC_INTERRUPTED", "sync interrupted; the checkpoint did not move. Run `mailbox sync` again") from None
    except GmailAuthError:
        index.conn.rollback()
        lease.finish("failed", "INTERRUPTED", "API_ERROR", "authorization failed")
        raise
    except GmailRateLimitError:
        index.conn.rollback()
        lease.finish("interrupted", "INTERRUPTED", "API_QUOTA", "rate limit")
        raise SyncStopped("SYNC_QUOTA", "the Gmail rate limit was reached; progress is safe and the checkpoint did not move. Try again later") from None
    except GmailApiError as exc:
        index.conn.rollback()
        lease.finish("interrupted", "INTERRUPTED", "API_ERROR", f"API error (HTTP {exc.status})")
        raise SyncStopped("SYNC_API_ERROR", f"sync stopped after repeated API errors (HTTP {exc.status}); the checkpoint did not move") from None
    except Exception:
        index.conn.rollback()
        lease.finish("interrupted", "INTERRUPTED", "API_ERROR", "unexpected error")
        raise
