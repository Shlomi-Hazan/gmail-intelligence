"""Shared synthetic helpers for the M7 sync-health guard (no Gmail, no network).

The M4 tests exercise plan/approval/execution behaviour, not index freshness, so they run with a HEALTHY synthetic sync state whose age gate is
switched off (`pin_age_gate`). Every other sync-health rule (state flag, running run, unfinished scans, basis) stays active in those tests; the
age rules themselves are tested precisely in tests/test_sync_health.py.
"""
from datetime import datetime, timedelta, timezone
from unittest import mock

from gmail_intelligence import sync_health


def utc_iso(dt=None):
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_healthy_sync(index, account, at=None, history_id="1000"):
    """Give `account` a healthy checkpoint that descends from its newest completed FULL scan (no-op if there is none)."""
    rows = index._q("SELECT MAX(id) AS n FROM scans WHERE account=? AND mode='full' AND status='completed'", account)
    basis = rows[0]["n"]
    if basis is None:
        return None
    stamp = utc_iso(at)
    with index.conn:
        index.conn.execute(
            "INSERT INTO sync_state (account, history_id, source, basis_scan_id, established_at, advanced_at, status, reason) "
            "VALUES (?,?,'PROFILE_BEFORE_FULL_LIST',?,?,?,'OK',NULL) ON CONFLICT(account) DO UPDATE SET basis_scan_id=excluded.basis_scan_id, "
            "advanced_at=excluded.advanced_at, status='OK', reason=NULL", (account, history_id, basis, stamp, stamp))
    return basis


def pin_age_gate(test):
    """Disable only the freshness-age rules for a test (the state rules stay active)."""
    for name, value in (("SYNC_MAX_AGE", timedelta(days=365 * 100)), ("CLOCK_TOLERANCE", timedelta(days=365 * 100))):
        patcher = mock.patch.object(sync_health, name, value)
        patcher.start()
        test.addCleanup(patcher.stop)
