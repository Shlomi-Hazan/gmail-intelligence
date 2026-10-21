"""Read-only report of what synchronization changed (M7B, docs/SYNC.md section 17). Local index only; never contacts Gmail, never writes.

Everything here is derived from rows the sync engine already stores: the per-run counters of `sync_run`, the linked `scans` row of a FULL or LIMITED run,
`message_tombstone` and `sync_state`. Nothing is inferred beyond that: where the stored evidence cannot support a statement (for example how many of the
`refreshed` messages were NEW and how many merely CHANGED, or how many were moved to Trash) the report says "not recorded" instead of guessing.
Output is aggregate only: counts, codes and times, never message ids, senders, label names, addresses or paths.
"""
import re
from datetime import datetime, timezone

from gmail_intelligence import sync_health

NOT_RECORDED = None  # JSON null / text "not recorded"
_SAFE_TEXT = re.compile(r"[^A-Za-z0-9 _().,:/%-]")


def _utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)


def _age_hours(ts, now):
    try:
        return round((now - sync_health.parse(ts)).total_seconds() / 3600, 2)
    except (ValueError, TypeError):
        return None


def _clean(text, limit=80):
    return _SAFE_TEXT.sub("?", str(text))[:limit] if text else None


def _run_phase(run, now):
    """How to read this run's numbers: COMPLETED, or PARTIAL with the evidence for why (never guessed)."""
    status = run["status"]
    if status == "completed":
        return "COMPLETED"
    if status == "running":
        try:
            alive = sync_health.parse(run["lease_expires_at"]) > now
        except (ValueError, TypeError):
            alive = None
        return "PARTIAL_RUNNING_LEASE_ACTIVE" if alive else "PARTIAL_ABANDONED_LEASE_EXPIRED" if alive is False else "PARTIAL_RUNNING_UNKNOWN"
    return {"interrupted": "PARTIAL_INTERRUPTED", "failed": "PARTIAL_FAILED", "needs_reconcile": "PARTIAL_NEEDS_RECONCILE"}.get(status, "PARTIAL_UNKNOWN")


def _tombstone_rows(index, account, run_id):
    return {r["reason"]: r["n"] for r in index._q("SELECT reason, COUNT(*) AS n FROM message_tombstone WHERE account=? AND run_id=? GROUP BY reason", account, run_id)}


def run_summary(index, account, run, now):
    base = {"run": run["id"], "kind": run["kind"], "status": run["status"], "phase": _run_phase(run, now), "started_at": run["started_at"],
            "finished_at": run["finished_at"], "note": _clean(run["error"])}
    tomb = _tombstone_rows(index, account, run["id"])
    base["tombstone_rows_for_run"] = {k: tomb[k] for k in sorted(tomb)}
    if run["kind"] == "INCREMENTAL":
        base.update({"history_pages": run["pages"], "history_records": run["records"], "messages_affected": run["affected"],
                     "new_or_changed": run["refreshed"], "new_only": NOT_RECORDED, "changed_only": NOT_RECORDED, "unchanged": run["unchanged"],
                     "deleted": run["tombstoned"], "never_indexed_and_gone": run["vanished"], "failed_refreshes": run["failed"],
                     "counters_consistent_with_tombstones": run["tombstoned"] == sum(tomb.values())})
        return base
    scan = None
    if run["scan_id"] is not None:
        rows = index._q("SELECT * FROM scans WHERE account=? AND id=?", account, run["scan_id"])
        scan = dict(rows[0]) if rows else None
    if scan is None:
        base["scan"] = "not recorded"
        return base
    base.update({"scan_id": scan["id"], "scan_mode": scan["mode"], "scan_status": scan["status"], "ids_listed": scan["listed"], "messages_fetched_or_refreshed": scan["indexed"],
                 "new_only": NOT_RECORDED, "changed_only": NOT_RECORDED, "never_indexed_and_gone": scan["vanished"], "failed_refreshes": scan["failed"],
                 "removed_by_reconciliation": scan["pruned"], "removal_tombstones": tomb.get("FULL_RECONCILE", 0),
                 "counters_consistent_with_tombstones": scan["pruned"] == tomb.get("FULL_RECONCILE", 0) if run["status"] == "completed" else None})
    return base


def changes_report(index, account, runs=5, now=None):
    now = _utc(now)
    state = sync_health.state_row(index, account)
    codes = sync_health.problems(index, account, now)
    last_inc = index._q("SELECT finished_at FROM sync_run WHERE account=? AND kind='INCREMENTAL' AND status='completed' ORDER BY id DESC LIMIT 1", account)
    last_full = index._q("SELECT finished_at FROM sync_run WHERE account=? AND kind='FULL' AND status='completed' ORDER BY id DESC LIMIT 1", account)
    rows = [dict(r) for r in index._q("SELECT * FROM sync_run WHERE account=? ORDER BY id DESC LIMIT ?", account, max(1, min(int(runs), 50)))]
    totals = {r["reason"]: r["n"] for r in index._q("SELECT reason, COUNT(*) AS n FROM message_tombstone WHERE account=? GROUP BY reason", account)}
    report = {
        "section": "sync-changes", "read_only": True, "gmail_contacted": False,
        "checkpoint": None if state is None else {"status": state["status"], "reason": state["reason"], "age_hours": _age_hours(state["advanced_at"], now),
                                                  "source": state["source"]},
        "health_codes": codes, "healthy": not codes,
        "last_completed_incremental_sync": last_inc[0][0] if last_inc else None,
        "last_completed_full_scan": last_full[0][0] if last_full else None,
        "runs": [run_summary(index, account, r, now) for r in rows],
        "deletions_recorded_in_total": {k: totals[k] for k in sorted(totals)},
        "deletions_recorded_in_total_count": sum(totals.values()),
        "not_recorded": ["how many of the 'new or changed' messages were new and how many were changed", "how many label changes were moves to Trash",
                         "which messages changed (ids are deliberately not reported)"],
    }
    return report


def _fmt(v):
    return "not recorded" if v is None else f"{v:,}" if isinstance(v, int) else str(v)


def changes_text(rep):
    out = ["Sync changes (local index only; Gmail was not contacted)"]
    cp = rep["checkpoint"]
    if cp is None:
        out.append("  checkpoint: none yet. Run a full scan first: mailbox scan --all")
    else:
        out.append(f"  checkpoint: {cp['status']}" + (f" ({cp['reason']})" if cp["reason"] else "") + (f", advanced {cp['age_hours']} hours ago" if cp["age_hours"] is not None else ""))
    out.append("  index health for cleanup plans: " + ("fresh" if rep["healthy"] else "NOT healthy: " + ", ".join(rep["health_codes"])))
    out.append(f"  last completed incremental sync: {rep['last_completed_incremental_sync'] or 'none'}; last completed full scan: {rep['last_completed_full_scan'] or 'none'}")
    if not rep["runs"]:
        out.append("  no runs recorded")
    for r in rep["runs"]:
        head = f"  run {r['run']} [{r['kind']}] {r['status']} - {r['phase']}"
        out.append(head + (f" ({r['note']})" if r["note"] else ""))
        if r["phase"] != "COMPLETED":
            out.append("    PARTIAL: these numbers are only what was durably applied before the run stopped; the history checkpoint did not move for it.")
        if r["kind"] == "INCREMENTAL":
            out.append(f"    history pages {_fmt(r['history_pages'])}, records {_fmt(r['history_records'])}, messages affected {_fmt(r['messages_affected'])}")
            out.append(f"    new or changed {_fmt(r['new_or_changed'])} (new vs changed: not recorded), unchanged {_fmt(r['unchanged'])}, "
                       f"deleted {_fmt(r['deleted'])}, never indexed and gone {_fmt(r['never_indexed_and_gone'])}, failed refreshes {_fmt(r['failed_refreshes'])}")
        elif "scan_id" in r:
            out.append(f"    ids listed {_fmt(r['ids_listed'])}, fetched or refreshed {_fmt(r['messages_fetched_or_refreshed'])} (new vs changed: not recorded), "
                       f"never indexed and gone {_fmt(r['never_indexed_and_gone'])}, failed refreshes {_fmt(r['failed_refreshes'])}")
            if r["kind"] == "FULL":
                out.append(f"    removed by reconciliation {_fmt(r['removed_by_reconciliation'])}" + (" (an unfinished run removes nothing)" if r["phase"] != "COMPLETED" else ""))
        else:
            out.append("    scan details: not recorded")
        if r["counters_consistent_with_tombstones"] is False:
            out.append("    WARNING: this run's deletion counter does not match the tombstone rows stored for it")
    out.append(f"  deletions recorded (all runs, all time): {rep['deletions_recorded_in_total_count']:,}"
               + ("  " + ", ".join(f"{k} {v:,}" for k, v in rep['deletions_recorded_in_total'].items()) if rep["deletions_recorded_in_total"] else ""))
    out.append("  notes: counts belong to one run each; a replayed range after an interruption counts the same messages again, so runs must not be added together.")
    out.append("  A move to Trash is a label change (inside 'new or changed'); only permanent deletion is counted as deleted.")
    out.append("  Not recorded by the index: " + "; ".join(rep["not_recorded"]) + ".")
    return "\n".join(out)
