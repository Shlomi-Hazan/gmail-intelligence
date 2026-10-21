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
UNRECOGNISED = "UNRECOGNISED"

# Stored free text (sync_run.error, sync_state.reason, scan columns, timestamps) is UNTRUSTED: it could in principle hold anything (an address, a sender name, a
# message or label id, a path, a token). The report therefore never echoes it. It shows only a STRICT ALLOW-LIST of known diagnostic codes (the vocabulary the sync
# and scan code writes), plus numbers parsed from two fixed shapes; every other value becomes the generic UNRECOGNISED marker. There is no character filtering to
# get wrong: alphanumeric-only secrets cannot pass because nothing outside the list is ever printed.
KNOWN_CODES = {
    "LEASE_EXPIRED": "the run's lease expired and the run was abandoned",
    "HISTORY_EXPIRED": "the saved history checkpoint is older than Gmail keeps history",
    "HISTORY_INVALID": "Gmail rejected the saved history checkpoint",
    "RANGE_TOO_LARGE": "too many changes to replay; a full scan is needed",
    "ID_REGRESSION": "the mailbox history id went backwards",
    "ACCOUNT_MISMATCH": "the connected account differs from the indexed account",
    "FULL_SCAN_INTERRUPTED": "a full scan was interrupted",
    "FULL_SCAN_INCOMPLETE": "a full scan did not complete",
    "COUNT_MISMATCH": "the listed message count differs from Gmail's estimate",
    "LARGE_PRUNE": "a large number of messages would have been removed; not applied",
    "API_QUOTA": "the Gmail rate limit was reached",
    "API_ERROR": "Gmail API errors stopped the run",
    "NO_BASELINE": "the scan predates sync support and set no checkpoint",
    "NO_HISTORY_ID": "Gmail returned no history id; the checkpoint was left unchanged",
}
FIXED_TEXTS = {"interrupted by user": "INTERRUPTED_BY_USER", "authorization failed": "AUTH_FAILED", "rate limit": "RATE_LIMIT", "unexpected error": "UNEXPECTED_ERROR",
               "nothing to resume": "NOTHING_TO_RESUME", "interrupted": "INTERRUPTED"}
FIXED_DESCRIPTIONS = {"INTERRUPTED_BY_USER": "stopped by the user", "AUTH_FAILED": "authorization failed", "RATE_LIMIT": "rate limited", "UNEXPECTED_ERROR": "stopped by an unexpected error",
                      "NOTHING_TO_RESUME": "nothing to resume", "INTERRUPTED": "interrupted", "API_ERROR_HTTP": "Gmail API error", "MESSAGE_FAILURES": "some messages could not be processed",
                      UNRECOGNISED: "a stored note that is not a known diagnostic code (not shown)"}
_HTTP = re.compile(r"API error \(HTTP ([1-5][0-9]{2})\)")
_FAILURES = re.compile(r"([0-9]{1,9}) messages could not be (indexed|refreshed)")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SCAN_STATUS = {"running", "completed", "interrupted", "failed", "incomplete"}
_SCAN_MODE = {"full", "limited"}


def classify_note(raw):
    """(code, text, detail) for a stored note; (None, None, None) when there is none. Unknown or oversized values map to UNRECOGNISED and are never shown."""
    if raw is None or raw == "":
        return None, None, None
    if not isinstance(raw, str) or len(raw) > 200:
        return UNRECOGNISED, FIXED_DESCRIPTIONS[UNRECOGNISED], None
    if raw in KNOWN_CODES:
        return raw, KNOWN_CODES[raw], None
    if raw in FIXED_TEXTS:
        code = FIXED_TEXTS[raw]
        return code, FIXED_DESCRIPTIONS[code], None
    m = _HTTP.fullmatch(raw)
    if m:
        return "API_ERROR_HTTP", f"Gmail API error (HTTP {int(m.group(1))})", {"http_status": int(m.group(1))}
    m = _FAILURES.fullmatch(raw)
    if m:
        return "MESSAGE_FAILURES", f"{int(m.group(1)):,} messages could not be {m.group(2)}", {"count": int(m.group(1)), "stage": m.group(2)}
    return UNRECOGNISED, FIXED_DESCRIPTIONS[UNRECOGNISED], None


def safe_reason(raw):
    """A sync_state reason: a known code, UNRECOGNISED, or None."""
    code, _, _ = classify_note(raw)
    return code if code in KNOWN_CODES or code in (None, UNRECOGNISED) else UNRECOGNISED


def safe_ts(raw):
    return raw if isinstance(raw, str) and _TS.fullmatch(raw) else (None if raw is None else UNRECOGNISED)


def _utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)


def _age_hours(ts, now):
    try:
        return round((now - sync_health.parse(ts)).total_seconds() / 3600, 2)
    except (ValueError, TypeError):
        return None


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
    code, text, detail = classify_note(run["error"])
    completed = run["status"] == "completed"
    base = {"run": run["id"], "kind": run["kind"], "status": run["status"], "phase": _run_phase(run, now), "started_at": safe_ts(run["started_at"]),
            "finished_at": safe_ts(run["finished_at"]), "note": code, "note_text": text, "note_detail": detail,
            "checkpoint_advanced_by_this_run": completed and run["kind"] in ("INCREMENTAL", "FULL")}
    tomb = _tombstone_rows(index, account, run["id"])
    base["tombstone_rows_for_run"] = {k: tomb[k] for k in sorted(tomb)}
    if run["kind"] == "INCREMENTAL":
        # COLLECTED (recorded once, after the whole history range was read and BEFORE any message is applied): pages, records, affected.
        # APPLIED (recorded in the same transaction as each chunk): new_or_changed, unchanged, deleted, never_indexed_and_gone; failed_refreshes follows its chunk.
        # Every affected message ends in exactly one applied bucket, so what is left is affected minus the buckets. 0 pages means "not recorded", not "none fetched".
        recorded = run["pages"] > 0
        applied = run["refreshed"] + run["unchanged"] + run["tombstoned"] + run["vanished"] + run["failed"]
        base.update({"history_collection_recorded": recorded, "history_pages": run["pages"], "history_records": run["records"], "messages_affected": run["affected"],
                     "new_or_changed": run["refreshed"], "new_only": NOT_RECORDED, "changed_only": NOT_RECORDED, "unchanged": run["unchanged"],
                     "deleted": run["tombstoned"], "never_indexed_and_gone": run["vanished"], "failed_refreshes": run["failed"],
                     "messages_not_yet_applied": None if completed or not recorded else max(run["affected"] - applied, 0),
                     "counters_consistent_with_tombstones": run["tombstoned"] == sum(tomb.values())})
        return base
    scan = None
    if run["scan_id"] is not None:
        rows = index._q("SELECT * FROM scans WHERE account=? AND id=?", account, run["scan_id"])
        scan = dict(rows[0]) if rows else None
    if scan is None:
        base["scan"] = "not recorded"
        return base
    mode = scan["mode"] if scan["mode"] in _SCAN_MODE else UNRECOGNISED
    status = scan["status"] if scan["status"] in _SCAN_STATUS else UNRECOGNISED
    base.update({"scan_id": scan["id"], "scan_mode": mode, "scan_status": status, "ids_listed": scan["listed"], "messages_fetched_or_refreshed": scan["indexed"],
                 "new_only": NOT_RECORDED, "changed_only": NOT_RECORDED, "never_indexed_and_gone": scan["vanished"], "failed_refreshes": scan["failed"],
                 "removed_by_reconciliation": scan["pruned"], "removal_tombstones": tomb.get("FULL_RECONCILE", 0),
                 "counters_consistent_with_tombstones": scan["pruned"] == tomb.get("FULL_RECONCILE", 0) if completed else None})
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
        "checkpoint": None if state is None else {"status": state["status"] if state["status"] in ("OK", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE") else UNRECOGNISED,
                                                  "reason": safe_reason(state["reason"]), "age_hours": _age_hours(state["advanced_at"], now),
                                                  "source": state["source"] if state["source"] in ("PROFILE_BEFORE_FULL_LIST", "HISTORY_RESPONSE") else UNRECOGNISED},
        "health_codes": codes, "healthy": not codes,
        "last_completed_incremental_sync": safe_ts(last_inc[0][0]) if last_inc else None,
        "last_completed_full_scan": safe_ts(last_full[0][0]) if last_full else None,
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
        partial = r["phase"] != "COMPLETED"
        head = f"  run {r['run']} [{r['kind']}] {r['status']} - {r['phase']}"
        out.append(head + (f" ({r['note_text']})" if r["note_text"] else ""))
        if r["kind"] == "INCREMENTAL":
            if r["history_collection_recorded"]:
                out.append(f"    Collected before any message was applied: history pages {_fmt(r['history_pages'])}, records {_fmt(r['history_records'])}, "
                           f"affected messages {_fmt(r['messages_affected'])}")
            else:
                out.append("    History collection: not recorded (the run stopped before the collected totals were saved; 0 here means not recorded, not 'nothing found')")
            out.append(f"    Applied durably{' before it stopped' if partial else ''}: new or changed {_fmt(r['new_or_changed'])} (new vs changed: not recorded), "
                       f"unchanged {_fmt(r['unchanged'])}, deleted {_fmt(r['deleted'])}, never indexed and gone {_fmt(r['never_indexed_and_gone'])}, "
                       f"failed refreshes {_fmt(r['failed_refreshes'])}")
            if partial and r["messages_not_yet_applied"] is not None:
                out.append(f"    Not yet applied: {_fmt(r['messages_not_yet_applied'])} of the affected messages; the next run will replay them. "
                           "The history checkpoint did not move for this run.")
            elif partial:
                out.append("    Not yet applied: unknown (nothing was recorded about the collected range). The history checkpoint did not move for this run.")
            else:
                out.append("    The history checkpoint advanced when this run completed.")
        elif "scan_id" in r:
            out.append(f"    Scan progress{' so far' if partial else ''}: ids listed {_fmt(r['ids_listed'])}, fetched or refreshed {_fmt(r['messages_fetched_or_refreshed'])} "
                       f"(new vs changed: not recorded), never indexed and gone {_fmt(r['never_indexed_and_gone'])}, failed refreshes {_fmt(r['failed_refreshes'])}")
            if r["kind"] == "FULL":
                if partial:
                    out.append(f"    This unfinished scan removed nothing and set no checkpoint (removed by reconciliation: {_fmt(r['removed_by_reconciliation'])}).")
                else:
                    out.append(f"    Removed by reconciliation {_fmt(r['removed_by_reconciliation'])}; the checkpoint was re-established when the scan completed.")
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
