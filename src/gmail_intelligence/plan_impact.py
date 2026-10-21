"""Read-only explanation of how the CURRENT index state affects stored M4 cleanup plans (M7B, docs/SYNC.md section 17).

It only reads. It never expires a plan, consumes or edits an approval, reserves an execution, appends an audit event or creates anything: it reuses the
existing freshness checks (`cleanup_plans.revalidate` / `verify_approved`, which only SELECT) and `sync_health`, and it is meant to be run on a
`ReadOnlyIndex`, where any hidden write would fail inside SQLite itself. It does NOT call `expire_due` or any `_plan_cmd` style helper.

A plan can have several reasons at once and all of them are listed. The headline is only a summary. Findings are observations about the LOCAL index; Gmail is
never contacted, and the executor re-reads live Gmail state before any write regardless of what this report says.
"""
from datetime import datetime, timezone

from gmail_intelligence import cleanup_plans as cp, sync_health, sync_report

ACTIVE_STATES = ("DRAFT", "REVIEWED", "APPROVED")
FIELDS = (("labels", "labels_sha256"), ("read_state", "unread"), ("sender", "sender_sha256"), ("thread", "thread_id"), ("received_time", "internal_ms"),
          ("classification", "class_sha256"))
STALE = ("TARGET_CHANGED", "TARGET_DELETED_OR_ABSENT", "CLASSIFICATION_NOT_CURRENT", "ELIGIBILITY_OR_RULES_CHANGED", "ANCHOR_CHANGED_BY_FULL_SCAN")
BLOCKED = ("SYNC_NOT_HEALTHY", "INDEX_INCOMPLETE")
INTEGRITY = {"ACCOUNT_MISMATCH", "HASH_MISMATCH", "SNAPSHOT_UNREADABLE", "SNAPSHOT_MALFORMED", "SNAPSHOT_NOT_CANONICAL", "COLUMN_MISMATCH", "ITEM_TABLE_MISMATCH",
             "CANARY_SHAPE", "PLAN_FROM_THE_FUTURE"}
ELIGIBILITY = {"POLICY_CHANGED", "PROTECTION_RULES_CHANGED"}
CLASSIFICATION = {"CLASSIFICATION_RULES_CHANGED", "REASON_CLASSIFICATION_STALE", "REASON_CLASSIFICATION_MISSING"}
APPROVAL = {"NOT_APPROVED", "NO_SINGLE_VALID_APPROVAL", "APPROVAL_MISMATCH", "APPROVAL_EXPIRED", "APPROVAL_TIMESTAMP_INVALID", "CLOCK_BEFORE_APPROVAL",
            "APPROVAL_TIMES_INCONSISTENT", "AUDIT_CHAIN_BROKEN", "APPROVAL_NOT_IN_AUDIT"}
CATEGORY_ORDER = ("EXPIRED", "STORED_PLAN_INCONSISTENT", "TARGET_CHANGED", "TARGET_DELETED_OR_ABSENT", "CLASSIFICATION_NOT_CURRENT", "ELIGIBILITY_OR_RULES_CHANGED", "ANCHOR_CHANGED_BY_FULL_SCAN",
                  "INDEX_INCOMPLETE", "SYNC_NOT_HEALTHY", "APPROVAL_NOT_USABLE")


def _utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)


def category(code):
    """The category of ONE problem code (ITEM_NOT_ELIGIBLE itself is resolved by `categories`, from the reasons that come with it)."""
    if code == "PLAN_EXPIRED":
        return "EXPIRED"
    if code in INTEGRITY:
        return "STORED_PLAN_INCONSISTENT"
    if code == "ITEM_CHANGED":
        return "TARGET_CHANGED"
    if code == "ITEM_MISSING":
        return "TARGET_DELETED_OR_ABSENT"
    if code in CLASSIFICATION:
        return "CLASSIFICATION_NOT_CURRENT"
    if code == "REASON_INDEX_PARTIAL" or code == "INDEX_NOT_COMPLETE":
        return "INDEX_INCOMPLETE"
    if code in ELIGIBILITY or code.startswith("REASON_") or code == "ITEM_NOT_ELIGIBLE":
        return "ELIGIBILITY_OR_RULES_CHANGED"
    if code == "INDEX_RESCANNED":
        return "ANCHOR_CHANGED_BY_FULL_SCAN"
    if code in sync_health.CODES:
        return "SYNC_NOT_HEALTHY"
    if code in APPROVAL:
        return "APPROVAL_NOT_USABLE"
    return "OTHER"


def categories(codes):
    """The reason categories of a problem list. ITEM_NOT_ELIGIBLE is only the umbrella over per-target reasons (a stale classification, a partial index, an
    eligibility rule): it is explained by those reasons and adds a category of its own only when it comes with none. So a target that merely lost its current
    classification after a sync is reported as that, and an unfinished full scan is reported as an incomplete index, not as a stale plan."""
    codes = set(codes)
    has_reason = any(c.startswith("REASON_") for c in codes)
    return {category(c) for c in codes if not (c == "ITEM_NOT_ELIGIBLE" and has_reason)}


def _target_breakdown(index, account, plan):
    """Field-level comparison of the plan snapshot with the current index (digests only; no values are read out or printed)."""
    items = cp.snapshot_of(plan)["items"]
    ids = [i["id"] for i in items]
    facts = cp._facts(index, account, ids)  # SELECT only
    changed_fields = {name: 0 for name, _ in FIELDS}
    changed_fields["rescan_stamp_only"] = 0
    changed = unchanged = 0
    missing = []
    for item in items:
        cur = facts.get(item["id"])
        if cur is None:
            missing.append(item["id"])
            continue
        diffs = [name for name, key in FIELDS if cur[key] != item[key]]
        stamp = cur["scan_id"] != item["scan_id"]
        if diffs:
            changed += 1
            for name in diffs:
                changed_fields[name] += 1
        elif stamp:
            changed += 1
            changed_fields["rescan_stamp_only"] += 1
        else:
            unchanged += 1
    reasons = {}
    for k in range(0, len(missing), 400):
        chunk = missing[k:k + 400]
        marks = ",".join("?" * len(chunk))
        for r in index._q(f"SELECT message_id, reason FROM message_tombstone WHERE account=? AND message_id IN ({marks})", account, *chunk):
            reasons[r["message_id"]] = r["reason"]
    by_reason = {}
    for mid in missing:
        key = reasons.get(mid, "NO_TOMBSTONE")
        by_reason[key] = by_reason.get(key, 0) + 1
    return {"total": len(items), "unchanged": unchanged, "changed": changed, "changed_by_field": changed_fields,
            "absent_from_index": len(missing), "absent_by_recorded_reason": {k: by_reason[k] for k in sorted(by_reason)}}


def _approvals(index, account, plan_id):
    counts = {r["status"]: r["n"] for r in index._q("SELECT status, COUNT(*) AS n FROM cleanup_approval WHERE account=? AND plan_id=? GROUP BY status", account, plan_id)}
    return {s: counts.get(s, 0) for s in ("VALID", "CONSUMED", "REVOKED", "EXPIRED")}


def _headline(state, reasons):
    if state not in ACTIVE_STATES:
        return "NON_EXECUTABLE"
    if "EXPIRED" in reasons:
        return "EXPIRED"
    if "STORED_PLAN_INCONSISTENT" in reasons:
        return "STORED_PLAN_INCONSISTENT"
    stale, blocked = any(r in reasons for r in STALE), any(r in reasons for r in BLOCKED)
    if stale and blocked:
        return "STALE_AND_BLOCKED"
    if stale:
        return "STALE"
    if blocked:
        return "BLOCKED_BY_SYNC"
    if "APPROVAL_NOT_USABLE" in reasons:
        return "NOT_EXECUTABLE_APPROVAL"
    return "FRESH"


def plan_entry(index, account, row, now, uncertain):
    plan = cp.get_plan(index, account, row["plan_id"])
    state = plan["state"]
    if state in ACTIVE_STATES:
        problems = cp.verify_approved(index, account, plan["plan_id"], now) if state == "APPROVED" else cp.revalidate(index, account, plan, now)
    else:
        problems = {}
    cats = categories(problems)
    reasons = sorted(cats - {"OTHER"}, key=CATEGORY_ORDER.index) + (["OTHER"] if "OTHER" in cats else [])
    approvals = _approvals(index, account, plan["plan_id"])
    entry = {"plan_id": plan["plan_id"], "state": state, "version": plan["version"], "items": plan["item_count"], "created_at": sync_report.safe_ts(plan["created_at"]),
             "expires_at": sync_report.safe_ts(plan["expires_at"]), "headline": _headline(state, reasons), "reasons": reasons,
             "codes": {k: problems[k] for k in sorted(problems)}, "approval_rows": approvals,
             "approval_rows_are_retained": True,
             "expiry_not_yet_recorded": state in ACTIVE_STATES and "EXPIRED" in reasons,
             "passes_every_local_check": state == "APPROVED" and not problems,
             "evidence": "UNCERTAIN_INDEX" if uncertain else "OBSERVED_LOCAL_INDEX"}
    if state in ACTIVE_STATES and not (INTEGRITY & set(problems)):
        entry["targets"] = _target_breakdown(index, account, plan)
    entry["execution_exists"] = bool(index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND plan_id=? LIMIT 1", account, plan["plan_id"]))
    return entry


def impact_report(index, account, now=None):
    now = _utc(now)
    codes = sync_health.problems(index, account, now)
    rows = index._q("SELECT plan_id FROM cleanup_plan WHERE account=? ORDER BY created_at, plan_id", account)
    entries = [plan_entry(index, account, r, now, bool(codes)) for r in rows]
    states, headlines = {}, {}
    for e in entries:
        states[e["state"]] = states.get(e["state"], 0) + 1
        headlines[e["headline"]] = headlines.get(e["headline"], 0) + 1
    return {"section": "plan-impact", "read_only": True, "gmail_contacted": False, "sync_health": {"healthy": not codes, "codes": codes},
            "plans_total": len(entries), "plans_by_state": {k: states[k] for k in sorted(states)}, "plans_by_headline": {k: headlines[k] for k in sorted(headlines)},
            "plans": [e for e in entries if e["state"] in ACTIVE_STATES], "closed_plans": [{"plan_id": e["plan_id"], "state": e["state"]} for e in entries if e["state"] not in ACTIVE_STATES],
            "limits": ["observations of the local index only; Gmail is not contacted and the executor re-reads live Gmail before any write",
                       "nothing is expired, approved, reserved or recorded by this report; an overdue plan is only marked 'expiry not yet recorded'",
                       "approval records are immutable rows and are never deleted or edited because a plan became stale"]}


def impact_text(rep):
    out = ["Cleanup plan impact (local index only; Gmail was not contacted; nothing was changed)"]
    sh = rep["sync_health"]
    out.append("  index health: " + ("fresh" if sh["healthy"] else "NOT healthy (" + ", ".join(sh["codes"]) + "): plan findings below are observed against an index of uncertain freshness"))
    out.append(f"  plans: {rep['plans_total']} in total; " + (", ".join(f"{k} {v}" for k, v in rep["plans_by_state"].items()) or "none"))
    for e in rep["plans"]:
        out.append(f"  {e['plan_id']} v{e['version']} [{e['state']}] {e['items']} targets -> {e['headline']}")
        if e["reasons"]:
            out.append("    reasons: " + ", ".join(e["reasons"]) + "   codes: " + ", ".join(f"{k}={v}" for k, v in e["codes"].items()))
        t = e.get("targets")
        if t:
            parts = [f"{k.replace('_', ' ')} {v}" for k, v in t["changed_by_field"].items() if v]
            out.append(f"    targets: unchanged {t['unchanged']}, changed {t['changed']}" + (" (" + ", ".join(parts) + ")" if parts else "")
                       + f", absent from the index {t['absent_from_index']}"
                       + (" (" + ", ".join(f"{k.lower().replace('_', ' ')} {v}" for k, v in t["absent_by_recorded_reason"].items()) + ")" if t["absent_from_index"] else ""))
        ap = e["approval_rows"]
        if any(ap.values()):
            out.append("    approval records: " + ", ".join(f"{k} {v}" for k, v in ap.items() if v) + " (immutable; stored regardless of the plan's freshness"
                       + ("; the VALID one can no longer authorize anything" if ap["VALID"] and e["headline"] not in ("FRESH",) else "") + ")")
        if e["expiry_not_yet_recorded"]:
            out.append("    expiry time has passed; the stored state is updated only when a plan operation runs (this report does not record it)")
        if e["passes_every_local_check"]:
            out.append("    passes every local check (the executor still re-reads live Gmail state)")
    if rep["closed_plans"]:
        out.append(f"  closed plans (not re-checked): {len(rep['closed_plans'])}")
    out.append("  Stale plans are never edited or regenerated automatically; create a new plan after the index is fresh.")
    return "\n".join(out)
