"""M12E: thin, strictly READ-ONLY projections of the local cleanup records for the dashboard (the Cleanup area). Local index only: no Gmail, no credentials, no write, no network.

Every figure is read from tables the M4/M12 modules already maintain (plans, approvals, executions, slices, items, the hash-chained audit log) or from the existing M12A discovery function;
nothing is invented and no business rule is re-implemented in the browser. The dashboard server must not import the cleanup EXECUTION modules (a test enforces it), so the few counts the CLI
reports through `cleanup_exec_report` are re-read here with plain SELECTs; `tests/test_dashboard_cleanup.py` pins the shared vocabulary to those modules so the two cannot drift apart.
Output carries local plan / execution / reversal identifiers, short plan hashes, state codes and counts only: never message ids, sender addresses (a discovery group is a sender DOMAIN, as
everywhere else in the dashboard), label names, subjects or content. A dashboard refresh re-reads these records; it never advances, approves, reconciles or changes anything.
"""
from collections import Counter

from gmail_intelligence import analytics, cleanup_audit, cleanup_discovery
from gmail_intelligence import cleanup_undo_ledger as ledger

SECTIONS = ("overview", "discovery", "plans", "executions", "reversals", "recovery")
LIVE_STATUS = "DISABLED_IN_THIS_BUILD"      # pinned by a test to the three source constants of exec_live_mailbox (this module must not import them)
DISCOVERY_LIMIT, DISCOVERY_MIN_GROUP = 20, 5
ITEM_BUCKETS = {"APPLIED": "archived", "SKIPPED_DRIFT": "skipped", "SKIPPED_GONE": "skipped", "UNKNOWN": "unknown", "CONFLICT": "conflict", "INTENT": "intent", "PENDING": "pending", "NOT_APPLIED": "not_applied"}
UNRESOLVED_BUCKETS = ("unknown", "conflict", "intent")
EXEC_NEEDS_OWNER = ("INTERRUPTED", "RECONCILIATION_REQUIRED", "AWAITING_CONTINUATION", "PREPARED")
UNDO_CATEGORY = {"RESTORED": "restored", "NOT_RESTORED": "not_restored", "NONE": "never_attempted", "AUTHORIZED": "pending", "OPEN": "uncertain", "UNKNOWN": "uncertain",
                 "CONFLICT": "conflict", "INCONSISTENT": "inconsistent"}
REVERSAL_NEEDS_OWNER = ("PLANNED", "APPROVED", "AWAITING_CONTINUATION", "INTERRUPTED", "STOPPED", "INCONSISTENT")
STOPPED_EXEC_STATES = ("PARTIAL", "FAILED", "ABORTED")


def _iso(now):
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _q(index, sql, *args):
    return [dict(r) for r in index._q(sql, *args)]


# ---------------------------------------------------------------- plans
def _approval_stage(plan, approvals, valid, at):
    """What the LOCAL approval record says about a plan whose state is APPROVED (same conditions as the CLI's approval check: exactly one VALID, unexpired approval that matches the plan).
    "Approved, not executed" is shown only for a genuinely valid approval; it is a local status, never permission to run (live execution is disabled in this build)."""
    if not approvals:
        return "APPROVAL_MISSING"
    if not valid:
        statuses = {a["status"] for a in approvals}
        return "APPROVAL_EXPIRED" if "EXPIRED" in statuses else "APPROVAL_REVOKED" if "REVOKED" in statuses else "APPROVAL_INVALID"   # only CONSUMED left: no execution recorded for it
    if len(valid) != 1:
        return "APPROVAL_INVALID"
    a = valid[0]
    if a["expires_at"] <= at or plan["expires_at"] <= at:
        return "APPROVAL_EXPIRED"
    if (a["plan_hash"], a["action"], a["item_count"]) != (plan["plan_hash"], plan["action"], plan["item_count"]):
        return "APPROVAL_INVALID"
    return "APPROVED_NOT_EXECUTED"


def plans(index, account, now):
    approvals = {}
    for r in _q(index, "SELECT plan_id, status, expires_at, plan_hash, action, item_count FROM cleanup_approval WHERE account=?", account):
        approvals.setdefault(r["plan_id"], []).append(r)
    execs = {r["plan_id"]: r for r in _q(index, "SELECT plan_id, exec_id, state FROM cleanup_execution WHERE account=?", account)}
    rows = []
    for p in _q(index, "SELECT plan_id, version, action, state, plan_hash, item_count, created_at, expires_at, reviewed_at FROM cleanup_plan WHERE account=? ORDER BY created_at, plan_id", account):
        ap = approvals.get(p["plan_id"], [])
        ex = execs.get(p["plan_id"])
        valid = [a for a in ap if a["status"] == "VALID"]
        if ex:
            stage = "EXECUTION_RESERVED"
        elif p["state"] == "APPROVED":
            stage = _approval_stage(p, ap, valid, _iso(now))
        elif p["state"] in ("CANCELLED", "EXPIRED", "SUPERSEDED"):
            stage = p["state"]
        elif p["state"] == "REVIEWED":
            stage = "REVIEWED"
        else:
            stage = "DRAFT"
        rows.append({"plan_id": p["plan_id"], "version": p["version"], "action": p["action"], "state": p["state"], "stage": stage, "hash8": p["plan_hash"][:8], "items": p["item_count"],
                     "created_at": p["created_at"], "expires_at": p["expires_at"], "reviewed_at": p["reviewed_at"], "approvals": dict(sorted(Counter(a["status"] for a in ap).items())),
                     "plan_expired": p["state"] not in ("CANCELLED", "EXPIRED", "SUPERSEDED") and p["expires_at"] <= _iso(now) and not ex,
                     "execution": {"exec_id": ex["exec_id"], "state": ex["state"]} if ex else None})
    return rows


# ---------------------------------------------------------------- executions
def _category(row, unresolved, now):
    st = row["state"]
    if st == "EXECUTING":
        return "RUNNING" if row["lease_expires_at"] and row["lease_expires_at"] > _iso(now) else "INTERRUPTED"
    if st == "EXECUTED":
        return "COMPLETED" if not unresolved else "COMPLETED_WITH_OPEN_ITEMS"
    return st


def executions(index, account, now):
    items = {}
    for r in _q(index, "SELECT exec_id, state, error_code, COUNT(*) n FROM cleanup_exec_item WHERE account=? GROUP BY exec_id, state, error_code", account):
        c = items.setdefault(r["exec_id"], Counter())
        c[ITEM_BUCKETS[r["state"]]] += r["n"]
        if r["error_code"] == "NEVER_ATTEMPTED":
            c["never_attempted"] += r["n"]
    slices = {}
    for r in _q(index, "SELECT exec_id, slice_no, size, state, confirmed_at, started_at, finished_at FROM cleanup_exec_slice WHERE account=? ORDER BY exec_id, slice_no", account):
        slices.setdefault(r["exec_id"], []).append(r)
    plan_hash = {r["plan_id"]: r["plan_hash"][:8] for r in _q(index, "SELECT plan_id, plan_hash FROM cleanup_plan WHERE account=?", account)}
    last_event = {r["plan_id"]: r["at"] for r in _q(index, "SELECT plan_id, MAX(at) at FROM cleanup_audit WHERE account=? AND plan_id IS NOT NULL GROUP BY plan_id", account)}
    out = []
    for e in _q(index, "SELECT exec_id, plan_id, state, item_count, slice_count, created_at, state_changed_at, lease_expires_at FROM cleanup_execution WHERE account=? ORDER BY created_at, exec_id", account):
        c = items.get(e["exec_id"], Counter())
        unresolved = sum(c.get(b, 0) for b in UNRESOLVED_BUCKETS)
        cat = _category(e, unresolved, now)
        sl, first, boundaries = slices.get(e["exec_id"], []), 1, []
        for s in sl:
            boundaries.append({"slice": s["slice_no"], "size": s["size"], "state": s["state"], "items": [first, first + s["size"] - 1], "confirmed_at": s["confirmed_at"],
                               "started_at": s["started_at"], "finished_at": s["finished_at"]})
            first += s["size"]
        out.append({"exec_id": e["exec_id"], "plan_id": e["plan_id"], "plan_hash8": plan_hash.get(e["plan_id"]), "state": e["state"], "category": cat, "items": e["item_count"],
                    "slices": boundaries, "slices_total": e["slice_count"], "slices_completed": sum(1 for s in sl if s["state"] == "COMPLETED"),
                    "slices_pending": sum(1 for s in sl if s["state"] in ("PENDING", "CONFIRMED")), "item_counts": {k: c.get(k, 0) for k in ("archived", "skipped", "not_applied", "never_attempted",
                                                                                                                                      "unknown", "conflict", "intent", "pending")},
                    "unresolved": unresolved, "owner_action": cat in EXEC_NEEDS_OWNER or unresolved > 0, "created_at": e["created_at"], "changed_at": e["state_changed_at"],
                    "last_audit_at": last_event.get(e["plan_id"])})
    return out


# ---------------------------------------------------------------- reversal plans and undo ledgers
def reversals(index, account, now):
    iso = _iso(now)
    plans_out, covered = [], set()
    for rev in ledger.all_reversals(index, account):
        ev = ledger.reversal_events(index, account, rev)
        st = ledger.reversal_state(ev, iso)
        if st["state"] == "INCONSISTENT":
            plans_out.append({"rev": rev, "state": "INCONSISTENT", "owner_action": True})
            continue
        per = Counter()
        for seq in st["items"]:
            per[UNDO_CATEGORY.get(ledger.undo_status(index, account, st["exec"], seq), "inconsistent")] += 1
            covered.add((st["exec"], seq))
        bad = sum(per.get(k, 0) for k in ("uncertain", "conflict", "inconsistent"))
        plans_out.append({"rev": rev, "exec_id": st["exec"], "state": st["state"], "approved": st["approved"], "approval_expires": st["approval_expires"], "items": len(st["items"]),
                          "slices": len(st["slices"]), "slices_done": st["done"], "restored": per.get("restored", 0), "skipped": len(st["skipped"]), "skip_codes": dict(sorted(Counter(st["skipped"].values()).items())),
                          "item_counts": {k: per.get(k, 0) for k in ("restored", "not_restored", "never_attempted", "pending", "uncertain", "conflict", "inconsistent")},
                          "planned_at": ev[0]["at"], "owner_action": st["state"] in REVERSAL_NEEDS_OWNER or bad > 0})
    single = Counter()
    for exec_id, seq, status in ledger.all_undos(index, account):
        if (exec_id, seq) not in covered:
            single[UNDO_CATEGORY.get(status, "inconsistent")] += 1
    return plans_out, dict(sorted(single.items()))


# ---------------------------------------------------------------- recovery
def recovery(execs, revs, single):
    attention = []
    for e in execs:
        if e["owner_action"]:
            nxt = {"INTERRUPTED": "RECONCILE", "RECONCILIATION_REQUIRED": "RECONCILE", "AWAITING_CONTINUATION": "CONFIRM_OR_ABORT", "PREPARED": "RUN_OR_ABORT"}.get(e["category"], "REVIEW")
            attention.append({"kind": "execution", "id": e["exec_id"], "code": e["category"], "unresolved": e["unresolved"], "next": nxt, "since": e["changed_at"]})
    for r in revs:
        if r.get("owner_action"):
            ic = r.get("item_counts", {})
            nxt = ("RECONCILE" if ic.get("uncertain") else "REVIEW_CONFLICT" if ic.get("conflict") or ic.get("inconsistent") or r["state"] == "INCONSISTENT" else
                   "APPROVE" if r["state"] == "PLANNED" else "RUN_OR_ABORT" if r["state"] in ("APPROVED", "AWAITING_CONTINUATION") else "ABORT_OR_NEW_PLAN")
            attention.append({"kind": "reversal", "id": r["rev"], "code": r["state"], "unresolved": ic.get("uncertain", 0) + ic.get("conflict", 0) + ic.get("inconsistent", 0), "next": nxt,
                              "since": r.get("planned_at")})
    for category, n in single.items():
        if category in ("uncertain", "conflict", "inconsistent", "pending"):
            attention.append({"kind": "undo", "id": None, "code": category.upper(), "unresolved": n, "next": "RECONCILE" if category == "uncertain" else "REVIEW_CONFLICT" if category != "pending" else "RUN_OR_EXPIRE", "since": None})
    return attention


# ---------------------------------------------------------------- the projections
def _discovery(index, account, now, limit=DISCOVERY_LIMIT, min_group=DISCOVERY_MIN_GROUP):
    return cleanup_discovery.compute(index, account, limit=limit, min_group=min_group, now=now)


def build(section, index, account, now, params=None):
    """The dashboard envelope for one Cleanup projection. `section` is one of SECTIONS; `params` are the already-validated query values."""
    params = params or {}
    an = analytics.Analytics(index, account, now=now)
    explain = ["LOCAL_RECORDS_NOT_GMAIL_STATE", "READ_ONLY_NOTHING_CAN_BE_CHANGED_HERE", "NO_MESSAGE_IDS_OR_LABELS", "SNAPSHOT_NOT_LIVE"]
    if section == "discovery":
        d = _discovery(index, account, now, params.get("limit", DISCOVERY_LIMIT), params.get("min_group", DISCOVERY_MIN_GROUP))
        data = {"discovery": d, "operations": LIVE_STATUS}
        return an._envelope("cleanup-discovery", data, "MIXED", ["SAME_POLICY_AS_CLEANUP_CANDIDATES", "CANDIDATES_NOT_CERTAINTY", "ATTENTION_IS_CONSERVATIVE_PROTECTION", "SNAPSHOT_NOT_LIVE"])
    p = plans(index, account, now)
    if section == "plans":
        return an._envelope("cleanup-plans", {"plans": p, "operations": LIVE_STATUS, "approvals_cli_only": True}, "OBSERVED", explain)
    ex = executions(index, account, now)
    if section == "executions":
        return an._envelope("cleanup-executions", {"executions": ex, "operations": LIVE_STATUS}, "OBSERVED", explain)
    revs, single = reversals(index, account, now)
    if section == "reversals":
        return an._envelope("cleanup-reversals", {"reversals": revs, "single_undos": single, "operations": LIVE_STATUS}, "OBSERVED", explain)
    attention = recovery(ex, revs, single)
    if section == "recovery":
        return an._envelope("cleanup-recovery", {"attention": attention, "operations": LIVE_STATUS, "audit_chain_ok": cleanup_audit.verify_chain(index, account)[0]}, "OBSERVED", explain)
    # overview: the lifecycle Discovery -> Review -> Plan -> Approval -> Execution -> Recovery / Undo
    disc = _discovery(index, account, now, 1, DISCOVERY_MIN_GROUP)
    t = disc["totals"]
    items = Counter()
    for e in ex:
        items.update(e["item_counts"])
    data = {"operations": LIVE_STATUS,
            "discovery": {"indexed": t["indexed"], "candidates": t["eligible"]["messages"], "groups": disc["groups_total"], "uncertain": t["uncertain"]["messages"], "protected": t["protected"]["messages"],
                          "unsafe_data": t["unsafe_data"]["messages"], "index_state": disc["index"]["state"], "warnings": disc["warnings"]},
            "review": {"stored": False},
            "plans": {"total": len(p), "by_state": dict(sorted(Counter(x["state"] for x in p).items())), "by_stage": dict(sorted(Counter(x["stage"] for x in p).items())),
                      "approvals": dict(sorted(sum((Counter(x["approvals"]) for x in p), Counter()).items()))},
            "executions": {"total": len(ex), "by_category": dict(sorted(Counter(x["category"] for x in ex).items())), "items": {k: items.get(k, 0) for k in ("archived", "skipped", "unknown", "conflict", "intent")},
                           "owner_action": sum(1 for x in ex if x["owner_action"])},
            "reversals": {"total": len(revs), "by_state": dict(sorted(Counter(x["state"] for x in revs).items())), "restored": sum(x.get("restored", 0) for x in revs), "single_undos": single},
            "recovery": {"attention": len(attention), "audit_chain_ok": cleanup_audit.verify_chain(index, account)[0]}}
    return an._envelope("cleanup-overview", data, "OBSERVED", explain + ["DISCOVERY_IS_THE_SAME_POLICY_AS_CLEANUP_CANDIDATES"])
