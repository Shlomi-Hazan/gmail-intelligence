"""Privacy-safe text output for local execution records and dry runs (M4C-A). No account, no message ids unless asked."""
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_protect, cleanup_undo_ledger as undo_ledger

NOTE = ("This version has NO Gmail execution: nothing here can archive, trash or change a message. Dry runs and listings write "
        "nothing and never consume an approval.")


EVIDENCE_NOTE = ("'Applied' here means the item was RECORDED with caller-supplied evidence of the expected archived state; the evidence is not "
                 "authenticated and the change is not attributed to this tool (another client could have made it).")
TRUSTED_NOTE = ("{n} item(s) were recorded from a trusted-adapter observation: the verified Gmail adapter observed the expected archived state (an in-process "
                "capability guard, not a cryptographic proof). Observing the desired state does not prove that this tool made the change.")
CALLER_NOTE = ("{n} item(s) were recorded with caller-supplied evidence: its structure was checked, but it is not authenticated.")


def evidence_notes(index, account, exec_id):
    """Lines that say, per evidence source, what an 'applied' record does and does not establish. No ids."""
    counts = {r["evidence_source"]: r["n"] for r in index._q(
        "SELECT evidence_source, COUNT(*) n FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='APPLIED' GROUP BY evidence_source", account, exec_id)}
    if not counts:
        return []
    lines = []
    if counts.get("CALLER_SUPPLIED"):
        lines.append(EVIDENCE_NOTE + " " + CALLER_NOTE.format(n=counts["CALLER_SUPPLIED"]))
    if counts.get("TRUSTED_ADAPTER"):
        lines.append(TRUSTED_NOTE.format(n=counts["TRUSTED_ADAPTER"]))
    if not lines:  # an APPLIED item without a recognized source is shown with the most cautious wording
        lines.append(EVIDENCE_NOTE)
    return lines


def _last_reason(index, account, ex):
    """Latest recorded reason code of this execution's transitions (a vocabulary code; never ids or free text)."""
    for e in audit.events(index, account, ex["plan_id"], 1000):
        if e["event_type"] == "EXECUTION_TRANSITION":
            meta = json.loads(e["meta"])
            if meta.get("exec") == ex["exec_id"] and meta.get("reason"):
                return meta["reason"]
    return None


def dry_run_text(d):
    out = [f"DRY RUN for plan {d['plan_id']} (account {cleanup_protect.HIDDEN_ACCOUNT})",
           f"  action: {d['action']}   targets: {d['targets']}   plan state: {d['plan_state']}   hash: {d['hash8']}",
           f"  slice sizes if executed: {', '.join(str(s) for s in d['slices'])} (canary 25 for plans over 100, then slices of at most 100)"]
    if d["problems"]:
        out.append("  NOT executable now: " + ", ".join(f"{k}={v}" for k, v in sorted(d["problems"].items())))
    else:
        out.append("  Locally executable: approval valid, plan fresh, no unresolved overlap with other executions.")
    if d["overlap_applied"]:
        out.append(f"  {d['overlap_applied']} target(s) were already archived by another execution and would be skipped.")
    out += ["  A later release would additionally need: a separate write authorization, a fresh typed execution confirmation, and",
            f"  live Gmail re-validation per message. The confirmation text would be: {d['confirmation_phrase']}", "", NOTE]
    return "\n".join(out)


def list_text(rows):
    out = [f"Executions for {cleanup_protect.HIDDEN_ACCOUNT}"]
    out += [f"  {r['exec_id']:<14}{r['state']:<24}plan {r['plan_id']:<15}{r['item_count']:>4} items  {r['slice_count']} slice(s)  {r['state_changed_at']}"
            for r in rows] or ["  (none)"]
    return "\n".join(out + ["", NOTE])


def show_text(index, account, ex, show_ids=False):
    out = [f"Execution {ex['exec_id']} for plan {ex['plan_id']} (account {cleanup_protect.HIDDEN_ACCOUNT})",
           f"  state: {ex['state']}   action: {ex['action']}   targets: {ex['item_count']}   created {ex['created_at']}   changed {ex['state_changed_at']}",
           "  items by state: " + (", ".join(f"{k}={v}" for k, v in sorted(ce.item_counts(index, account, ex["exec_id"]).items())) or "-")]
    for s in ce.slices(index, account, ex["exec_id"]):
        out.append(f"  slice {s['slice_no']}: {s['state']:<10} size {s['size']}" + (f"  confirmed {s['confirmed_at']}" if s["confirmed_at"] else ""))
    codes = ce.code_counts(index, account, ex["exec_id"])
    if codes:
        out.append("  reasons for items not recorded as applied (state / reason / count):")
        for (state, code), n in sorted(codes.items()):
            out.append(f"    {state:<14}{code:<26}{n:>5}   {ce.CODE_MEANING.get(code, '')}")
    state = ex["state"]
    if state == "RECONCILIATION_REQUIRED":
        out.append("  RECONCILIATION REQUIRED: some outcomes are UNKNOWN (an attempt may or may not have changed the mailbox). Nothing is "
                   "retried automatically; they must be compared with the real mailbox state before anything else can run.")
    elif state == "AWAITING_CONTINUATION":
        pending = [s["slice_no"] for s in ce.slices(index, account, ex["exec_id"]) if s["state"] == "PENDING"]
        out.append(f"  AWAITING CONTINUATION: slice(s) {', '.join(map(str, pending))} still need their own fresh typed confirmation, or the execution can be aborted.")
    elif state == "PARTIAL":
        out.append("  PARTIAL (final): some targets were recorded as applied (observed archived state) and some were not. Nothing continues from here; "
                   "use a new plan for the rest.")
    elif state == "FAILED":
        out.append("  FAILED (final): no target was recorded as applied. Nothing continues from here.")
    elif state == "ABORTED":
        out.append("  ABORTED (final): the owner abandoned the remaining slices; the consumed approval cannot be reused.")
    if state in ("PARTIAL", "FAILED", "EXECUTED") and _last_reason(index, account, ex) == "UNSAFE_SLICE":
        out.append("  STOPPED SAFELY: a completed slice had no applied item, or contained rejected, unknown or conflicting items, so the remaining "
                   "targets were never attempted (policy: no ordinary continuation after an unsafe slice).")
    if state == "EXECUTED":
        out.append("  EXECUTED: every slice finished; a final slice made only of safe skips (nothing attempted) can still end EXECUTED when earlier "
                   "slices had applied items and nothing failed.")
    for line in evidence_notes(index, account, ex["exec_id"]):
        out.append("  " + line)
    if show_ids:
        out.append("  items (id : state : code):")
        out += [f"    {r['message_id']} : {r['state']} : {r['error_code'] or '-'}" for r in index._q(
            "SELECT message_id, state, error_code FROM cleanup_exec_item WHERE account=? AND exec_id=? ORDER BY seq", account, ex["exec_id"])]
    return "\n".join(out + ["", NOTE])


# ---------------------------------------------------------------- M12C.1: local read-only execution status
# The M4D recovery report helpers (moved here unchanged from cleanup_recovery so the CLI can show them without importing the recovery or undo engine; the engine imports them from here).
# They read the local execution journal only: no Gmail, no mailbox object, no write, no retry, no resume. An UNKNOWN outcome stays UNKNOWN: resolving it needs a fresh observation of the real
# mailbox and a separate owner authorization, neither of which exists here. Undo records exist only for the in-memory fake mailbox and are not part of this view.

KNOWN_APPLIED = ("APPLIED",)
KNOWN_NOT_APPLIED = ("NOT_APPLIED", "NEVER_ATTEMPTED", "SKIPPED")
UNKNOWN = ("UNKNOWN", "INTENT")
MANUAL = ("CONFLICT",)


@dataclass(frozen=True)
class ExecutionReport:
    exec_id: str
    state: str
    counts: tuple  # ((name, n), ...): APPLIED, NOT_APPLIED, NEVER_ATTEMPTED, SKIPPED, CONFLICT, UNKNOWN, PENDING, INTENT (zero counts omitted)
    resolved_now: int  # UNKNOWN items resolved by this call
    unresolved: tuple  # sequence numbers of items that still need the owner (UNKNOWN or CONFLICT)
    notes: tuple


def _counts(index, account, exec_id):
    names = {"APPLIED": "APPLIED", "CONFLICT": "CONFLICT", "UNKNOWN": "UNKNOWN", "PENDING": "PENDING", "INTENT": "INTENT"}
    out = {}
    for r in index._q("SELECT state, error_code, COUNT(*) n FROM cleanup_exec_item WHERE account=? AND exec_id=? GROUP BY state, error_code", account, exec_id):
        if r["state"] in names:
            key = names[r["state"]]
        elif r["state"] in ("SKIPPED_DRIFT", "SKIPPED_GONE"):
            key = "SKIPPED"
        else:
            key = "NEVER_ATTEMPTED" if r["error_code"] == "NEVER_ATTEMPTED" else "NOT_APPLIED"
        out[key] = out.get(key, 0) + r["n"]
    return tuple(sorted(out.items()))


def _execution_report(index, account, exec_id, resolved, notes):
    ex = ce.get_execution(index, account, exec_id)
    unresolved = tuple(r["seq"] for r in index._q("SELECT seq FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state IN ('UNKNOWN','CONFLICT','INTENT') ORDER BY seq",
                                                  account, exec_id))
    notes = list(notes)
    if ex["state"] == "EXECUTING":
        notes.append("in progress: a live lease holds this execution; it was not touched")
    if any(r["state"] == "CONFLICT" for r in index._q("SELECT state FROM cleanup_exec_item WHERE account=? AND exec_id=?", account, exec_id)):
        notes.append("a conflicting observation needs the owner; nothing is retried")
    return ExecutionReport(exec_id, ex["state"], _counts(index, account, exec_id), resolved, unresolved, tuple(notes))


def _relevant(index, account):
    """Executions that are not finished, plus finished ones that still hold an UNKNOWN or CONFLICT item."""
    return [r["exec_id"] for r in index._q(
        "SELECT e.exec_id FROM cleanup_execution e WHERE e.account=? AND (e.state IN ('PREPARED','EXECUTING','AWAITING_CONTINUATION','RECONCILIATION_REQUIRED') "
        "OR EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account=e.account AND i.exec_id=e.exec_id AND i.state IN ('UNKNOWN','CONFLICT'))) ORDER BY e.created_at, e.exec_id", account)]



def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


OPEN_DECISION = {
    "PREPARED": "prepared and not started: nothing has been attempted or recorded yet, so it is not settled; it stays open and needs an owner decision",
    "AWAITING_CONTINUATION": "waiting: the remaining slice(s) each need their own fresh typed confirmation, or the owner must abort; nothing continues automatically, so it is not settled"}


def status(index, account, now=None):
    """[ExecutionReport] for every open or uncertain execution, oldest first, and whether anything needs the owner. Read-only; works on a read-only index handle."""
    now = (now or datetime.now(timezone.utc))
    out = []
    for exec_id in _relevant(index, account):
        er = _execution_report(index, account, exec_id, 0, ())
        row = ce.get_execution(index, account, exec_id)
        if er.state == "EXECUTING" and (not row.get("lease_expires_at") or row["lease_expires_at"] <= _iso(now)):
            notes = tuple(n for n in er.notes if not n.startswith("in progress")) + (
                "the lease has expired: the process appears to have been interrupted; it is NOT recovered here (recovery needs a fresh observation of the real mailbox and a separate authorization)",)
            er = ExecutionReport(er.exec_id, er.state, er.counts, er.resolved_now, er.unresolved, notes)
        if er.state in OPEN_DECISION:  # open, though nothing is UNKNOWN: it is NOT settled and still waits for an owner decision
            er = ExecutionReport(er.exec_id, er.state, er.counts, er.resolved_now, er.unresolved, er.notes + (OPEN_DECISION[er.state],))
        out.append(er)
    needs = any(e.unresolved or e.state in OPEN_DECISION or any(n.startswith("the lease has expired") for n in e.notes) or e.state == "RECONCILIATION_REQUIRED" for e in out)
    return out, needs


def view(er):
    """Known / unknown / manual-review split of one execution's recorded outcomes (counts only)."""
    c = dict(er.counts)
    return {"exec_id": er.exec_id, "state": er.state,
            "known_applied": sum(c.get(k, 0) for k in KNOWN_APPLIED), "known_not_applied": sum(c.get(k, 0) for k in KNOWN_NOT_APPLIED),
            "unknown": sum(c.get(k, 0) for k in UNKNOWN), "manual_review": sum(c.get(k, 0) for k in MANUAL), "pending": c.get("PENDING", 0),
            "items_needing_owner": list(er.unresolved), "notes": list(er.notes)}


RECOVERY_NOTE = ("Local, read-only: this reads the local execution journal and undo ledgers only. Gmail was not contacted and nothing was retried, resumed, archived, restored or changed. "
                 "An UNKNOWN outcome stays UNKNOWN until a fresh, execution-bound observation of the real mailbox is compared with the record; that live step is not available "
                 "in this version and needs a separate owner authorization.")


UNDO_CATEGORY = {"RESTORED": "restored", "NOT_RESTORED": "not_restored", "UNKNOWN": "unresolved", "OPEN": "unresolved", "CONFLICT": "conflict",
                 "INCONSISTENT": "inconsistent", "AUTHORIZED": "pending"}
UNDO_MEANING = {"restored": "restored (confirmed by a fresh observation)", "not_restored": "not restored (observed unmodified; nothing changed; a new owner authorization is possible)",
                "unresolved": "UNRESOLVED (an attempt may or may not have changed the mailbox; only a fresh observation can settle it; never repeated automatically)",
                "conflict": "CONFLICT (the mailbox shows something unexpected; manual owner review; final, not a restoration)",
                "inconsistent": "INCONSISTENT ledger (never acted on; manual owner review)", "pending": "authorized but not run (the authorization expires; nothing happened)"}
UNDO_NEEDS_OWNER = ("unresolved", "conflict", "inconsistent", "pending")
REVERSAL_NEEDS_OWNER = ("PLANNED", "APPROVED", "AWAITING_CONTINUATION", "INTERRUPTED", "STOPPED", "INCONSISTENT")   # a plan awaiting a decision, or ended unfinished; COMPLETED / ABORTED / IN_PROGRESS do not


def reversal_data(index, account, now=None):
    """Read-only view of every bulk reversal plan (M12D): state, item and slice counts, restored and skipped counts. Reversal ids and counts only; no message ids, labels or accounts."""
    now = now or datetime.now(timezone.utc)
    out = []
    for rev in undo_ledger.all_reversals(index, account):
        st = undo_ledger.reversal_state(undo_ledger.reversal_events(index, account, rev), _iso(now))
        out.append({"rev": rev, "state": st["state"], "items": len(st.get("items", ())), "slices": len(st.get("slices", ())), "slices_done": st.get("done", 0),
                    "restored": st.get("restored", 0), "skipped": len(st.get("skipped", {}))})
    return out


def undo_data(index, account):
    """Read-only view of every undo ledger (M12C.3): execution id, item sequence number, status and a category; no message ids, labels or accounts. Needs no mailbox and no Gmail."""
    rows = [{"exec_id": e, "item": i, "status": st, "category": UNDO_CATEGORY.get(st, "inconsistent")} for e, i, st in undo_ledger.all_undos(index, account)]
    return rows


def recovery_data(index, account, now=None):
    """The M12C.1 status as plain data (counts, states and item sequence numbers; no message ids, account address, labels, senders or credentials; local execution ids may appear)."""
    reports, needs = status(index, account, now)
    undos = undo_data(index, account)
    reversals = reversal_data(index, account, now)
    needs = needs or any(u["category"] in UNDO_NEEDS_OWNER for u in undos) or any(r["state"] in REVERSAL_NEEDS_OWNER for r in reversals)
    return {"executions": [view(r) for r in reports], "undos": undos, "reversals": reversals, "needs_owner": needs, "read_only": True, "gmail_contacted": False, "retried_or_changed": 0}


def recovery_text(data):
    out = [f"Execution recovery status for {cleanup_protect.HIDDEN_ACCOUNT} (local journal only)"]
    for e in data["executions"]:
        out.append(f"  execution {e['exec_id']}: {e['state']}")
        out.append(f"    known: {e['known_applied']} recorded as applied, {e['known_not_applied']} known not applied (not applied / never attempted / skipped)")
        out.append(f"    UNKNOWN: {e['unknown']} (an attempt may or may not have changed the mailbox)   manual review: {e['manual_review']} (conflicting observation)   pending: {e['pending']}")
        if e["items_needing_owner"]:
            out.append("    items needing the owner: " + ", ".join(str(s) for s in e["items_needing_owner"]))
        out += [f"    note: {n}" for n in e["notes"]]
    if not data["executions"]:
        out.append("  no open or uncertain executions")
    for r in data.get("reversals", ()):
        out.append(f"  reversal plan {r['rev']}: {r['state']}; {r['items']} item(s), {r['slices_done']}/{r['slices']} slice(s) done, {r['restored']} restored, {r['skipped']} skipped")
    if data.get("undos"):
        out.append("  archive undos (per item, by sequence number):")
        out += [f"    execution {u['exec_id']} item {u['item']}: {UNDO_MEANING[u['category']]}" for u in data["undos"]]
    out.append("  OWNER ACTION REQUIRED" if data["needs_owner"] else "  no owner decision needed right now; open executions, finished undos or reversal plans remain (see above)" if data["executions"] or data.get("undos") or data.get("reversals") else "  nothing needs the owner")
    return "\n".join(out + ["", RECOVERY_NOTE])
