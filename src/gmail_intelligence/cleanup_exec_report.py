"""Privacy-safe text output for local execution records and dry runs (M4C-A). No account, no message ids unless asked."""
import json

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_protect

NOTE = ("This version has NO Gmail execution: nothing here can archive, trash or change a message. Dry runs and listings write "
        "nothing and never consume an approval.")


EVIDENCE_NOTE = ("'Applied' here means the item was RECORDED with caller-supplied evidence of the expected archived state; the evidence is not "
                 "authenticated and the change is not attributed to this tool (another client could have made it).")


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
    if ce.item_counts(index, account, ex["exec_id"]).get("APPLIED"):
        out.append("  " + EVIDENCE_NOTE)
    if show_ids:
        out.append("  items (id : state : code):")
        out += [f"    {r['message_id']} : {r['state']} : {r['error_code'] or '-'}" for r in index._q(
            "SELECT message_id, state, error_code FROM cleanup_exec_item WHERE account=? AND exec_id=? ORDER BY seq", account, ex["exec_id"])]
    return "\n".join(out + ["", NOTE])
