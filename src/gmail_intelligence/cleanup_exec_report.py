"""Privacy-safe text output for local execution records and dry runs (M4C-A). No account, no message ids unless asked."""
from gmail_intelligence import cleanup_exec as ce, cleanup_protect

NOTE = ("This version has NO Gmail execution: nothing here can archive, trash or change a message. Dry runs and listings write "
        "nothing and never consume an approval.")


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
    if ex["state"] == "RECONCILIATION_REQUIRED":
        out.append("  RECONCILIATION REQUIRED: some outcomes are unknown. Nothing is retried automatically; they must be checked against "
                   "the real mailbox state before anything else can run.")
    if ex["state"] in ("PARTIAL",):
        out.append("  PARTIAL: some targets were not applied. Remaining slices need their own fresh confirmation.")
    if show_ids:
        out.append("  items (id : state : code):")
        out += [f"    {r['message_id']} : {r['state']} : {r['error_code'] or '-'}" for r in index._q(
            "SELECT message_id, state, error_code FROM cleanup_exec_item WHERE account=? AND exec_id=? ORDER BY seq", account, ex["exec_id"])]
    return "\n".join(out + ["", NOTE])
