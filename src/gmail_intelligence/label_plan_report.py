"""Plain-text rendering of M5D label-change plans. LOCAL ONLY. Label names are private: hidden by default (`--show-names`), always sanitized."""
from gmail_intelligence import cleanup_protect, label_model as lm, label_plans as lp
from gmail_intelligence.label_report import LOCAL_ONLY, safe

NOT_AN_AUTH = ("A local approval is only a record of your typed confirmation. It grants no Gmail permission, and nothing in this build can execute a label plan. "
               "No label, filter or message in Gmail is changed by creating, reviewing or approving a plan.")


def _name(value, show_names):
    return f'"{safe(value)}"' if show_names else "(name hidden)"


def op_line(n, op, show_names, counts=None):
    kind = op["op"]
    if kind == "CREATE":
        text = f"CREATE a new label {_name(op['new_name'], show_names)}"
    elif kind == "RENAME":
        text = f"RENAME label {op['label_id']} {_name(op['old_name'], show_names)} to {_name(op['new_name'], show_names)}"
    elif kind == "NEST":
        text = f"NEST label {op['label_id']} {_name(op['old_name'], show_names)} to {_name(op['new_name'], show_names)}"
    else:
        text = f"MERGE label {op['label_id']} {_name(op['old_name'], show_names)} into {op['target_id']} {_name(op['new_name'], show_names)}"
    notes = []
    if op["descendants"]:
        notes.append(f"changes the full path of {op['descendants']} child label(s)")
    if kind == "MERGE":
        notes.append("may be IRREVERSIBLE: the source label would disappear" + (f"; {counts.get(op['label_id'], 0)} indexed message(s) carry it" if counts is not None else ""))
    return f"  {n:>3}. {text}" + ("".join(f"\n       note: {x}" for x in notes))


def plan_text(index, account, plan, show_names=False):
    counts = lm.message_counts(index, account)
    snap = lp.snapshot_of(plan)
    out = [f"Label plan {plan['plan_id']}", "  " + LOCAL_ONLY, f"  account: {cleanup_protect.HIDDEN_ACCOUNT}",
           f"  state {plan['state']} · {plan['op_count']} operation(s) · hash {lp.short(plan['plan_hash'])} · created {plan['created_at']} · expires {plan['expires_at']}",
           f"  built from a local inventory of {snap['labels_total']} label(s) (inventory hash {lp.short(plan['inventory_hash'])})", "", "Operations (applied in this order):"]
    out += [op_line(o["seq"], o, show_names, counts) for o in snap["ops"]]
    if not show_names:
        out.append("  (label names hidden; use --show-names)")
    out += ["", "Limitations:"] + [f"  - {x}" for x in lp.LIMITATIONS] + ["", NOT_AN_AUTH]
    return "\n".join(out)


def list_text(plans):
    out = ["Label plans", "  " + LOCAL_ONLY]
    if not plans:
        return "\n".join(out + ["", "No label plans."])
    out.append("")
    out += [f"  {p['plan_id']}  {p['state']:<9} {p['op_count']:>3} op(s)  hash {lp.short(p['plan_hash'])}  expires {p['expires_at']}" for p in plans]
    return "\n".join(out)
