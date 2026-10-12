"""Privacy-safe text output for M4B plans and approvals. Local only. The account is never printed; message ids appear only
in the explicit target views a reviewer asks for."""
from gmail_intelligence import cleanup_candidates as cc, cleanup_plans as cp, cleanup_protect

NOT_AN_AUTH = ("An approval is a LOCAL record only. It grants no Gmail permission and nothing can be executed in this version "
               "(execution requires the later M4C milestone and a separate owner approval).")
_BUCKETS = ((90, "<90d"), (180, "90-180d"), (365, "180-365d"), (10**9, ">365d"))


def _age(days):
    return "n/a" if days is None else next(label for limit, label in _BUCKETS if days < limit)


def plan_list_text(plans):
    out = [f"Cleanup plans for {cleanup_protect.HIDDEN_ACCOUNT}"]
    for p in plans:
        out.append(f"  {p['plan_id']:<15} v{p['version']:<3}{p['state']:<11}{p['item_count']:>5} items  hash {cp.short(p['plan_hash'])}"
                   f"  expires {p['expires_at']}" + (f"  (revises {p['parent_id']})" if p["parent_id"] else ""))
    return "\n".join(out + (["  (none)"] if not plans else []))


def summary(plan, decisions):
    ev, ages = {}, {}
    for i in plan["items"]:
        d = decisions.get(i["message_id"])
        if d is None:
            continue
        for t, c, rid in d.evidence:
            ev[(t, c, rid)] = ev.get((t, c, rid), 0) + 1
        ages[_age(d.age_days)] = ages.get(_age(d.age_days), 0) + 1
    return ev, ages


def plan_show_text(plan, problems, decisions, approvals, page=None, page_size=cp.PAGE_SIZE, show_ids=False):
    snap = cp.snapshot_of(plan)
    out = [f"Plan {plan['plan_id']} (version {plan['version']}" + (f", revises {plan['parent_id']}" if plan["parent_id"] else "") + ")",
           f"  account: {cleanup_protect.HIDDEN_ACCOUNT}   action: {plan['action']}   targets: {plan['item_count']}   state: {plan['state']}",
           f"  plan hash: {cp.short(plan['plan_hash'])}... (SHA-256 {plan['plan_hash']})",
           f"  created {plan['created_at']}   expires {plan['expires_at']}" + (f"   reviewed {plan['reviewed_at']}" if plan["reviewed_at"] else ""),
           f"  policy: cleanup v{snap['policy']['cleanup_policy']}, archive >= {snap['policy']['min_age_days']} days; "
           f"message-level only (no thread expansion)"]
    if plan["state"] in cp.TERMINAL:
        out.append(f"  This plan is {plan['state']} and can no longer be reviewed or approved.")
    elif problems:
        out.append("  FRESHNESS: STALE - " + cp._describe(problems) + ". It cannot be reviewed or approved; create a new plan.")
    else:
        out.append("  FRESHNESS: fresh against the LOCAL index (this cannot see mailbox changes after the last scan).")
    if decisions:
        ev, ages = summary(plan, decisions)
        out += ["  targets by approving evidence:"] + [f"    {t:<12}{c:<8}{rid:<26}{n:>6}" for (t, c, rid), n in sorted(ev.items())]
        out += ["  targets by age:"] + [f"    {k:<10}{n:>6}" for k, n in sorted(ages.items())]
    for a in approvals["approvals"]:
        out.append(f"  approval {a['nonce']}: {a['status']} (created {a['created_at']}, expires {a['expires_at']})")
    if page is not None:
        pages = max(1, -(-plan["item_count"] // page_size))
        if not 1 <= page <= pages:
            out.append(f"  page {page} does not exist (1-{pages})")
        else:
            out.append(f"  targets, page {page}/{pages}:")
            chunk = plan["items"][(page - 1) * page_size:page * page_size]
            out += [f"    {(page - 1) * page_size + n:>4}. " + (i["message_id"] if show_ids else "(id hidden; use --show-ids)")
                    for n, i in enumerate(chunk, 1)]
    out += ["", NOT_AN_AUTH]
    return "\n".join(out)
