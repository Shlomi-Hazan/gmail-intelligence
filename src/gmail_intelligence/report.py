"""Text reports built from the local index only (never contacts Gmail)."""
from datetime import datetime, timezone

CATEGORIES = {"CATEGORY_PERSONAL": "Personal", "CATEGORY_SOCIAL": "Social", "CATEGORY_PROMOTIONS": "Promotions",
              "CATEGORY_UPDATES": "Updates", "CATEGORY_FORUMS": "Forums"}


def _date(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d") if ms else "n/a"


def _mb(n):
    return f"{n / 1_000_000:,.1f} MB"


def completeness(index, account):
    """('complete'|'partial'|'empty', explanation)."""
    scans = index.recent_scans(account, 50)
    n = index.overview(account)["n"]
    if n == 0 and not scans:
        return "empty", "no scan has been run"
    full_ok = next((s for s in scans if s["mode"] == "full" and s["status"] == "completed"), None)
    latest = scans[0] if scans else None
    if full_ok and latest and latest["mode"] == "full" and latest["status"] != "completed":
        return "partial", f"a newer full scan is {latest['status']}; data may be stale"
    if full_ok:
        return "complete", f"last full scan completed {full_ok['finished_at']}"
    return "partial", "no complete full scan yet (limited, interrupted or incomplete scans only)"


def status_text(index, account):
    state, why = completeness(index, account)
    ov = index.overview(account)
    lines = [f"Account: {account}", f"Index: {index.path}", f"Indexed messages: {ov['n']:,}",
             f"Index state: {state.upper()} - {why}"]
    scans = index.recent_scans(account, 3)
    for s in scans:
        lines.append(f"  scan {s['id']} [{s['mode']}] {s['status']} started {s['started_at']}"
                     f" listed={s['listed']:,} indexed={s['indexed']:,} vanished={s['vanished']} failed={s['failed']}"
                     + (f" pruned={s['pruned']}" if s["pruned"] else "") + (f" ({s['error']})" if s["error"] else ""))
    if not scans:
        lines.append("  no scans yet. First run: mailbox scan --limit 100")
    return "\n".join(lines)


def report_text(index, account):
    state, why = completeness(index, account)
    ov = index.overview(account)
    out = [f"Mailbox report for {account} (local index only; Gmail was not contacted)",
           f"Index state: {state.upper()} - {why}"]
    if state != "complete":
        out.append("WARNING: this is a PARTIAL view; counts do not describe the whole mailbox.")
    if ov["n"] == 0:
        return "\n".join(out + ["No messages indexed."])
    read = ov["n"] - ov["u"]
    out += ["", "Overview",
            f"  messages: {ov['n']:,}   threads represented: {ov['t']:,}   (messages != threads)",
            f"  unread: {ov['u']:,}   read: {read:,}",
            f"  size estimate: {_mb(ov['sz'])} (sum of Gmail sizeEstimate; NOT your account storage usage)",
            f"  oldest: {_date(ov['lo'])}   newest: {_date(ov['hi'])}"]
    labels = index.label_counts(account)
    cats = {l["id"]: l["n"] for l in labels}
    out += ["", "Categories (messages without a category tag are not listed)"]
    out += [f"  {name:<11}{cats.get(k, 0):>9,}" for k, name in CATEGORIES.items()]
    sysl = [l for l in labels if l["id"] not in CATEGORIES and l["type"] != "user" and not l["id"].startswith("Label_")]
    usrl = [l for l in labels if l["type"] == "user" or l["id"].startswith("Label_")]
    out += ["", "Labels (a message can carry several labels, so these totals can exceed the message count)",
            "  system:"] + [f"    {l['id']:<22}{l['n']:>9,}" for l in sysl[:15]]
    out += ["  user:"] + ([f"    {(l['name'] or l['id'])[:30]:<32}{l['n']:>9,}" for l in usrl[:15]] or ["    (none)"])
    years = index.by_period(account, "%Y")
    out += ["", "Messages by year"] + [f"  {p}{n:>10,}" for p, n in years]
    months = index.by_period(account, "%Y-%m")[-12:]
    out += ["", "Messages by month (last 12 months present)"] + [f"  {p}{n:>10,}" for p, n in months]
    out += ["", "Top sender domains (use `mailbox top-senders` for addresses)"]
    out += [f"  {r['who'][:40]:<42}{r['n']:>8,}  unread {r['unread']:,}" for r in index.top_senders(account, 5, domains=True)]
    out += ["", "Counts only describe the index. Nothing here is a recommendation to delete anything."]
    return "\n".join(out)


def senders_text(index, account, limit, unread_only, domains):
    rows = index.top_senders(account, limit, unread_only, domains)
    kind = "domains" if domains else "addresses"
    state, _ = completeness(index, account)
    out = [f"Top sender {kind}{' (unread only)' if unread_only else ''} - index state: {state.upper()}"]
    out += [f"  {r['n']:>7,}  unread {r['unread']:>6,}  {_mb(r['size']):>10}  {r['who']}" for r in rows]
    return "\n".join(out or ["  (none)"])
