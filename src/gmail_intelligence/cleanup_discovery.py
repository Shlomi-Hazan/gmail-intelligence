"""M12A: cleanup discovery. A read-only, metadata-only report that groups the messages the EXISTING M4A candidate engine already finds eligible, with counts, estimated volume and reasons.

It adds no cleanup policy: eligibility, protections (hard labels, user protection rules, unsafe data, unread/important/attention/AI/user-label review signals, mixed threads, partial index)
are exactly `cleanup_candidates.evaluate_all`; nothing here can make a message eligible or weaken a protection. M8 attention reaches this report only as that engine's existing
conservative review signal (ATTENTION_SIGNAL), and M9A subscription estimates are shown as INFERRED context beside a group and never change it. It never contacts Gmail, creates a plan,
writes anything or executes anything (planning and execution are the separate M12B-M12D). A group is a possibility for the owner to review, never a statement that its mail is unnecessary.
"""
import json
from collections import defaultdict
from datetime import datetime, timezone

from gmail_intelligence import analytics, cleanup_candidates as cc, subscriptions

DAY_MS = cc.DAY_MS
MAX_LIMIT = 100
DEFAULT_LIMIT, DEFAULT_MIN_GROUP = 20, 5
MAX_MIN_GROUP = 1000
MAX_MIN_AGE = 3650
CAUTION_ESTIMATE = "NOT_RECOMMENDED"   # an M9A estimate that rules a review out is shown as a caution beside the group


class ParameterError(ValueError):
    """A bad command-line parameter; its text is fixed (built from constants), so it is the only ValueError the command may print."""


def _params(limit, min_group, min_age_days):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ParameterError("--limit must be between 1 and %d" % MAX_LIMIT)
    if isinstance(min_group, bool) or not isinstance(min_group, int) or not 1 <= min_group <= MAX_MIN_GROUP:
        raise ParameterError("--min-group-size must be between 1 and %d" % MAX_MIN_GROUP)
    if isinstance(min_age_days, bool) or not isinstance(min_age_days, int) or not cc.MIN_AGE_DAYS <= min_age_days <= MAX_MIN_AGE:
        raise ParameterError("--min-age-days must be between %d and %d (you may only be stricter than the default)" % (cc.MIN_AGE_DAYS, MAX_MIN_AGE))


def _tally(rows):
    """{messages, bytes, unknown_size}: bytes counts only messages whose size is indexed."""
    return {"messages": len(rows), "bytes": sum(s for s in rows if s), "unknown_size": sum(1 for s in rows if not s)}


def _share(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


def compute(index, account, *, limit=DEFAULT_LIMIT, min_group=DEFAULT_MIN_GROUP, min_age_days=cc.MIN_AGE_DAYS, now=None):
    """The discovery report. `index` is any open index (a ReadOnlyIndex in the command); nothing is written. Raises ParameterError for a bad parameter."""
    _params(limit, min_group, min_age_days)
    now = now if now is not None else datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000)
    res = cc.evaluate_all(index, account, now_ms=now_ms, min_age_days=min_age_days)  # the ONE policy; raises nothing for the validated age
    s = res.summary
    sizes = {r["id"]: r["size"] for r in index._q("SELECT id, size FROM messages WHERE account=?", account)}

    groups = defaultdict(list)
    uncertain, protected, unsafe, not_applicable = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    n_unc, n_prot, n_unsafe, n_na, n_elig = [], [], [], [], []
    for d in res.decisions:
        size = sizes.get(d.message_id)
        if d.outcome == cc.ELIGIBLE:
            groups[analytics.clean(d.sender.rpartition("@")[2]) or "(unknown)"].append((d, size))
            n_elig.append(size)
            continue
        cats = {x.category for x in d.reasons}
        if d.outcome == cc.REVIEW:
            n_unc.append(size)
            for code in d.codes:
                uncertain[code].append(size)
        elif cc.HARD in cats:
            n_prot.append(size)
            for code in {x.code for x in d.reasons if x.category == cc.HARD}:
                protected[code].append(size)
        elif cc.DATA in cats:
            n_unsafe.append(size)
            for code in {x.code for x in d.reasons if x.category == cc.DATA}:
                unsafe[code].append(size)
        else:
            n_na.append(size)
            for code in {x.code for x in d.reasons if x.category == cc.NA}:
                not_applicable[code].append(size)

    context = {}
    if groups:
        try:  # M9A context only: INFERRED, never an input to eligibility
            sub = subscriptions.compute(index, account, show_all=True, limit=subscriptions.MAX_LIMIT, now=now)
            context = {i["group"]["display"]: i for i in sub["items"]}
        except subscriptions.ParameterError:
            context = {}

    rows = []
    for domain, members in groups.items():
        ds = [d for d, _ in members]
        evidence = defaultdict(int)
        for d in ds:
            for t, c, rid in d.evidence:
                evidence[(t, c, rid)] += 1
        ages = [d.age_days for d in ds if d.age_days is not None]
        item = {"domain": domain, "threads": len({d.thread_id for d in ds}), **_tally([sz for _, sz in members]),
                "oldest_days": max(ages) if ages else None, "newest_days": min(ages) if ages else None,
                "evidence": [{"type": t, "confidence": c, "rule": rid, "messages": n} for (t, c, rid), n in sorted(evidence.items(), key=lambda kv: (-kv[1], kv[0]))],
                "why": ["IN_INBOX", "NO_HARD_PROTECTION", "NOT_UNREAD_NOT_IMPORTANT", "NO_ATTENTION_SIGNAL", "CLASSIFIED_BY_RULE", "OLDER_THAN_%dD" % min_age_days],
                "subscription_review": None}
        m9 = context.get(domain)
        if m9:
            item["subscription_review"] = {"basis": "INFERRED", "estimate": m9["estimate"], "unsubscribe": m9["unsubscribe"]["status"],
                                           "caution": m9["estimate"] == CAUTION_ESTIMATE}
        rows.append(item)
    rows.sort(key=lambda r: (-r["messages"], -r["bytes"], r["domain"]))
    big = [r for r in rows if r["messages"] >= min_group]
    for i, r in enumerate(big, 1):
        r["rank"] = i
    small = [r for r in rows if r["messages"] < min_group]

    def reasons(table):
        return [{"code": k, **_tally(v)} for k, v in sorted(table.items(), key=lambda kv: (-len(kv[1]), kv[0]))]

    total = len(res.decisions)
    warnings = []
    if total == 0:
        warnings.append("INDEX_EMPTY")
    if s["index_state"] != "complete":
        warnings.append("INDEX_PARTIAL")
    if any(not sz for sz in n_elig):
        warnings.append("SOME_SIZES_UNKNOWN")
    if n_elig and not big:
        warnings.append("NO_GROUP_REACHES_MIN_SIZE")
    return {
        "policy": s["policy"], "reference_day": now.strftime("%Y-%m-%d"), "min_age_days": min_age_days, "min_group_size": min_group,
        "index": {"state": s["index_state"], "why": analytics.clean(s["index_why"], 200)},
        "protection": {"fingerprint": s["protection_fingerprint"], "active_user_rules": s["protection_rules_active"]},
        "totals": {"indexed": total, "eligible": {**_tally(n_elig), "share_pct": _share(len(n_elig), total)}, "uncertain": _tally(n_unc), "protected": _tally(n_prot),
                   "unsafe_data": _tally(n_unsafe), "not_applicable": _tally(n_na)},
        "groups_total": len(rows), "groups_shown": min(limit, len(big)), "groups": big[:limit],
        "below_min_group": {"groups": len(small), "messages": sum(r["messages"] for r in small), "bytes": sum(r["bytes"] for r in small)},
        "uncertain_reasons": reasons(uncertain), "protected_reasons": reasons(protected), "unsafe_data_reasons": reasons(unsafe), "not_applicable_reasons": reasons(not_applicable),
        "warnings": warnings,
        "explain": ["CANDIDATES_NOT_CERTAINTY", "SAME_POLICY_AS_CLEANUP_CANDIDATES", "PROTECTIONS_NEVER_WEAKENED", "ATTENTION_IS_CONSERVATIVE_PROTECTION",
                    "SUBSCRIPTION_CONTEXT_IS_INFERRED", "SIZES_ARE_INDEXED_ESTIMATES", "NOTHING_PLANNED_OR_CHANGED"],
        "mutations": 0, "read_only": True}


def as_json(res):
    return json.dumps(res, indent=2, sort_keys=True)


def _mb(n):
    return "%.1f MB" % (n / 1_000_000) if n >= 100_000 else "%d KB" % round(n / 1000)


def render_text(res):
    t = res["totals"]
    e = t["eligible"]
    out = ["cleanup discovery (local metadata only, read-only; nothing is planned, changed or sent; reference day %s)" % res["reference_day"],
           "policy %s (the same rules as `cleanup candidates`); index %s" % (res["policy"], res["index"]["state"]),
           "%d indexed: %d possible candidates (%s of mail), %d need your review, %d protected, %d unsafe or incomplete data, %d not applicable (not in inbox or too recent)." % (
               t["indexed"], e["messages"], "%s%%" % e["share_pct"], t["uncertain"]["messages"], t["protected"]["messages"], t["unsafe_data"]["messages"], t["not_applicable"]["messages"]),
           "these are possibilities to review, not statements that any mail is unnecessary; estimated volume %s%s (indexed sizes)." % (
               _mb(e["bytes"]), ", %d without a size" % e["unknown_size"] if e["unknown_size"] else "")]
    if res["warnings"]:
        out.append("warnings: " + ", ".join(w.lower() for w in res["warnings"]))
    if not res["groups"]:
        out.append("Nothing to show: no sender group reaches %d possible candidates." % res["min_group_size"])
    for g in res["groups"]:
        ev = ", ".join("%s/%s x%d" % (x["type"].lower(), x["confidence"].lower(), x["messages"]) for x in g["evidence"][:3])
        line = "  %d. %s | %d messages in %d threads, ~%s%s | %s to %s days old | classified by rule: %s" % (
            g["rank"], g["domain"], g["messages"], g["threads"], _mb(g["bytes"]), " (+%d unsized)" % g["unknown_size"] if g["unknown_size"] else "",
            g["newest_days"], g["oldest_days"], ev or "n/a")
        out.append(line)
        out.append("       why suggested: in inbox, read, older than %d days, no protection, no unread/important/attention signal, classified by a strong rule." % res["min_age_days"])
        m9 = g["subscription_review"]
        if m9:
            out.append("       subscription context (inferred, does not change this group): %s%s" % (m9["estimate"].lower(), "; CAUTION: that review rules this sender out" if m9["caution"] else ""))
    if res["below_min_group"]["groups"]:
        out.append("  (%d smaller group(s), %d messages, not listed)" % (res["below_min_group"]["groups"], res["below_min_group"]["messages"]))
    for title, key in (("needs review (uncertain; never a recommendation)", "uncertain_reasons"), ("protected", "protected_reasons")):
        if res[key]:
            out.append(title + ": " + ", ".join("%s %d" % (r["code"].lower(), r["messages"]) for r in res[key][:6]))
    out.append("next step, only if you choose: review these groups by hand; planning, approval and any execution are separate, separately approved steps.")
    return "\n".join(out)
