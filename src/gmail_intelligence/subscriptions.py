"""M9A: subscription intelligence from METADATA ONLY: which senders look like low-value subscriptions, for the owner to review BY HAND. Read-only, offline, stdlib only.

What it reads: the sender (address or domain), the unread flag, the received date, the STARRED/SENT labels and the existing M3 classification (the same grouping and types the dashboard
and `mailbox top-senders` use). What it never does: contact a sender, open a link, send an unsubscribe request, write anything, invent an unsubscribe address, or assume that a header
exists (no header is indexed; recognising List-Unsubscribe is the separate, header-gated M9B). Every finding separates OBSERVED evidence (counts and dates from the index) from INFERRED
evidence (the M3 type, a heuristic) and is a possibility, never a statement that a sender is a subscription or that the owner wants to leave it.
The thresholds are plain constants (heuristics, not validated on a real mailbox); the result is a pure function of the index and the reference time (deterministic).
"""
import json
from datetime import datetime, timedelta, timezone

from gmail_intelligence import analytics, classify

DAY_MS = 86_400_000
MIN_MESSAGES = 5            # a group with fewer messages is "not enough evidence"
MIN_SPAN_DAYS = 14          # ... and so is a group seen over less than two weeks (no frequency can be estimated)
BULK_TYPES = ("NEWSLETTER", "PROMOTIONAL", "AUTOMATED_NOTIFICATION", "SOCIAL")  # M3 types that look like bulk or list mail
BULK_SHARE = 0.5            # the bulk types must account for at least this share of the group's messages
UNREAD_HIGH, UNREAD_MEDIUM = 0.8, 0.6
STALE_UNREAD_DAYS = 30      # an unread message older than this counts as left unread
REGULAR_PER_30_DAYS = 2.0   # at least this many messages per 30 days looks regular
STILL_ARRIVING_DAYS = 90    # the last message is at most this old
DORMANT_DAYS = 180          # nothing for this long: reviewing it would not help
STRONG_POINTS, MODERATE_POINTS = 4, 2
BLOCKING_LABELS = ("STARRED", "SENT")
BY = ("domain", "address")
MAX_LIMIT = 100
UNRECOGNISED = "UNRECOGNISED"

ESTIMATES = ("STRONGER_EVIDENCE", "MODERATE_EVIDENCE", "WEAK_EVIDENCE", "NOT_ENOUGH_EVIDENCE", "NOT_RECOMMENDED")  # NOT_RECOMMENDED: a protection or dormancy rules a review out


class ParameterError(ValueError):
    """A bad command-line parameter; its text is fixed (built from constants), so it is the only ValueError the command may print."""


def _params(by, limit, min_messages):
    if by not in BY:
        raise ParameterError("--by must be one of: " + ", ".join(BY))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ParameterError(f"--limit must be between 1 and {MAX_LIMIT}")
    if isinstance(min_messages, bool) or not isinstance(min_messages, int) or not 2 <= min_messages <= 1000:
        raise ParameterError("--min-messages must be between 2 and 1000")


def _round(x, digits=2):
    return round(x + 0.0, digits)


def _evaluate(g, now_ms, min_messages):
    """The deterministic assessment of one group from its aggregates `g`. Returns (estimate, points, signals, blockers, notes)."""
    signals, blockers = [], []
    n, unread = g["n"], g["unread"]
    ratio = unread / n if n else 0.0
    span_days = (g["hi"] - g["lo"]) / DAY_MS if g["lo"] is not None and g["hi"] is not None else 0.0
    per_30 = n / span_days * 30 if span_days >= MIN_SPAN_DAYS else None
    since_last = (now_ms - g["hi"]) / DAY_MS if g["hi"] is not None else None
    signals.append(("VOLUME", "OBSERVED", {"messages": n}))
    signals.append(("UNREAD_RATIO", "OBSERVED", {"unread": unread, "messages": n, "ratio": _round(ratio)}))
    if g["oldest_unread_ms"] is not None:
        signals.append(("OLDEST_UNREAD", "OBSERVED", {"days": max(int((now_ms - g["oldest_unread_ms"]) // DAY_MS), 0)}))
    if per_30 is not None:
        signals.append(("FREQUENCY", "OBSERVED", {"per_30_days": _round(per_30), "span_days": int(span_days)}))
    signals.append(("TREND", "OBSERVED", {"last_90_days": g["recent"], "previous_90_days": g["previous"]}))
    bulk = sum(g["types"].get(t, 0) for t in BULK_TYPES)
    classified = sum(c for t, c in g["types"].items() if t != analytics.UNCLASSIFIED)
    dominant = None
    if g["types"]:
        dominant = sorted(g["types"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    bulk_share = bulk / n if n else 0.0
    signals.append(("DOMINANT_TYPE", "INFERRED", {"type": dominant if dominant in (*classify.TYPES, analytics.UNCLASSIFIED) else UNRECOGNISED, "classified": classified}))
    if g["starred"]:
        blockers.append(("STARRED_MESSAGE", "OBSERVED", {"messages": g["starred"]}))
    if g["sent"]:
        blockers.append(("SENT_MESSAGE", "OBSERVED", {"messages": g["sent"]}))
    if g["types"].get("PERSONAL", 0):
        blockers.append(("PERSONAL_MAIL_PRESENT", "INFERRED", {"messages": g["types"]["PERSONAL"]}))
    if since_last is not None and since_last > DORMANT_DAYS:
        blockers.append(("DORMANT", "OBSERVED", {"days_since_last": int(since_last)}))
    if n < min_messages or span_days < MIN_SPAN_DAYS:
        return "NOT_ENOUGH_EVIDENCE", 0, signals, blockers + [("INSUFFICIENT_HISTORY", "OBSERVED", {"messages": n, "span_days": int(span_days)})]
    if blockers:
        return "NOT_RECOMMENDED", 0, signals, blockers
    if bulk_share < BULK_SHARE:
        return "NOT_ENOUGH_EVIDENCE", 0, signals, [("NO_BULK_TYPE_EVIDENCE", "INFERRED", {"bulk_share": _round(bulk_share)})]
    points = 0
    support = [("BULK_TYPE", "INFERRED", {"share": _round(bulk_share)})]
    if ratio >= UNREAD_HIGH:
        points += 2
        support.append(("HIGH_UNREAD_RATIO", "OBSERVED", {"ratio": _round(ratio)}))
    elif ratio >= UNREAD_MEDIUM:
        points += 1
        support.append(("MEDIUM_UNREAD_RATIO", "OBSERVED", {"ratio": _round(ratio)}))
    old_unread = g["old_unread"]
    if unread and old_unread / unread >= 0.5:
        points += 1
        support.append(("UNREAD_LEFT_OLD", "OBSERVED", {"older_than_days": STALE_UNREAD_DAYS, "unread_messages": old_unread}))
    if per_30 is not None and per_30 >= REGULAR_PER_30_DAYS:
        points += 1
        support.append(("REGULAR_FREQUENCY", "OBSERVED", {"per_30_days": _round(per_30)}))
    if since_last is not None and since_last <= STILL_ARRIVING_DAYS:
        points += 1
        support.append(("STILL_ARRIVING", "OBSERVED", {"days_since_last": int(since_last)}))
    # Reading what arrives is engagement: without a clearly low read rate nothing is recommended, however regular the mail is.
    estimate = "WEAK_EVIDENCE" if ratio < UNREAD_MEDIUM else "STRONGER_EVIDENCE" if points >= STRONG_POINTS else "MODERATE_EVIDENCE" if points >= MODERATE_POINTS else "WEAK_EVIDENCE"
    return estimate, points, signals + support, blockers


def compute(index, account, *, by="domain", limit=20, min_messages=MIN_MESSAGES, show_all=False, reveal_senders=False, now=None):
    """The subscription review list. `index` is any open index (a ReadOnlyIndex in the command); nothing is written. Raises ParameterError for a bad parameter."""
    _params(by, limit, min_messages)
    now = now if now is not None else datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000)
    an = analytics.Analytics(index, account, now=now, reveal_senders=reveal_senders)
    an._load()
    blocking = {}
    for r in index._q("SELECT message_id, label_id FROM message_labels WHERE account=? AND label_id IN (?, ?)", account, *BLOCKING_LABELS):
        blocking.setdefault(r["message_id"], set()).add(r["label_id"])
    stale_ms = now_ms - STALE_UNREAD_DAYS * DAY_MS
    groups = {}
    for r in an._rows:
        sender = (r["sender"] or "").strip().lower()
        if not sender or "@" not in sender:
            continue
        key = analytics._domain(sender) if by == "domain" else sender
        g = groups.setdefault(key, {"n": 0, "unread": 0, "lo": None, "hi": None, "types": {}, "oldest_unread_ms": None, "old_unread": 0, "recent": 0, "previous": 0, "starred": 0, "sent": 0})
        g["n"] += 1
        bucket = an._bucket(r["id"])
        g["types"][bucket] = g["types"].get(bucket, 0) + 1
        labels = blocking.get(r["id"], ())
        g["starred"] += "STARRED" in labels
        g["sent"] += "SENT" in labels
        g["unread"] += bool(r["unread"])
        ms = r["internal_ms"]
        if isinstance(ms, bool) or not isinstance(ms, (int, float)):
            continue  # an undated message still counts above, it just has no age
        g["lo"] = ms if g["lo"] is None else min(g["lo"], ms)
        g["hi"] = ms if g["hi"] is None else max(g["hi"], ms)
        age_days = (now_ms - ms) / DAY_MS
        g["recent"] += 0 <= age_days <= 90
        g["previous"] += 90 < age_days <= 180
        if r["unread"]:
            g["oldest_unread_ms"] = ms if g["oldest_unread_ms"] is None else min(g["oldest_unread_ms"], ms)
            g["old_unread"] += ms < stale_ms
    rows = []
    for key, g in groups.items():
        estimate, points, signals, blockers = _evaluate(g, now_ms, min_messages)
        rows.append((key, g, estimate, points, signals, blockers))
    shown = [x for x in rows if show_all or x[2] in ("STRONGER_EVIDENCE", "MODERATE_EVIDENCE")]
    shown.sort(key=lambda x: (-x[3], -x[1]["unread"], -x[1]["n"], x[0]))
    items = []
    for rank, (key, g, estimate, points, signals, blockers) in enumerate(shown[:limit], 1):
        reviewable = estimate in ("STRONGER_EVIDENCE", "MODERATE_EVIDENCE")
        display = analytics.clean(key) if by == "domain" or reveal_senders else analytics.mask_address(key)
        items.append({"rank": rank, "group": {"by": by, "display": display, "masked": by == "address" and not reveal_senders},
                      "estimate": estimate, "points": points, "messages": g["n"], "unread": g["unread"],
                      "first_seen": analytics._day(g["lo"]), "last_seen": analytics._day(g["hi"]),
                      "signals": [{"code": c, "basis": b, "detail": d} for c, b, d in signals], "blockers": [{"code": c, "basis": b, "detail": d} for c, b, d in blockers],
                      "recommendation": "REVIEW_MANUALLY" if reviewable else "NONE",
                      "unsubscribe": {"status": "NOT_CHECKED", "reason": "NO_HEADERS_INDEXED"}})
    totals = {"groups": len(rows), "candidates": sum(1 for x in rows if x[2] in ("STRONGER_EVIDENCE", "MODERATE_EVIDENCE")),
              "not_recommended": sum(1 for x in rows if x[2] == "NOT_RECOMMENDED"), "not_enough_evidence": sum(1 for x in rows if x[2] == "NOT_ENOUGH_EVIDENCE"),
              "weak": sum(1 for x in rows if x[2] == "WEAK_EVIDENCE"), "shown": len(items), "indexed": len(an._rows)}
    facts = an.freshness_facts()
    warnings = []
    for issue, code in (("EMPTY", "INDEX_EMPTY"), ("PARTIAL", "INDEX_PARTIAL"), ("STALE", "SCAN_STALE"), ("CLASSIFICATION_STALE", "CLASSIFICATION_STALE"), ("UNCLASSIFIED", "UNCLASSIFIED")):
        if issue in facts["issues"]:
            warnings.append(code)
    if not facts["sync"]["healthy"]:
        warnings.append("SYNC_NOT_HEALTHY")
    return {"section": "subscriptions", "params": {"by": by, "limit": limit, "min_messages": min_messages, "all": bool(show_all)}, "reference_day": now.astimezone(timezone.utc).date().isoformat(),
            "thresholds": {"min_messages": min_messages, "min_span_days": MIN_SPAN_DAYS, "unread_high": UNREAD_HIGH, "unread_medium": UNREAD_MEDIUM, "stale_unread_days": STALE_UNREAD_DAYS,
                           "regular_per_30_days": REGULAR_PER_30_DAYS, "still_arriving_days": STILL_ARRIVING_DAYS, "dormant_days": DORMANT_DAYS},
            "totals": totals, "warnings": warnings, "freshness": {"as_of": facts["as_of"], "sync_state": facts["sync"]["state"]}, "items": items,
            "explain": ["POSSIBLE_NOT_CERTAIN", "METADATA_ONLY", "HEURISTIC_THRESHOLDS", "NO_UNSUBSCRIBE_DATA", "NOTHING_IS_SENT_OR_VISITED", "REVIEW_BY_HAND"]}


def as_json(result):
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True)


def _detail(d):
    return ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in d.items())


def render_text(result):
    t = result["totals"]
    out = [f"Subscription review (possible low-value senders, by {result['params']['by']}; metadata only, read-only, nothing is sent or visited; reference day {result['reference_day']})",
           f"{t['groups']} group(s) in {t['indexed']} indexed message(s): {t['candidates']} with enough evidence to review, {t['not_recommended']} ruled out by a protection or dormancy, {t['not_enough_evidence']} without enough evidence, "
           f"{t['weak']} weak. Showing {t['shown']}.",
           "These are possibilities from counts and dates, not statements that a sender is a subscription or that you want to leave it. Heuristic thresholds, not validated on a real mailbox."]
    if result["warnings"]:
        out.append("Warnings (the list may be out of date or incomplete): " + ", ".join(result["warnings"]))
    for it in result["items"]:
        out.append(f"{it['rank']:>3}. [{it['estimate']} {it['points']}] {it['group']['display']} | {it['messages']} messages, {it['unread']} unread | {it['first_seen'] or '?'} to {it['last_seen'] or '?'}")
        for s in it["signals"]:
            out.append(f"       {s['basis']:<8} {s['code']}: {_detail(s['detail'])}")
        for b in it["blockers"]:
            out.append(f"       {b['basis']:<8} NOT A CANDIDATE / NOTE {b['code']}: {_detail(b['detail'])}")
        if it["recommendation"] == "REVIEW_MANUALLY":
            out.append("       Manual review: open one of these messages in Gmail yourself and look for an unsubscribe option. Unsubscribe data: NOT CHECKED (no header is indexed).")
    if not result["items"]:
        out.append("Nothing to show. (The absence of a finding proves nothing.)")
    return "\n".join(out)
