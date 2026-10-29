"""M11A: deterministic question answering over the local METADATA index. No model, no embeddings, no SQL generation: the question is untrusted text that is only ever matched against
a small allow-list of intents (keyword cues) and a few validated integer parameters; each intent calls one existing read-only report function (`analytics`, `subscriptions`).
The question is never echoed, executed, or used to build a query. Read-only, offline, stdlib only; the answer is a pure function of the index and the reference time.

An answer names its source (the index and the function that produced the figures), the period it covers, the index freshness, and separates OBSERVED figures (counted from
the index) from HEURISTIC conclusions (M3 classification, trend direction, M9A review estimates). Anything else gets a fixed UNSUPPORTED / AMBIGUOUS / INSUFFICIENT_EVIDENCE reply.
"""
import json
import re
from datetime import datetime, timezone

from gmail_intelligence import analytics, subscriptions

MAX_QUESTION = 300
DEFAULT_MONTHS, MAX_MONTHS = 12, 60
DEFAULT_TOP, MAX_TOP = 5, 20
TREND_BAND = 0.10          # unread totals within +-10% between the two halves of the window count as FLAT
ACTIONS = frozenset("delete remove trash archive unsubscribe label unlabel move mark send forward reply block spam create apply run execute drop select insert update".split())
INTENTS = ("TOTAL_MESSAGES", "MESSAGES_OVER_TIME", "TOP_SENDERS", "UNREAD", "CATEGORIES", "SUBSCRIPTIONS")
EXAMPLES = ("How many messages do I have?", "How many messages per month in the last 6 months?", "Which senders email me most?", "Top 10 sender addresses",
            "How many unread messages do I have?", "What is the unread trend over the last 12 months?", "What categories of mail do I get?", "How many subscriptions should I review?")
SUPPORTED = "Supported topics: message counts (total / per month), top senders, unread counts and trend, mail categories, subscription review statistics. Examples: " + " | ".join(EXAMPLES)
FIXED = {
    "UNSUPPORTED": "This question is not supported. Only the metadata questions listed here can be answered (no message content, subjects or actions). " + SUPPORTED,
    "AMBIGUOUS": "This question matches more than one topic; ask about one thing at a time. " + SUPPORTED,
    "PARAMETER": "A number in the question is out of range (months 1-%d, top 1-%d). " % (MAX_MONTHS, MAX_TOP) + SUPPORTED,
    "EMPTY_INDEX": "The local index holds no messages, so there is nothing to answer from. Run a scan first.",
    "NO_DATES": "No indexed message has a usable date, so no period can be answered.",
    "NO_CLASSIFICATION": "No message has a current classification, so categories cannot be answered. Classification has not run on the current rules.",
}


class ParameterError(ValueError):
    """A bad question argument; its text is fixed, so it is the only ValueError the command may print."""


def _tokens(question):
    if not isinstance(question, str) or not 1 <= len(question.strip()) <= MAX_QUESTION:
        raise ParameterError("the question must be 1 to %d characters" % MAX_QUESTION)
    return re.findall(r"[a-z0-9]+", question.lower())


def _intents(t):
    s = set(t)
    text = " ".join(t)
    if s & ACTIONS:  # an instruction, not a question: nothing here changes a mailbox or contacts anyone
        return []
    found = []
    if s & {"subscription", "subscriptions", "newsletter", "newsletters"}:
        found.append("SUBSCRIPTIONS")
    if s & {"sender", "senders", "domain", "domains", "address", "addresses"} or re.search(r"\bwho (emails|sends|mails|writes)\b", text):
        found.append("TOP_SENDERS")
    if s & {"category", "categories", "type", "types", "kind", "kinds"}:
        found.append("CATEGORIES")
    if "unread" in s:
        found.append("UNREAD")
    over_time = s & {"month", "months", "monthly", "year", "volume", "trend", "timeline"} or "over time" in text or "per month" in text or "each month" in text
    if over_time and "unread" not in s and not (set(found) - {"UNREAD"}):
        found.append("MESSAGES_OVER_TIME")
    if not found and re.search(r"\bhow many\b", text) and s & {"message", "messages", "email", "emails", "mail", "mails"}:
        found.append("TOTAL_MESSAGES")
    return found


def _numbers(t):
    """The two allow-listed integer parameters: 'last/past N months' and 'top N' / 'N senders'. Anything else is ignored; out of range is refused."""
    months = top = None
    for i, w in enumerate(t):
        if w.isdigit() and len(w) <= 6:
            n = int(w)
            prev, nxt = (t[i - 1] if i else ""), (t[i + 1] if i + 1 < len(t) else "")
            if nxt in ("month", "months") and prev in ("last", "past", "previous", "over", "in", "for", "the"):
                months = n
            elif prev == "top" or nxt in ("sender", "senders", "domain", "domains", "address", "addresses"):
                top = n
    if (months is not None and not 1 <= months <= MAX_MONTHS) or (top is not None and not 1 <= top <= MAX_TOP):
        return None
    return {"months": months, "top": top}


def _reply(status, now, an=None, **kw):
    out = {"status": status, "intent": kw.get("intent"), "parameters": kw.get("parameters", {}), "summary": kw.get("summary", FIXED.get(status, "")), "observations": kw.get("observations", []),
           "heuristics": kw.get("heuristics", []), "source": kw.get("source"), "reference_period": kw.get("period"), "freshness": None, "read_only": True}
    if an is not None:
        f = an.freshness_facts()
        out["freshness"] = {"as_of": f["as_of"], "age_days": f["age_days"], "index_state": f["state"], "health": f["health"], "issues": list(f["issues"]), "snapshot_not_live": True}
    out["reference_time"] = now.strftime("%Y-%m-%d")
    return out


def _window(points, months):
    return points[-months:] if months else points[-DEFAULT_MONTHS:]


def _period(points):
    return {"from": points[0]["period"], "to": points[-1]["period"], "months": len(points)} if points else None


def answer(index, account, question, *, reveal_senders=False, now=None):
    """Answer one allow-listed metadata question. Never raises for an unsupported question (it returns a fixed reply); raises ParameterError only for an invalid question string."""
    t = _tokens(question)
    now = now if now is not None else datetime.now(timezone.utc)
    found = _intents(t)
    if not found:
        return _reply("UNSUPPORTED", now)
    if len(found) > 1:
        return _reply("AMBIGUOUS", now)
    intent = found[0]
    nums = _numbers(t)
    if nums is None:
        return _reply("UNSUPPORTED", now, summary=FIXED["PARAMETER"], intent=intent)
    an = analytics.Analytics(index, account, now=now, reveal_senders=reveal_senders)
    ov = an.overview()["data"]
    if ov["messages"] == 0:
        return _reply("INSUFFICIENT_EVIDENCE", now, an, intent=intent, summary=FIXED["EMPTY_INDEX"])
    return _HANDLERS[intent](an, ov, nums, t, now)


def _total(an, ov, nums, t, now):
    obs = [{"fact": "messages_indexed", "value": ov["messages"]}, {"fact": "threads", "value": ov["threads"]}, {"fact": "oldest", "value": ov["oldest"]}, {"fact": "newest", "value": ov["newest"]}]
    return _reply("ANSWERED", now, an, intent="TOTAL_MESSAGES", observations=obs, period={"from": ov["oldest"], "to": ov["newest"]},
                  source={"index": "local metadata index", "function": "analytics.Analytics.overview", "aggregate": "COUNT of indexed messages"},
                  summary="%d message(s) in %d thread(s) are indexed, from %s to %s (a snapshot, not live)." % (ov["messages"], ov["threads"], ov["oldest"], ov["newest"]))


def _over_time(an, ov, nums, t, now):
    pts = an.volume()["data"]["points"]
    if not pts:
        return _reply("INSUFFICIENT_EVIDENCE", now, an, intent="MESSAGES_OVER_TIME", summary=FIXED["NO_DATES"])
    win = _window(pts, nums["months"])
    obs = [{"period": p["period"], "messages": p["messages"], "in_progress": p["in_progress"]} for p in win]
    return _reply("ANSWERED", now, an, intent="MESSAGES_OVER_TIME", parameters={"months": len(win)}, observations=obs, period=_period(win),
                  source={"index": "local metadata index", "function": "analytics.Analytics.volume", "aggregate": "COUNT of messages per month by message date"},
                  summary="%d message(s) over the last %d month(s) (%s to %s); the newest month may be incomplete." % (sum(p["messages"] for p in win), len(win), win[0]["period"], win[-1]["period"]))


def _top_senders(an, ov, nums, t, now):
    kind = "address" if set(t) & {"address", "addresses"} else "domain"
    top = nums["top"] or DEFAULT_TOP
    d = an.senders(kind=kind, limit=top)["data"]
    if not d["items"]:
        return _reply("INSUFFICIENT_EVIDENCE", now, an, intent="TOP_SENDERS", summary="No indexed message has a usable sender.")
    obs = [{"rank": i + 1, "sender": r["display"], "masked": r["masked"], "messages": r["messages"], "unread": r["unread"], "share_of_indexed_pct": r["share_of_indexed_pct"]} for i, r in enumerate(d["items"])]
    return _reply("ANSWERED", now, an, intent="TOP_SENDERS", parameters={"by": kind, "top": top}, observations=obs, period={"from": ov["oldest"], "to": ov["newest"]},
                  source={"index": "local metadata index", "function": "analytics.Analytics.senders", "aggregate": "COUNT of messages per sender " + kind},
                  summary="Top %d sender %s%s: %s." % (len(obs), kind + "s", " (addresses masked)" if kind == "address" and not an.reveal_senders else "",
                                                       "; ".join("%s %d" % (r["sender"], r["messages"]) for r in obs)))


def _unread(an, ov, nums, t, now):
    pts = an.volume()["data"]["points"]
    win = _window([p for p in pts if not p["in_progress"]], nums["months"])
    obs = [{"fact": "unread_now", "value": ov["unread"]}, {"fact": "messages_indexed", "value": ov["messages"]}, {"fact": "unread_share_pct", "value": ov["unread_share_pct"]}]
    heur, summary, period = [], "%d of %d indexed message(s) are unread (%s%%)." % (ov["unread"], ov["messages"], ov["unread_share_pct"]), None
    if len(win) >= 2:
        half = len(win) // 2
        first, last = sum(p["unread"] for p in win[:half]), sum(p["unread"] for p in win[-half:])
        direction = "FLAT" if first == last or abs(last - first) <= TREND_BAND * max(first, 1) else "UP" if last > first else "DOWN"
        obs += [{"period": p["period"], "messages": p["messages"], "unread": p["unread"]} for p in win]
        heur.append({"conclusion": "unread_direction", "value": direction, "basis": "unread still unread from messages of the last %d full month(s): earlier half %d, later half %d (+-%d%% counts as FLAT); the in-progress month is excluded" % (len(win), first, last, int(TREND_BAND * 100))})
        period = _period(win)
        summary += " Unread messages received %s to %s, earlier half vs later half: %d vs %d (%s, a heuristic)." % (win[0]["period"], win[-1]["period"], first, last, direction)
    else:
        summary += " Fewer than two full months are indexed, so no trend is given."
    return _reply("ANSWERED", now, an, intent="UNREAD", parameters={"months": len(win)}, observations=obs, heuristics=heur, period=period or {"from": ov["oldest"], "to": ov["newest"]},
                  source={"index": "local metadata index", "function": "analytics.Analytics.overview + volume", "aggregate": "COUNT of unread messages; unread per message month"}, summary=summary)


def _categories(an, ov, nums, t, now):
    d = an.categories()["data"]
    if d["classified"] == 0:
        return _reply("INSUFFICIENT_EVIDENCE", now, an, intent="CATEGORIES", summary=FIXED["NO_CLASSIFICATION"])
    shown = [r for r in d["types"] if r["messages"]]
    return _reply("ANSWERED", now, an, intent="CATEGORIES", heuristics=[{"type": r["type"], "messages": r["messages"], "share_of_indexed_pct": r["share_of_indexed_pct"]} for r in shown],
                  observations=[{"fact": "messages_indexed", "value": d["indexed"]}, {"fact": "classified", "value": d["classified"]}, {"fact": "unclassified", "value": d["unclassified"]}],
                  period={"from": ov["oldest"], "to": ov["newest"]},
                  source={"index": "local metadata index", "function": "analytics.Analytics.categories", "aggregate": "COUNT of messages per current M3 type (a message is counted once)"},
                  summary="%d of %d message(s) have a current classification (an inference by rule, not a fact): %s." % (d["classified"], d["indexed"], "; ".join("%s %d" % (r["type"].lower(), r["messages"]) for r in shown)))


def _subscriptions(an, ov, nums, t, now):
    r = subscriptions.compute(an.index, an.account, show_all=True, limit=subscriptions.MAX_LIMIT, now=now)
    tot = r["totals"]
    if tot["groups"] == 0:
        return _reply("INSUFFICIENT_EVIDENCE", now, an, intent="SUBSCRIPTIONS", summary="No sender group could be formed from the indexed metadata.")
    return _reply("ANSWERED", now, an, intent="SUBSCRIPTIONS", observations=[{"fact": "sender_domains_assessed", "value": tot["groups"]}, {"fact": "messages_indexed", "value": tot["indexed"]}],
                  heuristics=[{"conclusion": "worth_reviewing_by_hand", "value": tot["candidates"]}, {"conclusion": "ruled_out_by_protection_or_dormancy", "value": tot["not_recommended"]},
                              {"conclusion": "not_enough_evidence", "value": tot["not_enough_evidence"]}, {"conclusion": "weak", "value": tot["weak"]}],
                  period={"from": ov["oldest"], "to": ov["newest"]},
                  source={"index": "local metadata index", "function": "subscriptions.compute (M9A, by domain)", "aggregate": "heuristic review estimate per sender domain; thresholds in `mailbox subscriptions --json`"},
                  summary="Of %d sender domain(s), %d have enough evidence to be worth a manual look (a heuristic, not a statement that they are subscriptions); see `mailbox subscriptions` for the reasons. Nothing is unsubscribed or contacted." % (tot["groups"], tot["candidates"]))


_HANDLERS = {"TOTAL_MESSAGES": _total, "MESSAGES_OVER_TIME": _over_time, "TOP_SENDERS": _top_senders, "UNREAD": _unread, "CATEGORIES": _categories, "SUBSCRIPTIONS": _subscriptions}


def as_json(res):
    return json.dumps(res, indent=2, sort_keys=True)


def render_text(res):
    lines = [res["summary"]]
    if res["status"] == "ANSWERED":
        src, f = res["source"], res["freshness"]
        lines.append("source: %s (%s; %s)" % (src["index"], src["function"], src["aggregate"]))
        if res["reference_period"]:
            lines.append("period: " + " to ".join(str(v) for v in (res["reference_period"]["from"], res["reference_period"]["to"])))
        lines.append("freshness: index as of %s (%s days old), state %s, health %s; a snapshot, not live" % (f["as_of"] or "unknown", "?" if f["age_days"] is None else f["age_days"], f["index_state"], f["health"]))
        if res["heuristics"]:
            lines.append("heuristic conclusions (inferred, not facts) are marked in the summary; all figures: --json")
    elif res["status"] == "INSUFFICIENT_EVIDENCE" and res["freshness"]:
        lines.append("freshness: index state %s, health %s" % (res["freshness"]["index_state"], res["freshness"]["health"]))
    return "\n".join(lines)
