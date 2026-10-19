"""Plain-text and JSON rendering of the M6A analytics. LOCAL ONLY. Text is English; the dashboard localizes the same stable codes itself."""
import json

LOCAL_ONLY = "LOCAL ONLY — read-only analytics of the local index; no Gmail access."


def as_json(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _fmt(n):
    return f"{n:,}"


def _head(env):
    idx = env["index"]
    age = "unknown" if idx["age_days"] is None else f"{idx['age_days']} day(s) old"
    return [f"{env['section']}  [{env['basis']}]", f"  as of {env['as_of'] or 'no completed scan'} ({age}); index {idx['state'].upper()}; health {idx['health']}"]


def _rows(pairs):
    return [f"  {k}: {v}" for k, v in pairs]


def section_text(env):
    d, name = env["data"], env["section"]
    out = _head(env)
    if name == "freshness":
        c = d["classification"]
        out += _rows([("index", f"{d['state']} - {d['why']}"), ("last full scan", d["last_full_scan"] or "none"), ("issues", ", ".join(d["issues"]) or "none"),
                      ("classification", f"{_fmt(c['current'])} current, {_fmt(c['stale'])} stale, {_fmt(c['unclassified'])} unclassified of {_fmt(c['indexed'])}")])
    elif name == "overview":
        out += _rows([("messages", _fmt(d["messages"])), ("threads", _fmt(d["threads"])), ("unread", f"{_fmt(d['unread'])} ({d['unread_share_pct']}%)"), ("in inbox", _fmt(d["in_inbox"])),
                      ("size", f"{d['size_bytes'] / 1e6:,.1f} MB"), ("range", f"{d['oldest']} .. {d['newest']}"), ("user labels", d["user_labels"]),
                      ("classified (current)", f"{_fmt(d['classified'])} ({d['classified_share_pct']}%)"), ("attention", ", ".join(f"{k}={v}" for k, v in d["attention"].items()))])
    elif name == "volume":
        out += _rows([("months", len(d["points"])), ("peak month", d["peak"] or "-"), ("undated messages", d["undated"])])
        out += [f"  {p['period']}  {_fmt(p['messages']):>8}  unread {_fmt(p['unread'])}" + ("  (month in progress)" if p["in_progress"] else "") for p in d["points"][-12:]]
    elif name == "categories":
        out += _rows([("indexed", _fmt(d["indexed"])), ("classified", _fmt(d["classified"])), ("unclassified", _fmt(d["unclassified"])), ("multi-type messages", d["multi_type_messages"])])
        out += [f"  {t['type']:<24} {_fmt(t['messages']):>8}  {t['share_of_indexed_pct']}% of indexed" for t in d["types"]]
    elif name == "senders":
        out += _rows([("kind", d["kind"]), ("distinct", _fmt(d["distinct"])), ("addresses revealed", d["addresses_revealed"])])
        out += [f"  {i['display']:<40} {_fmt(i['messages']):>7}  {i['share_of_indexed_pct']}%  {i['dominant_type']}" for i in d["items"]]
    elif name == "subscriptions":
        for t in d["types"]:
            out.append(f"  {t['type']}: {_fmt(t['messages'])} messages ({t['share_of_indexed_pct']}% of indexed) from {_fmt(t['domains'])} domain(s)")
            out += [f"      {x['domain']:<36} {_fmt(x['messages']):>7}  last seen {x['last_seen']}" for x in t["top_domains"][:5]]
    elif name == "cleanup-summary":
        out += _rows([(k, _fmt(v)) for k, v in d["outcomes"].items()] + [("protection rules active", d["protection_rules_active"]), ("min age (days)", d["min_age_days"])])
        out += ["  Recommendations only: nothing is applied by this report."]
    elif name == "cleanup-history":
        a = d["audit"]
        out += _rows([("plans", sum(d["plan_states"].values())), ("plan states", d["plan_states"]), ("approvals", d["approvals"]), ("executions", len(d["executions"])),
                      ("items recorded as applied", d["items_applied"]), ("audit events", a["events"]), ("audit chain", "OK" if a["chain_ok"] else f"BROKEN at {a['first_bad_seq']}")])
    elif name == "organization":
        out += _rows([("labels", d["labels"]), ("hygiene findings", d["hygiene"]["findings"]), ("recommendations", d["recommendations"]["total"]),
                      ("rule proposals", d["rule_proposals"]["total"]), ("filter suggestions", d["filter_suggestions"]["total"]), ("label plans", d["label_plans"])])
    out.append("  explains: " + ", ".join(env["explain"]))
    return "\n".join(out)


def text(envs):
    return "\n\n".join([LOCAL_ONLY] + [section_text(e) for e in envs])
