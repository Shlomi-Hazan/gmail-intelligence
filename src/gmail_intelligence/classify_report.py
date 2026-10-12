"""Text output for classification (M3). Local index only. No sender addresses unless explicitly requested."""
from gmail_intelligence import ai, classifier, classify, report

_CONF = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}
_NOTE = ("Confidence labels describe rule evidence strength, not probabilities. Classification is local metadata "
         "triage only; it is never a recommendation to delete, archive or label anything.")


def status_text(index, account):
    state, why = report.completeness(index, account)
    c = classifier.counts(index, account)
    rules = classifier.rule_rows(index, account)
    out = [f"Account: {account}", f"Index state: {state.upper()} - {why}",
           f"Indexed messages: {c['indexed']:,}",
           f"  classified (current): {c['current']:,}",
           f"  stale (rules changed or message rescanned since): {c['stale']:,}",
           f"  not yet classified: {c['unclassified']:,}",
           f"User rules: {sum(r['enabled'] for r in rules)} enabled, {sum(not r['enabled'] for r in rules)} disabled "
           f"(+ {len(classify.BUILTIN_RULES)} built-in)"]
    try:
        cfg = ai.load_config()
        out.append("Local AI: " + ("configured (loopback only; used only with `classify run --ai`)" if cfg["enabled"]
                                   else "disabled (" + cfg["reason"] + ")"))
    except ai.AiError as exc:
        out.append(f"Local AI: configuration problem - {exc}")
    if state != "complete":
        out.append("WARNING: the index is PARTIAL, so classification covers only the indexed messages.")
    if c["indexed"] and (c["stale"] or c["unclassified"]):
        out.append("Next: classify preview --limit 100   then   classify run --limit 100")
    return "\n".join(out)


def summary_text(s, title):
    out = [title, f"  selected: {s['selected']:,}   classified: {s['classified']:,}   "
                  f"weak/unknown only: {s['weak']:,}"]
    out += ["  types:"] + _rows(s["types"])
    if s["attention"]:
        out += ["  attention signals:"] + _rows(s["attention"])
    out += ["  by rule:"] + _rows(s["rules"])
    if s["ai_asked"]:
        out.append(f"  local AI: asked {s['ai_asked']:,}, added {s['ai_added']:,}, invalid {s['ai_invalid']:,}")
    return "\n".join(out)


def _rows(d):
    return [f"    {k:<26}{n:>8,}" for k, n in sorted(d.items(), key=lambda x: (-x[1], x[0]))] or ["    (none)"]


def report_text(index, account, show_senders=False):
    state, why = report.completeness(index, account)
    c = classifier.counts(index, account)
    out = [f"Classification report for {account} (local index only; Gmail was not contacted)",
           f"Index state: {state.upper()} - {why}"]
    if state != "complete":
        out.append("WARNING: PARTIAL index; these numbers do not describe the whole mailbox.")
    out += ["", f"Indexed {c['indexed']:,} | classified (current) {c['current']:,} | stale {c['stale']:,} | "
                f"not classified {c['unclassified']:,}"]
    if c["stale"] or c["unclassified"]:
        out.append("Not every indexed message has a current result. Unclassified/stale messages are not counted below "
                   "as understood.")
    types = classifier.distribution(index, account, "type")
    out += ["", "Message types (a message can have several; totals can exceed the message count)"]
    out += [f"  {k:<24}{n:>9,}   strongest evidence: {_CONF[cf]}" for k, (n, cf) in types.items()] or ["  (none)"]
    att = classifier.distribution(index, account, "attention")
    out += ["", "Attention signals (separate from type; a prompt to look, not a verdict)"]
    out += [f"  {k:<24}{n:>9,}   strongest evidence: {_CONF[cf]}" for k, (n, cf) in att.items()] or ["  (none)"]
    out += ["", "Results by rule (which rule produced which result)"]
    rows = index._q("SELECT rule_id, kind, value, source, confidence, COUNT(*) n FROM message_class WHERE account=? "
                    "GROUP BY rule_id, kind, value, source, confidence ORDER BY n DESC, rule_id, value", account)
    out += [f"  {r['rule_id']:<26}{r['kind']}:{r['value']:<24}{r['confidence']:<7}{r['source']:<6}{r['n']:>8,}"
            for r in rows] or ["  (none)"]
    out += ["", "Unknown / weak-evidence groups (sender domains; use --show-senders for addresses)"]
    key = "m.sender" if show_senders else "COALESCE(substr(m.sender, instr(m.sender,'@')+1), '(unknown)')"
    groups = index._q(f"SELECT {key} who, COUNT(*) n FROM message_class c JOIN messages m ON m.account=c.account "
                      "AND m.id=c.message_id WHERE c.account=? AND c.kind='type' AND c.value='UNKNOWN' "
                      "GROUP BY who ORDER BY n DESC, who LIMIT 10", account)
    out += [f"  {(r['who'] or '(unknown)')[:40]:<42}{r['n']:>8,}" for r in groups] or ["  (none)"]
    out += ["", _NOTE]
    return "\n".join(out)


def explain_text(index, account, message_id, show_sender=False):
    rows = index._q("SELECT * FROM message_class WHERE account=? AND message_id=? ORDER BY kind, value", account, message_id)
    if not rows:
        return f"No stored classification for message {message_id} (not classified yet, or unknown id)."
    cur = classifier.counts(index, account)["hash"]
    out = [f"Message {message_id}: {len(rows)} result(s); classified {rows[0]['classified_at']}"]
    if rows[0]["ruleset_hash"] != cur:
        out.append("  NOTE: stale - the ruleset changed since; run `classify run` to refresh.")
    if show_sender:
        m = index._q("SELECT sender FROM messages WHERE account=? AND id=?", account, message_id)
        out.append(f"  sender: {m[0]['sender'] if m else '(not in index)'}")
    for r in rows:
        out.append(f"  {r['kind']}: {r['value']}  [{r['confidence']} evidence, via {r['source']}:{r['rule_id']}] - "
                   f"{r['explanation']}")
    return "\n".join(out)


def rules_text(index, account):
    out = ["Built-in rules (conservative defaults; user rules always take precedence):"]
    for r in classify.BUILTIN_RULES:
        out.append(f"  {r.id:<28}{r.kind}:{r.value:<24}{r.confidence:<7}{r.note}")
    out += ["", "User rules (higher priority wins among user rules; then stronger confidence):"]
    rows = classifier.rule_rows(index, account)
    for r in rows:
        cond = " AND ".join(x for x in (
            f"sender={r['c_sender']}" if r["c_sender"] else "", f"domain={r['c_domain']}" if r["c_domain"] else "",
            f"label={r['c_label']}" if r["c_label"] else "",
            "" if r["c_unread"] is None else ("unread" if r["c_unread"] else "read")) if x)
        out.append(f"  {r['id']:<6}{'on ' if r['enabled'] else 'OFF'} {r['kind']}:{r['value']:<24}{r['confidence']:<7}"
                   f"prio {r['priority']:<5}{cond}" + (f"  # {r['note']}" if r["note"] else ""))
    if not rows:
        out.append("  (none yet; add one with `classify rules add`)")
    return "\n".join(out)
