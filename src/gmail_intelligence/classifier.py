"""Local classification store and runner (M3): rules CRUD, selection of work, batched persistence.

Reads the M2 index tables and writes only `class_rules` / `message_class` in the same local SQLite file. Never contacts
Gmail and never writes outside that database. Parameterized SQL only.
"""
from gmail_intelligence import ai, classify
from gmail_intelligence.classify import Features, Rule, Result
from gmail_intelligence.index import _now

BATCH = 200
_IN_CHUNK = 500


# ---- user rules -------------------------------------------------------------------------------------------------
def _row_rule(r):
    return Rule(r["id"], r["kind"], r["value"], r["confidence"], r["note"] or "user rule", tier=classify.TIER_USER,
                priority=r["priority"], sender=r["c_sender"], domain=r["c_domain"], label=r["c_label"],
                unread=None if r["c_unread"] is None else bool(r["c_unread"]))


def rule_rows(index, account):
    return [dict(r) for r in index._q("SELECT * FROM class_rules WHERE account=? ORDER BY CAST(substr(id,2) AS INTEGER)",
                                      account)]


def active_rules(index, account):
    return [_row_rule(r) for r in rule_rows(index, account) if r["enabled"]]


def current_hash(index, account):
    return classify.ruleset_hash(account, active_rules(index, account))


def add_rule(index, account, **fields):
    """Validate and store a user rule; returns its id. Raises classify.RuleError on bad input."""
    v = classify.validate_new_rule(**fields)
    with index.conn:
        nums = [int(r["id"][1:]) for r in index._q("SELECT id FROM class_rules WHERE account=?", account)]
        rid = f"u{max(nums, default=0) + 1}"
        index.conn.execute(
            "INSERT INTO class_rules (account,id,kind,value,c_sender,c_domain,c_label,c_unread,confidence,priority,"
            "enabled,note,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (account, rid, v["kind"], v["value"], v.get("sender"), v.get("domain"), v.get("label"),
             None if "unread" not in v else int(v["unread"]), v["confidence"], v["priority"], v["note"], _now()))
    return rid


def set_enabled(index, account, rule_id, enabled):
    with index.conn:
        cur = index.conn.execute("UPDATE class_rules SET enabled=? WHERE account=? AND id=?",
                                 (1 if enabled else 0, account, rule_id))
    return cur.rowcount == 1


def remove_rule(index, account, rule_id):
    with index.conn:
        cur = index.conn.execute("DELETE FROM class_rules WHERE account=? AND id=?", (account, rule_id))
    return cur.rowcount == 1


# ---- reading work -----------------------------------------------------------------------------------------------
_WEAK_AND_UNASKED = (" OR (? AND NOT EXISTS (SELECT 1 FROM message_class w WHERE w.account=m.account AND w.message_id=m.id"
                     " AND w.kind='type' AND (w.confidence<>'LOW' OR w.rule_id LIKE 'u%'))"
                     " AND NOT EXISTS (SELECT 1 FROM message_class a WHERE a.account=m.account AND a.message_id=m.id"
                     " AND a.source='ai'))")


def targets(index, account, ruleset_hash, limit=None, with_ai=False):
    """Newest-first messages that are unclassified or stale (rules changed / message rescanned)."""
    sql = ("SELECT m.id, m.sender, m.unread, m.scan_id FROM messages m WHERE m.account=? AND (NOT EXISTS ("
           "SELECT 1 FROM message_class c WHERE c.account=m.account AND c.message_id=m.id AND c.ruleset_hash=? "
           "AND c.msg_scan_id=m.scan_id)" + (_WEAK_AND_UNASKED if with_ai else "") + ") ORDER BY m.internal_ms DESC, m.id")
    params = [account, ruleset_hash] + ([1] if with_ai else [])
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return index._q(sql, *params)


def features_for(index, account, rows):
    names = {r["id"]: (r["name"] or "").lower() for r in index._q("SELECT id, name FROM labels WHERE account=?", account)}
    ids = [r["id"] for r in rows]
    labels = {i: set() for i in ids}
    for k in range(0, len(ids), _IN_CHUNK):
        chunk = ids[k:k + _IN_CHUNK]
        marks = ",".join("?" * len(chunk))
        for r in index._q(f"SELECT message_id, label_id FROM message_labels WHERE account=? AND message_id IN ({marks})",
                          account, *chunk):
            labels[r["message_id"]].add(r["label_id"])
    return {r["id"]: Features((r["sender"] or "").lower(), bool(r["unread"]), frozenset(labels[r["id"]]),
                              frozenset(n for l in labels[r["id"]] for n in [names.get(l)] if n))
            for r in rows}


# ---- running ----------------------------------------------------------------------------------------------------
def _is_weak(outcome):
    """True when only weak evidence exists and no user rule applied: the only case a local model may be asked."""
    types = [r for r in outcome.results if r.kind == "type"]
    return all(r.confidence == "LOW" and not r.rule_id.startswith("u") for r in types)


def _apply_ai(outcome, answer):
    results = list(outcome.results)
    if answer is None:
        results.append(Result("attention", "REVIEW_NEEDED", "LOW", "ai.invalid",
                              "local model output failed validation and was ignored", source="ai"))
    elif answer != "UNKNOWN":
        have = {r.value for r in results if r.kind == "type"}
        results = [r for r in results if not (r.kind == "type" and r.value == "UNKNOWN")]
        if answer not in have:
            results.append(Result("type", answer, "LOW", "ai.local",
                                  "suggested by a local model from sender domain and system labels only "
                                  "(uncalibrated; not a probability)", source="ai"))
    return results


def run(index, account, limit=None, persist=False, backend=None, progress=None):
    """Classify unclassified/stale messages. persist=False is a pure preview (no database writes at all).

    Returns a summary dict. `backend` (optional, from ai.py) is consulted only for weak-evidence messages.
    """
    user = active_rules(index, account)
    rhash = classify.ruleset_hash(account, user)
    rows = targets(index, account, rhash, limit, with_ai=backend is not None)
    summary = {"selected": len(rows), "classified": 0, "types": {}, "attention": {}, "rules": {}, "weak": 0,
               "ai_asked": 0, "ai_added": 0, "ai_invalid": 0, "persisted": persist, "hash": rhash}
    for k in range(0, len(rows), BATCH):
        chunk = rows[k:k + BATCH]
        feats = features_for(index, account, chunk)
        batch = []
        for r in chunk:
            outcome = classify.evaluate(feats[r["id"]], user)
            results = outcome.results
            if backend is not None and _is_weak(outcome):
                summary["ai_asked"] += 1
                answer = ai.suggest(backend, feats[r["id"]])  # AiError (server down) aborts the run before any write
                results = _apply_ai(outcome, answer)
                summary["ai_invalid"] += answer is None
                summary["ai_added"] += answer not in (None, "UNKNOWN")
            batch.append((r, results))
            for res in results:
                bucket = summary["types"] if res.kind == "type" else summary["attention"]
                bucket[res.value] = bucket.get(res.value, 0) + 1
                summary["rules"][res.rule_id] = summary["rules"].get(res.rule_id, 0) + 1
            summary["weak"] += all(x.confidence == "LOW" for x in results if x.kind == "type")
        if persist:
            _save(index, account, rhash, batch)
        summary["classified"] += len(batch)
        if progress:
            progress(summary["classified"], len(rows))
    return summary


def _save(index, account, rhash, batch):
    now = _now()
    with index.conn:  # one transaction per batch: all rows of the batch, or none
        for r, results in batch:
            index.conn.execute("DELETE FROM message_class WHERE account=? AND message_id=?", (account, r["id"]))
            index.conn.executemany(
                "INSERT INTO message_class (account,message_id,kind,value,confidence,source,rule_id,explanation,"
                "ruleset_hash,msg_scan_id,classified_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(account, r["id"], x.kind, x.value, x.confidence, x.source, x.rule_id, x.explanation, rhash,
                  r["scan_id"], now) for x in results])


def clear(index, account):
    """Remove this account's stored classifications (derived data). Rules and the M2 index are untouched."""
    with index.conn:
        return index.conn.execute("DELETE FROM message_class WHERE account=?", (account,)).rowcount


def preview_rule(index, account, **fields):
    """Impact of a not-yet-saved rule on the local index; read-only. Returns match/change counts."""
    v = classify.validate_new_rule(**fields)
    cand = Rule("preview", v["kind"], v["value"], v["confidence"], v["note"] or "candidate rule",
                priority=v["priority"], sender=v.get("sender"), domain=v.get("domain"), label=v.get("label"),
                unread=v.get("unread"))
    user = active_rules(index, account)
    rows = index._q("SELECT id, sender, unread FROM messages WHERE account=?", account)
    out = {"messages": len(rows), "matched": 0, "type_changes": 0, "now_unknown": 0}
    for k in range(0, len(rows), BATCH):
        chunk = rows[k:k + BATCH]
        feats = features_for(index, account, chunk)
        for r in chunk:
            f = feats[r["id"]]
            if not cand.matches(f):
                continue
            out["matched"] += 1
            before, after = classify.evaluate(f, user), classify.evaluate(f, [*user, cand])
            out["now_unknown"] += before.values() == ["UNKNOWN"]
            out["type_changes"] += (sorted(before.values()), sorted(before.values("attention"))) != (
                sorted(after.values()), sorted(after.values("attention")))
    return out


def counts(index, account):
    """Status numbers: indexed vs classified (current) vs stale vs unclassified, plus value distributions."""
    rhash = current_hash(index, account)
    total = index._q("SELECT COUNT(*) FROM messages WHERE account=?", account)[0][0]
    current = index._q("SELECT COUNT(DISTINCT c.message_id) FROM message_class c JOIN messages m ON m.account=c.account "
                       "AND m.id=c.message_id WHERE c.account=? AND c.ruleset_hash=? AND c.msg_scan_id=m.scan_id",
                       account, rhash)[0][0]
    anyclass = index._q("SELECT COUNT(DISTINCT c.message_id) FROM message_class c JOIN messages m ON m.account=c.account "
                        "AND m.id=c.message_id WHERE c.account=?", account)[0][0]
    return {"indexed": total, "current": current, "stale": max(anyclass - current, 0),
            "unclassified": max(total - anyclass, 0), "hash": rhash}


def distribution(index, account, kind):
    return {r["value"]: (r["n"], r["conf"]) for r in index._q(
        "SELECT value, COUNT(DISTINCT message_id) n, MAX(CASE confidence WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 "
        "ELSE 1 END) conf FROM message_class WHERE account=? AND kind=? GROUP BY value ORDER BY n DESC, value",
        account, kind)}
