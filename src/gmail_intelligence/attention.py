"""M8A-1: deterministic, explainable attention ranking over ALREADY INDEXED metadata. Read-only, offline, stdlib only.

Design: docs/ATTENTION.md. In short:
  * Inputs are the labels (STARRED, IMPORTANT, UNREAD, ...), the unread flag, the received date, the sender address and the existing M3 classification, recomputed
    in memory from the active rules. Persisted `message_class` rows (including `source=ai`) are never read. No subject, snippet, body or attachment exists here.
  * `score` (0-100) is the primary ranking key and a total order completes it; `evidence` and `flags` are separate axes that never change the score.
  * Results are complete or the call fails (`RESULT_INCOMPLETE`): nothing is truncated by age or size. Reads are short and fully fetched (a long read
    transaction would block the sync writer) and are validated with `PRAGMA data_version` on ONE connection; a change means a bounded retry, then an error.
  * Pagination is stateless: an opaque cursor carries a snapshot digest of the whole visible result; any change fails explicitly with no items.
The weights are approved for EXPERIMENTAL v1 only and are not validated on a real mailbox, hence the output label PROVISIONAL (docs/ATTENTION.md, docs/ATTENTION-EVALUATION.md).
"""
import hashlib
import heapq
import json
import re
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from gmail_intelligence import analytics, classifier, classify
from gmail_intelligence import index as idx

ALGORITHM_VERSION = 1
WEIGHTS_STATUS = "PROVISIONAL"
RETAINED_THREAD_BUDGET = 250_000  # approved by the owner for EXPERIMENTAL v1 only (measured ~0.72 KB peak RSS per retained thread; docs/ATTENTION-EVALUATION.md); not validated on a real mailbox
BATCH = 2000
MAX_RETRIES = 2
DEFAULT_LIMIT, MAX_LIMIT = 25, 100
DEFAULT_SENDER_LIMIT, MAX_SENDER_LIMIT = 3, 10

SORTS = ("priority", "date", "oldest")
SIGNALS = ("starred", "important", "unread", "rule")
TIERS = ("low", "medium", "high")
EXCLUDED_LABELS = frozenset({"SENT", "DRAFT", "TRASH", "SPAM", "CHAT"})
SIGNAL_LABEL = {"starred": "STARRED", "important": "IMPORTANT", "unread": "UNREAD"}
EVIDENCE = ("MAILBOX_STATE", "GMAIL_HEURISTIC", "OWNER_ASSERTED")  # index = rank
_MAX_MS = 1 << 62

# Fixed texts. Nothing here (or in any error) contains an identifier, a path or exception text.
ERRORS = {
    "RESULT_INCOMPLETE": "the result is too large to be computed completely within the memory budget; nothing is shown. Narrow it with --signal or --min-tier",
    "SNAPSHOT_CHANGED": "the list changed since the cursor was issued (data, rules or parameters differ); nothing is shown. Start again without --cursor",
    "CURSOR_INVALID": "the cursor is not valid; nothing is shown. Start again without --cursor",
    "INDEX_CHANGED_DURING_READ": "the local index kept changing while it was being read; nothing is shown. Try again when no sync or scan is running",
}


class AttentionError(Exception):
    """A closed, fixed-text failure. `str()` is the code only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code
        self.message = f"{code}: {ERRORS[code]}"


@dataclass(frozen=True)
class Weights:
    """Ranking weights of EXPERIMENTAL algorithm version 1 (approved for v1 only; not validated on a real mailbox)."""
    star: int = 50
    owner_cap: int = 70
    rule: tuple = (("LOW", 20), ("MEDIUM", 40), ("HIGH", 60))
    important: int = 20
    age: tuple = ((2, 10), (14, 15), (60, 5))  # (max age in days, points); older: 0
    personal: tuple = (("MEDIUM", 5), ("HIGH", 10))
    gmail_cap: int = 40
    penalty: tuple = (("PROMOTIONAL", 30), ("NEWSLETTER", 30), ("SOCIAL", 30), ("AUTOMATED_NOTIFICATION", 15))
    exempt_types: tuple = ("TRANSACTIONAL", "FINANCIAL")
    tiers: tuple = (("HIGH", 60), ("MEDIUM", 35), ("LOW", 15))
    min_score: int = 15
    low_min_score: int = 1


DEFAULT_WEIGHTS = Weights()

Rec = namedtuple("Rec", "id thread sender ms score owner ev star rule_pts rule_conf rule_id imp unread age_pts pers pen pen_type types flags")
_STRONG = ("MEDIUM", "HIGH")


def _ms_day(ms):
    try:
        return datetime.fromtimestamp(ms / 1000, timezone.utc).date()
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def score_message(features, outcome, ms, ref_day, user_rule_ids, weights=DEFAULT_WEIGHTS):
    """The pure scoring function: returns a `Rec` without id/thread/sender (filled in by the caller)."""
    labels = features.label_ids
    flags = set()
    types = [(r.value, r.confidence) for r in outcome.results if r.kind == "type"]
    rule_pts, rule_conf, rule_id = 0, "", ""
    for r in outcome.results:
        if r.kind != "attention":
            continue
        if r.value == "POTENTIALLY_IMPORTANT" and r.rule_id in user_rule_ids:
            rule_pts, rule_conf, rule_id = dict(weights.rule)[r.confidence], r.confidence, r.rule_id
        elif r.value == "REVIEW_NEEDED":
            flags.add("TYPE_CONFLICT" if r.rule_id == classify.CONFLICT_RULE else "REVIEW_FLAGGED")
    star = weights.star if "STARRED" in labels else 0
    imp = weights.important if "IMPORTANT" in labels else 0
    unread = "UNREAD" in labels
    if features.unread != unread:
        flags.add("UNREAD_MISMATCH")
    day = None if ms is None else _ms_day(ms)
    if day is None:
        flags.add("DATE_MISSING")
    age_pts = 0
    if unread and day is not None:
        age = max((ref_day - day).days, 0)
        age_pts = next((pts for limit, pts in weights.age if age <= limit), 0)
    pers = max([dict(weights.personal).get(c, 0) for v, c in types if v == "PERSONAL"] or [0])
    pen, pen_type = 0, ""
    if not any(v in weights.exempt_types for v, _ in types):
        table = dict(weights.penalty)
        for v, c in sorted(types):
            if c in _STRONG and table.get(v, 0) > pen:
                pen, pen_type = table[v], v
    owner = min(weights.owner_cap, star + rule_pts)
    gmail = min(weights.gmail_cap, imp + age_pts + pers)
    score = min(100, owner + max(0, gmail - pen))
    ev = 2 if star or (rule_pts and rule_conf in _STRONG) else 1 if imp or rule_pts else 0
    if not features.sender or "@" not in features.sender:
        flags.add("SENDER_MISSING")
    elif not features.domain.isascii():
        flags.add("NON_ASCII_DOMAIN")
    if "INBOX" not in labels:
        flags.add("NOT_IN_INBOX")
    return Rec("", "", features.sender, ms, score, owner, ev, star, rule_pts, rule_conf, rule_id, imp, int(unread), age_pts, pers, pen, pen_type,
               tuple(sorted({v for v, _ in types})), tuple(sorted(flags)))


def tier_of(score, weights=DEFAULT_WEIGHTS):
    return next((name for name, floor in weights.tiers if score >= floor), "MINIMAL")


def gmail_points(rec, weights=DEFAULT_WEIGHTS):
    return min(weights.gmail_cap, rec.imp + rec.age_pts + rec.pers)


def _pkey(r):
    return (-r.score, -r.owner, -r.ev, -(r.ms or 0), r.id)


_SORT_KEYS = {"priority": _pkey,
              "date": lambda r: (-(r.ms or 0), r.id),
              "oldest": lambda r: (r.ms if r.ms else _MAX_MS, r.id)}


# ---------------------------------------------------------------------------------------------- parameters and cursor
def _params(limit, sort, signals, min_tier, sender_limit, collapse, include_low_score, reveal_senders):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"--limit must be between 1 and {MAX_LIMIT}")
    if sort not in SORTS:
        raise ValueError("--sort must be one of: " + ", ".join(SORTS))
    sigs = tuple(sorted(set(signals or ())))
    if any(s not in SIGNALS for s in sigs):
        raise ValueError("--signal must be one of: " + ", ".join(SIGNALS))
    if min_tier is not None and min_tier not in TIERS:
        raise ValueError("--min-tier must be one of: " + ", ".join(TIERS))
    if isinstance(sender_limit, bool) or not isinstance(sender_limit, int) or not 0 <= sender_limit <= MAX_SENDER_LIMIT:
        raise ValueError(f"--sender-limit must be between 0 and {MAX_SENDER_LIMIT}")
    return {"limit": limit, "sort": sort, "signals": sigs, "min_tier": min_tier, "sender_limit": sender_limit,
            "collapse": bool(collapse), "include_low_score": bool(include_low_score), "reveal": bool(reveal_senders)}


_CURSOR = re.compile(r"a1\.(\d{8})\.([0-9a-f]{64})\.(\d{1,7})\.([0-9a-f]{16})")


def _parse_cursor(text):
    if not isinstance(text, str) or len(text) > 128:
        raise AttentionError("CURSOR_INVALID")
    m = _CURSOR.fullmatch(text)
    if m is None:
        raise AttentionError("CURSOR_INVALID")
    try:
        day = datetime.strptime(m.group(1), "%Y%m%d").date()
    except ValueError:
        raise AttentionError("CURSOR_INVALID") from None
    n = int(m.group(3))
    if n < 1:
        raise AttentionError("CURSOR_INVALID")
    return day, m.group(2), n, m.group(4)


def _canon(rec, count):
    """The canonical bytes of everything visible about one item (the sender enters the digest, never the output)."""
    return json.dumps([rec.id, rec.thread, rec.sender, rec.ms, rec.score, rec.owner, rec.ev, rec.star, rec.rule_pts, rec.rule_conf, rec.rule_id, rec.imp,
                       rec.unread, rec.age_pts, rec.pers, rec.pen, rec.pen_type, list(rec.types), list(rec.flags), count],
                      separators=(",", ":"), ensure_ascii=True).encode("ascii")


# --------------------------------------------------------------------------------------------------- streaming reads
def _data_version(index):
    return index.conn.execute("PRAGMA data_version").fetchone()[0]


def _label_ids(index, account, label):
    """Message ids carrying `label`, in id order, read in short fully fetched keyset pages (index-driven, no temporary sort)."""
    last = ""
    while True:
        rows = index.conn.execute("SELECT message_id FROM message_labels WHERE account=? AND label_id=? AND message_id>? ORDER BY message_id LIMIT ?",
                                  (account, label, last, BATCH)).fetchall()
        for r in rows:
            yield r[0]
        if len(rows) < BATCH:
            return
        last = rows[-1][0]


def _unique(stream):
    prev = None
    for item in stream:
        if item != prev:
            yield item
            prev = item


def _rows_for(index, account, ids):
    out = {}
    for k in range(0, len(ids), 500):
        chunk = ids[k:k + 500]
        marks = ",".join("?" * len(chunk))
        for r in index.conn.execute(f"SELECT id, thread_id, internal_ms, sender, unread FROM messages WHERE account=? AND id IN ({marks})", (account, *chunk)).fetchall():
            out[r["id"]] = r
    return [out[i] for i in ids if i in out]


def _batches(index, account, labels, full):
    """Batches of message rows: one primary-key-ordered stream (full) or the de-duplicated merge of per-label id streams."""
    if full:
        last = ""
        while True:
            rows = index.conn.execute("SELECT id, thread_id, internal_ms, sender, unread FROM messages WHERE account=? AND id>? ORDER BY id LIMIT ?",
                                      (account, last, BATCH)).fetchall()
            if rows:
                yield rows
            if len(rows) < BATCH:
                return
            last = rows[-1]["id"]
        return
    ids = _unique(heapq.merge(*[_label_ids(index, account, label) for label in labels]))
    chunk = []
    for i in ids:
        chunk.append(i)
        if len(chunk) >= BATCH:
            rows = _rows_for(index, account, chunk)
            if rows:
                yield rows
            chunk = []
    if chunk:
        rows = _rows_for(index, account, chunk)
        if rows:
            yield rows


# ------------------------------------------------------------------------------------------------------- computation
def _run(index, account, p, ref_day, budget, hook, weights=DEFAULT_WEIGHTS):
    rules = classifier.active_rules(index, account)
    rhash = classify.ruleset_hash(account, rules)
    user_ids = frozenset(r.id for r in rules)
    has_attention_rules = any(r.kind == "attention" for r in rules)
    sigs = set(p["signals"])
    want_rule = not sigs or "rule" in sigs
    full = has_attention_rules and want_rule
    labels = sorted({SIGNAL_LABEL[s] for s in (sigs or SIGNAL_LABEL) if s in SIGNAL_LABEL})
    threshold = max(weights.low_min_score if p["include_low_score"] else weights.min_score, dict((n, f) for n, f in weights.tiers).get((p["min_tier"] or "").upper(), 0))
    table = {}
    interned = {}
    evaluated = excluded = kept = 0
    batch_no = 0
    for rows in _batches(index, account, labels, full) if (full or labels) else ():
        feats = classifier.features_for(index, account, rows)
        for row in rows:
            f = feats[row["id"]]
            if f.label_ids & EXCLUDED_LABELS:
                excluded += 1
                continue
            evaluated += 1
            rec = score_message(f, classify.evaluate(f, rules), row["internal_ms"], ref_day, user_ids, weights)
            if sigs and not ((("starred" in sigs and rec.star) or ("important" in sigs and rec.imp) or ("unread" in sigs and rec.unread) or ("rule" in sigs and rec.rule_pts))):
                continue
            if rec.score < threshold:
                continue
            kept += 1
            thread = (row["thread_id"] or "") if p["collapse"] else ""
            key = thread if thread else "m:" + row["id"]
            rec = rec._replace(id=row["id"], thread=key, types=interned.setdefault(rec.types, rec.types), flags=interned.setdefault(rec.flags, rec.flags))
            entry = table.get(key)
            if entry is None:
                table[key] = [rec, 1]
                if len(table) > budget:
                    raise AttentionError("RESULT_INCOMPLETE")
            else:
                entry[1] += 1
                if _pkey(rec) < _pkey(entry[0]):
                    entry[0] = rec
        batch_no += 1
        if hook is not None:
            hook(batch_no)
    entries = sorted(table.values(), key=lambda e: _pkey(e[0]))
    suppressed = 0
    if p["sender_limit"]:
        seen, kept_entries = {}, []
        for e in entries:
            s = e[0].sender or ""
            seen[s] = seen.get(s, 0) + 1
            if seen[s] <= p["sender_limit"]:
                kept_entries.append(e)
            else:
                suppressed += 1
        entries = kept_entries
    entries.sort(key=lambda e: _SORT_KEYS[p["sort"]](e[0]))
    totals = {"evaluated": evaluated, "excluded": excluded, "kept_messages": kept, "threads": len(table), "collapsed_messages": kept - len(table),
              "suppressed_by_sender_limit": suppressed, "total": len(entries)}
    header = {"v": ALGORITHM_VERSION, "tax": classify.TAXONOMY_VERSION, "builtin": classify.BUILTIN_VERSION, "account": account.lower(), "rules": rhash,
              "day": ref_day.isoformat(), "sort": p["sort"], "signals": list(p["signals"]), "threshold": threshold, "collapse": p["collapse"],
              "sender_limit": p["sender_limit"], "reveal": p["reveal"], "totals": totals}
    digest = hashlib.sha256(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii"))
    for rec, count in entries:
        digest.update(_canon(rec, count))
        digest.update(b"\n")
    return {"entries": entries, "totals": totals, "snapshot": digest.hexdigest(), "rules_hash": rhash, "threshold": threshold}


def compute(index, account, *, limit=DEFAULT_LIMIT, cursor=None, sort="priority", signals=(), min_tier=None, sender_limit=DEFAULT_SENDER_LIMIT, collapse=True,
            include_low_score=False, reveal_senders=False, now=None, budget=None, _after_batch=None, _weights=DEFAULT_WEIGHTS):
    """One page of attention candidates. `index` must be a `ReadOnlyIndex`. Raises `AttentionError` (fixed codes) or `ValueError` (bad parameter)."""
    if not isinstance(index, idx.ReadOnlyIndex):
        raise TypeError("attention needs a ReadOnlyIndex")
    p = _params(limit, sort, signals, min_tier, sender_limit, collapse, include_low_score, reveal_senders)
    moment = now if now is not None else datetime.now(timezone.utc)
    today = moment.astimezone(timezone.utc).date()
    ref_day, want = today, None
    if cursor is not None:
        want = _parse_cursor(cursor)
        if want[0] not in (today, today - timedelta(days=1)):
            raise AttentionError("SNAPSHOT_CHANGED")
        ref_day = want[0]
    budget = RETAINED_THREAD_BUDGET if budget is None else budget
    index.conn.execute("PRAGMA temp_store = MEMORY")
    for attempt in range(MAX_RETRIES + 1):
        before = _data_version(index)
        res = _run(index, account, p, ref_day, budget, _after_batch, _weights)
        if _data_version(index) == before:
            break
    else:
        raise AttentionError("INDEX_CHANGED_DURING_READ")
    entries, start = res["entries"], 0
    if want is not None:
        _, snap, n, key = want
        if snap != res["snapshot"]:
            raise AttentionError("SNAPSHOT_CHANGED")
        if n > len(entries) or hashlib.sha256(_canon(*entries[n - 1])).hexdigest()[:16] != key:
            raise AttentionError("CURSOR_INVALID")
        start = n
    page = entries[start:start + p["limit"]]
    nxt = None
    if start + len(page) < len(entries):
        last = entries[start + len(page) - 1]
        nxt = f"a1.{ref_day.strftime('%Y%m%d')}.{res['snapshot']}.{start + len(page)}.{hashlib.sha256(_canon(*last)).hexdigest()[:16]}"
    warnings, as_of, sync_state = _freshness(index, account, moment)
    return {"section": "attention", "algorithm_version": ALGORITHM_VERSION, "weights_status": WEIGHTS_STATUS, "reference_day": ref_day.isoformat(),
            "snapshot": res["snapshot"], "ruleset_hash": res["rules_hash"],
            "params": {"sort": p["sort"], "signals": list(p["signals"]), "min_tier": p["min_tier"], "sender_limit": p["sender_limit"], "collapse": p["collapse"],
                       "include_low_score": p["include_low_score"], "threshold": res["threshold"], "limit": p["limit"]},
            "totals": res["totals"], "warnings": warnings, "freshness": {"as_of": as_of, "sync_state": sync_state},
            "items": [_item(start + i + 1, rec, count, p["reveal"], ref_day, _weights) for i, (rec, count) in enumerate(page)], "next_cursor": nxt,
            "explain": ["POSSIBLY_NEEDS_ATTENTION", "METADATA_ONLY", "WEIGHTS_PROVISIONAL", "SNAPSHOT_FROM_LOCAL_INDEX", "ABSENCE_PROVES_NOTHING"]}


def _freshness(index, account, moment):
    """Warnings only (never a block). Deliberately avoids `classifier.counts`: nothing on the ranking path reads persisted classification."""
    from gmail_intelligence import report

    state, _ = report.completeness(index, account)
    scans = index.recent_scans(account, 50)
    full = next((s for s in scans if s["mode"] == "full" and s["status"] == "completed"), None)
    done = next((s for s in scans if s["status"] == "completed"), None)
    as_of = (full or done or {}).get("finished_at")
    warnings = []
    if state == "empty":
        warnings.append("INDEX_EMPTY")
    elif state == "partial":
        warnings.append("INDEX_PARTIAL")
    if as_of and max((moment - analytics._parse(as_of)).days, 0) > analytics.STALE_DAYS:
        warnings.append("SCAN_STALE")
    sync = analytics.Analytics(index, account, now=moment)._sync_facts()
    if not sync["healthy"]:
        warnings.append("SYNC_NOT_HEALTHY")
    return warnings, as_of, sync["state"]


def _item(rank, rec, count, reveal, ref_day, weights):
    signals = []
    if rec.star:
        signals.append({"code": "STARRED", "points": rec.star, "basis": "OBSERVED"})
    if rec.rule_pts:
        signals.append({"code": "USER_RULE", "points": rec.rule_pts, "basis": "OBSERVED", "rule": rec.rule_id, "confidence": rec.rule_conf})
    if rec.imp:
        signals.append({"code": "GMAIL_IMPORTANT", "points": rec.imp, "basis": "INFERRED"})
    if rec.unread:
        signals.append({"code": "UNREAD", "points": rec.age_pts, "basis": "OBSERVED"})
    if rec.pers:
        signals.append({"code": "PERSONAL_SENDER", "points": rec.pers, "basis": "INFERRED"})
    if rec.pen:
        signals.append({"code": "PENALTY_" + rec.pen_type, "points": -rec.pen, "basis": "INFERRED"})
    gmail = gmail_points(rec, weights)
    day = None if rec.ms is None else _ms_day(rec.ms)
    sender = rec.sender or ""
    domain = analytics.clean(sender.rpartition("@")[2]) if "@" in sender else None
    if not sender or "@" not in sender:
        who = {"display": None, "masked": True, "domain": None}
    elif reveal:
        who = {"display": analytics.clean(sender, 254), "masked": False, "domain": domain}
    else:
        who = {"display": analytics.mask_address(sender), "masked": True, "domain": domain}
    return {"rank": rank, "score": rec.score, "tier": tier_of(rec.score, weights), "evidence": EVIDENCE[rec.ev], "flags": list(rec.flags),
            "components": {"owner": rec.owner, "inferred": max(0, gmail - rec.pen), "penalty": rec.pen}, "signals": signals, "types": list(rec.types),
            "sender": who, "date": None if day is None else day.isoformat(),
            "unread_days": max((ref_day - day).days, 0) if rec.unread and day is not None else None, "thread_messages": count,
            "link": {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"}}


# ------------------------------------------------------------------------------------------------------------ output
def as_json(result):
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True)


def render_text(result):
    p, t = result["params"], result["totals"]
    out = [f"Attention candidates (possibly needs attention; metadata only, read-only, weights {result['weights_status']}; reference day {result['reference_day']})",
           f"{t['total']} item(s) after filters; showing {len(result['items'])}. Sort: {p['sort']}; sender limit: {p['sender_limit'] or 'off'}; threshold: score >= {p['threshold']}.",
           f"Evaluated {t['evaluated']} message(s), excluded {t['excluded']}, collapsed {t['collapsed_messages']} into threads, suppressed by the sender limit {t['suppressed_by_sender_limit']}."]
    if result["warnings"]:
        out.append("Warnings (the list may be out of date): " + ", ".join(result["warnings"]) + f"; sync state {result['freshness']['sync_state']}; as of {result['freshness']['as_of'] or 'unknown'}")
    for it in result["items"]:
        who = it["sender"]["display"] or "(sender unknown)"
        sigs = ", ".join(f"{s['code']}{s['points']:+d}" for s in it["signals"]) or "none"
        extra = f" | {it['thread_messages']} messages in thread" if it["thread_messages"] > 1 else ""
        age = f" | unread {it['unread_days']}d" if it["unread_days"] is not None else ""
        out.append(f"{it['rank']:>3}. [{it['tier']} {it['score']}] {it['date'] or 'no date'} | {who} | evidence {it['evidence']}{age}{extra}")
        out.append(f"     signals: {sigs}" + (f" | flags: {', '.join(it['flags'])}" if it["flags"] else "") + (f" | types: {', '.join(it['types'])}" if it["types"] else ""))
    if not result["items"]:
        out.append("Nothing to show. (The absence of a finding proves nothing.)")
    if result["next_cursor"]:
        out.append(f"More: --cursor {result['next_cursor']}")
    return "\n".join(out)
