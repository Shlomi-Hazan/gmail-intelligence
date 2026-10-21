"""Aggregate, explainable, privacy-safe mailbox analytics (M6A). LOCAL ONLY, read-only: nothing here calls Gmail, the network, the Keychain or OAuth, and nothing writes.

Every section returns the same envelope: {"section", "data", "basis", "explain", "as_of", "index"} where
  * `basis` says what the numbers are: OBSERVED (counted from the local index), INFERRED (built on the M3 classification) or MIXED;
  * `explain` is a list of stable codes (never prose) that a renderer turns into text;
  * `as_of`/`index` carry the data's age and completeness, because an indexed snapshot is NOT the current state of Gmail.
Results are deterministic for the same index, account and `now`: ties are broken by key, never by insertion order.

Classification semantics are not re-implemented: type/attention values come from the stored M3 results, counted only when they are CURRENT (same rule-set hash and same scan as
the message). A message that carries two compatible types (for example TRANSACTIONAL and FINANCIAL) is counted once in the category breakdown, under the first of them in taxonomy
order (`classify.TYPES`); this is a presentation grouping, not a new classification. Sender addresses are masked unless `reveal_senders` is set; domains are shown.
"""
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from gmail_intelligence import classifier, classify, cleanup_audit, cleanup_candidates as cc, label_hygiene, label_model as lm, label_suggest, filter_suggest, report, sync_health, sync_report

STALE_DAYS = 7
MASK = "•••"
UNCLASSIFIED = "UNCLASSIFIED"
SUBSCRIPTION_TYPES = ("NEWSLETTER", "AUTOMATED_NOTIFICATION", "PROMOTIONAL")
SECTIONS = ("freshness", "overview", "volume", "categories", "senders", "subscriptions", "cleanup-summary", "cleanup-history", "organization")
# Control characters, bidirectional formatting/override/isolate controls and zero-width marks: never passed on from the mailbox to a renderer.
_UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u061c\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]")


def clean(text, limit=120):
    """Untrusted text made safe for display: unsafe characters become a space, runs of spaces collapse, length is bounded."""
    out = re.sub(" +", " ", _UNSAFE.sub(" ", str(text or ""))).strip()
    return out if len(out) <= limit else out[:limit - 1] + "…"


def mask_address(address):
    local, at, domain = clean(address, 254).partition("@")
    if not at:
        return MASK
    return (local[:1] + MASK if len(local) > 1 else MASK) + "@" + domain


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _day(ms):
    return None if ms is None else datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d")


def _month(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m")


def _pct(part, whole):
    return 0.0 if not whole else round(100.0 * part / whole, 1)


def _domain(sender):
    return sender.rpartition("@")[2] if "@" in sender else ""


class Analytics:
    """All sections for one account. Load once, ask many times (the per-message rows are loaded lazily and reused)."""

    def __init__(self, index, account, now=None, reveal_senders=False, reveal_names=False):
        self.index, self.account = index, account
        self.now = now if now is not None else datetime.now(timezone.utc)
        self.reveal_senders, self.reveal_names = bool(reveal_senders), bool(reveal_names)
        self._rows = self._types = self._fresh = None

    # ------------------------------------------------------------------ shared facts
    def freshness_facts(self):
        if self._fresh is not None:
            return self._fresh
        index, account = self.index, self.account
        state, why = report.completeness(index, account)
        scans = index.recent_scans(account, 50)
        full = next((s for s in scans if s["mode"] == "full" and s["status"] == "completed"), None)
        done = next((s for s in scans if s["status"] == "completed"), None)
        as_of = (full or done or {}).get("finished_at")
        age = None if not as_of else max((self.now - _parse(as_of)).days, 0)
        cls = classifier.counts(index, account)
        issues = []
        if state == "empty":
            issues.append("EMPTY")
        elif state == "partial":
            issues.append("PARTIAL")
        if age is not None and age > STALE_DAYS:
            issues.append("STALE")
        if cls["stale"]:
            issues.append("CLASSIFICATION_STALE")
        if cls["unclassified"] and cls["indexed"]:
            issues.append("UNCLASSIFIED")
        self._fresh = {"state": state, "why": clean(why, 200), "sync": self._sync_facts(), "as_of": as_of, "age_days": age, "stale_after_days": STALE_DAYS,
                       "last_full_scan": full["finished_at"] if full else None, "scans_recorded": len(scans),
                       "classification": {"indexed": cls["indexed"], "current": cls["current"], "stale": cls["stale"], "unclassified": cls["unclassified"]},
                       "issues": issues, "health": issues[0] if issues else "OK"}
        return self._fresh

    SYNC_PRECEDENCE = (("SYNC_NEEDS_RECONCILE", "NEEDS_RECONCILE"), ("SYNC_STATE_INCONSISTENT", "INCONSISTENT"), ("SYNC_FULL_SCAN_INCOMPLETE", "FULL_SCAN_UNFINISHED"),
                       ("SYNC_IN_PROGRESS", "IN_PROGRESS"), ("SYNC_INTERRUPTED", "INTERRUPTED"), ("SYNC_CHECKPOINT_MISSING", "MISSING"), ("SYNC_STALE", "STALE"))

    def _sync_facts(self):
        """Aggregate, cheap sync information for the freshness screen (M7C). Local records only; the expensive integrity checks live in `mailbox maintenance`, never here.

        Additive: it is kept OUT of `issues` / `health`, so existing consumers see exactly what they saw before."""
        index, account = self.index, self.account
        codes = sync_health.problems(index, account, self.now)
        row = sync_health.state_row(index, account)
        last = index._q("SELECT finished_at FROM sync_run WHERE account=? AND status='completed' ORDER BY id DESC LIMIT 1", account)
        label = next((name for code, name in self.SYNC_PRECEDENCE if code in codes), "OK")
        return {"state": label, "healthy": not codes, "checkpoint": "present" if row else "missing",
                "status": row["status"] if row and row["status"] in ("OK", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE") else None,
                "reason": sync_report.safe_reason(row["reason"]) if row else None, "age_hours": sync_report._age_hours(row["advanced_at"], self.now) if row else None,
                "last_completed_sync_at": sync_report.safe_ts(last[0][0]) if last else None, "codes": codes, "maintenance_command": "mailbox maintenance"}

    def _envelope(self, section, data, basis, explain):
        f = self.freshness_facts()
        return {"section": section, "data": data, "basis": basis, "explain": list(explain), "as_of": f["as_of"],
                "index": {"state": f["state"], "age_days": f["age_days"], "stale": "STALE" in f["issues"], "health": f["health"]}}

    def _load(self):
        if self._rows is not None:
            return
        index, account = self.index, self.account
        rhash = classifier.current_hash(index, account)
        self._rows = [dict(r) for r in index._q(
            "SELECT id, sender, unread, internal_ms, size, scan_id FROM messages WHERE account=? ORDER BY id", account)]
        types = defaultdict(set)
        for r in index._q("SELECT c.message_id, c.value FROM message_class c JOIN messages m ON m.account=c.account AND m.id=c.message_id "
                          "WHERE c.account=? AND c.kind='type' AND c.ruleset_hash=? AND c.msg_scan_id=m.scan_id", account, rhash):
            types[r["message_id"]].add(r["value"])
        order = {t: i for i, t in enumerate(classify.TYPES)}
        self._types = {mid: min(vals, key=lambda v: order.get(v, 99)) for mid, vals in types.items()}
        self._multi = sum(1 for vals in types.values() if len(vals) > 1)

    def _months(self):
        """Every month from the oldest to the newest dated message, gaps included (so every series shares one axis)."""
        dated = sorted({_month(r["internal_ms"]) for r in self._rows if r["internal_ms"] is not None})
        out = []
        if dated:
            y, m = map(int, dated[0].split("-"))
            ey, em = map(int, dated[-1].split("-"))
            while (y, m) <= (ey, em):
                out.append(f"{y:04d}-{m:02d}")
                y, m = (y + 1, 1) if m == 12 else (y, m + 1)
        return out

    def _bucket(self, message_id):
        return self._types.get(message_id, UNCLASSIFIED)

    # ------------------------------------------------------------------ sections
    def freshness(self):
        return self._envelope("freshness", self.freshness_facts(), "OBSERVED", ["SNAPSHOT_NOT_LIVE", "DATA_AGE_FROM_LAST_SCAN", "SYNC_FROM_LOCAL_RECORDS"])

    def overview(self):
        self._load()
        index, account = self.index, self.account
        ov = index.overview(account)
        n = ov["n"]
        inbox = index._q("SELECT COUNT(DISTINCT message_id) FROM message_labels WHERE account=? AND label_id='INBOX'", account)[0][0]
        labels = lm.load_labels(index, account)
        rhash = classifier.current_hash(index, account)
        attention = {r["value"]: r["n"] for r in index._q(
            "SELECT c.value, COUNT(DISTINCT c.message_id) n FROM message_class c JOIN messages m ON m.account=c.account AND m.id=c.message_id "
            "WHERE c.account=? AND c.kind='attention' AND c.ruleset_hash=? AND c.msg_scan_id=m.scan_id GROUP BY c.value ORDER BY c.value", account, rhash)}
        f = self.freshness_facts()
        data = {"messages": n, "threads": ov["t"], "unread": ov["u"], "unread_share_pct": _pct(ov["u"], n), "in_inbox": inbox, "size_bytes": ov["sz"],
                "oldest": _day(ov["lo"]), "newest": _day(ov["hi"]), "user_labels": sum(1 for lab in labels if lab.user), "classified": f["classification"]["current"],
                "classified_share_pct": _pct(f["classification"]["current"], n),
                "attention": {k: attention.get(k, 0) for k in classify.ATTENTION}, "health": f["health"], "issues": f["issues"]}
        return self._envelope("overview", data, "OBSERVED", ["COUNTS_FROM_LOCAL_INDEX", "SNAPSHOT_NOT_LIVE", "CLASSIFIED_IS_CURRENT_RULES_ONLY"])

    def volume(self):
        self._load()
        counts, unread = Counter(), Counter()
        for r in self._rows:
            if r["internal_ms"] is None:
                continue
            period = _month(r["internal_ms"])
            counts[period] += 1
            unread[period] += bool(r["unread"])
        points = [{"period": p, "messages": counts.get(p, 0), "unread": unread.get(p, 0)} for p in self._months()]
        f = self.freshness_facts()
        open_month = f["as_of"][:7] if f["as_of"] else None
        for p in points:
            p["in_progress"] = p["period"] == open_month
        undated = sum(1 for r in self._rows if r["internal_ms"] is None)
        return self._envelope("volume", {"granularity": "month", "points": points, "undated": undated,
                                         "peak": max(points, key=lambda p: (p["messages"], p["period"]))["period"] if points else None},
                              "OBSERVED", ["MONTHLY_BY_MESSAGE_DATE", "EMPTY_MONTHS_SHOWN_AS_ZERO", "LAST_MONTH_MAY_BE_INCOMPLETE", "SNAPSHOT_NOT_LIVE"])

    def categories(self, by="total"):
        self._load()
        if by not in ("total", "month"):
            raise ValueError("by must be 'total' or 'month'")
        total = len(self._rows)
        tally = Counter(self._bucket(r["id"]) for r in self._rows)
        classified = total - tally.get(UNCLASSIFIED, 0)
        order = list(classify.TYPES) + [UNCLASSIFIED]
        types = [{"type": t, "messages": tally.get(t, 0), "share_of_indexed_pct": _pct(tally.get(t, 0), total),
                  "share_of_classified_pct": _pct(tally.get(t, 0), classified) if t != UNCLASSIFIED else 0.0} for t in order if tally.get(t, 0) or t in ("UNKNOWN", UNCLASSIFIED)]
        data = {"indexed": total, "classified": classified, "unclassified": tally.get(UNCLASSIFIED, 0), "multi_type_messages": self._multi, "types": types}
        if by == "month":
            months = defaultdict(Counter)
            for r in self._rows:
                if r["internal_ms"] is not None:
                    months[_month(r["internal_ms"])][self._bucket(r["id"])] += 1
            data["by_month"] = [{"period": p, "counts": {t: months[p].get(t, 0) for t in order if months[p].get(t, 0)}} for p in sorted(months)]
        return self._envelope("categories", data, "INFERRED", ["CLASSIFICATION_IS_INFERRED", "COUNTED_ONCE_UNDER_FIRST_TYPE", "ONLY_CURRENT_CLASSIFICATIONS", "SNAPSHOT_NOT_LIVE"])

    def _sender_row(self, key, kind, stats):
        shown = kind == "domain" or self.reveal_senders
        row = {"key": clean(key) if shown else None, "display": clean(key) if shown else mask_address(key), "masked": not shown, "messages": stats["n"],
               "unread": stats["unread"], "size_bytes": stats["size"], "first_seen": _day(stats["lo"]), "last_seen": _day(stats["hi"])}
        top = stats["types"].most_common(1)
        row["dominant_type"] = sorted(t for t, c in stats["types"].items() if c == top[0][1])[0] if top else UNCLASSIFIED
        return row

    def _senders(self, kind, rows=None):
        self._load()
        groups = defaultdict(lambda: {"n": 0, "unread": 0, "size": 0, "lo": None, "hi": None, "types": Counter()})
        for r in (self._rows if rows is None else rows):
            sender = (r["sender"] or "").strip().lower()
            if not sender or "@" not in sender:
                continue
            g = groups[_domain(sender) if kind == "domain" else sender]
            g["n"] += 1
            g["unread"] += bool(r["unread"])
            g["size"] += r["size"] or 0
            ms = r["internal_ms"]
            if ms is not None:
                g["lo"] = ms if g["lo"] is None else min(g["lo"], ms)
                g["hi"] = ms if g["hi"] is None else max(g["hi"], ms)
            g["types"][self._bucket(r["id"])] += 1
        return groups

    def senders(self, kind="domain", limit=10):
        if kind not in ("domain", "address") or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("kind must be 'domain' or 'address' and limit between 1 and 100")
        groups = self._senders(kind)
        total = len(self._rows)
        ranked = sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:limit]
        items = []
        for key, st in ranked:
            row = self._sender_row(key, kind, st)
            row["share_of_indexed_pct"] = _pct(st["n"], total)
            items.append(row)
        data = {"kind": kind, "limit": limit, "distinct": len(groups), "covered_messages": sum(st["n"] for _, st in ranked), "indexed": total, "items": items,
                "addresses_revealed": self.reveal_senders}
        return self._envelope("senders", data, "OBSERVED", ["COUNTS_FROM_LOCAL_INDEX", "ADDRESSES_MASKED_BY_DEFAULT", "DOMAIN_NOT_MASKED", "DOMINANT_TYPE_IS_INFERRED", "SNAPSHOT_NOT_LIVE"])

    def subscriptions(self, limit=8):
        self._load()
        total = len(self._rows)
        by_type = {t: [r for r in self._rows if self._bucket(r["id"]) == t] for t in SUBSCRIPTION_TYPES}
        monthly = {t: Counter(_month(r["internal_ms"]) for r in rows if r["internal_ms"] is not None) for t, rows in by_type.items()}
        periods = self._months()
        data = {"indexed": total, "types": []}
        for t in SUBSCRIPTION_TYPES:
            rows = by_type[t]
            groups = self._senders("domain", rows)
            top = sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:limit]
            data["types"].append({"type": t, "messages": len(rows), "share_of_indexed_pct": _pct(len(rows), total), "unread": sum(bool(r["unread"]) for r in rows),
                                  "domains": len(groups), "monthly": [{"period": p, "messages": monthly[t].get(p, 0)} for p in periods],
                                  "top_domains": [{"domain": clean(k), "messages": st["n"], "unread": st["unread"], "last_seen": _day(st["hi"])} for k, st in top]})
        return self._envelope("subscriptions", data, "INFERRED", ["CLASSIFICATION_IS_INFERRED", "NO_SUBJECTS_OR_BODIES", "DOMAIN_NOT_MASKED", "SNAPSHOT_NOT_LIVE"])

    def cleanup_summary(self):
        now_ms = int(self.now.timestamp() * 1000)
        s = cc.evaluate_all(self.index, self.account, now_ms=now_ms).summary
        data = {"total": s["total"], "outcomes": {k: s["outcomes"].get(k, 0) for k in (cc.ELIGIBLE, cc.REVIEW, cc.EXCLUDED)},
                "excluded_reasons": _top(s["decisive"].get(cc.EXCLUDED, {})), "review_reasons": _top(s["decisive"].get(cc.REVIEW, {})),
                "min_age_days": s["min_age_days"], "protection_rules_active": s["protection_rules_active"], "threads": s["threads"], "mixed_threads": s["mixed_threads"],
                "recommendations_only": True}
        return self._envelope("cleanup-summary", data, "MIXED", ["RECOMMENDATIONS_ONLY_NOTHING_APPLIED", "PROTECTED_MESSAGES_EXCLUDED", "ELIGIBLE_IS_NOT_A_DECISION", "SNAPSHOT_NOT_LIVE"])

    def cleanup_history(self, recent=25):
        index, account = self.index, self.account
        plans = [dict(r) for r in index._q("SELECT plan_id, state, item_count, created_at, expires_at FROM cleanup_plan WHERE account=? ORDER BY created_at, plan_id", account)]
        approvals = Counter(r["status"] for r in index._q("SELECT status FROM cleanup_approval WHERE account=?", account))
        execs = [dict(r) for r in index._q("SELECT exec_id, plan_id, state, item_count, created_at, state_changed_at FROM cleanup_execution WHERE account=? ORDER BY created_at, exec_id", account)]
        item_states = defaultdict(Counter)
        for r in index._q("SELECT exec_id, state, COUNT(*) n FROM cleanup_exec_item WHERE account=? GROUP BY exec_id, state", account):
            item_states[r["exec_id"]][r["state"]] = r["n"]
        events = Counter(r["event_type"] for r in index._q("SELECT event_type FROM cleanup_audit WHERE account=?", account))
        ok, count, bad = cleanup_audit.verify_chain(index, account)
        data = {"plans": plans, "plan_states": dict(sorted(Counter(p["state"] for p in plans).items())), "approvals": dict(sorted(approvals.items())),
                "executions": [{**e, "items": dict(sorted(item_states[e["exec_id"]].items()))} for e in execs],
                "items_applied": sum(c.get("APPLIED", 0) for c in item_states.values()),
                "audit": {"events": count, "chain_ok": ok, "first_bad_seq": bad, "by_type": dict(sorted(events.items())),
                          "recent": [{"at": e["at"], "event": e["event_type"], "plan_id": e["plan_id"]} for e in cleanup_audit.events(index, account, None, recent)]}}
        return self._envelope("cleanup-history", data, "OBSERVED", ["LOCAL_LEDGER_NOT_GMAIL_STATE", "AUDIT_CHAIN_VERIFIED_LOCALLY", "NO_MESSAGE_IDS_OR_LABELS", "SNAPSHOT_NOT_LIVE"])

    def organization(self):
        index, account = self.index, self.account
        h = label_hygiene.analyze(index, account)
        groups = label_suggest.gather(index, account)  # read once and shared: recommendations, rule proposals and filter suggestions all start from the same per-group facts
        rec = label_suggest.recommend(index, account, groups=groups)
        rules = label_suggest.suggest_rules(index, account, groups=groups)
        filt = filter_suggest.suggest(index, account, recommendation=rec)
        names = {lab.id: lab.name for lab in lm.load_labels(index, account)}

        def tally(items, key):
            return dict(sorted(Counter(key(i) for i in items).items()))
        findings = []
        for f in list(h.findings)[:8]:
            item = {"code": f.code, "variant": f.variant, "confidence": f.confidence, "basis": f.basis, "labels": list(f.labels)}
            if self.reveal_names:
                item["names"] = [clean(names.get(i, "")) for i in f.labels]
            findings.append(item)
        plans = tally([dict(r) for r in index._q("SELECT state FROM label_plan WHERE account=?", account)], lambda r: r["state"])
        data = {"labels": {"total": h.labels_total, "user": h.user_labels, "system": h.system_labels, "user_in_use": h.user_in_use},
                "hygiene": {"findings": len(h.findings), "by_code": tally(h.findings, lambda f: f.code), "by_confidence": tally(h.findings, lambda f: f.confidence), "top": findings},
                "recommendations": {"total": len(rec.items), "by_kind": tally(rec.items, lambda r: r.kind), "by_confidence": tally(rec.items, lambda r: r.confidence),
                                    "suppressed_groups": sum(n for _, n in rec.suppressed)},
                "rule_proposals": {"total": len(rules.items), "by_confidence": tally(rules.items, lambda r: r.confidence), "suppressed_groups": sum(n for _, n in rules.suppressed)},
                "filter_suggestions": {"total": len(filt.items), "by_confidence": tally(filt.items, lambda r: r.confidence)},
                "label_plans": plans, "names_revealed": self.reveal_names, "read_only": True}
        return self._envelope("organization", data, "MIXED", ["M5_ANALYSIS_READ_ONLY", "NOTHING_APPLIED_OR_CREATED", "LABEL_NAMES_HIDDEN_BY_DEFAULT", "CONFIDENCE_IS_EVIDENCE_STRENGTH", "SNAPSHOT_NOT_LIVE"])

    def section(self, name, **kw):
        fn = {"freshness": self.freshness, "overview": self.overview, "volume": self.volume, "categories": self.categories, "senders": self.senders,
              "subscriptions": self.subscriptions, "cleanup-summary": self.cleanup_summary, "cleanup-history": self.cleanup_history, "organization": self.organization}.get(name)
        if fn is None:
            raise ValueError(f"unknown section {name!r}")
        return fn(**kw)


def _top(counter, n=10):
    return [{"code": k, "messages": v} for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]
