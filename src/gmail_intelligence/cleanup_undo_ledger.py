"""The undo and REVERSAL ledgers, read-only (M4D, moved here unchanged in M12C.3; reversal plans added in M12D so reporting can read it without importing the undo engine, the executor or any mailbox type).

An undo's state is derived from the hash-chained, append-only audit log by a STRICT state machine: UNDO_AUTHORIZED -> UNDO_INTENT -> UNDO_RESULT (see `cleanup_undo`). Nothing here writes,
contacts Gmail or takes a mailbox. Any event sequence the machine does not allow yields INCONSISTENT, which authorizes nothing and is only ever reported.
"""
import json

UNDO_EVENTS = ("UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT")
RESULTS = ("RESTORED", "NOT_RESTORED", "CONFLICT", "UNKNOWN")
STATUSES = ("NONE", "AUTHORIZED", "OPEN", "INCONSISTENT") + RESULTS


def _ledger(index, account, exec_id, seq):
    out = []
    marks = ",".join("?" * len(UNDO_EVENTS))
    for r in index._q(f"SELECT seq, event_type, at, meta, hash FROM cleanup_audit WHERE account=? AND event_type IN ({marks}) ORDER BY seq", account, *UNDO_EVENTS):
        meta = json.loads(r["meta"])
        if meta.get("exec") == exec_id and meta.get("item") == seq:
            out.append({"type": r["event_type"], "at": r["at"], "meta": meta, "hash": r["hash"]})
    return out


def _state(ledger):
    """(status, last authorization event, last intent event, last result event) derived from the ledger by a STRICT state machine.

    NONE -> AUTHORIZED -> OPEN (intent, referencing that authorization) -> a result that references that intent: RESTORED | NOT_RESTORED | CONFLICT | UNKNOWN. UNKNOWN is
    resolved only by a RECONCILE result. A new authorization is possible only from NONE or NOT_RESTORED. ANY other sequence (a second intent, an authorization while an
    attempt is open, a result for another intent, events after RESTORED or CONFLICT, missing or unknown fields) yields INCONSISTENT, which authorizes nothing."""
    bad = ("INCONSISTENT", None, None, None)
    status, auth, intent, result = "NONE", None, None, None
    for ev in ledger:
        kind, meta = ev["type"], ev["meta"]
        if kind == "UNDO_AUTHORIZED":
            if status not in ("NONE", "NOT_RESTORED"):
                return bad
            status, auth, intent, result = "AUTHORIZED", ev, None, None
        elif kind == "UNDO_INTENT":
            if status != "AUTHORIZED" or meta.get("auth") != auth["hash"]:
                return bad
            status, intent, result = "OPEN", ev, None
        elif kind == "UNDO_RESULT":
            res, via = meta.get("result"), meta.get("via")
            resolves = status == "OPEN" and via in ("DIRECT", "RECONCILE") or status == "UNKNOWN" and via == "RECONCILE"
            if res not in RESULTS or not resolves or meta.get("intent") != intent["hash"] or (via == "RECONCILE" and res == "UNKNOWN"):
                return bad
            status, result = res, ev
        else:
            return bad
    return status, auth, intent, result


def undo_status(index, account, exec_id, seq):
    return _state(_ledger(index, account, exec_id, seq))[0]


def open_undos(index, account):
    """[(exec_id, item seq, status)] for undos that need attention: an intent without a result, an UNKNOWN result or an inconsistent ledger."""
    seen, out = set(), []
    marks = ",".join("?" * len(UNDO_EVENTS))
    for r in index._q(f"SELECT meta FROM cleanup_audit WHERE account=? AND event_type IN ({marks}) ORDER BY seq", account, *UNDO_EVENTS):
        meta = json.loads(r["meta"])
        if "exec" not in meta or "item" not in meta:
            continue
        key = (meta["exec"], meta["item"])
        if key in seen:
            continue
        seen.add(key)
        status = undo_status(index, account, *key)
        if status in ("OPEN", "UNKNOWN", "INCONSISTENT"):  # an inconsistent ledger is never acted on, only reported
            out.append((key[0], key[1], status))
    return out


def all_undos(index, account):
    """[(exec_id, item seq, status)] for EVERY item that has any undo event, oldest first (read-only; for reporting)."""
    seen, out = set(), []
    marks = ",".join("?" * len(UNDO_EVENTS))
    for r in index._q(f"SELECT meta FROM cleanup_audit WHERE account=? AND event_type IN ({marks}) ORDER BY seq", account, *UNDO_EVENTS):
        meta = json.loads(r["meta"])
        if "exec" not in meta or "item" not in meta:
            continue
        key = (meta["exec"], meta["item"])
        if key not in seen:
            seen.add(key)
            out.append((key[0], key[1], undo_status(index, account, *key)))
    return out


# ---------------------------------------------------------------- bulk reversal plans (M12D)
# A reversal plan is NOT a new table: it is a sequence of events in the same hash-chained, append-only audit log, so it is immutable by construction (a plan's item list and digest are
# fixed by its REVERSAL_PLANNED event). Its state is derived by a STRICT state machine; any other sequence is INCONSISTENT and authorizes nothing. Each item is still undone by the
# unchanged per-item engine and keeps its own per-item undo ledger.
REVERSAL_EVENTS = ("REVERSAL_PLANNED", "REVERSAL_APPROVED", "REVERSAL_SLICE_STARTED", "REVERSAL_ITEM_SKIPPED", "REVERSAL_SLICE_DONE", "REVERSAL_ABORTED")
REVERSAL_STATES = ("PLANNED", "APPROVED", "IN_PROGRESS", "INTERRUPTED", "AWAITING_CONTINUATION", "COMPLETED", "STOPPED", "ABORTED", "INCONSISTENT")
RUN_TTL_SECONDS = 30 * 60   # a started slice with no result for this long is INTERRUPTED (it can only be aborted, never resumed)


def reversal_events(index, account, rev):
    out = []
    marks = ",".join("?" * len(REVERSAL_EVENTS))
    for r in index._q(f"SELECT seq, event_type, at, meta, hash FROM cleanup_audit WHERE account=? AND event_type IN ({marks}) ORDER BY seq", account, *REVERSAL_EVENTS):
        meta = json.loads(r["meta"])
        if meta.get("rev") == rev:
            out.append({"type": r["event_type"], "at": r["at"], "meta": meta, "hash": r["hash"]})
    return out


def reversal_state(events, now_iso=None):
    """Derive a reversal plan's state from its events. Returns a dict (counts and sequence numbers only; no message ids)."""
    bad = {"state": "INCONSISTENT"}
    if not events or events[0]["type"] != "REVERSAL_PLANNED":
        return bad
    plan = events[0]["meta"]
    raw_sizes, raw_items = plan.get("slices"), plan.get("items")      # flat audit metadata: {"1": size, ...} and {"<item seq>": slice number}
    try:
        sizes = [raw_sizes[str(i)] for i in range(1, len(raw_sizes) + 1)]
        items = sorted(int(k) for k in raw_items)
        assign = {int(k): v for k, v in raw_items.items()}
    except (TypeError, KeyError, ValueError, AttributeError):
        return bad
    if not sizes or not all(isinstance(x, int) and x > 0 for x in sizes) or sum(sizes) != len(items) or any(
            sum(1 for s in items if assign[s] == n) != sizes[n - 1] for n in range(1, len(sizes) + 1)) or any(assign[s] > assign[t] for s, t in zip(items, items[1:])):
        return bad
    st = {"state": "PLANNED", "exec": plan.get("exec"), "items": items, "assign": assign, "digest": plan.get("digest"), "slices": list(sizes), "approved": False, "approval_expires": None,
          "done": 0, "started": None, "started_at": None, "stopped": False, "aborted": False, "skipped": {}, "restored": 0, "unresolved": 0}
    for ev in events[1:]:
        kind, meta = ev["type"], ev["meta"]
        if st["aborted"] or st["stopped"] and kind != "REVERSAL_ABORTED":
            if not (kind == "REVERSAL_ABORTED" and not st["aborted"]):
                return bad
        if kind == "REVERSAL_PLANNED":
            return bad
        elif kind == "REVERSAL_APPROVED":
            if st["approved"] or st["started"] is not None or st["done"] or meta.get("digest") != st["digest"]:
                return bad
            st["approved"], st["approval_expires"] = True, meta.get("expires")
        elif kind == "REVERSAL_SLICE_STARTED":
            if not st["approved"] or st["started"] is not None or meta.get("slice") != st["done"] + 1 or st["done"] >= len(sizes) or meta.get("size") != sizes[st["done"]]:
                return bad
            st["started"], st["started_at"] = meta["slice"], ev["at"]
        elif kind == "REVERSAL_ITEM_SKIPPED":
            if st["started"] is None or meta.get("slice") != st["started"] or not isinstance(meta.get("item"), int) or meta["item"] in st["skipped"]:
                return bad
            st["skipped"][meta["item"]] = meta.get("code")
        elif kind == "REVERSAL_SLICE_DONE":
            if st["started"] is None or meta.get("slice") != st["started"]:
                return bad
            st["done"], st["started"], st["started_at"] = st["done"] + 1, None, None
            st["stopped"] = bool(meta.get("stopped"))
            st["restored"] += int(meta.get("restored", 0))
        elif kind == "REVERSAL_ABORTED":
            if st["started"] is not None and not _expired(st["started_at"], now_iso):
                return bad
            st["aborted"] = True
    if st["aborted"]:
        st["state"] = "ABORTED"
    elif st["started"] is not None:
        st["state"] = "INTERRUPTED" if _expired(st["started_at"], now_iso) else "IN_PROGRESS"
    elif st["stopped"]:
        st["state"] = "STOPPED"
    elif st["done"] == len(sizes):
        st["state"] = "COMPLETED"
    elif st["done"]:
        st["state"] = "AWAITING_CONTINUATION"
    else:
        st["state"] = "APPROVED" if st["approved"] else "PLANNED"
    return st


def _expired(started_at, now_iso):
    if not now_iso or not started_at:
        return False
    from datetime import datetime
    a, b = datetime.fromisoformat(started_at.replace("Z", "+00:00")), datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    return (b - a).total_seconds() > RUN_TTL_SECONDS


def all_reversals(index, account):
    """[rev ids] in creation order (read-only)."""
    return [json.loads(r["meta"])["rev"] for r in index._q("SELECT meta FROM cleanup_audit WHERE account=? AND event_type='REVERSAL_PLANNED' ORDER BY seq", account)
            if "rev" in json.loads(r["meta"])]


def reversal_approved(index, account, rev):
    return any(e["type"] == "REVERSAL_APPROVED" for e in reversal_events(index, account, rev))

