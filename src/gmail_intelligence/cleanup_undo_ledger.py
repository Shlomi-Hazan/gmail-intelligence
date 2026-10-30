"""The undo LEDGER, read-only (M4D, moved here unchanged in M12C.3 so reporting can read it without importing the undo engine, the executor or any mailbox type).

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
