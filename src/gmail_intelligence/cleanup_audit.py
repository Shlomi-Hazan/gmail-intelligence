"""Append-only, hash-chained local audit log for cleanup plans and approvals (M4B). Local SQLite only; no Gmail.

Each event stores the hash of the previous event of the same account, so editing or removing an EARLIER row is detectable by
`verify_chain`. Database triggers also refuse UPDATE/DELETE. Limits, stated plainly:
  * deleting the LAST events (or the whole log) cannot be detected from the database alone; only an independently stored
    checkpoint (a head hash the owner wrote down earlier, see `contains`) can reveal that;
  * a person or program that controls the same macOS user account can drop the triggers and rewrite or re-chain everything;
  * it is therefore tamper-EVIDENT at best, never tamper-proof and never authenticated.
Events carry counts, hashes and state names only: never message ids, subjects, senders, label names or contents.
"""
import hashlib
import json

GENESIS = "0" * 64
EVENTS = ("PLAN_CREATED", "PLAN_REVIEWED", "REVIEW_REJECTED", "PLAN_APPROVED", "APPROVAL_REJECTED", "PLAN_SUPERSEDED",
          "PLAN_CANCELLED", "PLAN_EXPIRED", "APPROVAL_REVOKED", "APPROVAL_EXPIRED", "ATTEMPTS_LOCKED_OUT",
          # M4C-A: local execution lifecycle (counts/state names only; item events carry a sequence number, never a message id)
          "EXECUTION_RESERVED", "RESERVATION_REJECTED", "SLICE_CONFIRMED", "EXECUTION_TRANSITION", "SLICE_TRANSITION",
          "ITEM_TRANSITION", "EXECUTION_INTERRUPTED")


def canonical(obj):
    """Deterministic JSON used for every hash in M4B (sorted keys, no whitespace, ASCII only)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _clean(meta):
    for k, v in meta.items():
        if not isinstance(k, str) or not (v is None or isinstance(v, (str, int, bool)) or
                                          (isinstance(v, dict) and all(isinstance(x, (str, int)) for x in v.values()))):
            raise ValueError("audit metadata must be flat counts/hashes")
        if isinstance(v, str) and len(v) > 200:
            raise ValueError("audit metadata value too long")
    return meta


def append(index, account, plan_id, event, at, meta=None):
    """Add one event. MUST be called inside the caller's transaction so the chain head cannot race."""
    if event not in EVENTS:
        raise ValueError(f"unknown audit event {event}")
    meta = _clean(dict(meta or {}))
    rows = index._q("SELECT hash FROM cleanup_audit WHERE account=? ORDER BY seq DESC LIMIT 1", account)
    prev = rows[0]["hash"] if rows else GENESIS
    h = sha256(canonical({"account": account, "plan_id": plan_id, "event": event, "at": at, "meta": meta, "prev": prev}))
    index.conn.execute("INSERT INTO cleanup_audit (account, plan_id, event_type, at, meta, prev_hash, hash) "
                       "VALUES (?,?,?,?,?,?,?)", (account, plan_id, event, at, canonical(meta), prev, h))
    return h


def verify_chain(index, account):
    """Recompute the account's chain. Returns (ok, event_count, first_bad_seq or None)."""
    prev, n = GENESIS, 0
    for r in index._q("SELECT * FROM cleanup_audit WHERE account=? ORDER BY seq", account):
        n += 1
        try:
            meta = json.loads(r["meta"])
        except ValueError:
            return False, n, r["seq"]
        want = sha256(canonical({"account": account, "plan_id": r["plan_id"], "event": r["event_type"], "at": r["at"],
                                 "meta": meta, "prev": prev}))
        if r["prev_hash"] != prev or r["hash"] != want:
            return False, n, r["seq"]
        prev = r["hash"]
    return True, n, None


def events(index, account, plan_id=None, limit=50):
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    sql, params = "SELECT seq, plan_id, event_type, at, meta FROM cleanup_audit WHERE account=?", [account]
    if plan_id:
        sql += " AND plan_id=?"
        params.append(plan_id)
    sql += " ORDER BY seq DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in reversed(index._q(sql, *params))]


def head(index, account):
    """(event_count, head_hash or None): the value an owner can write down as an independent checkpoint."""
    rows = index._q("SELECT COUNT(*) n, (SELECT hash FROM cleanup_audit WHERE account=? ORDER BY seq DESC LIMIT 1) h "
                    "FROM cleanup_audit WHERE account=?", account, account)
    return rows[0]["n"], rows[0]["h"]


def contains(index, account, hash_prefix):
    """True if an event whose hash starts with `hash_prefix` (>= 8 hex chars) is still in the account's chain."""
    prefix = (hash_prefix or "").strip().lower()
    if len(prefix) < 8 or any(c not in "0123456789abcdef" for c in prefix):
        raise ValueError("a checkpoint is at least 8 hexadecimal characters")
    return bool(index._q("SELECT 1 FROM cleanup_audit WHERE account=? AND substr(hash, 1, ?) = ? LIMIT 1",
                         account, len(prefix), prefix))


def last_time(index, account):
    rows = index._q("SELECT at FROM cleanup_audit WHERE account=? ORDER BY seq DESC LIMIT 1", account)
    return rows[0]["at"] if rows else None


def recent(index, account, plan_id, events_, since):
    """Count events of the given types for one plan at or after the ISO time `since`."""
    marks = ",".join("?" * len(events_))
    return index._q(f"SELECT COUNT(*) FROM cleanup_audit WHERE account=? AND plan_id=? AND at>=? AND event_type IN ({marks})",
                    account, plan_id, since, *events_)[0][0]
