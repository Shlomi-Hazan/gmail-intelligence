"""Append-only, hash-chained local audit log for cleanup plans and approvals (M4B). Local SQLite only; no Gmail.

Each event stores the hash of the previous event of the same account, so editing or removing an earlier row is DETECTABLE by
`verify_chain`. Database triggers also refuse UPDATE/DELETE. This is tamper-EVIDENT only: a person or program that controls
the same macOS user account can drop the triggers and rewrite the whole chain. It is not an authenticated or tamper-proof log.
Events carry counts, hashes and state names only: never message ids, subjects, senders, label names or contents.
"""
import hashlib
import json

GENESIS = "0" * 64
EVENTS = ("PLAN_CREATED", "PLAN_REVIEWED", "REVIEW_REJECTED", "PLAN_APPROVED", "APPROVAL_REJECTED", "PLAN_SUPERSEDED",
          "PLAN_CANCELLED", "PLAN_EXPIRED", "APPROVAL_REVOKED", "APPROVAL_EXPIRED")


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
    sql, params = "SELECT seq, plan_id, event_type, at, meta FROM cleanup_audit WHERE account=?", [account]
    if plan_id:
        sql += " AND plan_id=?"
        params.append(plan_id)
    sql += " ORDER BY seq DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in reversed(index._q(sql, *params))]
