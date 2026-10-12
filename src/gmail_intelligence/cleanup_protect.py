"""User protection rules for cleanup (M4A): messages matching an ENABLED rule are never cleanup candidates.

Same exact-match vocabulary as M3 classification rules (sender address, sender domain, Gmail label id or name; all given
conditions must match, several rules combine as OR). Local SQLite only; no Gmail, no code evaluation, no wildcards.
"""
import hashlib
import json

from gmail_intelligence import classify
from gmail_intelligence.classify import Rule, RuleError
from gmail_intelligence.index import _now


def rows(index, account):
    return [dict(r) for r in index._q("SELECT * FROM protect_rules WHERE account=? ORDER BY CAST(substr(id,2) AS INTEGER)",
                                      account)]


def _rule(r):
    return Rule(r["id"], "protect", "PROTECT", "HIGH", r["note"] or "user protection rule", sender=r["c_sender"],
                domain=r["c_domain"], label=r["c_label"])


def active(index, account):
    return [_rule(r) for r in rows(index, account) if r["enabled"]]


def fingerprint(account, rules):
    """Fingerprint of the ENABLED protection rules; any change alters candidate output and this value."""
    payload = [account.lower(), sorted((r.id, r.sender, r.domain, r.label) for r in rules)]
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()[:16]


def add(index, account, sender=None, domain=None, label=None, note=None):
    cond = classify.validate_conditions(sender, domain, label)
    if not cond:
        raise RuleError("a protection rule needs at least one of sender, domain or label")
    note = (note or "").strip()[:200]
    if any(ord(c) < 32 for c in note):
        raise RuleError("note must not contain control characters")
    with index.conn:
        nums = [int(r["id"][1:]) for r in index._q("SELECT id FROM protect_rules WHERE account=?", account)]
        rid = f"p{max(nums, default=0) + 1}"
        index.conn.execute("INSERT INTO protect_rules (account,id,c_sender,c_domain,c_label,enabled,note,created_at) "
                           "VALUES (?,?,?,?,?,1,?,?)", (account, rid, cond.get("sender"), cond.get("domain"),
                                                         cond.get("label"), note, _now()))
    return rid


def set_enabled(index, account, rule_id, enabled):
    with index.conn:
        cur = index.conn.execute("UPDATE protect_rules SET enabled=? WHERE account=? AND id=?",
                                 (1 if enabled else 0, account, rule_id))
    return cur.rowcount == 1


def remove(index, account, rule_id):
    with index.conn:
        cur = index.conn.execute("DELETE FROM protect_rules WHERE account=? AND id=?", (account, rule_id))
    return cur.rowcount == 1


HIDDEN_ACCOUNT = "<account hidden>"
HIDDEN_VALUE = "<hidden>"


def mask_value(kind, value):
    """Default display of a stored condition: fully hidden (use --show-values to reveal)."""
    return None if value is None else HIDDEN_VALUE
