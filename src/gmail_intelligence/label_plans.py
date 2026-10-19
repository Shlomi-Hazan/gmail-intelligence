"""Immutable label-change plans and one-time LOCAL approvals (M5D). Local SQLite only; NEVER contacts Gmail; NO executor exists.

A plan is a finite, explicit list of operations on Gmail USER labels of ONE account: CREATE, RENAME (leaf only), NEST (move under another parent or to top level) and MERGE
(fold one label into another). It is frozen as canonical JSON, bound by its full SHA-256 and by the hash of the label inventory it was built from. An approval is only a LOCAL
LEDGER RECORD of a typed confirmation: it grants no OAuth permission and nothing in this build can execute a label plan (a static test enforces that there is no execute path).

Everything fails closed: any invalid, ambiguous or stale operation rejects the WHOLE plan (nothing is trimmed). Audit events share the M4 `cleanup_audit` hash chain, so the
existing chain verification covers label plans; events carry counts, kinds and hashes only, never label names or ids.

Limitations, stated plainly (also in docs/LABELS.md):
  * there is no real undo; a MERGE may be irreversible in Gmail (the source label disappears and its messages keep only the target), and renaming or nesting a parent changes the
    full path of every child label;
  * Gmail's actual behaviour for these operations is NOT verified by this build;
  * freshness is judged against the LOCAL label inventory (the last scan); changes made in Gmail after that scan are invisible here.
"""
import json
import secrets
import sqlite3

from gmail_intelligence import cleanup_audit as audit, label_model as lm
from gmail_intelligence.cleanup_audit import canonical, sha256
from gmail_intelligence.cleanup_plans import APPROVAL_TTL, CLOCK_TOLERANCE, LOCKOUT_WINDOW, MAX_FAILED_ATTEMPTS, PLAN_TTL, PlanError, _check_clock, _iso, _parse, _txn, _utc, short, valid_id

FORMAT_VERSION = 1
KINDS = ("CREATE", "RENAME", "NEST", "MERGE")
MAX_OPS = 50
SNAPSHOT_KEYS = ("format", "kind", "plan_id", "account", "created_at", "expires_at", "inventory_sha256", "labels_total", "max_depth", "executable", "reversible", "ops")
OP_KEYS = frozenset({"seq", "op", "label_id", "target_id", "old_name", "new_name", "descendants"})
LIVE_STATES = ("DRAFT", "REVIEWED", "APPROVED")
LIMITATIONS = ("No label plan can be executed: no executor exists in this build.", "There is no real undo; a MERGE may be irreversible in Gmail.",
               "Renaming or nesting a parent label changes the full path of its child labels.", "Gmail's behaviour for these operations is not verified by this tool.",
               "Freshness is judged against the local label inventory (last scan), not live Gmail.")


def review_phrase(plan):
    return f"REVIEWED LABEL PLAN {plan['op_count']} {short(plan['plan_hash'])}"


def approval_phrase(plan):
    return f"APPROVE LABEL PLAN {plan['op_count']} {short(plan['plan_hash'])}"


# ---------------------------------------------------------------- the operation model (pure)
class _State:
    """The label inventory as a plan changes it: current names by id, a normalized-name map (duplicate detection), and which labels earlier operations already used."""

    def __init__(self, labels):
        self.by_id = {l.id: l for l in labels}
        self.name = {l.id: l.name for l in labels}
        self.norm = {}
        for l in labels:
            self.norm.setdefault(lm.normalize(l.name), l.id)
        self.created = []
        self.subjects, self.removed, self.targets = set(), set(), set()

    def descendants(self, lid):
        prefix = self.name[lid] + "/"
        return sorted(i for i, n in self.name.items() if n.startswith(prefix) and i not in self.removed)


def inventory_hash(labels):
    return sha256(canonical(sorted([l.id, l.name, l.type or ""] for l in labels)))


def _user(st, lid):
    lab = st.by_id.get(lid)
    if lab is None:
        raise PlanError("NO_SUCH_LABEL", "an operation refers to a label that is not in this account's local inventory")
    if lab.system:
        raise PlanError("SYSTEM_LABEL", "system labels are never changed by a plan")
    if lid in st.removed:
        raise PlanError("CONFLICTING_OPS", "an operation refers to a label that an earlier operation merges away")
    return lab


def _check_new_name(st, new, own=()):
    problem = lm.name_problem(new)
    if problem:
        raise PlanError("BAD_NAME", f"the new label name is not allowed ({problem})")
    if lm.reserved(new):
        raise PlanError("RESERVED_NAME", "the new label name collides with a system label name")
    if lm.depth(new) > lm.MAX_DEPTH:
        raise PlanError("TOO_DEEP", f"nesting deeper than {lm.MAX_DEPTH} levels is not allowed")
    parent = lm.parent_path(new)
    if parent and lm.normalize(parent) not in st.norm:
        raise PlanError("PARENT_MISSING", "the parent label does not exist (create it earlier in the same plan)")
    other = st.norm.get(lm.normalize(new))
    if other is not None and other not in own:
        raise PlanError("DUPLICATE_NAME", "a label with this name (ignoring case and spacing) already exists")


def _step(st, op):
    """Validate one explicit operation against the state and apply it. Raises PlanError (stable code); the caller rejects the whole plan."""
    kind, lid, new = op["op"], op["label_id"], op["new_name"]
    if kind == "CREATE":
        if lid or op["target_id"] or op["old_name"]:
            raise PlanError("BAD_OP", "a CREATE operation carries only a new name")
        _check_new_name(st, new)
        st.norm[lm.normalize(new)] = "new:" + str(len(st.created))
        st.created.append(new)
    elif kind in ("RENAME", "NEST"):
        _user(st, lid)
        cur = st.name[lid]
        if op["old_name"] != st.name[lid]:
            raise PlanError("STALE_OLD_NAME", "the label no longer has the name the operation was built for")
        if lid in st.subjects or lid in st.targets:
            raise PlanError("CONFLICTING_OPS", "a label may be the subject of one operation and is not changed if another operation merges into it")
        if new == cur:
            raise PlanError("NO_CHANGE", "the operation does not change the label")
        if kind == "RENAME" and lm.parent_path(new) != lm.parent_path(cur):
            raise PlanError("BAD_OP", "a rename changes only the last name segment")
        if kind == "NEST" and lm.leaf(new) != lm.leaf(cur):
            raise PlanError("BAD_OP", "a nest keeps the last name segment")
        if kind == "NEST" and (lm.normalize(new) + "/").startswith(lm.normalize(cur) + "/"):
            raise PlanError("CYCLE", "a label cannot be nested under itself or one of its own children")
        desc = st.descendants(lid)
        deepest = max([lm.depth(st.name[d]) - lm.depth(cur) for d in desc], default=0)
        if lm.depth(new) + deepest > lm.MAX_DEPTH:
            raise PlanError("TOO_DEEP", f"the label or one of its children would be nested deeper than {lm.MAX_DEPTH} levels")
        if op.get("descendants") != len(desc):
            raise PlanError("STALE_OLD_NAME", "the label's children changed since the operation was built")
        for i in (lid, *desc):
            st.norm = {k: v for k, v in st.norm.items() if v != i}
        _check_new_name(st, new)
        st.norm[lm.normalize(new)] = lid
        renamed = {d: new + st.name[d][len(cur):] for d in sorted(desc, key=lambda d: lm.depth(st.name[d]))}  # parents first, so each child's parent exists
        for d, n in renamed.items():
            _check_new_name(st, n)
            st.norm[lm.normalize(n)] = d
        st.name[lid] = new
        st.name.update(renamed)
        st.subjects.add(lid)
    elif kind == "MERGE":
        _user(st, lid)
        dst_id = op["target_id"]
        _user(st, dst_id)
        if lid == dst_id:
            raise PlanError("SAME_LABEL", "a label cannot be merged into itself")
        if op["old_name"] != st.name[lid] or new != st.name[dst_id]:
            raise PlanError("STALE_OLD_NAME", "a label no longer has the name the operation was built for")
        if lid in st.subjects or lid in st.targets or dst_id in st.subjects:
            raise PlanError("CONFLICTING_OPS", "a label may be the subject of one operation; merge chains are not allowed")
        if st.descendants(lid):
            raise PlanError("HAS_CHILDREN", "a label with child labels cannot be merged away (its children would be orphaned)")
        st.removed.add(lid)
        st.targets.add(dst_id)
        st.norm = {k: v for k, v in st.norm.items() if v != lid}
    else:
        raise PlanError("BAD_OP", "unknown operation")


def _find(st, ref, what="label"):
    ref = (ref or "").strip()
    if not ref:
        raise PlanError("NO_SUCH_LABEL", f"give a {what} id or exact name")
    if ref in st.by_id:
        found = [ref]
    else:
        found = sorted(i for i, n in st.name.items() if n == ref and i not in st.removed)
    if len(found) > 1:
        raise PlanError("AMBIGUOUS_LABEL", f"{len(found)} labels share this name; use the label id")
    if not found:
        if ref in lm.SYSTEM_IDS or lm.reserved(ref):
            raise PlanError("SYSTEM_LABEL", "system labels are never changed by a plan")
        raise PlanError("NO_SUCH_LABEL", f"no such {what} in this account's local inventory")
    return found[0]


def build_ops(labels, specs):
    """Resolve owner specs into explicit, validated operations. Specs: ('CREATE', name), ('RENAME', ref, new_leaf), ('NEST', ref, parent_ref_or_''), ('MERGE', ref, target_ref).
    Returns (ops, state). Any problem raises PlanError and nothing is built."""
    if not specs:
        raise PlanError("NO_OPS", "no operations given; nothing is selected by default")
    if len(specs) > MAX_OPS:
        raise PlanError("TOO_MANY_OPS", f"a plan may contain at most {MAX_OPS} operations")
    if not labels:
        raise PlanError("NO_INVENTORY", "the local index has no label inventory; run `mailbox scan` first")
    st = _State(labels)
    ops = []
    for seq, spec in enumerate(specs, 1):
        kind = str(spec[0]).upper() if spec else ""
        if kind not in KINDS:
            raise PlanError("BAD_OP", "operations are CREATE, RENAME, NEST or MERGE")
        if kind == "CREATE":
            op = {"op": kind, "label_id": "", "target_id": "", "old_name": "", "new_name": spec[1], "descendants": 0}
        elif kind == "MERGE":
            sid, tid = _find(st, spec[1]), _find(st, spec[2], "target label")
            op = {"op": kind, "label_id": sid, "target_id": tid, "old_name": st.name[sid], "new_name": st.name[tid], "descendants": 0}
        else:
            lid = _find(st, spec[1])
            _user(st, lid)
            cur = st.name[lid]
            if kind == "RENAME":
                leaf = spec[2]
                if not isinstance(leaf, str) or "/" in leaf:
                    raise PlanError("BAD_NAME", "a rename takes the new last name segment only (no '/')")
                parent = lm.parent_path(cur)
                new, target = (parent + "/" if parent else "") + leaf, ""
            else:
                ref = (spec[2] or "").strip()
                if not ref:
                    new, target = lm.leaf(cur), ""
                else:
                    if ref in st.by_id or any(n == ref for i, n in st.name.items() if i not in st.removed):
                        pid = _find(st, ref, "parent label")
                        _user(st, pid)
                        pname, target = st.name[pid], pid
                    elif ref in st.created:
                        pname, target = ref, ""
                    else:
                        raise PlanError("NO_SUCH_LABEL", "no such parent label in this account's local inventory or earlier in this plan")
                    new = pname + "/" + lm.leaf(cur)
            op = {"op": kind, "label_id": lid, "target_id": target, "old_name": cur, "new_name": new, "descendants": len(st.descendants(lid))}
        op["seq"] = seq
        _step(st, op)
        ops.append(op)
    return ops, st


def validate_snapshot_ops(labels, ops):
    """Re-run every stored operation against the CURRENT inventory. Returns {code: n}; empty means all still valid."""
    st, problems = _State(labels), {}
    for op in ops:
        try:
            _step(st, op)
        except PlanError as exc:
            problems["OP_" + exc.code] = problems.get("OP_" + exc.code, 0) + 1
    return problems


# ---------------------------------------------------------------- snapshot, loading and integrity
def _snapshot(plan_id, account, created, expires, inv_hash, labels_total, ops):
    return {"format": FORMAT_VERSION, "kind": "LABEL_PLAN", "plan_id": plan_id, "account": account, "created_at": created, "expires_at": expires,
            "inventory_sha256": inv_hash, "labels_total": labels_total, "max_depth": lm.MAX_DEPTH, "executable": False, "reversible": False, "ops": ops}


def _row(index, account, plan_id):
    rows = index._q("SELECT * FROM label_plan WHERE account=? AND plan_id=?", account, plan_id)
    if not rows:
        raise PlanError("NO_SUCH_PLAN", "no such label plan for this account")
    return dict(rows[0])


def get_plan(index, account, plan_id):
    p = _row(index, account, plan_id)
    p["ops"] = [dict(r) for r in index._q("SELECT seq, op, label_id, target_id, old_name, new_name, op_digest FROM label_plan_op WHERE account=? AND plan_id=? ORDER BY seq", account, plan_id)]
    return p


def _shape_ok(snap):
    try:
        return (isinstance(snap, dict) and all(k in snap for k in SNAPSHOT_KEYS) and snap["format"] == FORMAT_VERSION and snap["kind"] == "LABEL_PLAN"
                and isinstance(snap["ops"], list) and all(isinstance(o, dict) and set(o) == OP_KEYS and o["op"] in KINDS for o in snap["ops"])
                and isinstance(snap["account"], str) and isinstance(snap["inventory_sha256"], str))
    except (KeyError, TypeError):
        return False


def snapshot_of(plan):
    try:
        snap = json.loads(plan["snapshot"])
    except (ValueError, TypeError):
        snap = None
    if not _shape_ok(snap):
        raise PlanError("SNAPSHOT_UNREADABLE", "the stored plan snapshot is unreadable or malformed; nothing was changed. Cancel this plan and create a new one.")
    return snap


def integrity_problems(plan):
    """Re-derive everything from the stored canonical snapshot: hash, bound columns and the redundant operation rows."""
    if sha256(plan["snapshot"]) != plan["plan_hash"]:
        return ["HASH_MISMATCH"]
    try:
        snap = json.loads(plan["snapshot"])
    except (ValueError, TypeError):
        return ["SNAPSHOT_UNREADABLE"]
    if not _shape_ok(snap):
        return ["SNAPSHOT_MALFORMED"]
    problems = []
    if canonical(snap) != plan["snapshot"]:
        problems.append("SNAPSHOT_NOT_CANONICAL")
    for key in ("account", "plan_id", "created_at", "expires_at"):
        if snap.get(key) != plan[key]:
            problems.append("COLUMN_MISMATCH")
    if snap["inventory_sha256"] != plan["inventory_hash"] or len(snap["ops"]) != plan["op_count"]:
        problems.append("COLUMN_MISMATCH")
    if snap["executable"] is not False or snap["reversible"] is not False:
        problems.append("FLAGS_TAMPERED")
    want = [(o["seq"], o["op"], o["label_id"], o["target_id"], o["old_name"], o["new_name"], sha256(canonical(o))) for o in snap["ops"]]
    have = [(o["seq"], o["op"], o["label_id"], o["target_id"], o["old_name"], o["new_name"], o["op_digest"]) for o in plan["ops"]]
    if want != have or [o["seq"] for o in snap["ops"]] != list(range(1, len(snap["ops"]) + 1)):
        problems.append("OP_TABLE_MISMATCH")
    return sorted(set(problems))


def revalidate(index, account, plan, now=None):
    """Fail-closed freshness check against the LOCAL inventory. Returns {problem_code: count}; empty means fresh."""
    now = _utc(now)
    problems = {}

    def bad(code, n=1):
        problems[code] = problems.get(code, 0) + n
    if plan["account"] != account:
        bad("ACCOUNT_MISMATCH")
    for code in integrity_problems(plan):
        bad(code)
    if problems:
        return problems
    snap = snapshot_of(plan)
    if _iso(now) >= plan["expires_at"]:
        bad("PLAN_EXPIRED")
    if now < _parse(plan["created_at"]) - CLOCK_TOLERANCE:
        bad("PLAN_FROM_THE_FUTURE")
    labels = lm.load_labels(index, account)
    if inventory_hash(labels) != snap["inventory_sha256"]:
        bad("INVENTORY_CHANGED")
    else:
        for code, n in validate_snapshot_ops(labels, snap["ops"]).items():
            bad(code, n)
    return problems


def _describe(problems):
    return ", ".join(f"{k}={v}" for k, v in sorted(problems.items()))


# ---------------------------------------------------------------- lifecycle
def _set_state(index, account, plan_id, state, at, reviewed=False):
    if reviewed:
        index.conn.execute("UPDATE label_plan SET state=?, reviewed_at=?, state_changed_at=? WHERE account=? AND plan_id=?", (state, at, at, account, plan_id))
    else:
        index.conn.execute("UPDATE label_plan SET state=?, state_changed_at=? WHERE account=? AND plan_id=?", (state, at, account, plan_id))


def _close_approvals(index, account, plan_id, status, at):
    return index.conn.execute("UPDATE label_plan_approval SET status=?, status_changed_at=? WHERE account=? AND plan_id=? AND status='VALID'", (status, at, account, plan_id)).rowcount


def expire_due(index, account, now=None):
    """Move label plans/approvals past their expiry to EXPIRED. Maintenance write; returns the number of plans expired."""
    now = _utc(now)
    at = _iso(now)
    due = [r["plan_id"] for r in index._q(
        "SELECT p.plan_id FROM label_plan p WHERE p.account=? AND p.state IN ('DRAFT','REVIEWED','APPROVED') AND (p.expires_at <= ? OR EXISTS "
        "(SELECT 1 FROM label_plan_approval a WHERE a.account=p.account AND a.plan_id=p.plan_id AND a.status='VALID' AND a.expires_at <= ?))", account, at, at)]
    if not due:
        return 0
    with _txn(index):
        for pid in due:
            if _close_approvals(index, account, pid, "EXPIRED", at):
                audit.append(index, account, pid, "LABEL_APPROVAL_EXPIRED", at, {})
            _set_state(index, account, pid, "EXPIRED", at)
            audit.append(index, account, pid, "LABEL_PLAN_EXPIRED", at, {})
    return len(due)


def create_plan(index, account, specs, now=None):
    """Create a DRAFT label plan. Fails closed (nothing created) on any invalid, ambiguous or conflicting operation."""
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)
    with _txn(index):
        _check_clock(index, account, now)
        labels = lm.load_labels(index, account)
        ops, _ = build_ops(labels, specs)
        plan_id = None
        for _ in range(5):
            cand = "lplan-" + secrets.token_hex(4)
            if not index._q("SELECT 1 FROM label_plan WHERE account=? AND plan_id=?", account, cand):
                plan_id = cand
                break
        if plan_id is None or not valid_id(plan_id):
            raise PlanError("ID_UNAVAILABLE", "could not allocate a plan id; try again")
        inv = inventory_hash(labels)
        snap = _snapshot(plan_id, account, at, _iso(now + PLAN_TTL), inv, len(labels), ops)
        text = canonical(snap)
        plan_hash = sha256(text)
        index.conn.execute("INSERT INTO label_plan (account, plan_id, state, plan_hash, inventory_hash, snapshot, op_count, created_at, expires_at, state_changed_at) "
                           "VALUES (?,?,'DRAFT',?,?,?,?,?,?,?)", (account, plan_id, plan_hash, inv, text, len(ops), at, snap["expires_at"], at))
        index.conn.executemany("INSERT INTO label_plan_op (account, plan_id, seq, op, label_id, target_id, old_name, new_name, op_digest) VALUES (?,?,?,?,?,?,?,?,?)",
                               [(account, plan_id, o["seq"], o["op"], o["label_id"], o["target_id"], o["old_name"], o["new_name"], sha256(canonical(o))) for o in ops])
        kinds = {k: sum(1 for o in ops if o["op"] == k) for k in KINDS if any(o["op"] == k for o in ops)}
        audit.append(index, account, plan_id, "LABEL_PLAN_CREATED", at, {"ops": len(ops), "plan_hash": plan_hash, "kinds": kinds})
    return get_plan(index, account, plan_id)


def _reject(index, account, plan_id, event, at, code):
    try:
        with _txn(index):
            audit.append(index, account, plan_id, event, at, {"code": code})
        return True
    except sqlite3.Error:
        return False


def _lockout(index, account, plan_id, now):
    since = _iso(now - LOCKOUT_WINDOW)
    if audit.recent(index, account, plan_id, ("LABEL_APPROVAL_REJECTED", "LABEL_REVIEW_REJECTED"), since) >= MAX_FAILED_ATTEMPTS:
        raise PlanError("LOCKED_OUT", f"{MAX_FAILED_ATTEMPTS} failed confirmations for this plan in the last {int(LOCKOUT_WINDOW.total_seconds() // 60)} minutes; "
                        "further attempts are refused until the window passes")


def _note_lockout(index, account, plan_id, now):
    since = _iso(now - LOCKOUT_WINDOW)
    try:
        with _txn(index):
            if not audit.recent(index, account, plan_id, ("LABEL_ATTEMPTS_LOCKED_OUT",), since):
                audit.append(index, account, plan_id, "LABEL_ATTEMPTS_LOCKED_OUT", _iso(now), {"window_minutes": int(LOCKOUT_WINDOW.total_seconds() // 60)})
    except sqlite3.Error:
        pass


def _guard(index, account, plan_id, event, now, body):
    at = _iso(now)
    err = None
    try:
        with _txn(index):
            _check_clock(index, account, now)
            plan = get_plan(index, account, plan_id)
            _lockout(index, account, plan_id, now)
            return body(plan)
    except sqlite3.IntegrityError:
        dup = bool(index._q("SELECT 1 FROM label_plan_approval WHERE account=? AND plan_id=? AND status='VALID'", account, plan_id))
        err = PlanError("ALREADY_APPROVED", "a valid approval already exists for this plan") if dup else PlanError(
            "DB_CONSTRAINT", "an unexpected database constraint stopped this step; nothing was changed")
    except PlanError as exc:
        err = exc
    if err.code == "LOCKED_OUT":
        _note_lockout(index, account, plan_id, now)
    elif err.code not in ("NO_SUCH_PLAN", "CLOCK_ROLLBACK") and not _reject(index, account, plan_id, event, at, err.code):
        err = PlanError(err.code, str(err) + " [warning: the audit entry for this failure could not be written]")
    raise err


def mark_reviewed(index, account, plan_id, phrase, now=None):
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)

    def body(plan):
        if plan["state"] != "DRAFT":
            raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a DRAFT plan can be reviewed")
        problems = revalidate(index, account, plan, now)
        if problems:
            raise PlanError("STALE", "label plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
        if (phrase or "").strip() != review_phrase(plan):
            raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; plan stays DRAFT")
        _set_state(index, account, plan_id, "REVIEWED", at, reviewed=True)
        audit.append(index, account, plan_id, "LABEL_PLAN_REVIEWED", at, {"ops": plan["op_count"], "plan_hash": plan["plan_hash"]})
    _guard(index, account, plan_id, "LABEL_REVIEW_REJECTED", now, body)
    return get_plan(index, account, plan_id)


def approve(index, account, plan_id, phrase, now=None):
    """Record a LOCAL one-time approval for a REVIEWED, fresh label plan. Grants no Gmail permission; executes nothing (nothing can)."""
    now = _utc(now)
    at = _iso(now)
    expire_due(index, account, now)

    def body(plan):
        if plan["state"] == "APPROVED":
            raise PlanError("ALREADY_APPROVED", "this plan already has an approval; approvals are one-time and cannot be repeated")
        if plan["state"] != "REVIEWED":
            raise PlanError("BAD_STATE", f"plan is {plan['state']}; only a REVIEWED plan can be approved")
        problems = revalidate(index, account, plan, now)
        if problems:
            raise PlanError("STALE", "label plan is stale or inconsistent: " + _describe(problems) + ". Create a new plan.")
        if (phrase or "").strip() != approval_phrase(plan):
            raise PlanError("BAD_CONFIRMATION", "confirmation text did not match; nothing was approved")
        nonce = secrets.token_hex(16)
        expires = min(now + APPROVAL_TTL, _parse(plan["expires_at"]))
        index.conn.execute("INSERT INTO label_plan_approval (account, plan_id, nonce, plan_hash, op_count, created_at, expires_at, status, status_changed_at) "
                           "VALUES (?,?,?,?,?,?,?,'VALID',?)", (account, plan_id, nonce, plan["plan_hash"], plan["op_count"], at, _iso(expires), at))
        _set_state(index, account, plan_id, "APPROVED", at)
        audit.append(index, account, plan_id, "LABEL_PLAN_APPROVED", at,
                     {"ops": plan["op_count"], "plan_hash": plan["plan_hash"], "nonce_sha256": sha256(nonce), "expires_at": _iso(expires)})
    _guard(index, account, plan_id, "LABEL_APPROVAL_REJECTED", now, body)
    return approval_status(index, account, plan_id)


def cancel(index, account, plan_id, now=None):
    now = _utc(now)
    at = _iso(now)
    with _txn(index):
        plan = _row(index, account, plan_id)
        if plan["state"] not in LIVE_STATES:
            raise PlanError("NOT_ACTIVE", f"plan is already {plan['state']}")
        if _close_approvals(index, account, plan_id, "REVOKED", at):
            audit.append(index, account, plan_id, "LABEL_APPROVAL_REVOKED", at, {"reason": "cancelled"})
        _set_state(index, account, plan_id, "CANCELLED", at)
        audit.append(index, account, plan_id, "LABEL_PLAN_CANCELLED", at, {"from_state": plan["state"]})
    return _row(index, account, plan_id)


def list_plans(index, account):
    return [dict(r) for r in index._q("SELECT plan_id, state, op_count, plan_hash, created_at, expires_at FROM label_plan WHERE account=? ORDER BY created_at, plan_id", account)]


def approval_status(index, account, plan_id):
    plan = _row(index, account, plan_id)
    rows = [dict(r) for r in index._q("SELECT nonce, status, created_at, expires_at, plan_hash, op_count FROM label_plan_approval WHERE account=? AND plan_id=? ORDER BY created_at", account, plan_id)]
    for r in rows:
        r["nonce"] = r["nonce"][:6] + "..."
    return {"plan_id": plan_id, "plan_state": plan["state"], "approvals": rows}


def verify_approved(index, account, plan_id, now=None):
    """Read-only consistency check of an approved plan: returns {problem: count}; empty means locally approved and fresh. It consumes nothing and authorizes nothing."""
    now = _utc(now)
    plan = get_plan(index, account, plan_id)
    problems = revalidate(index, account, plan, now)

    def bad(code):
        problems[code] = problems.get(code, 0) + 1
    if plan["state"] != "APPROVED":
        bad("NOT_APPROVED")
    valid = index._q("SELECT * FROM label_plan_approval WHERE account=? AND plan_id=? AND status='VALID'", account, plan_id)
    if len(valid) != 1:
        bad("NO_SINGLE_VALID_APPROVAL")
        return problems
    a = valid[0]
    if a["plan_hash"] != plan["plan_hash"] or a["op_count"] != plan["op_count"]:
        bad("APPROVAL_MISMATCH")
    if _iso(now) >= a["expires_at"]:
        bad("APPROVAL_EXPIRED")
    try:
        created, expires, plan_expires = _parse(a["created_at"]), _parse(a["expires_at"]), _parse(plan["expires_at"])
    except ValueError:
        bad("APPROVAL_TIMESTAMP_INVALID")
        return problems
    if now < created - CLOCK_TOLERANCE:
        bad("CLOCK_BEFORE_APPROVAL")
    if expires - created > APPROVAL_TTL or expires > plan_expires:
        bad("APPROVAL_TIMES_INCONSISTENT")
    if not audit.verify_chain(index, account)[0]:
        bad("AUDIT_CHAIN_BROKEN")
    logged = False
    for e in audit.events(index, account, plan_id, 1000):
        if e["event_type"] == "LABEL_PLAN_APPROVED":
            meta = json.loads(e["meta"])
            logged = logged or (meta.get("plan_hash") == plan["plan_hash"] and meta.get("nonce_sha256") == sha256(a["nonce"]))
    if not logged:
        bad("APPROVAL_NOT_IN_AUDIT")
    return problems
