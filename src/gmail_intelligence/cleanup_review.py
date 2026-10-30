"""M12B: review of M12A cleanup groups before a plan exists. Read-only except `create_plan_from_selection`, which only calls the existing M4B `cleanup_plans.create_plan`.

A selection is: one or more discovery groups (sender domains) minus the messages the owner excluded one by one, taken ONLY from the set the M4A engine (`cleanup_candidates.evaluate_all`)
currently finds eligible. This module adds no eligibility rule and no plan format: the plan is the unchanged M4B plan (immutable, hash-bound, ARCHIVE only, at most `MAX_PLAN_ITEMS`
messages), re-validated by M4B itself inside its transaction. A *selection digest* binds a plan to exactly what was previewed: if anything the preview depended on changed (messages,
sizes, classification, protections, or the owner's exclusions), the digest differs and no plan is created. Any change to a selection is a new selection, hence a new plan and a new
approval. Nothing here executes, approves, trashes or deletes; TRASH is unavailable and permanent deletion is never offered. Message ids stay local and are shown only on request.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

from gmail_intelligence import analytics, classifier, cleanup_candidates as cc, cleanup_plans as cp, cleanup_protect
from gmail_intelligence.cleanup_audit import canonical, sha256

ACTION = cp.ACTION
UNAVAILABLE = {"TRASH": "unavailable: needs a separate design, write-policy review and owner authorization", "PERMANENT_DELETE": "never offered"}
MAX_GROUPS = 50
MAX_EXCLUDES = 5000
DIGEST_VERSION = 1
DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE = 25, 200


class ReviewError(ValueError):
    """A refused selection. Its text is fixed (built from constants and counts, never from the input), so it is the only ValueError the command may print."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Selection:
    ids: tuple            # sorted, de-duplicated message ids: exactly the planned set
    rows: tuple           # (id, domain, thread_id, age_days, size) in the same order
    groups: tuple         # (domain, selected, excluded_by_owner)
    duplicates_ignored: int
    not_eligible_same_domains: int
    min_age_days: int
    digest: str
    index_state: str


def check_action(action):
    """Only ARCHIVE exists. Trash and permanent deletion are named so the refusal is unambiguous."""
    a = (action or "archive").lower()
    if a == "archive":
        return ACTION
    if a == "trash":
        raise ReviewError("ACTION_UNAVAILABLE", "action TRASH is unavailable: it needs a separate design, write-policy review and owner authorization; only ARCHIVE can be planned")
    if a in ("delete", "permanent-delete", "permanent_delete"):
        raise ReviewError("ACTION_NEVER", "permanent deletion is never offered; only ARCHIVE can be planned")
    raise ReviewError("BAD_ACTION", "--action must be archive (trash is unavailable and permanent deletion is never offered)")


def _norm_group(g):
    if not isinstance(g, str) or not 1 <= len(g) <= 253:
        raise ReviewError("BAD_GROUP", "a --group must be a sender domain from `cleanup discover` (1-253 characters)")
    g = g.strip().lower()
    if not g or any(not (c.isalnum() or c in ".-") for c in g):
        raise ReviewError("BAD_GROUP", "a --group must be a sender domain from `cleanup discover` (letters, digits, '.' and '-')")
    return g


def resolve(index, account, groups, exclude_ids=(), *, min_age_days=cc.MIN_AGE_DAYS, now=None):
    """The reviewed selection, computed from the CURRENT eligible set. Raises ReviewError (fixed text) for any bad, empty or inconsistent input; never writes."""
    now = now if now is not None else datetime.now(timezone.utc)
    if isinstance(min_age_days, bool) or not isinstance(min_age_days, int) or not cc.MIN_AGE_DAYS <= min_age_days <= 3650:
        raise ReviewError("BAD_AGE", "--min-age-days must be between %d and 3650 (you may only be stricter than the default)" % cc.MIN_AGE_DAYS)
    groups = list(groups or [])
    if not groups:
        raise ReviewError("NO_GROUP", "select at least one --group (nothing is selected by default)")
    if len(groups) > MAX_GROUPS:
        raise ReviewError("TOO_MANY_GROUPS", "at most %d groups can be selected at once" % MAX_GROUPS)
    wanted = sorted({_norm_group(g) for g in groups})
    exclude_ids = list(exclude_ids or [])
    if len(exclude_ids) > MAX_EXCLUDES:
        raise ReviewError("TOO_MANY_EXCLUDES", "at most %d exclusions can be given at once" % MAX_EXCLUDES)
    if any(not cp.valid_id(i) for i in exclude_ids):
        raise ReviewError("BAD_ID", "message ids may only contain letters, digits, '-' and '_' (max 64 characters)")
    exclude = set(exclude_ids)

    res = cc.evaluate_all(index, account, now_ms=int(now.timestamp() * 1000), min_age_days=min_age_days)  # the ONE policy
    sizes = {r["id"]: r["size"] for r in index._q("SELECT id, size FROM messages WHERE account=?", account)}
    pool, other = {}, 0
    for d in res.decisions:
        dom = analytics.clean(d.sender.rpartition("@")[2]) or "(unknown)"
        if dom not in wanted:
            continue
        if d.outcome == cc.ELIGIBLE:
            pool[d.message_id] = (dom, d.thread_id, d.age_days, sizes.get(d.message_id))
        else:
            other += 1
    missing = [g for g in wanted if not any(v[0] == g for v in pool.values())]
    if missing:
        raise ReviewError("NO_SUCH_GROUP", "%d selected group(s) have no eligible messages right now; run `cleanup discover` again" % len(missing))
    stray = exclude - set(pool)
    if stray:
        raise ReviewError("EXCLUDE_NOT_IN_SELECTION", "%d excluded id(s) are not in the selected eligible set; nothing was selected" % len(stray))
    ids = tuple(sorted(set(pool) - exclude))
    if not ids:
        raise ReviewError("NO_TARGETS", "excluding everything leaves no targets")
    rows = tuple((i, *pool[i]) for i in ids)
    per = {g: [0, 0] for g in wanted}
    for i, (dom, *_rest) in pool.items():
        per[dom][0 if i not in exclude else 1] += 1
    facts = cp._facts(index, account, ids)
    body = {"v": DIGEST_VERSION, "action": ACTION, "policy": cc.POLICY_VERSION, "min_age_days": min_age_days, "ruleset": classifier.current_hash(index, account),
            "protection": cleanup_protect.digest(account, cleanup_protect.active(index, account)),
            "items": [{**facts[i], "size": sizes.get(i)} for i in ids]}
    return Selection(ids, rows, tuple((g, per[g][0], per[g][1]) for g in wanted), len(exclude_ids) - len(exclude), other, min_age_days, sha256(canonical(body)),
                     res.summary["index_state"])


def preview(sel, *, page=1, page_size=DEFAULT_PAGE_SIZE, show_ids=False):
    """The exact effect of the selection. Ids appear only with show_ids; the digest is what `plan create --selection-digest` must repeat."""
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ReviewError("BAD_PAGE", "--page-size must be between 1 and %d" % MAX_PAGE_SIZE)
    pages = max(1, -(-len(sel.rows) // page_size))
    if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= pages:
        raise ReviewError("BAD_PAGE", "--page must be between 1 and %d" % pages)
    start = (page - 1) * page_size
    items = []
    for k, (mid, dom, _thread, age, size) in enumerate(sel.rows[start:start + page_size], start + 1):
        row = {"n": k, "group": dom, "age_days": age, "bytes": size}
        if show_ids:
            row["id"] = mid
        items.append(row)
    sizes = [r[4] for r in sel.rows]
    return {"action": ACTION, "action_meaning": "remove from the inbox (archive); nothing is trashed or deleted", "unavailable_actions": dict(UNAVAILABLE),
            "groups": [{"group": g, "selected": n, "excluded_by_you": x} for g, n, x in sel.groups],
            "totals": {"messages": len(sel.rows), "threads": len({r[2] for r in sel.rows}), "bytes": sum(s for s in sizes if s), "unknown_size": sum(1 for s in sizes if not s)},
            "duplicates_ignored": sel.duplicates_ignored, "not_eligible_in_same_domains": sel.not_eligible_same_domains,
            "plan_limit": {"max_messages": cp.MAX_PLAN_ITEMS, "exceeded": len(sel.rows) > cp.MAX_PLAN_ITEMS},
            "min_age_days": sel.min_age_days, "index_state": sel.index_state, "selection_digest": sel.digest,
            "page": {"page": page, "pages": pages, "page_size": page_size, "ids_shown": bool(show_ids)}, "items": items,
            "explain": ["SAME_ELIGIBILITY_AS_CLEANUP_CANDIDATES", "SELECTION_NEVER_EXPANDS", "NO_PLAN_CREATED_BY_PREVIEW", "APPROVAL_DOES_NOT_EXECUTE"], "read_only": True}


def create_plan_from_selection(index, account, groups, exclude_ids, expected_digest, *, min_age_days=cc.MIN_AGE_DAYS, now=None):
    """Freeze the reviewed selection as a DRAFT M4B plan. Refuses (nothing created) if the selection no longer matches the previewed digest. Returns the plan."""
    if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(c not in "0123456789abcdef" for c in expected_digest):
        raise ReviewError("BAD_DIGEST", "--selection-digest must be the 64-character digest printed by `cleanup preview`")
    sel = resolve(index, account, groups, exclude_ids, min_age_days=min_age_days, now=now)
    if sel.digest != expected_digest:
        raise ReviewError("STALE_SELECTION", "the selection no longer matches the preview (messages, protections, classification or exclusions changed); preview again")
    if len(sel.ids) > cp.MAX_PLAN_ITEMS:
        raise ReviewError("PLAN_LIMIT", "the selection has more than %d messages, the plan limit; narrow it with fewer groups or more exclusions" % cp.MAX_PLAN_ITEMS)
    plan = cp.create_plan(index, account, list(sel.ids), min_age_days=min_age_days, now=now)  # M4B re-validates every id inside its own transaction
    if [i["message_id"] for i in plan["items"]] != list(sel.ids):  # defensive: the plan must be exactly the reviewed set
        cp.cancel(index, account, plan["plan_id"], now=now)
        raise ReviewError("PLAN_MISMATCH", "the created plan did not match the reviewed selection and was cancelled")
    return plan


def render_text(p):
    t = p["totals"]
    out = ["selection preview (local metadata only; nothing is planned, approved, changed or sent)",
           "action: %s - %s. TRASH: %s. PERMANENT DELETE: %s." % (p["action"], p["action_meaning"], p["unavailable_actions"]["TRASH"], p["unavailable_actions"]["PERMANENT_DELETE"]),
           "%d message(s) in %d thread(s), estimated %d KB%s, from %d group(s); %d excluded by you%s." % (
               t["messages"], t["threads"], round(t["bytes"] / 1000), " (+%d without a size)" % t["unknown_size"] if t["unknown_size"] else "", len(p["groups"]),
               sum(g["excluded_by_you"] for g in p["groups"]), "; %d duplicate exclusion(s) ignored" % p["duplicates_ignored"] if p["duplicates_ignored"] else "")]
    out += ["  group %s: %d selected, %d excluded by you" % (g["group"], g["selected"], g["excluded_by_you"]) for g in p["groups"]]
    if p["not_eligible_in_same_domains"]:
        out.append("  %d other message(s) from these domains are not eligible and are never included." % p["not_eligible_in_same_domains"])
    if p["plan_limit"]["exceeded"]:
        out.append("WARNING: more than %d messages; a plan cannot hold them. Narrow the selection." % p["plan_limit"]["max_messages"])
    pg = p["page"]
    out.append("page %d/%d%s:" % (pg["page"], pg["pages"], "" if pg["ids_shown"] else " (ids hidden; --show-ids to see them)"))
    for r in p["items"]:
        out.append("  %4d. %s | %s days old | %s bytes%s" % (r["n"], r["group"], r["age_days"], r["bytes"] if r["bytes"] else "unknown", " | id=" + r["id"] if "id" in r else ""))
    out.append("selection digest: " + p["selection_digest"])
    out.append("next: `cleanup plan create --group ... --selection-digest <digest>` freezes exactly this selection as a DRAFT plan; approval records a typed confirmation and executes nothing.")
    return "\n".join(out)
