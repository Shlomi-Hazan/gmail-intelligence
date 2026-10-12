"""Privacy-safe text output for M4A candidate previews and protection rules. Local only; nothing is persisted."""
from gmail_intelligence import cleanup_candidates as cc, cleanup_protect

_FOOTER = ("These are RECOMMENDATIONS ONLY, not approvals. Nothing was changed, Gmail was not contacted, and no plan was "
           "created. Executing any cleanup requires later, separately approved steps (M4B/M4C).")
_BUCKETS = ((90, "<90d"), (180, "90-180d"), (365, "180-365d"), (10**9, ">365d"))


def _bucket(age):
    if age is None:
        return "n/a"
    return next(label for limit, label in _BUCKETS if age < limit)


def _counts(d):
    return [f"    {k:<28}{n:>8,}" for k, n in sorted(d.items(), key=lambda x: (-x[1], x[0]))] or ["    (none)"]


def candidates_text(result, account, review=False, limit=20, show_ids=False, show_senders=False, by_domain=False):
    s = result.summary
    o = s["outcomes"]
    out = [f"Cleanup candidates for {cleanup_protect.mask_account(account)} (local index only; Gmail was not contacted)",
           f"Index state: {s['index_state'].upper()} - {s['index_why']}"]
    if s["index_state"] != "complete":
        out.append("WARNING: PARTIAL index; thread completeness cannot be established, so nothing is recommended.")
    out += [f"Policy: {s['policy']}; protection fingerprint {s['protection_fingerprint']} "
            f"({s['protection_rules_active']} active protection rule(s)); Trash recommendations: none in M4A",
            "", f"Evaluated {s['total']:,} messages in {s['threads']:,} threads ({s['mixed_threads']:,} mixed-risk threads).",
            f"  EXCLUDED                              {o[cc.EXCLUDED]:>9,}",
            f"  REVIEW_REQUIRED (informational only)  {o[cc.REVIEW]:>9,}",
            f"  ELIGIBLE (archive recommendation)     {o[cc.ELIGIBLE]:>9,}"]
    if review:
        out += ["", "REVIEW_REQUIRED reasons (a message can have several). These are NOT actionable."]
        out += _counts(s["reasons"].get(cc.REVIEW, {}))
    else:
        out += ["", "Eligible by approving evidence (type, strength, rule)"]
        out += [f"    {t:<14}{c:<8}{rid:<28}{n:>8,}" for (t, c, rid), n in sorted(s["evidence"].items(), key=lambda x: -x[1])] \
            or ["    (none)"]
        out += ["", "Why messages were excluded"] + _counts(s["reasons"].get(cc.EXCLUDED, {}))
        out += ["", "Why messages need review (not recommended)"] + _counts(s["reasons"].get(cc.REVIEW, {}))
    want = cc.REVIEW if review else cc.ELIGIBLE
    chosen = [d for d in result.decisions if d.outcome == want]
    if by_domain and chosen:
        dom = {}
        for d in chosen:
            k = d.sender.rpartition("@")[2] or "(unknown)"
            dom[k] = dom.get(k, 0) + 1
        out += ["", f"Top sender domains among {'REVIEW_REQUIRED' if review else 'ELIGIBLE'}"] + [
            f"    {k[:40]:<42}{n:>8,}" for k, n in sorted(dom.items(), key=lambda x: (-x[1], x[0]))[:10]]
    if limit and chosen:
        out += ["", f"Examples (oldest first, up to {limit}; ids/senders hidden unless requested)"]
        for i, d in enumerate(chosen[:limit], 1):
            bits = [f"#{i}", f"age {_bucket(d.age_days)}", ",".join(d.codes) or ",".join(f"{t}:{c}" for t, c, _ in d.evidence)]
            if show_ids:
                bits.append(f"id={d.message_id}")
            if show_senders:
                bits.append(f"sender={d.sender}")
            out.append("    " + "  ".join(b for b in bits if b))
    out += ["", _FOOTER]
    return "\n".join(out)


def protect_text(index, account, show_values=False):
    rows = cleanup_protect.rows(index, account)
    out = [f"Protection rules for {cleanup_protect.mask_account(account)} (a matching message is never a cleanup candidate;"
           f" all conditions of one rule must match, several rules combine as OR)"]
    for r in rows:
        conds = [f"{k}={v if show_values else cleanup_protect.mask_value(k, v)}" for k, v in
                 (("sender", r["c_sender"]), ("domain", r["c_domain"]), ("label", r["c_label"])) if v]
        out.append(f"  {r['id']:<5}{'on ' if r['enabled'] else 'OFF'} {' AND '.join(conds)}"
                   + (f"  # {r['note']}" if show_values and r["note"] else ""))
    if not rows:
        out.append("  (none yet; add one with `cleanup protect add`)")
    elif not show_values:
        out.append("  (values are partly masked; use --show-values to display them)")
    return "\n".join(out)
