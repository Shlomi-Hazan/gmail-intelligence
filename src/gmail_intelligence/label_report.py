"""Plain-text rendering for the M5 label features. LOCAL ONLY. Label names and sender addresses are private: they are hidden by default and shown only when the owner passes
the matching flag. Whatever is shown is sanitized, because a label name comes from the mailbox and is untrusted input (no control or escape characters reach the terminal)."""
from gmail_intelligence import cleanup_protect, label_model as lm

LOCAL_ONLY = "LOCAL ONLY — no Gmail changes performed."
CONFIDENCE_NOTE = "Confidence is the strength of the evidence, not a probability. OBSERVED = a fact computed from the local index; INFERRED = a judgement built on facts."
_MAX_SHOWN = 80
_DESCRIPTIONS = {
    "INVALID_NAME": "Invalid label name", "EXACT_DUPLICATE": "Exact duplicate labels", "NEAR_DUPLICATE": "Near-duplicate labels", "UNUSED": "Unused labels",
    "UNUSED_UNCERTAIN": "Possibly unused labels (index not complete)", "ORPHANED_PARENT": "Orphaned parent paths", "DEEP_NESTING": "Deep nesting",
    "INCONSISTENT_NESTING": "Inconsistent nesting"}


def safe(text, limit=_MAX_SHOWN):
    """Printable, bounded, single-line version of untrusted text."""
    out = "".join(ch if ch.isprintable() and ch not in "\r\n\t\x1b" else "?" for ch in str(text))
    return out if len(out) <= limit else out[:limit - 1] + "…"


def label_display(label, show_names):
    return f'"{safe(label.name)}"' if show_names else "(name hidden)"


def index_line(state, why):
    if state == "complete":
        return f"Index: COMPLETE ({safe(why, 120)})"
    return f"Index: {state.upper()} ({safe(why, 120)}). Findings that depend on a complete index are marked uncertain or withheld."


def hygiene_text(index, account, h, show_names=False):
    by_id = {lab.id: lab for lab in lm.load_labels(index, account)}
    out = ["Label hygiene report", "  " + LOCAL_ONLY, f"  account: {cleanup_protect.HIDDEN_ACCOUNT}", "  " + index_line(h.index_state, h.index_why),
           f"  labels: {h.labels_total} total ({h.user_labels} user, {h.system_labels} system and never analyzed); user labels carried by at least one indexed message: {h.user_in_use}; "
           f"indexed messages: {h.messages_indexed}"]
    if not h.messages_indexed:
        out.append("  The index holds no messages, so no label is judged unused. Run `mailbox scan` first.")
    if not h.findings:
        out += ["", "No findings.", "", CONFIDENCE_NOTE]
        return "\n".join(out)
    out += ["", f"Findings: {len(h.findings)}"]
    last = None
    for f in h.findings:
        if f.code != last:
            out += ["", f"== {_DESCRIPTIONS[f.code]} =="]
            last = f.code
        out.append(f"  [{f.code}{('/' + f.variant) if f.variant else ''}] confidence {f.confidence} · {f.basis}")
        out.append("    labels: " + ", ".join(f"{i}" + (f" {label_display(by_id[i], True)}" if show_names and i in by_id else "") for i in f.labels)
                   + ("" if show_names else "   (names hidden; use --show-names)"))
        out.append(f"    why: {f.reason}")
        out.append("    evidence: " + ", ".join(f"{k}={v}" for k, v in f.evidence))
    out += ["", CONFIDENCE_NOTE, "Nothing was changed: this report cannot create, rename, merge or delete a label."]
    return "\n".join(out)
