"""M5A: deterministic, read-only label hygiene analysis of the local index. LOCAL ONLY: no Gmail, no network, nothing is ever edited, merged, deleted or created.

Input: the account's label inventory (`labels`, refreshed by every scan) and how many indexed messages carry each label (`message_labels`). Every finding carries a code, the label
ids involved, an explanation WITHOUT label names, evidence counts, a confidence tier and a basis:
  OBSERVED  a fact computed from the inventory or the index (for example "two names are equal after normalization");
  INFERRED  a judgement built on a fact (for example "these two labels are probably duplicates").
Confidence is the strength of the evidence, never a probability. System labels are ignored entirely. An "unused" claim is made only against a COMPLETE index: with a partial or
empty index the observation (zero indexed messages) is reported as UNUSED_UNCERTAIN and says nothing about the real mailbox.
"""
from collections import defaultdict
from dataclasses import dataclass

from gmail_intelligence import label_model as lm, report

CODE_ORDER = ("INVALID_NAME", "EXACT_DUPLICATE", "NEAR_DUPLICATE", "UNUSED", "UNUSED_UNCERTAIN", "ORPHANED_PARENT", "DEEP_NESTING", "INCONSISTENT_NESTING")
CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_FLAT_DELIMITERS = " -_:.>"


@dataclass(frozen=True)
class Finding:
    code: str
    labels: tuple  # label ids, sorted
    confidence: str  # HIGH | MEDIUM | LOW (evidence strength)
    basis: str  # OBSERVED | INFERRED
    reason: str  # never contains a label name
    evidence: tuple  # ((key, value), ...) sorted by key; counts and codes only
    variant: str = ""  # sub-kind, for example NORMALIZED / PUNCTUATION / SIMILAR for NEAR_DUPLICATE


@dataclass(frozen=True)
class Hygiene:
    findings: tuple
    labels_total: int
    user_labels: int
    system_labels: int
    user_in_use: int
    messages_indexed: int
    index_state: str  # complete | partial | empty
    index_why: str


def _ev(**kw):
    return tuple(sorted(kw.items()))


def analyze(index, account):
    labels = lm.load_labels(index, account)
    counts = lm.message_counts(index, account)
    state, why = report.completeness(index, account)
    n_messages = index.overview(account)["n"]
    users = [lab for lab in labels if lab.user]
    findings = []

    # ---- invalid names (structural problems that make the other checks less reliable)
    for lab in users:
        problem = lm.name_problem(lab.name)
        if problem:
            findings.append(Finding("INVALID_NAME", (lab.id,), "HIGH", "OBSERVED", "the label name has a structural problem (" + problem.lower().replace("_", " ") + ")",
                                    _ev(problem=problem)))

    # ---- duplicates: exact, normalized, punctuation-insensitive, and a bounded edit distance
    reported_pairs = set()

    def mark(ids):
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                reported_pairs.add(frozenset((ids[i], ids[j])))

    by_exact = defaultdict(list)
    for lab in users:
        by_exact[lab.name].append(lab.id)
    for name, ids in sorted(by_exact.items(), key=lambda kv: sorted(kv[1])):
        if len(ids) > 1:
            ids = sorted(ids)
            findings.append(Finding("EXACT_DUPLICATE", tuple(ids), "HIGH", "OBSERVED", "several labels carry exactly the same name", _ev(labels=len(ids))))
            mark(ids)
    by_norm = defaultdict(list)
    for lab in users:
        by_norm[lm.normalize(lab.name)].append(lab)
    for key, group in sorted(by_norm.items(), key=lambda kv: sorted(l.id for l in kv[1])):
        names = {lab.name for lab in group}
        if len(group) > 1 and len(names) > 1 and key.strip("/"):
            ids = sorted(lab.id for lab in group)
            findings.append(Finding("NEAR_DUPLICATE", tuple(ids), "HIGH", "OBSERVED", "the names are equal after case, spacing and Unicode-compatibility normalization",
                                    _ev(labels=len(ids), distinct_names=len(names)), "NORMALIZED"))
            mark(ids)
    by_loose = defaultdict(list)
    for lab in users:
        by_loose[lm.normalize_loose(lab.name)].append(lab)
    for key, group in sorted(by_loose.items(), key=lambda kv: sorted(l.id for l in kv[1])):
        norms = {lm.normalize(lab.name) for lab in group}
        ids = sorted(lab.id for lab in group)
        if len(group) > 1 and len(norms) > 1 and key.replace("/", "").strip() and not all(frozenset(p) in reported_pairs for p in _pairs(ids)):
            findings.append(Finding("NEAR_DUPLICATE", tuple(ids), "MEDIUM", "INFERRED", "the names differ only in punctuation (hyphen, underscore, dot) after normalization",
                                    _ev(labels=len(ids), distinct_names=len(norms)), "PUNCTUATION"))
            mark(ids)
    by_parent = defaultdict(list)
    for lab in users:
        by_parent[lm.normalize(lm.parent_path(lab.name))].append(lab)
    for _parent, group in sorted(by_parent.items()):
        group = sorted(group, key=lambda lab: lab.id)
        leaves = {lab.id: lm.normalize(lm.leaf(lab.name)) for lab in group}
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                la, lb = leaves[a.id], leaves[b.id]
                if frozenset((a.id, b.id)) in reported_pairs or la == lb or min(len(la), len(lb)) < lm.NEAR_MIN_LEN:
                    continue
                if lm.edit_distance_within(la, lb):
                    findings.append(Finding("NEAR_DUPLICATE", (a.id, b.id), "LOW", "INFERRED", "the names under the same parent differ by a single character",
                                            _ev(distance=1), "SIMILAR"))
                    mark([a.id, b.id])

    # ---- unused labels (a container whose children are in use is not unused)
    if n_messages:
        norm_in_use = [lm.normalize(lab.name) for lab in users if counts.get(lab.id, 0)]
        for lab in users:
            if counts.get(lab.id, 0):
                continue
            mine = lm.normalize(lab.name)
            if any(other.startswith(mine + "/") for other in norm_in_use):
                continue
            if state == "complete":
                findings.append(Finding("UNUSED", (lab.id,), "MEDIUM", "OBSERVED", "no message in the last complete full scan carries this label",
                                        _ev(indexed_messages=0, messages_indexed=n_messages)))
            else:
                findings.append(Finding("UNUSED_UNCERTAIN", (lab.id,), "LOW", "OBSERVED", "no indexed message carries this label, but the index is not a complete full scan, "
                                        "so this says nothing about the mailbox", _ev(indexed_messages=0, messages_indexed=n_messages)))

    # ---- nesting
    existing = {lm.normalize(lab.name) for lab in users}
    missing = defaultdict(list)
    for lab in users:
        segs = lm.segments(lab.name)
        for k in range(1, len(segs)):
            path = lm.normalize("/".join(segs[:k]))
            if path.strip("/") and path not in existing:
                missing[path].append(lab.id)
    for path, ids in sorted(missing.items(), key=lambda kv: sorted(kv[1])):
        ids = sorted(set(ids))
        findings.append(Finding("ORPHANED_PARENT", tuple(ids), "HIGH", "OBSERVED", "these labels are nested under a path that has no label of its own",
                                _ev(children=len(ids), missing_depth=lm.depth(path))))
    for lab in users:
        if lm.depth(lab.name) > lm.MAX_DEPTH and not lm.name_problem(lab.name):
            findings.append(Finding("DEEP_NESTING", (lab.id,), "HIGH", "OBSERVED", f"the label is nested deeper than the recommended maximum of {lm.MAX_DEPTH} levels",
                                    _ev(depth=lm.depth(lab.name), recommended_max=lm.MAX_DEPTH)))
    parents = {lm.normalize(lab.name) for lab in users if any(o.name != lab.name and lm.normalize(o.name).startswith(lm.normalize(lab.name) + "/") for o in users)}
    for lab in users:
        norm = lm.normalize(lab.name)
        for parent in sorted(parents):
            if norm.startswith(parent) and len(norm) > len(parent) and norm[len(parent)] in _FLAT_DELIMITERS and not norm.startswith(parent + "/") \
                    and norm[len(parent) + 1:].strip(_FLAT_DELIMITERS):
                owner = next(o.id for o in sorted(users, key=lambda o: o.id) if lm.normalize(o.name) == parent)
                findings.append(Finding("INCONSISTENT_NESTING", tuple(sorted((lab.id, owner))), "MEDIUM", "INFERRED",
                                        "the name looks like a child of an existing parent label but uses a different separator instead of nesting", _ev(kind=1), "FLAT_PREFIX"))
                break
    spellings = defaultdict(lambda: defaultdict(list))
    for lab in users:
        if lm.depth(lab.name) > 1:
            spellings[lm.normalize(lm.parent_path(lab.name))][lm.parent_path(lab.name)].append(lab.id)
    for _norm, variants in sorted(spellings.items()):
        if len(variants) > 1:
            ids = sorted(i for group in variants.values() for i in group)
            findings.append(Finding("INCONSISTENT_NESTING", tuple(ids), "MEDIUM", "OBSERVED", "children of the same parent path use different spellings of that parent",
                                    _ev(spellings=len(variants), children=len(ids)), "PARENT_SPELLING"))

    findings.sort(key=lambda f: (CODE_ORDER.index(f.code), CONFIDENCE_RANK[f.confidence], f.labels, f.variant))
    return Hygiene(tuple(findings), len(labels), len(users), len(labels) - len(users), sum(1 for lab in users if counts.get(lab.id, 0)), n_messages, state, why)


def _pairs(ids):
    return [(ids[i], ids[j]) for i in range(len(ids)) for j in range(i + 1, len(ids))]
