# Labels, recommendations and label-change plans (M5)

**Every `labels` command is LOCAL ONLY.** It reads the local SQLite index (and, for plans, writes its own plan records there). None of it calls Gmail, reads the Keychain,
uses OAuth credentials, creates a label or a filter, or changes a message, and no label plan can be executed: **M5F (executing label changes) is not implemented and is not
part of this milestone.** Every report starts with `LOCAL ONLY — no Gmail changes performed.` (`gmail-intelligence labels --help` repeats it.)

## 1. Commands

| Command | What it does |
|---|---|
| `labels report [--show-names]` | M5A label hygiene report: invalid names, exact and near duplicates, unused labels, orphaned parents, deep and inconsistent nesting |
| `labels recommend [--show-names] [--show-senders]` | M5B recommendations from existing label usage, sender/domain patterns and the M3 classification |
| `labels suggest-rules [--show-senders]` | M5C proposed M3 classification rules, each with the standard M3 preview; **never saves a rule** |
| `labels suggest-filters [--show-names] [--show-senders]` | M5E Gmail filter suggestions as text only; **creates no filter** and needs no filter-management scope |
| `labels plan create` / `list` / `show` / `review` / `cancel` | M5D offline label-change plans |
| `labels approve PLAN_ID` | one-time **local** approval record for a reviewed label plan |

All commands take the usual `--account` (omit it and the account is read from the read-only Keychain entry as for the other commands). Label names and sender addresses are
private: they are **hidden by default** and shown only with `--show-names` / `--show-senders`; everything displayed is sanitized (no control or escape characters). The
account address is never printed.

## 2. Evidence model

* **Confidence is evidence strength, not a probability.** `LOW`, `MEDIUM`, `HIGH` mean how much local evidence supports a finding.
* **OBSERVED vs INFERRED.** OBSERVED is a fact computed from the local index (for example two labels with identical names). INFERRED is a judgement built on facts (for
  example a classification-based suggestion, or an edit-distance near-duplicate).
* **Partial index.** A finding that depends on a complete index is withheld or downgraded when the index is partial or empty: a label is reported `UNUSED` (MEDIUM) only when a
  completed full scan exists, otherwise as `UNUSED_UNCERTAIN` (LOW, "the index says nothing about the mailbox"). A label is never called globally unused from a partial index.
* **Tiers** (recommendations and proposals): `LOW` ≥ 3 messages and ≥ 60% agreement; `MEDIUM` ≥ 5 and ≥ 80%; `HIGH` ≥ 20 and ≥ 95%. Small samples cannot reach HIGH. A partial
  index, an INFERRED basis, stale classifications or any AI-sourced classification cap a suggestion at `MEDIUM`, so such evidence never yields HIGH on its own.
* **Protected mail is never suggested.** Groups containing starred/important/sent/draft mail, potentially-important or review-needed classifications, personal mail, or mail
  matching a cleanup protection rule are suppressed and counted. Trash and spam are ignored. System labels are never analyzed, recommended or planned.
* "**Tag**" means the local classification type/attention concept (for example `NEWSLETTER`); "**label**" means an existing Gmail user label.

## 3. Hygiene findings (M5A)

Conservative normalization: Unicode NFKC, case-folding and whitespace trimming/collapsing. Accents and plurals are never normalized away.
`EXACT_DUPLICATE` (HIGH, OBSERVED) · `NEAR_DUPLICATE` (`NORMALIZED` HIGH, `PUNCTUATION` MEDIUM, `SIMILAR` LOW: edit distance 1, leaf at least 5 characters, same parent) ·
`INVALID_NAME` · `UNUSED` / `UNUSED_UNCERTAIN` · `ORPHANED_PARENT` · `DEEP_NESTING` (more than 3 levels) · `INCONSISTENT_NESTING` (`FLAT_PREFIX`, `PARENT_SPELLING`).
Findings are listed in a stable order and each has a reason, evidence, confidence and basis. The report cannot create, rename, merge or delete a label.

## 4. Recommendations, rule proposals and filter suggestions (M5B, M5C, M5E)

* **Recommendations** are `APPLY_LABEL` (an existing label already used for most of a sender's or domain's messages) or `CREATE_LABEL` (a generic name such as "Newsletters",
  aggregated per classification type). They show the target, evidence, confidence, basis and source (`label-usage`, `classification-rules`, `classification-ai`). Nothing is
  applied. Only local metadata is used (no subjects or bodies exist in the index).
* **Rule proposals** reuse the M3 rule model (`classify.validate_new_rule`) and the single M3 preview (`classifier.preview_rule`); there is no second preview. Each shows the
  explanation, the proposed rule, the preview, supporting evidence vs possible false positives, and the existing coverage. A proposal is omitted when an enabled rule on the same
  condition already exists (never duplicated or contradicted) or when it would change nothing. To adopt one you run `classify rules add` yourself.
* **Filter suggestions** are distinct from classification rules: a filter would act inside Gmail, a rule only labels the local index. Criteria are an exact sender or domain; the
  only suggested action is "apply an existing user label". `filter_suggest.validate_filter` rejects forwarding, Trash, delete, skip-Inbox/archive, send, mark-spam, star,
  mark-read, system labels and every unknown action. Estimated effect counts messages already indexed; the effect on future mail is stated as unmeasurable.

## 5. Label-change plans (M5D)

A plan is an ordered list of operations on **user** labels of one account: `CREATE` (a full path), `RENAME` (last segment only), `NEST` (move under another parent or to top level)
and `MERGE` (fold a source label into a target). It is frozen as canonical JSON bound by its SHA-256 and by the hash of the label inventory it was built from, and stored in
the `label_plan`, `label_plan_op` and `label_plan_approval` tables (database triggers keep content immutable and states forward-only).

```
labels plan create --create "Archive" --rename Label_3=Bills --nest Label_4=Archive --merge Label_5=Label_6
labels plan show lplan-1a2b3c4d [--show-names]
labels plan review lplan-1a2b3c4d      # prints the plan, then asks for the typed phrase (terminal only)
labels approve lplan-1a2b3c4d          # typed phrase again; records a one-time local approval
labels plan cancel lplan-1a2b3c4d
```

* **States:** `DRAFT` → `REVIEWED` → `APPROVED`; `CANCELLED` and `EXPIRED` from any live state. A plan lives 48 hours, an approval 24 hours (never beyond the plan).
* **Phrases:** review `REVIEWED LABEL PLAN <n> <hash8>`, approve `APPROVE LABEL PLAN <n> <hash8>`; wrong phrases are refused and audited, 10 failures in 15 minutes lock the plan
  out, and typed confirmations are accepted from a real terminal only.
* **Fail-closed validation:** the whole plan is rejected for system labels, reserved names, empty/invalid/duplicate names (case- and Unicode-insensitive), nesting beyond 3 levels,
  missing parents, cycles, ambiguous names (use the label id), labels of another account, merging a label with children, merge chains, a label used by two operations, and stale
  or drifted inventory. Review and approval re-run the validation against the current inventory.
* **Audit:** events (`LABEL_PLAN_CREATED`, `…_REVIEWED`, `…_APPROVED`, `…_REJECTED`, `…_CANCELLED`, `…_EXPIRED`, …) join the existing M4 `cleanup_audit` hash chain, so
  `cleanup audit verify` covers them and a clock rollback is refused for both. They contain counts, kinds and hashes only, never label names or ids.
* **An approval is only a local record.** It grants no Gmail permission and nothing in this build can execute a label plan (a static test enforces that there is no execute path).

### Limitations (also printed by `labels plan show`)
No real undo exists. A merge may be irreversible in Gmail. Renaming or nesting a parent changes the full path of every child. Gmail's behaviour for these operations is not
verified by this project. Freshness is judged against the local inventory (the last scan), not live Gmail. Names containing `=` must be given by label id in `--rename/--nest/--merge`.

## 6. Schema v6 and the mandatory backup

M5D adds the three label-plan tables (additive, no existing table or row is touched; the schema version goes from 5 to 6). The first time a build with M5D opens an existing v5
index it creates an automatic, verified, owner-only backup `index.sqlite3.pre-m5-backup-<UTC>` (the same machinery as the earlier upgrades) and applies the change in one
transaction; a failure leaves the v5 file unchanged and keeps the backup. **Before first opening the real index with this version, make your own verified copy of
`index.sqlite3` first.** Older builds refuse a v6 index.

## 7. Not in this milestone
Executing label changes (M5F), creating Gmail labels or filters, any new OAuth scope (including filter management), content-based analysis, M6 and M7.
