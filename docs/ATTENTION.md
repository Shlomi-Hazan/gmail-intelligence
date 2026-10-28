# M8A-1: attention engine and `mailbox attention` (metadata only, read-only)

> **Status: implemented on a feature branch against synthetic data only, pending independent code review (tracking issue #51, umbrella #23).** The owner approved the ranking weights and thresholds below and a retained-thread budget of 250,000 **for experimental algorithm v1 only**: this is NOT validated real-world accuracy, the output keeps the label `PROVISIONAL` for the weights, and real Gmail acceptance has NOT occurred. Evidence and measurements: [ATTENTION-EVALUATION.md](ATTENTION-EVALUATION.md). There are no Gmail links and no link flags in this milestone, and no message identifiers are shown; the dashboard screen is a separate issue (#53).

## 1. What it is and is not
A local, deterministic, explainable list of messages that **may** deserve attention, built only from metadata that the index already stores: the STARRED and IMPORTANT labels, the unread flag and received date, and the existing M3 classification (rules only). Findings are recommendations ("possibly needs attention"), never guaranteed detections; the absence of a finding proves nothing. It reads no subject, snippet, body or attachment, contacts no Gmail API, needs no OAuth or Keychain, writes nothing, and changes no schema (v7).

## 2. Ranking (experimental algorithm version 1; weights approved for v1 only, not validated)
Three separate axes. Only the first one orders the list.

| Axis | Meaning | Values |
|---|---|---|
| `score` | what to look at first | integer 0-100 |
| `evidence` | who said it matters | `OWNER_ASSERTED`, `GMAIL_HEURISTIC`, `MAILBOX_STATE` |
| `flags` | how far to trust the data | closed set, never change the score |

Score (a pure function of labels, the classification outcome, the received date and the reference day):

1. `owner` = 50 for the label `STARRED` + the weight of a user attention rule that fired (`POTENTIALLY_IMPORTANT`: LOW 20, MEDIUM 40, HIGH 60), capped at **70**.
2. `gmail` = 20 for the label `IMPORTANT` + unread-age points (only when unread: 0-2 days 10, 3-14 days 15, 15-60 days 5, older 0) + a personal bonus (a `PERSONAL` type result at MEDIUM 5, at HIGH 10; LOW gives 0), capped at **40**.
3. `penalty` = the single strongest of PROMOTIONAL / NEWSLETTER / SOCIAL 30 and AUTOMATED_NOTIFICATION 15, counting only results of MEDIUM confidence or higher; **0** when TRANSACTIONAL or FINANCIAL is among the types (financial and transactional mail is never penalised automatically).
4. `score = min(100, owner + max(0, gmail - penalty))`.

Consequences, by arithmetic and not by a special rule: penalties never touch the owner's points, so a starred message always scores at least 50 (tier MEDIUM) and a penalty can never raise a score.

Tiers: HIGH >= 60, MEDIUM >= 35, LOW >= 15. Items below 15 are not shown unless `--include-low-score` (threshold 1; score 0 is never shown). `--min-tier` raises the threshold.

`STARRED` and `IMPORTANT` are read from the message's label ids, **not** from the classification outcome: `classify.evaluate` keeps one attention result per value and a user rule outranks the built-in star rule, so the outcome can hide a star.

Classification is recomputed in memory from the active rules (`classifier.features_for`, `classifier.active_rules`, `classify.evaluate`, `classify.ruleset_hash`). Persisted `message_class` rows, including `source=ai`, are never read, so a stale or AI-assisted persisted result cannot change the order. Consequently another screen may show a different persisted type than the one that influenced the ranking.

Order key (a total order, no ties): `(-score, -owner, -evidence_rank, -received_ms, message_id)`. Other sorts: `date` (newest first) and `oldest`; messages without a date go last.

Evidence is the strongest source present: `OWNER_ASSERTED` (a star, or a user rule at MEDIUM or HIGH), `GMAIL_HEURISTIC` (Gmail's IMPORTANT guess, or a user rule at LOW), `MAILBOX_STATE` (unread/age only). Flags: `SENDER_MISSING`, `NON_ASCII_DOMAIN`, `NOT_IN_INBOX`, `TYPE_CONFLICT`, `REVIEW_FLAGGED`, `DATE_MISSING`.

## 3. Processing order (fixed)
account -> candidate selection -> exclusions -> classification -> scoring -> filters and threshold -> thread collapse -> sender diversity -> sort -> snapshot -> pagination.

* **Candidates.** Messages carrying `STARRED`, `IMPORTANT` or `UNREAD`, read as one index-ordered keyset stream per label (no temporary sort), merged and de-duplicated, in batches of 2,000. If an enabled user attention rule exists, one primary-key-ordered stream over all messages of the account is used instead (rules are evaluated with the classifier itself).
* **Exclusions.** `SENT`, `DRAFT`, `TRASH`, `SPAM`, `CHAT` (a starred sent message is excluded too). Archived messages are included.
* **Filters.** `--signal starred|important|unread|rule` (any of), `--min-tier`, and the score threshold, applied before collapsing.
* **Thread collapse.** One representative per thread: the best message by the order key among those that passed the filters; a message without a thread id is its own thread. `--no-collapse` disables it.
* **Sender diversity.** At most K (default 3, `--sender-limit 0` disables) representatives per sender, chosen by the order key; messages without a sender form one group. The count of removed items is reported.
* **Pagination.** Page size 25 (max 100).

## 4. Complete results or explicit failure
Nothing is ever truncated or dropped because of its age or the size of the mailbox. Only messages that pass the threshold are kept, one record per thread. If the number of kept threads exceeds `RETAINED_THREAD_BUDGET`, the command fails with `RESULT_INCOMPLETE` and shows **no items**; no partial result is ever presented as complete. The failure depends only on the set of kept threads, not on row order. The budget in the code is 250,000 retained threads, approved by the owner for **experimental v1**. Measured at exactly the budget on synthetic data (one machine): first page 3.3-5.5 s, absolute peak RSS 198-215 MB, incremental 179-195 MB; see [ATTENTION-EVALUATION.md](ATTENTION-EVALUATION.md) for the environment and limits. With `--no-collapse` the budget counts messages.

## 5. Consistent reads
The index is opened with `ReadOnlyIndex`. `PRAGMA data_version` is read on the **same** connection before and after all batched reads; any change (another connection committed) discards the work and retries, at most twice, then fails with `INDEX_CHANGED_DURING_READ`. Every read is a short, fully fetched statement: a long read transaction would block the synchronisation writer ("database is locked"), so none is ever held. No temporary files are created (`temp_store=MEMORY`, index-ordered queries).

**What the consistency check covers, and what it does not.** The check wraps everything that produces the list: the rules, the candidate streams, the classification, the scores, the totals and the snapshot. The items, the totals and the snapshot are therefore one consistent state, and page details are built from the in-memory records (no further database read). The `warnings`, `freshness.as_of` and `freshness.sync_state` fields are read AFTER the final check, in a few short statements on the same read-only connection, and may describe a state slightly newer than the items. They are advisory (they warn and never block), are not part of the snapshot, and are deliberately outside the check so that the report neither widens its read window nor holds a lock that would block the synchronisation writer. A write that lands between the final check and the return is not detectable by any design.

## 6. Snapshot and cursor
`snapshot` is a SHA-256 over: the algorithm and taxonomy versions, the account, the ruleset hash, the reference day, the normalised parameters (sort, signals, threshold, collapse, sender limit, privacy mode), every visible field of **every** item of the full ordered list (including a one-way hash of the sender), and the totals. Page size, warnings and `as_of` are not part of it.

Cursor: `a1.<YYYYMMDD>.<snapshot 64 hex>.<n>.<key 16 hex>`: the reference day, the snapshot, the number of items already delivered and a one-way key of the last delivered item. It contains no account, sender, message id, thread id or text. Validation, in order: strict grammar and length; the reference day must be today or yesterday (UTC) else `SNAPSHOT_CHANGED`; the whole list is recomputed with that day; a different snapshot gives `SNAPSHOT_CHANGED` (no items); an equal snapshot but a wrong position gives `CURSOR_INVALID`. There is no server state. A cursor of another account or with other parameters simply fails the snapshot comparison.

## 7. Output
JSON and text, both from the same function. Per item: rank, score, tier, evidence, flags, signals (code, points, basis OBSERVED or INFERRED), types, a masked sender (the domain is shown; `--reveal-senders` shows the address), received date, unread age in days, the number of messages in the thread, and `link: {"status": "UNAVAILABLE", "reason": "LINKS_NOT_IMPLEMENTED"}`. No message or thread id and no URL is printed. Request level: totals, warnings (empty index, partial index, scan older than 7 days, sync not healthy; they warn and never block), `as_of`, the ruleset hash, and `weights_status: PROVISIONAL`.

## 8. Fixed errors
Only two kinds of text can reach the user from the command: the fixed texts of `AttentionError` and of the parameter validation (`ParameterError`, built from constants). Every other exception, including a `ValueError` raised while processing stored data, ends in the generic message. Classification-derived output is validated against the authoritative definitions: a type outside `classify.TYPES` or a rule id that is not `u` plus up to nine ASCII digits is shown as `UNRECOGNISED`, never as the stored text.

`RESULT_INCOMPLETE`, `SNAPSHOT_CHANGED`, `CURSOR_INVALID`, `INDEX_CHANGED_DURING_READ`, plus the existing index errors; unexpected internal errors give the generic reporting message. Messages are fixed text; none contains an identifier or exception text.

## 9. Known limits
* The personal-versus-automated signal is weak without user rules: only the sender's local part, Gmail's tabs and the user's own rules are available. Gmail's IMPORTANT is an automatic guess. Starred mail may be old and forgotten; the unread flag is as old as the last synchronisation.
* A message may have changed or disappeared since the last sync; the output states `as_of` and the sync state.
* Without a message id or a link the item has to be found by date and sender domain; links are a separately gated, unverified feature (#52).
* The retained-thread budget (250,000) and the weights are approved for experimental v1 only; they are not validated on a real mailbox.
* No message identifier is shown in v1 (a decision of the owner).
* The sender group is the full normalized address as stored by the scanner (lowercase, trimmed). The engine applies no Unicode normalization, so visually identical addresses written in different Unicode forms, plus-addressing variants and addresses differing in a trailing space count as different senders.
