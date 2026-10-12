# Safe Cleanup (M4)

M4 will let the owner archive (and eventually Trash) individual messages through staged, approval-gated steps. **Only M4A is
implemented**: a local, read-only candidate preview plus protection rules. Nothing in M4A can change Gmail, create a plan
or run an action. Decisions: [D27-D35](DECISIONS.md). Phases: M4A candidate engine (this document), M4B immutable plans,
approvals and audit, M4C separate write authorization and executor, M4D recovery/undo and final audit.

## M4A in one paragraph
`cleanup candidates` evaluates every indexed message of one account against its M2 metadata, its **current** M3 rules-based
classification and the user's protection rules, and puts it in exactly one of three groups. The result is computed on demand
and never stored, so changing a protection rule or reclassifying changes the next output (the printed *protection
fingerprint* changes too; M4B will bind plans to it). Eligibility is a **recommendation, not an approval**.

## Outcomes
| Outcome | Meaning | Examples of reasons |
|---|---|---|
| `EXCLUDED` | Never a candidate | hard protections `STARRED`, `SENT`, `DRAFT`, `TRASH`, `SPAM`, `USER_PROTECTED`; unsafe data `MISSING_THREAD_ID`, `MISSING_DATE`, `MISSING_SENDER`, `UNREAD_FLAG_MISMATCH`, `CLASSIFICATION_MISSING`, `CLASSIFICATION_STALE`; nothing to archive `NOT_IN_INBOX`, `TOO_RECENT` |
| `REVIEW_REQUIRED` | Informational only; **not actionable** (a separate individual-review workflow would be a future decision) | `IMPORTANT_LABEL`, `ATTENTION_SIGNAL`, `RISKY_TYPE` (personal/financial/transactional/educational), `UNKNOWN_TYPE`, `TYPE_NOT_APPROVED`, `WEAK_EVIDENCE`, `UNREAD`, `USER_LABEL`, `AI_EVIDENCE`, `AMBIGUOUS_TYPES`, `MIXED_THREAD`, `INDEX_PARTIAL` |
| `ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION` | Recommendation only | read, in INBOX, at least 90 days old, current rules-based classification with MEDIUM+ evidence for `PROMOTIONAL`, `SOCIAL` or `NEWSLETTER`, none of the reasons above |

`AUTOMATED_NOTIFICATION` may accompany an approved type but never suffices alone. A message is eligible only when it has **no**
reason at all, so a protected message can never be promoted by another rule. AI-origin results (`source='ai'`) are never
evidence. There are **no Trash recommendations** in M4A; Gmail categories, Updates or `noreply`-style senders are never enough
for Trash (a future Trash path needs a user-defined HIGH-evidence rule or individual selection, at least 180 days of age and a
separate approval).

## Threads
Execution will be message-level only; a message id is never expanded to its thread. Candidate safety still looks at thread
context using the **local index**: an otherwise eligible message becomes `REVIEW_REQUIRED` (`MIXED_THREAD`) if any other indexed
message of the thread is protected, unsafe, stale/unclassified or itself needs review. Siblings that are merely recent or already
archived are harmless. **Limitation:** the index cannot prove that no newer message arrived after the last scan, and a limited
or interrupted scan cannot show all messages of a thread. Therefore unless the latest full scan is complete, every
otherwise-eligible message is downgraded to `REVIEW_REQUIRED` (`INDEX_PARTIAL`), and a missing `thread_id` excludes the message.
No Gmail lookup is used to fill gaps; M4C will re-validate each message immediately before acting and skip anything that changed,
without claiming protection against concurrent changes.

## Commands (local only; `--account` avoids the Keychain lookup)
```bash
gmail-intelligence cleanup candidates --account EMAIL [--limit N] [--review] [--min-age-days N] [--show-ids] [--show-senders] [--by-domain]
gmail-intelligence cleanup protect list    --account EMAIL [--show-values]
gmail-intelligence cleanup protect add     --account EMAIL [--sender ADDRESS] [--domain DOMAIN] [--label LABEL] [--note TEXT]
gmail-intelligence cleanup protect disable|enable|remove RULE_ID --account EMAIL
```
Default output is aggregate: counts, reasons, approving evidence by rule, and anonymized example rows (age bucket and reason
codes). Message ids, sender addresses, domains and rule values appear only with the explicit flags (`--show-ids`, `--show-senders`, `--by-domain`, `--show-values`); the account is always shown as `<account hidden>`, and `protect list` shows `<hidden>` for every stored value. The exclusion summary separates the *decisive* reasons from *accompanying* review signals that an excluded message also carries (they are not why it was excluded). Reason codes and evaluation are unchanged by this presentation.
`--min-age-days` may only be stricter than 90. Run `classify run --all` first so classifications are current.

**Protection rules** use the M3 vocabulary (exact sender, exact domain, label id or name; no wildcards or regex). All conditions
of one rule must match; several rules combine as OR. They are stored per account in the local database, are kept by
`mailbox purge`, and do not alter M3 classifications.

## Storage and migration (schema v3)
One new table, `protect_rules`. Opening a v2 (or v1) index backs the database up first (`index.sqlite3.pre-m4a-backup-<UTC>` or
`pre-m3-backup-...`, mode 600), then adds the missing tables in one transaction; failure leaves the old version intact. M2/M3 data
is untouched. To go back, quit the tool and copy the backup over `index.sqlite3` (an older build cannot open a newer schema).
There is no table for candidates, plans or approvals in M4A.

## Audit retention (placeholder until M4B)
Audit and recovery data will stay local. The tool will never delete recovery-relevant history automatically; the concrete
retention policy is defined in M4B and must exist before any live execution.

## Status
Implemented and covered by offline tests with synthetic data. Not measured: recommendation quality on a real mailbox. No live
verification has been run; any later one needs a separate owner approval. Zero Additional Cost: no new dependency or service.
