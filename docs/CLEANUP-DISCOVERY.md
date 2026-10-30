# Cleanup discovery (M12A)

`gmail-intelligence cleanup discover` groups the messages that the **existing M4A candidate engine** already finds eligible, with counts, estimated volume and reasons (issue #59, part of M12 — Smart Bulk Cleanup, which expands M4 and does not replace it).

```
gmail-intelligence cleanup discover [--account EMAIL] [--limit 1-100] [--min-group-size 1-1000] [--min-age-days 90+] [--json]
```

## One policy, no new rules
Eligibility is `cleanup_candidates.evaluate_all`, unchanged: INBOX, at least 90 days old (you may only be stricter), read, strongly classified as promotional/social/newsletter by a rule, and none of the hard protections (STARRED, SENT, DRAFT, TRASH, SPAM, your protection rules), unsafe/missing data, important/unread/user-label/AI signals, mixed threads or a partial index. `cleanup discover` cannot make a message eligible or weaken a protection; it only groups what is already eligible (by sender domain).

- **M8 attention** reaches it only as the engine's existing conservative review signal (`ATTENTION_SIGNAL`, including the IMPORTANT label): such messages are reported as *needs review*, never as candidates.
- **M9A subscription estimates** are shown beside a group as INFERRED context (and a caution if M9A rules the sender out). They never change a group.
- **M3 classification** supplies the type and the strength of the rule behind each group.

## What the report shows
Totals in exactly one bucket each: possible candidates, needs review (uncertain), protected, unsafe or incomplete data, not applicable (not in inbox / too recent). Groups ranked by messages, then volume, then name: messages, threads, estimated volume, age range, the classifying rules, and why it is suggested. Smaller groups are counted but not listed. Reasons for the uncertain and protected buckets are listed with counts. `--json` carries every figure.

## Limits and honesty
- A group is a **possibility for you to review**, not a statement that its mail is unnecessary.
- Volume is the sum of indexed message sizes (Gmail's size estimate); messages without a size are counted separately (`SOME_SIZES_UNKNOWN`), and Gmail's own storage accounting may differ.
- A partial index recommends nothing (`INDEX_PARTIAL`); an empty index yields an empty report.
- Output has no message ids, addresses or links; only sender domains, as in the other reports.

## Guarantees
Read-only index handle; no Gmail, OAuth, Keychain or network; no plan, approval or execution is created; no new schema, scope or dependency; the M4 write-policy boundary is untouched; `LIVE_EXECUTION_ENABLED` stays False. Zero Additional Cost: standard library only.

## What comes next (not in this change)
M12B review and approval is now available ([CLEANUP-REVIEW.md](CLEANUP-REVIEW.md)); M12C recovery and safety (with #41), M12D controlled execution and M12E dashboard screens each need their own approval.
