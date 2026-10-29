# Subscription review (M9A)

`gmail-intelligence mailbox subscriptions` lists **possible** low-value subscriptions from the local index, with the evidence for each. It is metadata only and read-only (issue #27). It is a new subcommand of `mailbox`; it reuses the existing sender analytics grouping and the M3 classification instead of re-aggregating, and no dashboard screen is added.

```
gmail-intelligence mailbox subscriptions [--account EMAIL] [--by domain|address] [--limit 1-100] [--min-messages 2-1000] [--all] [--reveal-senders] [--json]
```

## What it can infer
Per sender domain (or address): message count, unread ratio, the age of the oldest unread message, messages per 30 days, last-90-days vs previous-90-days trend, and the dominant M3 class (promotional / newsletter / automated notification). Each signal is labelled `OBSERVED` (counted from the index) or `INFERRED` (from the M3 heuristic classification).

A group is `STRONGER_EVIDENCE`, `MODERATE_EVIDENCE` or `WEAK_EVIDENCE` by a small point score, and the recommendation is always `REVIEW_MANUALLY`: open a message in Gmail yourself and look for an unsubscribe option. Reading what arrives counts as engagement: a group that is not clearly unread is never above weak. A group is `NOT_RECOMMENDED` when it has a starred or sent-to message, personal-category mail, or has been silent for over a year; `NOT_ENOUGH_EVIDENCE` with too little history or no bulk-type classification. By default only reviewable groups are shown; `--all` lists the rest with the reason.

## What it cannot infer
Whether a sender is really a subscription, whether you want it, or whether an unsubscribe option exists: no subject, snippet, body or header other than `From` is indexed. Unsubscribe data is always reported as `NOT_CHECKED`. Thresholds are heuristics, shown in the JSON output, and have not been validated on a real mailbox.

## Guarantees
Read-only index access; no Gmail, OAuth or Keychain; no network; no unsubscribe request, URL visit or sender contact; no message ids or links in the output; addresses are masked unless `--reveal-senders`; stored text is never echoed except sender domains/addresses. Output is deterministic. No new schema, scope, dependency or cost (Zero Additional Cost: standard library only).

## M9A vs M9B
M9B (recognising `List-Unsubscribe` / `List-Id` headers) needs a separately reviewed header extension and is **not** implemented here.
