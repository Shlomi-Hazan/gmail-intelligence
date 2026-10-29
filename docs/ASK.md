# Metadata question answering (M11A)

`gmail-intelligence mailbox ask "QUESTION"` answers a small, fixed set of English questions about the **local metadata index** (issue #31). It is deterministic: no language model, no embeddings, no SQL generation, no network. It is a new `mailbox` subcommand; no dashboard chat is added.

## How it works
The question is untrusted text. It is lowercased, split into words and matched against an allow-list of six intents; only two integers may be taken from it (`last N months`, 1-60, and `top N`, 1-20). Each intent calls one existing read-only report function (`analytics`, `subscriptions`). The question is never echoed, executed, or turned into a query, and an instruction ("delete", "unsubscribe", "mark", "send"...) is never a question.

## Supported questions (examples)
| Intent | Example |
|---|---|
| Total messages | `How many messages do I have?` |
| Messages over time | `How many messages per month in the last 6 months?` |
| Top senders | `Which senders email me most?`, `Top 10 sender addresses` (addresses masked) |
| Unread count and trend | `How many unread messages do I have?`, `What is the unread trend over the last 12 months?` |
| Categories | `What categories of mail do I get?` |
| Subscription review statistics | `How many subscriptions should I review?` |

## Unsupported
Anything about message content, subjects, snippets or attachments; any action (delete, archive, label, unsubscribe, send); questions that match two topics (`ANSWERED` is never guessed: the reply is `AMBIGUOUS`); numbers out of range; non-English questions (Hebrew is a possible later enhancement). These get a fixed reply listing what is supported. An empty index, or no usable dates or classification, gives `INSUFFICIENT_EVIDENCE`, not a guess. Unsupported and insufficient replies still exit 0; the `status` field (`--json`) tells them apart.

## What an answer contains
`status`, `summary`, `observations` (figures counted from the index), `heuristics` (inferences: M3 classification, unread trend direction, M9A review estimates), `source` (index, report function and aggregate), `reference_period` and `freshness` (when the index was last scanned, its age and health; a snapshot, not live). Sender addresses are masked unless `--reveal-senders`; domains are shown. No ids, Gmail links or message content appear.

## Limits
Figures are only as fresh as the last scan (see `freshness`). Classification-based answers depend on the current M3 rules. The unread trend compares two halves of the window and excludes the in-progress month; it is a heuristic. Intent matching is keyword-based and can refuse valid but unusual phrasings.

## M11A vs a future local model
M11A is rule-based and needs no model. A later step may let a local model only *propose* a validated query plan from the same allow-list (never SQL or an action); that is not part of this change and needs separate approval, a model decision and a prompt-injection review.

## Guarantees and cost
Read-only index handle; no Gmail, OAuth, Keychain or network; no new schema, scope or dependency; `LIVE_EXECUTION_ENABLED` stays False. Zero Additional Cost: standard library only, no paid service or model.
