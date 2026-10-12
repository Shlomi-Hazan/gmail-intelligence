# Classification (M3)

Local, offline, explainable triage of the metadata already in the M2 index. It never contacts Gmail, never changes a
mailbox, and its output is **not** a recommendation to delete, archive or label anything (that is M4/M5, with separate
approval).

## What it can and cannot know
The index stores only: message id, thread id, date, size estimate, lower-cased `From` address, unread flag and Gmail label
ids (plus label names). **No subject, body, snippet, recipients or attachments.** Rules and the optional model see nothing
more. Consequently most mail has no evidence for a precise type and ends up `UNKNOWN`; that is the intended, honest
outcome. Subject-based classification would need a separate, approved collection-policy change (see D16).

## Three separate ideas
| Idea | Values | Notes |
|------|--------|-------|
| **Type** (what it is; several may apply) | `PERSONAL`, `PROMOTIONAL`, `NEWSLETTER`, `SOCIAL`, `AUTOMATED_NOTIFICATION`, `TRANSACTIONAL`, `FINANCIAL`, `EDUCATIONAL`, `UNKNOWN` | `UNKNOWN` = no rule matched. |
| **Attention signal** (worth a look?) | `POTENTIALLY_IMPORTANT`, `REVIEW_NEEDED` | Independent of type: a message can be `TRANSACTIONAL` *and* potentially important. `REVIEW_NEEDED` is raised by rule conflicts or invalid model output. |
| **Evidence** (how sure) | `LOW`, `MEDIUM`, `HIGH` + rule id + one-line explanation | Strength of the rule's evidence, **not a probability**. |

Compatible types may coexist (`TRANSACTIONAL`+`FINANCIAL`, `NEWSLETTER`+`EDUCATIONAL`, `NEWSLETTER`+`PROMOTIONAL`,
`FINANCIAL`+`PROMOTIONAL`, and `AUTOMATED_NOTIFICATION` with anything except `PERSONAL`). Any other combination produced
at the same precedence is a **conflict**: both types are kept and `REVIEW_NEEDED` is added.

## Rule format
A rule is data, never code: one result (`--type X` or `--attention Y`) plus conditions, all of which must match:
`--sender` (exact address), `--domain` (exact domain, subdomains not matched), `--label` (Gmail label id or name,
case-insensitive), optional `--unread`/`--read`. At least one of sender/domain/label is required (unread alone is not
evidence). No regex, no wildcards, no shell/Python evaluation. Inputs are validated and normalized.

## Precedence (deterministic)
1. A **user rule beats any built-in rule**; among user rules higher `--priority` wins; then stronger `--confidence`.
2. Only the best group wins; lower-precedence matches are recorded as "overrode N" in the explanation.
3. Ties keep all tied types (see compatibility above). Attention signals are additive.
4. No type rule matched -> `UNKNOWN` (LOW, rule `engine.no-match`).
Results depend only on the message metadata and the active ruleset, so repeated runs are identical.

## Built-in rules (conservative; no personal data)
| Rule id | Evidence | Result |
|---------|----------|--------|
| `builtin.label-promotions` | Gmail Promotions tab | `PROMOTIONAL` MEDIUM |
| `builtin.label-social` | Gmail Social tab | `SOCIAL` MEDIUM |
| `builtin.label-forums` | Gmail Forums tab | `SOCIAL` LOW |
| `builtin.label-updates` | Gmail Updates tab (mixed content) | `AUTOMATED_NOTIFICATION` LOW |
| `builtin.label-primary` | Gmail Primary tab (only "not another tab") | `PERSONAL` LOW |
| `builtin.sender-automated` | local part like `noreply`, `notifications`, `mailer-daemon` | `AUTOMATED_NOTIFICATION` MEDIUM |
| `builtin.label-important` | Gmail's automatic IMPORTANT marker | attention `POTENTIALLY_IMPORTANT` LOW |
| `builtin.label-starred` | starred by the owner | attention `POTENTIALLY_IMPORTANT` MEDIUM |

Deliberately **not** assumed: all mail from a domain has one purpose; frequent senders are unimportant; unread means
urgent; any financial, medical, legal or academic meaning. `TRANSACTIONAL`, `FINANCIAL` and `EDUCATIONAL` are assigned
only by user rules (or the optional model, with LOW evidence).

## Commands (all local; `--account EMAIL` defaults to the logged-in account stored with the Keychain login)
```bash
gmail-intelligence classify status                  # coverage: current / stale / not yet classified
gmail-intelligence classify preview --limit 100     # shows results; saves NOTHING; never calls a model
gmail-intelligence classify run --limit 100         # classify the newest 100 messages needing work, store locally
gmail-intelligence classify run --all               # explicit intent: everything that needs work
gmail-intelligence classify report [--show-senders] # aggregates, results by rule, unknown groups (domains by default)
gmail-intelligence classify explain MESSAGE_ID      # stored results + reasons (sender hidden unless --show-sender)
gmail-intelligence classify rules list
gmail-intelligence classify rules add --type NEWSLETTER --domain news.example.test [--dry-run] [--priority N] [--confidence LEVEL] [--note TEXT]
gmail-intelligence classify rules disable|enable|remove u1
gmail-intelligence classify clear                   # delete stored classifications (rules and the index stay)
gmail-intelligence classify ai status               # shows configuration only; contacts nothing
```
Nothing reclassifies on its own: only `classify run` writes results. `rules add --dry-run` reports how many indexed
messages would match and change, without saving.

## Storage (schema v2)
Two additive tables in the same local SQLite file: `class_rules` (user rules, per account; kept by `mailbox purge`) and
`message_class` (one row per message/kind/value with confidence, source `rules`|`ai`, rule id, explanation, ruleset hash,
the message's scan id and time). A result is **stale** when the active ruleset changed (any user rule added, edited,
enabled, disabled, removed) or the message was rescanned; stale and unclassified messages are what `run` processes.
Re-running replaces a message's rows in one transaction per batch, so there are no duplicates and a failure leaves earlier
results intact. `status`/`report` count current, stale and unclassified separately and warn when the index is PARTIAL.

**Migration:** the first time any command opens a v1 (M2) index, the tool copies the database to
`index.sqlite3.pre-m3-backup-<UTC time>` (mode 600, same private folder) and adds the two tables in one transaction. No M2
row is read-modified or removed and no rescan is needed. If the upgrade fails the database stays at v1. To go back, quit
the tool and copy the backup over `index.sqlite3`; an M2-only build cannot open a v2 file, so restore the backup first.

## Optional local AI (disabled by default; NOT VERIFIED)
- Opt-in twice: `ai.json` (`{"enabled": true, "model": "<already installed local model>", "host": "127.0.0.1", "port": 11434}`)
  in the app-data folder, **and** `classify run --ai`. Preview never calls a model.
- Loopback hosts only (other hosts are refused), proxy settings ignored, no model download/pull, no cloud provider.
- Asked only about messages with **weak evidence** (only LOW rules, no user rule). It never overrides MEDIUM/HIGH evidence or any
  user rule. It sees the sender **domain**, Gmail system label ids and the unread flag only.
- Its reply must be exactly `{"type": "<known type>"}`; anything else is discarded, the message stays `UNKNOWN`/weak and gets
  `REVIEW_NEEDED`. Accepted answers are stored as LOW evidence with source `ai` ("uncalibrated; not a probability").
- It has no tools, no credentials and no way to start a mailbox operation; message-derived text is data, not instructions.
- Status: boundary, validation and local HTTP adapter are implemented and unit-tested with a **fake backend**. No local
  runtime is installed in the development environment, so **real inference has not been run**.

## Verification status
| Area | Status |
|------|--------|
| Rules engine, store, migration, CLI, reports | **Implemented and verified** by the offline test suite (synthetic data) and by an owner-run check on a real local index (migration with backup, a read-only preview, then persisted classification). Real mailbox figures are private and deliberately not published here. |
| Local AI (`--ai`) | Boundary, schema validation and loopback adapter implemented and tested with a **fake backend only**. **Real local inference is NOT VERIFIED.** |
| Classification accuracy | **Not measured.** |

Full processing coverage is not semantic accuracy: every indexed message can have a current result while many results rest on
weak evidence. In particular the Gmail **Primary** tab only means "not sorted into another tab" and the **Updates** tab mixes
receipts, bills and alerts, so `PERSONAL` (from Primary) and `AUTOMATED_NOTIFICATION` (from Updates) are LOW evidence and must
not be read as facts. Treat results as triage hints, never as grounds to delete anything.

## Day-to-day use
- Inspect: `classify status`, `classify report`, `classify explain MESSAGE_ID`, `classify rules list`.
- Change behavior: add/disable/remove a rule, then `classify preview --limit 100` and `classify run --all` to refresh
  (rule changes and rescans make results stale; nothing is recomputed automatically).
- Start over without touching mail data: `classify clear --yes` removes stored classifications only; the indexed messages,
  labels, scan history and your rules are kept.
- An unreadable or corrupt index is reported as an error and never modified; restore the pre-M3 backup or rescan.

## Zero Additional Cost
No paid API, model, dependency, billing setting or GitHub feature; no new dependencies at all (stdlib only); no automatic
download. If a local runtime is not installed, the AI path simply stays off.
