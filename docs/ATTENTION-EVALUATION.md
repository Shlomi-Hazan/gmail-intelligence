# M8A-1: synthetic evaluation and measurements

> **Status: the owner approved, for EXPERIMENTAL algorithm v1 only, the ranking weights and thresholds and a retained-thread budget of 250,000. This is NOT validated real-world accuracy and NOT live Gmail acceptance.** The output keeps the label `PROVISIONAL` for the weights because they have not been validated on a real mailbox. All data below are synthetic; no Gmail, OAuth, Keychain or personal index was involved. The numbers say how the code behaves on invented data; they do not show that the ranking is useful for a real mailbox. Merge still needs an independent code review and CI results (the CI workflow is manual-only by policy).

Environment of every measurement: one Apple-silicon Mac (macOS, arm64, 11 cores, 18 GB RAM), Python 3.13.5, SQLite 3.45.3, rollback-journal mode (the index never uses WAL), the machine in normal use (no other load was controlled or measured). Reproduce with `.venv/bin/python -I tests/attention_bench.py` and `.venv/bin/python -I tests/attention_eval.py`.

Limitations: one machine and one Python/SQLite build; synthetic distributions of labels, threads and senders (a real mailbox differs); three repetitions per configuration, so the ranges are indicative, not statistical; `ru_maxrss` is a process high-water mark (it includes about 19 MB of interpreter and imports, listed separately); wall times vary by several tenths of a second between runs; nothing was measured on a real mailbox or a loaded machine.

## A. Performance and peak RSS (complete computation)

Method (`tests/attention_bench.py`): the synthetic index is built first; each scenario is then measured in a fresh child process, so the figure covers only the engine: candidate streaming, classification, scoring, thread collapse, sender diversity, sorting, the full snapshot hash and the cursor page. Two complete computations run per scenario (first page, then the next page through its cursor: every page recomputes the whole list). "Peak RSS delta" is the process high-water mark after minus before (`ru_maxrss`), about 20 MB of interpreter and imports excluded.

| Scenario (messages) | Retained threads | First page | Cursor page | Peak RSS delta |
|---|---|---|---|---|
| balanced mailbox (200,000) | 14,271 | 0.89 s | 0.84 s | 18.6 MB |
| 90% unread, all ages (200,000) | 3,720 | 1.81 s | 1.89 s | 12.7 MB |
| balanced + one user attention rule: full scan (200,000) | 14,705 | 3.26 s | 2.44 s | 17.3 MB |
| worst case, every message retained (100,000) | 100,000 | 2.24 s | 1.49 s | 84.9 MB |
| worst case (200,000) | 200,000 | 3.78 s | 3.70 s | 146.6 MB |
| worst case (400,000) | 400,000 | 7.59 s | 8.56 s | 286.4 MB |
| worst case (500,000, budget 500,000: complete) | 500,000 | 10.71 s | 10.04 s | 356.1 MB |
| worst case (600,000, budget 500,000) | > 500,000 | fails `RESULT_INCOMPLETE` after 7.01 s | - | 258.3 MB at the failure |

Reading: memory grows linearly with the number of RETAINED threads, about **0.72 KB per thread** at the peak (sorting and hashing included); the size of the mailbox matters only for time, because messages below the score threshold are never retained. Typical mailboxes retain a few percent. The failure case stops before sorting and hashing, so it peaks lower than a successful run of the same size.

## B. Retained-thread budget: 250,000 (approved for experimental v1)

Measured at EXACTLY the budget, with the code's constant, on a synthetic index of 250,000 messages that are all retained (the worst case), three runs per configuration (`first page` is one complete computation; the second column is the next page through its cursor, which recomputes everything):

| Configuration | Result | First page | Cursor page | Peak RSS, absolute | Peak RSS, incremental |
|---|---|---|---|---|---|
| 250,000 retained threads, sender limit off | complete | 4.3-4.6 s | 3.9-4.4 s | 198-207 MB | 179-188 MB |
| 250,000 retained threads, default sender limit (3) | complete | 3.3-5.5 s | 3.2-4.0 s | 201-215 MB | 182-195 MB |
| **Overall, exactly at the budget** | complete | **3.3-5.5 s** | 3.2-4.4 s | **198-215 MB** | **179-195 MB** |
| 250,001 retained threads (one over the budget) | `RESULT_INCOMPLETE`, no items | 2.7-3.6 s to the failure | - | 152-161 MB | 132-142 MB |

The earlier interpolation ("about 180 MB") was slightly low; the measured values above replace it. The increment is the high-water mark after minus before the computation; the absolute value adds about 19 MB of interpreter and imports.

* **Decision (owner):** `RETAINED_THREAD_BUDGET = 250,000` for **experimental v1**. It was reached on synthetic data on one machine; it is not validated on a real mailbox. The constant can be changed later without a schema change.
* Over the budget the command fails with `RESULT_INCOMPLETE` and shows no items; the user narrows with `--signal` or `--min-tier`. Nothing is truncated. With `--no-collapse` the budget counts messages instead of threads.
* A 500,000 budget measured 356 MB incremental and about 10 s per page (section A); it is not used.

## C. Ranking evaluation

Caveat that matters: the archetypes below were written to express the design's intent, and the weights were chosen with the same intent in mind, so the "intent" table checks consistency of the arithmetic with what the design says, not independent validity. It also shows where the provisional weights sit: for example, "important + unread from a personal sender" (40) is capped below a starred message (50) on purpose.

### C1. Documented intent (11 archetypes, written before scoring)

| archetype | intended level | score | tier |
|---|---|---|---|
| starred, personal, unread, recent | 4 | 70 | HIGH |
| starred, read, very old | 3 | 50 | MEDIUM |
| starred promotion | 3 | 50 | MEDIUM |
| important + unread, personal sender | 3 | 40 | MEDIUM |
| important + unread, unknown sender | 2 | 35 | MEDIUM |
| important + unread, transactional (user rule) | 2 | 35 | MEDIUM |
| important, read | 1 | 20 | LOW |
| unread, 3-14 days | 1 | 15 | LOW |
| promotion + important + unread | 0 | 5 | MINIMAL |
| noreply notification, unread | 0 | 0 | MINIMAL |
| unread, very old | 0 | 0 | MINIMAL |

Pairs with a higher intended level that score strictly higher: **47/47**.

### C2. Invariants over 20,000 random label/sender/age combinations

- bounds: 0 violation(s)
- star_floor: 0 violation(s)
- positive_monotone: 0 violation(s)
- penalty_monotone: 0 violation(s)

### C3. Sensitivity: each weight moved by +/-20% (corpus of 600 mixed messages)

| change | Kendall tau vs baseline | top-25 overlap | intent pairs kept |
|---|---|---|---|
| star x0.8 | 1.000 | 25/25 | 47/47 |
| owner_cap x0.8 | 1.000 | 25/25 | 47/47 |
| user rule weights x0.8 | 1.000 | 25/25 | 47/47 |
| important x0.8 | 0.998 | 25/25 | 47/47 |
| age points x0.8 | 0.998 | 25/25 | 47/47 |
| personal bonus x0.8 | 0.998 | 25/25 | 47/47 |
| inferred cap x0.8 | 0.975 | 25/25 | 45/47 |
| penalties x0.8 | 0.997 | 25/25 | 47/47 |
| star x1.2 | 1.000 | 25/25 | 47/47 |
| owner_cap x1.2 | 1.000 | 25/25 | 47/47 |
| user rule weights x1.2 | 1.000 | 25/25 | 47/47 |
| important x1.2 | 1.000 | 25/25 | 47/47 |
| age points x1.2 | 0.995 | 25/25 | 47/47 |
| personal bonus x1.2 | 1.000 | 25/25 | 47/47 |
| inferred cap x1.2 | 0.998 | 25/25 | 47/47 |
| penalties x1.2 | 0.998 | 25/25 | 47/47 |

Worst case: tau 0.975, top-25 overlap 25/25, intent pairs kept 45/47.

### C4. Flood scenarios (through the full pipeline)

| scenario | items listed | starred among them | total after filters |
|---|---|---|---|
| 10,000 look-alike unread mails from ONE sender among 25 starred (sender limit 3) | 28 | 25 | 28 |
| 10,000 look-alike unread mails from ONE sender among 25 starred (sender limit off) | 100 | 25 | 10025 |
| 5,000 look-alikes from 5,000 senders, each Gmail-IMPORTANT + unread (score 35) among 25 starred | 100 | 25 | 5025 |

### C5. Findings the owner should weigh
* The owner approved these weights and thresholds for **experimental algorithm v1** (the output still says `PROVISIONAL`: they are not validated on a real mailbox, and changing them later bumps `ALGORITHM_VERSION`).
* The order is stable: no single +/-20% change of a weight moves the top 25 at all on the 600-message corpus (overlap 25/25) and the worst rank correlation is 0.975.
* The only weight whose -20% change breaks intent pairs is the cap on inferred points (32 instead of 40): "important + unread from a personal sender" then no longer scores strictly above "important + unread from an unknown sender". Moving that cap is the most consequential single change.
* A flood of look-alike mail can fill the LOW and MEDIUM part of the list but can never outrank a starred message, because the star adds owner points that no inferred signal or penalty can reduce. With the default sender limit (3) one sender cannot occupy more than three places. Many different forged senders each carrying Gmail's IMPORTANT guess can still fill everything below the starred messages: the sender limit is not a defence against that, and the evidence class (`GMAIL_HEURISTIC`) is what tells the reader how weak those items are.
* The personal-versus-automated signal is weak without user rules (only the sender's local part and Gmail tabs are available), so with built-in rules alone the personal bonus never applies.
* Everything above is synthetic. Real usefulness (precision of what a person finds worth opening) has not been measured and cannot be without real data; that is a separate, separately authorized step.
