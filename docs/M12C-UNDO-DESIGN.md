# M12C.2 — Real archive undo: design and fake-mailbox validation

Status: **design only** (issues #61 and #41). It authorizes no code for a real Gmail undo, no change to the live write policy and no Gmail access. `LIVE_EXECUTION_ENABLED` stays `False`. Everything below describes what exists today (all against the in-memory fake mailbox), what is missing, and the decisions the owner must take before any real undo can be built.

## 1. What exists (M4D, fake mailbox only, unchanged)
`cleanup_undo.py` implements the whole undo flow against `FakeMailbox`; it is unreachable from the CLI and `type(mailbox) is FakeMailbox` is enforced.

1. **Separate owner authorization** — a typed phrase unique to one item (`UNDO <seq> <exec> <hash8>`), valid 15 minutes, one authorization = one attempt, lockout after repeated wrong phrases. The archive approval authorizes nothing here.
2. **Eligibility** — only an item recorded `APPLIED` with checked trusted-adapter evidence whose recorded previous labels contain `INBOX`; intact plan and the one consumed approval; execution not running.
3. **Live preflight** (read-only) — account verified; the message is in *exactly* the archived label set recorded for it; same thread; no protected or changed sibling in the thread.
4. **Durable `UNDO_INTENT`** committed before any mutation, then **at most one** mutation (`restore_inbox`: adds INBOX only), never retried.
5. **Independent, execution-bound trusted post-read** → `RESTORED` only if the labels equal exactly the originally recorded set; otherwise `UNKNOWN`.
6. **Reconciliation** (`reconcile_undo`) — no mutation; a fresh bound observation resolves `OPEN`/`UNKNOWN` to `RESTORED`, `NOT_RESTORED` (observed unmodified) or `CONFLICT` (anything else, including an absent message). Failure to observe leaves it `UNKNOWN`.
7. **Ledger** — `UNDO_AUTHORIZED → UNDO_INTENT → UNDO_RESULT` in the hash-chained, append-only audit log, with a strict state machine (any other sequence is `INCONSISTENT` and authorizes nothing). The original item rows, evidence and archive audit events are never touched. Events carry no message ids, labels or phrase.

### Requirement → current fake implementation
| Requirement | Today | Gap |
|---|---|---|
| Explicit owner selection and approval | per-item typed phrase, TTL, lockout | no owner CLI; per-item only (no bulk undo model) |
| Only previously archived messages | `_original` (APPLIED + trusted evidence + INBOX in previous labels) | — |
| Restore INBOX only where verified safe | exact-state and thread preflight, protected-sibling check | — |
| Do not alter unrelated labels | the inverse adds INBOX only; success needs exact original label set | real route does not exist |
| Preserve execution history | undo has its own ledger; history is frozen | — |
| Durable intent before mutation | `UNDO_INTENT` committed first | — |
| Fresh execution-bound observation | trusted observation bound to a context | live adapter needs an undo-phase context (see §3) |
| At most one attempt, no auto retry | one authorization, one attempt; tested | — |
| UNKNOWN stays UNKNOWN | yes; only a fresh observation resolves it | — |
| Drift / conflict detection | preflight refusal; reconcile → `CONFLICT` | — |
| Refuse unsafe or unverified undo | yes | — |
| Separate written authorization for live use | not modelled | needs its own switch and approval (§3) |
| No delete, Trash or other class | the fake mutation is INBOX-add only | must be enforced in the real policy |

## 2. Gaps that prevent a real Gmail undo
1. **The live write policy is archive-only.** `gmail_write_policy` allows exactly four request families; the only mutation body is `{"removeLabelIds":["INBOX"]}`. Restoring INBOX needs a *new mutation body* (`addLabelIds`), i.e. a new mutation class. A guard test deliberately forbids `addLabelIds`/`restore_inbox` in the write modules today. This is a write-policy change and needs the owner's explicit decision; it is **not** made here.
2. **No real adapter method.** `ArchiveAdapter` has `verify_account`, `message_state`, `thread_state`, `archive_message` and `observe`, but no restore operation, and `cleanup_undo._gate` accepts only `FakeMailbox`. The live entry points (`cleanup_live`) say undo is deferred.
3. **No live switch for undo.** `LIVE_EXECUTION_ENABLED` is False and gates archive execution; undo has no gate of its own.
4. **No owner entry point.** There is no CLI to select, authorize, run or reconcile an undo (by design so far). Recovery status (M12C.1) deliberately excludes undo records.
5. **Write token usability (#41).** The write token lasts about an hour, nothing refreshes it and a new login is refused while one is stored; an interactive authorize-then-undo needs this decided without weakening the separate write boundary.
6. **Bulk undo has no model.** The engine is per item; undoing a 500-message execution as 500 separate typed phrases is not usable, and a single phrase for many items is a new approval semantic.
7. **Live reconciliation is read-only but unbuilt** (M12C.1 only reports the local journal).
8. **Consolidated security review** of the finished M4 plus the undo addition has not been done (#41).

## 3. Design decisions (proposed; each needs owner approval before code)
- **D1. One additive mutation class, nothing else.** A second fixed request in the allowlist: `POST …/messages/{id}/modify` with body exactly `{"addLabelIds":["INBOX"]}` and the same fixed response projection. No other label may be added, no removal, no Trash/untrash, no delete, no batch endpoints. The existing archive body stays unchanged; both bodies are compared byte-for-byte.
- **D2. Separate type and gate.** A distinct undo capability on the adapter (`restore_inbox`) reachable only from the undo flow, a distinct permit like the canary's, and its **own** disabled constant (e.g. `LIVE_UNDO_ENABLED = False`) that does not piggyback on the archive switch. Flipping it needs a separate written owner authorization.
- **D3. Reuse the M4D engine unchanged.** The real undo calls the same `authorize_undo` / `undo_item` / `reconcile_undo` logic with a mailbox that satisfies the same interface; the fake-only `_gate` becomes an explicit `FAKE`/`LIVE` allow, mirroring `cleanup_recovery._recover`. No second engine.
- **D4. Context-bound live observation.** The real adapter must produce observations bound to the undo phase contexts (`UNDO_POSTREAD`, `UNDO_RECONCILE`) exactly as the fake does; an observation made for the archive, another intent or another phase must be refused (already tested for the fake).
- **D5. Strict preconditions kept.** Message must still be in exactly the archived state, same thread, no protected sibling; any drift refuses *before* the intent. A message the owner legitimately changed since archiving is therefore not undone (conservative by design; the owner can do it by hand).
- **D6. Outcome vocabulary kept.** Restore is `RESTORED` only on an exact original label set; ambiguity is `UNKNOWN`; reconciliation may end `CONFLICT` (final, including an absent message). No automatic retry, ever; a `NOT_RESTORED` result may be followed by a *new* authorization.
- **D7. Bulk undo = a reviewed reversal plan, later.** Per-item undo stays the primitive. A bulk reversal would be its own plan derived only from `APPLIED` items of one execution, reviewed and approved like M12B, executed in slices under M12D's rules. Not designed here; flagged as a decision for M12D.
- **D8. Token handling.** Keep the separate write grant; decide the refresh/re-login usability under #41 without merging the read and write boundaries.
- **D9. Read-only visibility first.** Before any live undo, extend the M12C.1 recovery status to include open/UNKNOWN undo ledgers (read-only). The existing guard tests restrict who may import the undo module, so this needs a deliberate, reviewed adjustment of that guard.

## 4. Safety boundaries (all remain in force)
Metadata only; no content; no permanent deletion; no Trash; no new OAuth scope beyond the existing separate write grant (`gmail.modify`, already the write scope); no automatic retry or resume; UNKNOWN on ambiguity; append-only audit; no real mailbox data in tests, issues or logs; Zero Additional Cost.

## 5. Synthetic validation added in this change
The M4D suite already covers: success restoring INBOX only, unrelated labels and other items untouched; drift (changed or extra labels, already-in-inbox, lost label, joined thread, vanished message); conflicting protections; ambiguous mutations (timeouts, 4xx/5xx, malformed) → `UNKNOWN`; crashes before/during/after the mutation → `OPEN` resolved by observation only; duplicate and racing attempts; lockout and expiry; no automatic retry; unchanged archive history.
`tests/test_undo_reconcile_conflict.py` adds what was missing: reconciliation ending in a final **`CONFLICT`** when Gmail shows a conflicting label set or the message vanished (no second mutation, no new authorization, nothing left to reconcile); an unobservable message keeping `UNKNOWN`; and byte-for-byte append-only audit rows across undo + reconciliation (the `UNKNOWN` result is kept, not rewritten). No engine, policy or approval semantics were changed.

## 6. Recommended next step
**M12C.3 — owner decision, then a policy-only increment.** First the owner decides D1/D2/D9 (the new mutation class, the separate undo switch, the guard adjustment). Only after that: (a) a policy-and-transport change adding the single `addLabelIds:["INBOX"]` request, tested against the fake HTTP layer with the new guard tests, disabled by default; (b) read-only undo visibility in the recovery status; (c) a reviewed owner CLI behind the disabled switch. Live use of any of it needs a separate written authorization after the consolidated security review.
