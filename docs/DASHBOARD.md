# Local dashboard (M6)

A calm, read-only dashboard over the local index. **LOCAL ONLY:** it never contacts Gmail, never reads the Keychain or OAuth data, never writes to the index, and has no action buttons.
Design language: "Quiet Ledger" (restrained colour, system fonts, precise type, no decoration). English and Hebrew (full RTL), light, dark or system appearance, desktop and mobile.

## 1. Use

```
gmail-intelligence dashboard serve [--account EMAIL] [--port N] [--open] [--reveal-senders] [--reveal-names] [--verbose]
gmail-intelligence mailbox insights [overview|freshness|volume|categories|senders|subscriptions|cleanup-summary|cleanup-history|organization|all] [--json] [--kind domain|address] [--limit N] [--by-month] [--reveal-senders] [--reveal-names]
```

`dashboard serve` prints one link such as `http://127.0.0.1:PORT/#t=<token>`; open it in your browser (or pass `--open`). The link is different on every launch and stops working when you stop the server (Ctrl-C).
There is **no `--host` option**: the server listens on `127.0.0.1` only. Without `--account` it uses the only account in the index (it never asks the Keychain). Sender addresses and label names are
hidden unless you start the server with `--reveal-senders` / `--reveal-names`. Try it without any real data: `python tests/dashboard_fixture.py --serve` serves a synthetic demo index.

`mailbox insights` is the same analytics as text or `--json` (M6A, issue #17), reusing the existing report/classification machinery.

## 2. Screens
| Screen | Shows |
|---|---|
| Overview | one plain-language summary, key figures, the **mailbox ribbon** (monthly volume stacked by type), type breakdown, leading sender domains |
| Trends | monthly volume (with unread), type mix over time (count or share), newsletter / notification / promotion trends |
| Senders | leading domains or masked addresses, and the domains behind subscription-like mail |
| Cleanup | what the cleanup policy would **recommend** (nothing is applied) and the history recorded by the local M4 audit ledger, with the audit chain status |
| Organization | the read-only M5 label analysis: hygiene findings, recommendation / rule / filter-suggestion counts, label plans by state |
| Data | index completeness, last full scan and its age, classification freshness, limits of an offline snapshot, privacy facts |

Every chart has a text equivalent (a keyboard-operable readout and a "View as table" alternative). Every panel loads on its own, so one failing request shows an error inside that panel only.

## 3. Honest data
Every number carries its **basis** (OBSERVED, INFERRED, MIXED), the age of the data and the index state. The header chip and a notice show when the index is partial or empty, when the last scan is older than 7 days, and
when classification rules changed after messages were classified (those messages are counted as unclassified, never as current). Months follow each message's own date; the month of the last scan is hatched because it may be incomplete.
A message with two compatible types (for example TRANSACTIONAL and FINANCIAL) is counted once, under the first in the fixed type order (`classify.TYPES`), so every breakdown adds up to the indexed total.
Cleanup figures are recommendations from the existing candidate engine (protected and potentially important mail excluded) and ledger records; they are not the current state of Gmail.

## 4. Local server security model (issue #18)
| Rule | Enforcement |
|---|---|
| Loopback only | binds `127.0.0.1` (random free port by default); no host parameter; tested |
| Read-only | only `GET` and `HEAD`; every other method gets 405; request bodies are refused; the database is opened with SQLite `mode=ro` + `query_only` (`index.ReadOnlyIndex`), so a write fails inside SQLite |
| Never migrates | an index not at schema v6 is refused with a clear message and left untouched (open it once with a normal command; a verified backup is made first) |
| Token | `secrets.token_urlsafe(32)`, per launch, held only in process memory, printed once as a URL **fragment** (never sent to a server), compared with `hmac.compare_digest`; every `/api/` request needs `Authorization: Bearer` |
| Browser handling of the token | read from the fragment, removed from the address bar with `history.replaceState`, kept in a JavaScript variable only: never in `localStorage`, cookies, the DOM, logs or URLs |
| Host (DNS rebinding) | exactly one `Host`, equal to `127.0.0.1:<port>` or `localhost:<port>`; anything else is refused, including for the page itself |
| Origin / fetch metadata | `Origin`, when present, must be this server's own origin; `Sec-Fetch-Site` must be `same-origin` (or `none` for the first page load); an API response is never a navigation |
| No CORS | no `Access-Control-*` header is ever sent and a preflight (`OPTIONS`) is refused, so a foreign page cannot read a response. A same-origin `GET` may omit `Origin` (browsers do); the token is the real gate, so such a request without the token is refused too |
| Static files | an in-memory allowlist built at start (regular files only, fixed extensions, no symlinks or dot-files); there is no path-to-file mapping at request time; traversal, `//`, backslashes, NUL and absolute-form targets are refused |
| Response headers | CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, CORP/COOP `same-origin` |
| Errors | fixed codes and messages; never a path, token, account or traceback; the token is never logged |
| No credentials | the server module imports no Gmail, OAuth, Keychain or write module (static test); the demo and tests also run with bombs on those entry points |

Limits, stated plainly: any program running as you on this Mac can read the index file or this process's memory; the token protects against web pages and other users of the network, not against local malware. The token appears in your terminal
and, until the server stops, may remain in the browser's global history (it is useless afterwards).

## 5. JSON API (all `GET`, under `/api/v1`)
Envelope: `{"section", "data", "basis", "explain": [CODES], "as_of", "index": {"state", "age_days", "stale", "health"}}`; `explain` holds stable codes the UI translates (never prose). Errors: `{"error": {"code", "message"}}` with 400/401/403/404/405/421/500/503.

| Route | Query | Data |
|---|---|---|
| `meta` | | app/API version, schema, languages, `read_only`, reveal flags (no account) |
| `overview` | | messages, threads, unread, inbox, size, date range, user labels, classified share, attention counts, health |
| `freshness` | | index state, last full scan, age, classification current/stale/unclassified, issues |
| `volume` | | monthly points (gap-filled) with unread and `in_progress`, peak, undated count |
| `categories` | `by=total|month` | type counts and shares, unclassified, multi-type count, optional monthly breakdown |
| `senders` | `kind=domain|address`, `limit=1..100` | ranked senders: display (masked addresses), counts, unread, first/last seen, dominant type |
| `subscriptions` | `limit=1..25` | newsletter / notification / promotion shares, monthly series, top domains |
| `cleanup/summary` | | candidate outcomes, decisive reasons, policy, protection rules |
| `cleanup/history` | `recent=1..100` | plans, approvals, executions with item outcomes, audit chain status and recent events |
| `organization` | | label counts, hygiene / recommendation / rule / filter summaries, label plans by state |

Unknown or repeated parameters are rejected. Whether addresses or names are revealed is a server-start choice; a client cannot ask for more.

## 6. Language, direction and appearance
* `en.json` / `he.json` hold every user-visible string, including the server's code vocabularies (types, states, audit events, reasons, explanation codes); tests check that both files have the same keys and placeholders and cover every code. Plurals use `Intl.PluralRules` (Hebrew has one, two, many and other). Numbers and dates use `Intl` with Latin digits in both languages.
* Direction follows the language (`dir="rtl"` for Hebrew). CSS uses logical properties only (a test rejects physical ones outside the time axis), so one stylesheet serves both. Time axes always run left to right; surrounding layout mirrors. Mailbox-derived text is wrapped in `<bdi>`, stripped of control and bidirectional-override characters on the server and in the browser, and rendered only as text.
* Language and appearance (System / Light / Dark) are chosen in the header menu and saved in `localStorage` under `gi.lang` / `gi.theme` (nothing else, never an account). A tiny script applies them before first paint; `matchMedia` tracks the system appearance.

## 7. Accessibility and responsiveness
Semantic landmarks and headings, a skip link, visible focus, keyboard-operable segmented controls and charts (arrow keys, Home/End, PageUp/PageDown), chart tables, `aria-live` readouts, text colours at WCAG AA in both themes (a test computes the ratios from the real tokens), chart colours at 3:1 or better and never the only carrier of meaning (labels, counts, tables), 44px touch targets on coarse pointers, safe-area padding, `dvh`, hover gated to `(hover: hover)`, `prefers-reduced-motion`, forced-colors fallback. Layouts: left sidebar (right in RTL) from 900px, bottom navigation below.

## 8. Synthetic-test workflow
Unit and integration tests use temporary synthetic indexes and real HTTP requests to a loopback server on a free port (`tests/test_analytics.py`, `test_dashboard_server.py`, `test_dashboard_ui.py`, `dashboard_fixture.py`). Browser checks use the demo server above with the in-app browser; screenshots are local and synthetic and are not committed.

## 9. Dependencies
Zero new runtime or frontend dependencies: Python standard library (`http.server`, `sqlite3`), vanilla JavaScript ES modules, hand-written CSS, hand-authored SVG, system fonts. No build step, no npm, no CDN, no telemetry, no billing.
Supply-chain review of dashboard dependencies: none exist. Decision record: D119-D127 in DECISIONS.md.

## 10. Design skill usage report (evidence)
Skills were discovered on disk, loaded through the Skill tool and applied while making the decisions below. The Impeccable launcher binary was **not** downloaded or run (owner restriction); its instructions were applied by hand.

| Skill | Instructions loaded | Invoked | Decisions it influenced | Inspection / audit actually performed |
|---|---|---|---|---|
| `frontend-design@claude-plugins-official` | yes (`SKILL.md`) | yes | two-pass plan (tokens, layout concept) reviewed against generic defaults; avoided cream/terracotta and near-black/acid accents and the identical-card kit; spent boldness in one place (the mailbox ribbon); plain, sentence-case copy and actionable empty/error states | design review of every screen in the rendered UI |
| `apple-design` | yes (`SKILL.md`, foundations, patterns) | yes | system font stack, 4/8 spacing, 44px targets, dark palette steps with off-white text, empty/loading/error patterns, restraint (tint only what is interactive); its Liquid Glass chrome was deliberately not used (flat tone steps instead) | checked against its self-check list |
| `impeccable` (v4.5.2) | yes (`SKILL.md`, `operate.md`; parts of `critique.md`/`visualize.md`) | yes | Operate mode: familiarity and density over expression, one family of system fonts, restrained accent, complete component states, no orchestrated page-load motion | manual critique rounds on the rendered UI; **its launcher, detector and critique tooling were not run** |
| `design-taste-frontend` | yes (`SKILL.md`) | yes | house rules: no gradients, no resting shadows, no hairline boxes, no tiny uppercase labels, no monospace labels, no emoji or decorative shapes | `lint.mjs` run (3 shadow FAILs fixed, 0 FAIL/0 WARN after); `inspect.mjs` run on the live demo: its picture, footage, focal-point and page-motion findings target marketing pages and were judged not applicable to an Operate surface; the 13px body size (dense dashboard text), the one resting-shadow finding (the real floating menu), 11-12px axis and tab labels and the scrollable chart table were reviewed and accepted |
| `emil-design-eng` | yes | yes | frequency rule (route changes are not animated), 120/180ms ease-out, press feedback `scale(.97)`, exact transition properties, hover gated by media query | reviewed in the browser |
| `mobile-native` | yes | yes | no tap highlight, `touch-action`, `user-select` on controls, `dvh`, safe areas, theme-color | 390px and 360px layouts in the browser; real-device behaviour **not** tested |
| `animation-performance` | yes | yes | only colour/transform/opacity transitions, no layout animation, no `transition: all` (tested) | static tests |
| `design-library` | no | no | not used (no brand reference was requested) | |

Findings from the rendered-UI review that were fixed in this PR: a `null` text node leaking into panels; concatenated meta text in rank lists; an over-heavy single-series chart colour and harsh unread overlay; a share bar that did not fill its width; a truncated "Organization" tab label on narrow phones; an oversized mini-chart on tablets; reversed number order next to Hebrew text (numbers are now isolated left-to-right); one empty state repeated per panel when the index is empty; a clipped status chip and split values at 200% text size; resting shadows flagged by the lint.

## 11. Known limitations
* Rendering was verified in the in-app (Chromium-based) browser only: no Safari, Firefox, real phone, VoiceOver or other screen-reader run. Increased text size was checked at 200% root font size, not browser page zoom.
* The data are a snapshot of the last scan; the dashboard cannot know about newer mail. Classification is inferred; subjects and bodies are not indexed.
* Heavy sections (`cleanup/summary`, `organization`) can take a few seconds on a large index; results are cached in memory while the database file is unchanged.
* Safari/Firefox support for `color-mix`, `:has()` and logical properties is assumed (current versions), not tested here.
