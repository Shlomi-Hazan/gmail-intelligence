# Development Workflow

## Setup and daily commands
Requires Python >= 3.10 and Git. Use a project-local venv; runtime dependencies are three free libraries (see [SETUP-GMAIL.md](SETUP-GMAIL.md) §8). `version` and `doctor` work without them.

```bash
git clone https://github.com/Shlomi-Hazan/gmail-intelligence.git && cd gmail-intelligence
git config core.hooksPath .githooks                     # enable the local secret-scan hook (once per clone)
PYTHONPATH=src python3 -m gmail_intelligence --help     # run without installing
PYTHONPATH=src python3 -m gmail_intelligence version
PYTHONPATH=src python3 -m gmail_intelligence doctor     # offline prerequisite check
python3 -m venv .venv && .venv/bin/pip install -e .       # dependencies + editable install (development)
# If `gmail-intelligence` fails with ModuleNotFoundError: the editable .pth file got the macOS "hidden" flag
# (iCloud-synced folder + Python 3.13+). Fix: chflags nohidden .venv/lib/python3.13/site-packages/*.pth
# or use a normal install: .venv/bin/pip install .   (`gmail-intelligence doctor` warns about this)
.venv/bin/python -I -m unittest discover -s tests -v    # all tests (offline; no Google account needed)
```
`version` and `doctor` are offline. Only `auth login` and `gmail check` contact Google (M1; see [SETUP-GMAIL.md](SETUP-GMAIL.md)). Exit codes: 0 success, 1 operational failure, 2 usage error. Local runtime data must live outside the repository.

## Branches and PRs
- `main` is stable and protected by ruleset `main-pr-only` (PR required; no force-push; no deletion). No direct pushes.
- One branch per Issue/theme: `docs/…`, `feat/…`, `fix/…`, `chore/…`.
- Open a **Draft PR** early; mark ready only after validation. **Never auto-merge**; the owner merges after review.
- Do not close Issues until the work is approved and merged.

## Commits
Small, genuine, reviewable; imperative English subject, Conventional-Commit style prefixes (`docs:`, `feat:`, `fix:`, `chore:`). Reference Issues with `(#N)`.

## Scope
Work milestone by milestone. Do not start the next milestone without explicit owner approval. Out-of-scope discoveries become new Issues, not silent changes.

## Validation before reporting completion
1. All tests pass: ``.venv/bin/python -I -m unittest discover -s tests -v`; `.venv/bin/python -m compileall -q src tests scripts`; `python3 -I scripts/scan_secrets.py --all` reports nothing; `git diff --check` is clean. The `gmail-project-check` Skill runs this gate.
2. Markdown relative links resolve.
3. `git ls-files` contains no env/token/db/mail files.
4. Working tree clean; branch pushed; PR base/head correct.
5. Tests/linters for the changed code (once code exists).
6. **Zero Additional Cost check:** the change adds no paid service, billing configuration, paid dependency, paid API or subscription.

## Local secret scanning
Enable once per clone:
```bash
git config core.hooksPath .githooks
```
The hook runs `python3 -I scripts/scan_secrets.py` on the exact staged blobs. It prints an escaped path, line and rule only — never matched content — and blocks the commit on findings (exit 1) or scanner errors (exit 2). Run the regression suite with `python3 -I -m unittest discover -s tests -v`. Hooks can be bypassed (`--no-verify`, clones without the hook); limits and residual risks are listed in [SECURITY.md](SECURITY.md) §5.3.

## Security review
Every PR answers the checklist in `.github/PULL_REQUEST_TEMPLATE.md`. Changes touching OAuth, token storage, the Gmail adapter, the executor, or LLM data flow need an explicit security note and owner approval.

## Evidence-based reporting
Completion reports cite commands and outputs (SHAs, check results, URLs). State what was *not* done or not verifiable. No success claims without evidence.

## Merging
The owner merges PRs manually after review. Agents open **Draft** PRs only, never merge, never enable auto-merge, and never mark a PR Ready. Issues are closed after the merge is verified.

## Continuous integration
`.github/workflows/ci.yml` runs compile check, tests and the full secret scan with read-only permissions, no secrets and a pinned checkout action. It is **manual-trigger only for now** (Zero Additional Cost): GitHub bills private-repo Actions minutes beyond the free quota when a payment method is on file, and this account's billing setup could not be verified from the API. To enable PR checks, confirm at https://github.com/settings/billing that no payment method is attached or the Actions budget is $0, then switch the trigger to `pull_request` for `main` as described in the workflow comment. CI is a second line of defense; the local hook remains the primary scanner entry point.

## Project Skills
Four read-only/advisory Skills live in `.claude/skills/` and are invoked in Claude Code by name (e.g. `/gmail-project-status`) or automatically when relevant: `gmail-project-status` (where are we, what is next), `gmail-project-check` (local test + scan gate), `gmail-security-review` (P0-P3 advisory review), `gmail-milestone-workflow` (branch -> tests -> Draft PR -> report). They contain no Gmail capability. See [SKILLS.md](SKILLS.md).

## Tracking
GitHub Milestones M0–M7 and Issues. Each PR links its Issues.

## Zero Additional Cost
Mandatory ([DECISIONS.md](DECISIONS.md) D8). Do not enable billing, paid APIs, paid dependencies, paid GitHub features or subscriptions. Every milestone's acceptance criteria include a cost verification. Unknown billing status blocks activation of a service.

## Safety during development
No real mailbox access until M1 is approved; tests use synthetic fixtures only. No mailbox-modifying execution without a separately approved workflow.
