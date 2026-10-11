# Development Workflow

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
1. Scanner regression suite passes: `python3 -I -m unittest discover -s tests -v`; and `python3 -I scripts/scan_secrets.py --all` reports nothing.
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

## Tracking
GitHub Milestones M0–M7 and Issues. Each PR links its Issues.

## Zero Additional Cost
Mandatory ([DECISIONS.md](DECISIONS.md) D8). Do not enable billing, paid APIs, paid dependencies, paid GitHub features or subscriptions. Every milestone's acceptance criteria include a cost verification. Unknown billing status blocks activation of a service.

## Safety during development
No real mailbox access until M1 is approved; tests use synthetic fixtures only. No mailbox-modifying execution without a separately approved workflow.
