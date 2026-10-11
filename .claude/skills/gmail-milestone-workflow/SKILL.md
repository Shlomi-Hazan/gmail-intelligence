---
name: gmail-milestone-workflow
description: Guide the Gmail Intelligence milestone workflow - feature branch, tests, Draft PR with issue reference, concise completion report. Use when starting, finishing or reporting on milestone work.
allowed-tools: Bash(git status:*), Bash(git branch:*), Bash(git log:*), Bash(git diff:*), Bash(gh issue list:*), Bash(gh pr list:*), Bash(gh pr view:*), Read, Grep
---

# gmail-milestone-workflow

Follow `docs/DEVELOPMENT.md`. Key rules:

1. **Before work:** sync `main` (fast-forward only), reuse the milestone's existing issue (`gh issue list`); create one only if none exists. Work on `feature/<milestone>-<topic>`; never push to `main`.
2. **During work:** small genuine commits, English messages, ending with the repository's Co-Authored-By trailer. Stay inside the milestone's scope; do not start the next milestone without the user's explicit approval.
3. **Before the PR:** run the `gmail-project-check` steps and, for security-relevant changes, `gmail-security-review`. Confirm Zero Additional Cost (no billing, paid service/API/dependency).
4. **PR:** one Draft PR to `main`, body with scope, tests (exact counts), risks, limitations, Zero Additional Cost confirmation, and `Refs #N` (use "Refs", not "Closes").
5. **Report:** facts and evidence only; list what was not verified.
6. **Never:** merge, enable auto-merge, mark Ready for Review, or close issues on the user's behalf before the merge. **The user merges manually**; after the merge, offer to close the issue.

Do not create redundant issues or run unrelated audits.
