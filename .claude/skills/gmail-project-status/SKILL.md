---
name: gmail-project-status
description: Read-only snapshot of the Gmail Intelligence project - current branch, working-tree state, current milestone, open issues/PRs and the next approved step. Use when the user asks where the project stands or what to do next.
allowed-tools: Bash(git status:*), Bash(git branch:*), Bash(git log:*), Bash(gh issue list:*), Bash(gh pr list:*), Bash(gh pr view:*), Read, Grep
---

# gmail-project-status

Read-only. Never modify files, branches or GitHub state. Never access Gmail.

1. `git branch --show-current`, `git status --short`, `git log --oneline -5`.
2. `gh pr list --state open` and `gh issue list --state open` (GitHub reads only; skip quietly if `gh` is unavailable).
3. Read `docs/ROADMAP.md` for the milestone list and `README.md` for the current status line.
4. Report concisely, in the user's language:
   - Branch and whether the tree is clean.
   - Current milestone (the lowest one with open work; M0A-M0C are foundation work, Gmail features start at M1).
   - Open PRs/issues relevant to it.
   - The next *approved* step. If the next milestone has not been explicitly approved by the user, say "awaiting your approval" rather than proposing to start it.

Gmail functionality is not implemented yet; do not describe it as available.
