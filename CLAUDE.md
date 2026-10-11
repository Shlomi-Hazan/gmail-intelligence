# CLAUDE.md — Gmail Intelligence

Claude-specific operating instructions. Shared rules for all AI agents live in `AGENTS.md`; this file does not repeat them.

## Communication
- Communicate with the user in Hebrew.
- Use English for code, filenames, commands, and commit messages.

## Working style
- Work milestone by milestone, within clear scope boundaries.
- Do not start the next milestone without explicit approval.
- Prefer small, reviewable changes.
- Report evidence (command output, verification results) rather than unsupported success claims.
- Run relevant validation before reporting completion.

## Claude Skills
- Project Skills live in `.claude/skills/`; plan in `docs/SKILLS.md`. A Skill does not grant Gmail API permissions; see `docs/SECURITY.md`.
- Do not install third-party Skills or MCP servers without approval.

## Workflow
Branch, PR and validation rules: `docs/DEVELOPMENT.md`. Enable the local secret-scan hook per clone: `git config core.hooksPath .githooks`.
