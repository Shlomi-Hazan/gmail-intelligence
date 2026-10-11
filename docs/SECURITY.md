# Security

## Principles (approved)
- Repository is PRIVATE and must remain so.
- No secrets, OAuth tokens, personal messages, attachments, or mailbox metadata in Git.
- Emails are untrusted input (prompt-injection risk); email content never acts as instructions.
- No Gmail modification without a separately approved execution workflow.
- Least-privilege scopes; read-only first.

## Defense in depth
`.gitignore` alone is insufficient. Planned/recommended additional layers (proposals): pre-commit secret scanning, GitHub secret scanning/push protection (availability to be verified), PR review, and avoiding real data in tests.

## Skills policy
A Claude Skill is only instructions/tooling; it does **not** grant Gmail API permissions. Permissions come solely from OAuth scopes granted to the application. Any future Skill that can modify emails must go through the application's dry-run, approval, and audit architecture.

Proposed future Skills (not created):
`gmail-audit`, `gmail-classify`, `gmail-cleanup-preview`, `gmail-execute`, `gmail-organize`, `gmail-maintain`.

## Open questions
- Threat model (tracked in the M0 security Issue).
- Token storage and revocation procedure.
