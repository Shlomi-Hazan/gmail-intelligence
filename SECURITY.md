# Security Policy

Gmail Intelligence handles access to a personal mailbox, so please report security problems privately.

## Reporting a vulnerability
Use GitHub's private vulnerability reporting (repository **Security** tab > **Report a vulnerability**) once the repository is public and the feature is enabled. If it is not available, open an issue that says only that you have a security concern, **without details**, and the maintainer will arrange a private channel.

**Never post** OAuth client files, tokens, authorization codes, mailbox content, message subjects or sender addresses in an issue, pull request or comment.

## Scope and design
- Gmail access is read-only (`gmail.readonly`); the application contains no code that sends, modifies or deletes mail.
- Each user creates their own Google OAuth client; tokens are stored in the macOS Keychain; the mailbox index is a local SQLite file outside the repository.
- Threat model, controls and known limitations: [docs/SECURITY.md](docs/SECURITY.md).

This is a personal, best-effort project without a service-level commitment.
