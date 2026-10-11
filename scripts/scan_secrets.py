#!/usr/bin/env python3
"""Minimal, dependency-free secret scanner for local development.

Modes:
  (default)  scan the exact blobs that are staged in the Git index for the next commit
  --all      scan every blob currently in the index (stage 0)

Design rules:
  * Staged content is read from the index by blob id, never from the working tree.
  * Enumeration uses NUL-delimited Git output with rename/copy detection disabled, so
    every added/modified/type-changed entry is scanned under its destination path.
  * Fail closed: any Git failure, unreadable blob or unmerged entry exits with status 2.
  * Findings print only an escaped path, a line number and a rule name -- never content.

Exit status: 0 clean, 1 findings, 2 scanner error (treat as blocked).

This is a best-effort local safety net, not a guarantee (see docs/SECURITY.md).
"""
import json
import re
import subprocess
import sys

MAX_BLOB_BYTES = 5 * 1024 * 1024  # blobs larger than this are blocked, not skipped

RULES = {
    "github-token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "aws-access-key-id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private-key-block": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "google-oauth-client-id": re.compile(r"\b[0-9]{6,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com\b"),
    "google-oauth-client-secret": re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"),
    "google-refresh-token": re.compile(r"\b1//[0-9A-Za-z_\-]{40,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    "oauth-json-secret": re.compile(
        r"(?i)\"(client_secret|refresh_token|access_token)\"\s*:\s*\"[^\"<>]{8,}\""
    ),
}
# key = value assignments; group "value" is the candidate secret.
GENERIC = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*"
    r"['\"]?(?P<value>[A-Za-z0-9/+_\-.]{16,})['\"]?"
)
# Exempt only values that are *entirely* an obvious placeholder, never substrings.
PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(changeme|change[_-]me|replace[_-]me|placeholder|your[_-][a-z0-9_-]+|x{16,}|\*{16,}|\.{16,})$"
)

# Matched case-insensitively against the lower-cased basename / path components.
BLOCKED_BASENAME = re.compile(
    r"^(?:"
    r"\.env(?:\.(?!example$|sample$|template$).+)?"            # .env, .env.local (not .env.example)
    r"|(?:.*[-_.])?tokens?\.json"                             # token.json, oauth-token.json
    r"|(?:refresh|access|oauth)[-_]?tokens?(?:\.[a-z0-9]+)?"
    r"|client[_-]?secrets?.*\.json"
    r"|credentials?\.json"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?"
    r"|.*\.(?:pem|key|p12|pfx|jks|keystore|ppk)"
    r"|.*\.(?:mbox|eml|emlx|msg|pst|ost|olm)"
    r"|.*\.(?:sqlite3?|db)(?:-journal|-wal|-shm)?"
    r")$"
)
BLOCKED_DIRS = {".oauth", "secrets", "mail-export", "gmail-export", "gmail-backup", "mailbox-export"}

REGULAR_MODES = {"100644", "100755"}


class ScanError(Exception):
    """Raised for any condition that prevents a complete scan (fail closed)."""


def git(*args):
    try:
        proc = subprocess.run(["git", *args], capture_output=True, check=False)
    except OSError:
        raise ScanError("cannot execute git") from None
    if proc.returncode != 0:
        raise ScanError(f"git {args[0]} failed (exit {proc.returncode})")
    return proc.stdout


def show_path(path):
    """Escape a path for terminal output (handles newlines, tabs, quotes, non-UTF-8)."""
    return json.dumps(path, ensure_ascii=True)[:240]


def staged_entries():
    """Yield (path, mode, blob_sha) for every entry that is new or changed in the index."""
    if git("ls-files", "-u", "-z"):
        raise ScanError("index has unmerged entries")
    parts = git("diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev").split(b"\0")
    i = 0
    while i < len(parts) and parts[i]:
        meta = parts[i].decode("ascii", "replace")
        if not meta.startswith(":") or i + 1 >= len(parts):
            raise ScanError("unexpected git diff output")
        _old_mode, new_mode, _old_sha, new_sha, status = meta[1:].split(" ")
        path = parts[i + 1].decode("utf-8", "surrogateescape")
        i += 2
        if status.startswith("D"):
            continue  # deletions carry no new content
        if status.startswith("U"):
            raise ScanError("index has unmerged entries")
        yield path, new_mode, new_sha


def all_entries():
    out = git("ls-files", "-s", "-z")
    for rec in out.split(b"\0"):
        if not rec:
            continue
        try:
            meta, raw_path = rec.split(b"\t", 1)
            mode, sha, stage = meta.decode("ascii").split(" ")
        except ValueError:
            raise ScanError("unexpected git ls-files output") from None
        if stage != "0":
            raise ScanError("index has unmerged entries")
        yield raw_path.decode("utf-8", "surrogateescape"), mode, sha


def check_filename(path):
    parts = path.replace("\\", "/").lower().split("/")
    if any(p in BLOCKED_DIRS for p in parts[:-1]) or BLOCKED_BASENAME.match(parts[-1]):
        return [(path, 0, "blocked-filename")]
    return []


def decode_for_scan(data):
    """Return text views of the blob. Never raises on undecodable content."""
    views = [data.decode("latin-1")]  # lossless byte->char view; secrets are ASCII
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        views.append(data.decode("utf-16", "replace"))
    return views


def scan_bytes(path, data):
    findings = []
    for text in decode_for_scan(data):
        for no, line in enumerate(text.split("\n"), 1):
            for rule, rx in RULES.items():
                if rx.search(line):
                    findings.append((path, no, rule))
            for m in GENERIC.finditer(line):
                if not PLACEHOLDER_VALUE.match(m.group("value")):
                    findings.append((path, no, "generic-assignment"))
    return sorted(set(findings))


def scan_entry(path, mode, sha):
    findings = check_filename(path)
    if mode == "160000":
        return findings + [(path, 0, "unsupported-submodule-entry")]
    if mode != "120000" and mode not in REGULAR_MODES:
        return findings + [(path, 0, "unsupported-entry-type")]
    size_txt = git("cat-file", "-s", sha).strip()
    try:
        size = int(size_txt)
    except ValueError:
        raise ScanError("cannot determine blob size") from None
    if size > MAX_BLOB_BYTES:
        return findings + [(path, 0, "oversized-blob")]
    data = git("cat-file", "blob", sha)  # exact staged bytes; symlinks yield their target text
    if len(data) != size:
        raise ScanError("blob size mismatch")
    return findings + scan_bytes(path, data)


def run(argv):
    if argv[:1] == ["--all"]:
        entries = list(all_entries())
    elif not argv:
        entries = list(staged_entries())
    else:
        raise ScanError("usage: scan_secrets.py [--all]")
    findings = []
    for path, mode, sha in entries:
        findings += scan_entry(path, mode, sha)
    for path, line, rule in findings:
        print(f"POTENTIAL SECRET: {show_path(path)}:{line} [{rule}] (content not shown)")
    if findings:
        print("Commit blocked. Remove the data (and rotate it if real).", file=sys.stderr)
        return 1
    return 0


def main(argv):
    try:
        return run(argv)
    except ScanError as exc:
        print(f"SCANNER ERROR: {exc}. Treating as blocked.", file=sys.stderr)
        return 2
    except Exception as exc:  # fail closed; report the type only, never content
        print(f"SCANNER ERROR: unexpected {type(exc).__name__}. Treating as blocked.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
