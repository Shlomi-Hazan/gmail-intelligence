#!/usr/bin/env python3
"""Minimal, dependency-free secret scanner for local development.

Scans staged changes (default), explicit files, or all tracked files.
Never prints matched content: only file, line number and rule name.
This is a best-effort safety net, not a guarantee. See docs/DEVELOPMENT.md.
"""
import re
import subprocess
import sys

RULES = {
    "github-token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "aws-access-key-id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private-key-block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "google-oauth-client-id": re.compile(r"\b[0-9]{6,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com\b"),
    "google-oauth-client-secret": re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"),
    "google-refresh-token": re.compile(r"\b1//[0-9A-Za-z_\-]{40,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    "generic-assignment": re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}['\"]?"
    ),
}
BLOCKED_NAMES = re.compile(
    r"(^|/)(\.env(\.(?!example$).+)?|token.*\.json|client_secret.*\.json|credentials\.json)$|\.(sqlite3?|db|mbox|eml|emlx|pem|p12)$"
)
PLACEHOLDER = re.compile(r"(?i)<[^>]*>|example|placeholder|changeme|your[_-]")


def scan_text(name, text):
    findings = []
    if BLOCKED_NAMES.search(name):
        findings.append((name, 0, "blocked-filename"))
    for no, line in enumerate(text.splitlines(), 1):
        for rule, rx in RULES.items():
            m = rx.search(line)
            if m and not (rule == "generic-assignment" and PLACEHOLDER.search(m.group(0))):
                findings.append((name, no, rule))
    return findings


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def self_test():
    # Synthetic, harmless strings assembled at runtime (never stored as literals).
    cases = {
        "github-token": "t = '" + "ghp_" + "A1" * 18 + "'",
        "aws-access-key-id": "k = " + "AKIA" + "ABCDEFGHIJKLMNOP",
        "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "google-oauth-client-secret": "s = " + "GOCSPX-" + "a" * 24,
        "google-refresh-token": "r = " + "1//" + "b" * 45,
        "generic-assignment": "api_key = '" + "Z9" * 12 + "'",
    }
    ok = True
    for rule, line in cases.items():
        hit = any(f[2] == rule for f in scan_text("x.py", line))
        print(f"{'PASS' if hit else 'FAIL'} detects {rule}")
        ok &= hit
    for name in (".env", "token.json", "mail.sqlite3", "a.mbox"):
        hit = bool(scan_text(name, ""))
        print(f"{'PASS' if hit else 'FAIL'} blocks filename {name}")
        ok &= hit
    for name, line in ((".env.example", "API_KEY=<set-locally>"), ("a.md", "plain text, nothing here")):
        clean = not scan_text(name, line)
        print(f"{'PASS' if clean else 'FAIL'} allows benign {name}")
        ok &= clean
    return ok


def main(argv):
    if argv[:1] == ["--self-test"]:
        return 0 if self_test() else 1
    if argv[:1] == ["--all"]:
        names = [n for n in git("ls-files").splitlines() if n]
        read = lambda n: open(n, encoding="utf-8", errors="ignore").read()
    elif argv:
        names, read = argv, lambda n: open(n, encoding="utf-8", errors="ignore").read()
    else:
        names = [n for n in git("diff", "--cached", "--name-only", "--diff-filter=ACM").splitlines() if n]
        read = lambda n: git("show", f":{n}")
    findings = []
    for n in names:
        try:
            findings += scan_text(n, read(n))
        except (OSError, subprocess.CalledProcessError):
            continue
    for f, no, rule in findings:
        print(f"POTENTIAL SECRET: {f}:{no} [{rule}] (content not shown)")
    if findings:
        print("Commit blocked. Remove the data (and rotate it if real).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
