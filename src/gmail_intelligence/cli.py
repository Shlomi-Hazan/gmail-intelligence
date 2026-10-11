"""Command-line interface. Fully offline: no Gmail, Google Cloud or network access."""
import argparse
import subprocess
import sys
from pathlib import Path

from gmail_intelligence import __version__

MIN_PYTHON = (3, 10)
OK, WARN, FAIL = "OK", "WARN", "FAIL"


def _git(*args, cwd=None):
    try:
        proc = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, check=False)
    except OSError:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def doctor_checks(cwd=None):
    """Return a list of (status, name, detail) for local development prerequisites only."""
    checks = []
    have = sys.version_info[:3]
    ok = have >= MIN_PYTHON
    checks.append((OK if ok else FAIL, "python", "%d.%d.%d (need >= %d.%d)" % (*have, *MIN_PYTHON)))

    if _git("--version") is None:
        checks.append((FAIL, "git", "git not found"))
        return checks
    checks.append((OK, "git", "available"))

    root = _git("rev-parse", "--show-toplevel", cwd=cwd)
    if root is None:
        checks.append((WARN, "repository", "not inside a git repository; repo checks skipped"))
        return checks
    root = Path(root)
    checks.append((OK, "repository", "git repository found"))

    scanner = root / "scripts" / "scan_secrets.py"
    checks.append((OK if scanner.is_file() else FAIL, "secret scanner", "scripts/scan_secrets.py"
                   + ("" if scanner.is_file() else " missing")))

    hooks = _git("config", "core.hooksPath", cwd=root)
    if hooks == ".githooks":
        checks.append((OK, "pre-commit hook", "enabled (core.hooksPath=.githooks)"))
    else:
        checks.append((WARN, "pre-commit hook", "not enabled; run: git config core.hooksPath .githooks"))

    tracked = _git("ls-files", ".env", cwd=root)
    checks.append((FAIL, "env file", ".env is tracked by git") if tracked
                  else (OK, "env file", ".env is not tracked"))
    return checks


def cmd_version(_args):
    print(f"gmail-intelligence {__version__}")
    return 0


def cmd_doctor(_args):
    checks = doctor_checks()
    for status, name, detail in checks:
        print(f"[{status:<4}] {name}: {detail}")
    failed = sum(1 for status, _, _ in checks if status == FAIL)
    warned = sum(1 for status, _, _ in checks if status == WARN)
    print(f"{failed} failed, {warned} warnings (local checks only; no network, no Gmail)")
    return 1 if failed else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gmail-intelligence",
        description="Gmail Intelligence (early development). Offline: no Gmail integration yet.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{version,doctor}")
    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="check local development prerequisites (offline)").set_defaults(func=cmd_doctor)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)  # argparse exits with status 2 on usage errors
    return args.func(args)
