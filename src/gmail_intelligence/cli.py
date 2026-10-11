"""Command-line interface.

`version` and `doctor` are fully offline. Only `auth login`, `gmail check` (and the token refresh
inside them) contact Google; all other commands work locally. Google libraries are imported lazily.
Exit codes: 0 success, 1 operational failure (not ready, auth/API/storage error, declined), 2 usage.
"""
import argparse
import os
import shutil
import site
import stat
import subprocess
import sys
from pathlib import Path

from gmail_intelligence import __version__, config

MIN_PYTHON = (3, 10)
OK, WARN, FAIL = "OK", "WARN", "FAIL"


def _git(*args, cwd=None):
    try:
        proc = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, check=False)
    except OSError:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def hidden_pth_files(dirs=None):
    """`.pth` files carrying the macOS hidden flag. Python 3.13+ silently ignores them, which breaks
    editable installs (seen on iCloud-synced folders such as ~/Documents)."""
    hidden_flag = getattr(stat, "UF_HIDDEN", 0)
    if dirs is None:
        dirs = site.getsitepackages()
    found = []
    for d in dirs:
        for p in sorted(Path(d).glob("*.pth")):
            if getattr(p.stat(), "st_flags", 0) & hidden_flag:
                found.append(p)
    return found


def doctor_checks(cwd=None):
    """Return a list of (status, name, detail) for local development prerequisites only."""
    checks = []
    have = sys.version_info[:3]
    ok = have >= MIN_PYTHON
    checks.append((OK if ok else FAIL, "python", "%d.%d.%d (need >= %d.%d)" % (*have, *MIN_PYTHON)))

    hidden = hidden_pth_files()
    if hidden:
        checks.append((WARN, "editable install", f"{len(hidden)} hidden .pth file(s) are ignored by Python; "
                       f"fix: chflags nohidden {Path(hidden[0]).parent}/*.pth  (or use: pip install .)"))

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


def _fail(message):
    print(f"error: {message}", file=sys.stderr)
    return 1


def _store():
    from gmail_intelligence.keystore import TokenStore
    return TokenStore()


def cmd_auth_setup(args):
    path = config.client_secret_path()
    if args.import_file:
        from gmail_intelligence.oauth import AuthError, load_client_config
        src = Path(args.import_file).expanduser()
        try:
            load_client_config(src)
        except AuthError as exc:
            return _fail(exc)
        config.ensure_app_dir()
        shutil.copyfile(src, path)
        os.chmod(path, 0o600)
        print(f"Client file validated and stored at {path} (permissions 600).")
        print(f"You can now delete the downloaded copy: {src}")
        return 0
    config.ensure_app_dir()
    print(f"""Google Cloud setup (manual; free; never enable billing). Full guide: docs/SETUP-GMAIL.md
 1. Create a project in the Google Cloud console and enable the Gmail API.
 2. Google Auth platform: audience External, status Testing, add yourself as the only test user.
 3. Data access: add exactly one scope: {_scope()}
 4. Clients: create an OAuth client of type 'Desktop app' and download its JSON file.
 5. Run: gmail-intelligence auth setup --import <downloaded-file>
    (stores it as {path}, outside Git, permissions 600)
 6. Run: gmail-intelligence auth login""")
    print("Client file: " + ("present" if path.exists() else "not yet imported"))
    return 0


def _scope():
    from gmail_intelligence.oauth import SCOPE
    return SCOPE


def cmd_auth_login(args):
    from gmail_intelligence import gmail, oauth
    from gmail_intelligence.keystore import KeystoreError

    path = config.client_secret_path()
    try:
        store = _store()
        oauth.load_client_config(path)
    except (KeystoreError, oauth.AuthError) as exc:
        return _fail(exc)
    print(f"Requested permission (read-only): {oauth.SCOPE}")
    print("Your browser will open. Sign in with the Google account you want to connect and review the consent.")
    try:
        creds, granted = oauth.run_login(path, open_browser=not args.no_browser)
        profile = gmail.build_reader(creds).get_profile()
    except (oauth.AuthError, gmail.GmailApiError) as exc:
        return _fail(exc)
    account = profile["emailAddress"]
    print(f"Authorized account: {account}")
    if args.expect_account:
        if args.expect_account.lower() != account.lower():
            return _fail(f"authorized account differs from --expect-account ({args.expect_account}); nothing stored")
    elif input("Store read-only credentials for this account in the Keychain? [y/N] ").strip().lower() != "y":
        return _fail("declined; nothing stored")
    try:
        store.save(oauth.credentials_to_blob(creds, account, granted))
    except KeystoreError as exc:
        return _fail(exc)
    print("Connected. Credentials stored in the macOS Keychain. Next: gmail-intelligence gmail check")
    return 0


def cmd_auth_status(_args):
    from gmail_intelligence import oauth
    from gmail_intelligence.keystore import KeystoreError

    path = config.client_secret_path()
    ready = True
    try:
        oauth.load_client_config(path)
        print(f"[OK  ] OAuth client file: {path}")
        if config.too_permissive(path):
            print("[WARN] client file is readable by others; run: chmod 600 " + str(path))
    except oauth.AuthError as exc:
        ready = False
        print(f"[FAIL] OAuth client file: {exc}")
    try:
        blob = _store().load()
    except KeystoreError as exc:
        print(f"[FAIL] token storage: {exc}")
        return 1
    if blob is None:
        ready = False
        print("[FAIL] token: none stored; run `auth login`")
    else:
        try:
            oauth.check_granted_scopes(blob.get("scopes"))
            print(f"[OK  ] token: stored for {blob.get('account')} (scope: read-only)")
        except oauth.AuthError as exc:
            ready = False
            print(f"[FAIL] token: {exc}")
    print("Local state only; not verified with Google. Run `gmail-intelligence gmail check` to verify.")
    return 0 if ready else 1


def cmd_auth_logout(args):
    from gmail_intelligence.keystore import KeystoreError

    try:
        store = _store()
        if store.load() is None:
            print("No stored credentials; nothing to remove.")
            return 0
        if not args.yes and input("Remove this application's stored Gmail tokens from the Keychain? [y/N] ").strip().lower() != "y":
            return _fail("cancelled")
        store.delete()
    except KeystoreError as exc:
        return _fail(exc)
    print("Local tokens removed. This does not revoke access in your Google account;")
    print("to revoke, visit https://myaccount.google.com/permissions")
    return 0


def cmd_gmail_check(_args):
    from gmail_intelligence import gmail, oauth
    from gmail_intelligence.keystore import KeystoreError

    try:
        store = _store()
        blob = store.load()
        if blob is None:
            return _fail("not logged in; run `auth login`")
        creds = oauth.blob_to_credentials(blob, oauth.load_client_config(config.client_secret_path()))
        if oauth.refresh_credentials(creds):
            blob = oauth.credentials_to_blob(creds, blob.get("account"), blob["scopes"])
            store.save(blob)
        reader = gmail.build_reader(creds)
        profile = reader.get_profile()
        labels = reader.list_labels()
    except (oauth.AuthError, gmail.GmailApiError, KeystoreError) as exc:
        return _fail(exc)
    if profile["emailAddress"].lower() != str(blob.get("account", "")).lower():
        return _fail("authenticated account differs from the stored account; run `auth logout` and `auth login`")
    print(f"Gmail read-only check OK for {profile['emailAddress']}")
    print(f"  messages: {profile['messagesTotal']}  threads: {profile['threadsTotal']}  labels: {len(labels)}")
    print("  (only profile counts were read; no message content)")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gmail-intelligence",
        description="Gmail Intelligence (early development). Offline: no Gmail integration yet.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{version,doctor,auth,gmail}")
    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="check local development prerequisites (offline)").set_defaults(func=cmd_doctor)

    auth = sub.add_parser("auth", help="manage the read-only Gmail connection")
    asub = auth.add_subparsers(dest="auth_command", required=True, metavar="{setup,login,status,logout}")
    p = asub.add_parser("setup", help="show Google Cloud setup steps, or import the OAuth client file")
    p.add_argument("--import", dest="import_file", metavar="FILE", help="validate and store the downloaded client JSON")
    p.set_defaults(func=cmd_auth_setup)
    p = asub.add_parser("login", help="authorize read-only access in the browser (contacts Google)")
    p.add_argument("--expect-account", metavar="EMAIL", help="fail unless the authorized account matches; skips the prompt")
    p.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser")
    p.set_defaults(func=cmd_auth_login)
    asub.add_parser("status", help="show local connection state (no network)").set_defaults(func=cmd_auth_status)
    p = asub.add_parser("logout", help="remove this app's local tokens")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_auth_logout)

    gm = sub.add_parser("gmail", help="read-only Gmail operations")
    gsub = gm.add_subparsers(dest="gmail_command", required=True, metavar="{check}")
    gsub.add_parser("check", help="verify connectivity and identity (reads profile counts only)").set_defaults(func=cmd_gmail_check)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)  # argparse exits with status 2 on usage errors
    return args.func(args)
