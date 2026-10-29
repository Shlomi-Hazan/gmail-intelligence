"""Command-line interface.

`version` and `doctor` are fully offline. Only `auth login`, `gmail check` (and the token refresh
inside them) contact Google; all other commands work locally. Google libraries are imported lazily.
Exit codes: 0 success, 1 operational failure (not ready, auth/API/storage error, declined), 2 usage.
"""
import argparse
import os
import shutil
import site
import sqlite3
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


# ---- separate WRITE authorization (M4C-B1). Every handler below is an explicit `auth *-write` command; nothing else reaches these modules.
def _write_store():
    from gmail_intelligence.keystore_write import WriteTokenStore
    return WriteTokenStore()


def cmd_auth_setup_write(args):
    from gmail_intelligence import oauth, oauth_write

    path = config.write_client_secret_path()
    if not args.import_file:
        print(f"""Write authorization setup (manual; free; never enable billing). Use a SEPARATE Google Cloud project and a SEPARATE Desktop client.
 1. In that separate project enable the Gmail API, set the audience to External/Testing with you as the only test user.
 2. Data access: add exactly one scope: {oauth_write.WRITE_SCOPE}
 3. Create an OAuth client of type 'Desktop app' and download its JSON file.
 4. Run: gmail-intelligence auth setup-write --import <downloaded-file> --confirm-separate-project   (stored as {path}, permissions 600)
    (the read-only client must already be set up; the two clients must belong to different projects, which is your attestation)
 5. Run: gmail-intelligence auth login-write --expect-account EMAIL
A separate project helps keep the grants apart but is not a security guarantee by itself.""")
        print("Write client file: " + ("present" if path.exists() else "not yet imported"))
        return 0
    if not args.confirm_separate_project:
        return _fail("revocation at Google is project-wide, so the write client must live in a SEPARATE Google Cloud project; confirm that you created it "
                     "there by passing --confirm-separate-project (this is your attestation, not something this tool can prove)")
    src = Path(args.import_file).expanduser()
    try:
        data = oauth_write.load_write_client_config(src)
        try:
            read = oauth.load_client_config(config.client_secret_path())
        except oauth.AuthError:
            return _fail("the read-only OAuth client file is missing or invalid, so project separation cannot be verified; set up the read-only connection first")
        oauth_write.check_project_separation(data, read)
    except oauth.AuthError as exc:
        return _fail(exc)
    config.ensure_app_dir()
    shutil.copyfile(src, path)
    os.chmod(path, 0o600)
    oauth_write.write_isolation_record(config.write_setup_path(), data, read)
    print(f"Write client file validated and stored at {path} (permissions 600); your separate-project attestation was recorded (fingerprints only).")
    print(f"Delete the downloaded copy: {src}")
    print("Different project numbers are necessary evidence of a separate project, not proof; keep it a project used for nothing else.")
    return 0


def _discard_new_grant(store, issued):
    """Best-effort revocation of a grant that Google just issued and that this tool will NOT use. Returns a privacy-safe sentence.

    Three distinct outcomes - revoked / revocation failed / not safely attempted - and never a claim that consent was undone unless Google
    confirmed it. It never touches a previously stored credential, and it refuses to revoke when the new grant might be the same as one that
    is already stored (the Keychain is re-checked immediately before the call).
    """
    from gmail_intelligence import oauth, oauth_write
    from gmail_intelligence.keystore import KeystoreError

    manual = "remove the app at https://myaccount.google.com/permissions"
    token = getattr(issued, "refresh_token", None) or getattr(issued, "token", None)
    if not token:
        return f"revocation was NOT attempted (no credential handle was available): Google consent may still exist; {manual}"
    try:  # revocation is project-wide at Google: never attempt it unless the write client is verifiably in a separate project
        oauth_write.verify_isolation(config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path())
    except oauth.AuthError:
        return (f"revocation was NOT attempted (project separation could not be verified, and revoking could affect the read-only authorization): "
                f"Google consent may still exist; {manual}")
    try:
        existing = store.load()
    except KeystoreError:
        return f"revocation was NOT attempted (the Keychain could not be checked, and a stored authorization might share this grant): Google consent still stands; {manual}"
    if existing is not None:
        return ("revocation was NOT attempted (a write authorization is already stored and might share this grant): nothing was stored or revoked, "
                f"Google consent still stands; {manual}")
    try:
        oauth_write.revoke_refresh_token(token)
    except oauth.AuthError:
        return f"revocation FAILED: Google consent still stands; {manual}"
    return "the newly issued grant was revoked at Google (confirmed by Google's response)"


def cmd_auth_login_write(args):
    from gmail_intelligence import gmail_write, oauth, oauth_write
    from gmail_intelligence.keystore import KeystoreError

    path = config.write_client_secret_path()
    try:
        client = oauth_write.load_write_client_config(path)
        oauth_write.verify_isolation(path, config.client_secret_path(), config.write_setup_path())  # fail closed before anything can create a grant
        store = _write_store()
        if store.load() is not None:  # never start a second authorization while one is stored: the stored credential is never replaced
            return _fail("a write authorization is already stored; run `auth revoke-write` or `auth logout-write` first")
    except (KeystoreError, oauth.AuthError) as exc:
        return _fail(exc)
    print(oauth_write.LOGIN_WARNING)
    if input(f"To continue type exactly: {oauth_write.LOGIN_PHRASE}\n> ").strip() != oauth_write.LOGIN_PHRASE:
        return _fail("declined; no authorization was requested")
    try:
        creds, granted = oauth_write.run_login_write(path, open_browser=not args.no_browser)
    except oauth_write.LoginRejected as exc:  # Google issued a grant, but this tool refuses it
        return _fail(f"{exc}; nothing was stored; {_discard_new_grant(store, exc.issued)}")
    except oauth.AuthError as exc:  # denied, cancelled or timed out: no credential was issued
        return _fail(exc)
    issued = oauth_write.IssuedToken(getattr(creds, "refresh_token", None), getattr(creds, "token", None))
    try:
        account = gmail_write.fetch_profile_email(creds)
    except (gmail_write.WriteTransportError, gmail_write.Denied) as exc:
        return _fail(f"could not confirm which account was authorized ({exc.code}); nothing was stored; {_discard_new_grant(store, issued)}")
    if account.strip().lower() != args.expect_account.strip().lower():
        return _fail(f"the authorized account differs from --expect-account; nothing was stored; {_discard_new_grant(store, issued)}")
    try:
        if store.load() is not None:  # an entry appeared during the browser flow: keep it, store nothing, and do not guess about the grant
            return _fail("a write authorization appeared in the Keychain during login; the existing entry was kept and nothing new was stored; "
                         f"{_discard_new_grant(store, issued)}")
        store.save(oauth_write.write_blob(creds, account, granted, client))
    except KeystoreError as exc:
        return _fail(f"{exc}; nothing was stored; {_discard_new_grant(store, issued)}")
    print("Write authorization stored in its own Keychain item. Nothing was archived or changed.")
    return 0


def cmd_auth_status_write(_args):
    """Local only: reads the write Keychain item and the write client file. No refresh, no network, no prompt."""
    import datetime

    from gmail_intelligence import oauth, oauth_write
    from gmail_intelligence.keystore import KeystoreError

    ready = True
    client = None
    try:
        client = oauth_write.load_write_client_config(config.write_client_secret_path())
        print("[OK  ] write OAuth client file present")
    except oauth.AuthError as exc:
        ready = False
        print(f"[FAIL] write OAuth client file: {exc}")
    try:
        oauth_write.verify_isolation(config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path())
        print("[OK  ] separate-project attestation matches both client files (the owner's attestation, not proof)")
    except oauth.AuthError as exc:
        ready = False
        print(f"[FAIL] project separation: {exc}")
    try:
        blob = _write_store().load()
    except KeystoreError as exc:
        print(f"[FAIL] write token storage: {exc}")
        return 1
    if blob is None:
        print("[INFO] no write authorization stored (this is the normal state)")
        return 1
    try:
        oauth_write.check_blob(blob, client)
        expiry = blob.get("expiry")
        left = oauth_write.remaining_validity(datetime.datetime.fromisoformat(expiry)) if expiry else None
        print(f"[OK  ] write authorization stored (scope: {oauth_write.WRITE_SCOPE}); access token valid for "
              f"{int(left.total_seconds() // 60) if left is not None else '?'} more minute(s) (it is NOT refreshed here)")
    except (oauth.AuthError, ValueError) as exc:
        ready = False
        print(f"[FAIL] write authorization: {exc}")
    print("Local state only; not verified with Google. The account is verified against Google only at a separately approved live stage.")
    return 0 if ready else 1


def cmd_auth_logout_write(args):
    from gmail_intelligence.keystore import KeystoreError

    try:
        store = _write_store()
        if store.load() is None:
            print("No stored write authorization; nothing to remove.")
            return 0
        if not args.yes and input("Remove the stored WRITE authorization from the Keychain? [y/N] ").strip().lower() != "y":
            return _fail("cancelled")
        store.delete()
    except KeystoreError as exc:
        return _fail(exc)
    print("The local write token was removed. This does NOT revoke it at Google: run `auth revoke-write` while it is still stored,")
    print("or remove the app at https://myaccount.google.com/permissions. The read-only authorization was not touched.")
    return 0


def cmd_auth_revoke_write(args):
    from gmail_intelligence import oauth, oauth_write
    from gmail_intelligence.keystore import KeystoreError

    try:
        store = _write_store()
        blob = store.load()
        if blob is None:
            print("No stored write authorization; nothing to revoke.")
            return 0
        oauth_write.check_blob(blob)
        oauth_write.verify_isolation(config.write_client_secret_path(), config.client_secret_path(), config.write_setup_path())  # revocation is project-wide
        if not args.yes and input(f"This contacts Google and revokes the write grant (project-wide at Google). Type exactly: {oauth_write.REVOKE_PHRASE}\n> ").strip() != oauth_write.REVOKE_PHRASE:
            return _fail("cancelled")
        oauth_write.revoke_refresh_token(blob.get("refresh_token"))
        store.delete()  # only reached after Google answered HTTP 200; otherwise the local token stays
    except (KeystoreError, oauth.AuthError) as exc:
        return _fail(exc)
    print("Google confirmed the revocation (HTTP 200) and the local token was removed.")
    print("The read-only authorization was not touched.")
    return 0


def _open_reader():
    """Load stored credentials (refreshing if needed) and build the read-only reader. Returns (reader, blob)."""
    from gmail_intelligence import gmail, oauth

    store = _store()
    blob = store.load()
    if blob is None:
        raise oauth.AuthError("not logged in; run `auth login`")
    creds = oauth.blob_to_credentials(blob, oauth.load_client_config(config.client_secret_path()))
    if oauth.refresh_credentials(creds):
        blob = oauth.credentials_to_blob(creds, blob.get("account"), blob["scopes"])
        store.save(blob)
    return gmail.build_reader(creds), blob


def cmd_gmail_check(_args):
    from gmail_intelligence import gmail, oauth
    from gmail_intelligence.keystore import KeystoreError

    try:
        reader, blob = _open_reader()
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


def _local_account(args):
    """Account for local-only commands: --account, else the one stored with the Keychain login."""
    from gmail_intelligence.keystore import KeystoreError

    if getattr(args, "account", None):
        return args.account.lower()
    try:
        blob = _store().load()
    except KeystoreError as exc:
        raise ValueError(str(exc)) from None
    if not blob or not blob.get("account"):
        raise ValueError("no account known; run `auth login` or pass --account EMAIL")
    return blob["account"].lower()


def _scan_precheck(index, args):
    """D144, decided from LOCAL state before any Gmail request: a limited scan may not run beside a sync checkpoint (any status)."""
    from gmail_intelligence import sync_health

    try:
        account = _local_account(args)
    except ValueError:
        return None  # not logged in: the reader reports that
    limited = args.limit is not None
    if args.resume:
        prev = index.find_resumable(account)
        limited = bool(prev and prev["mode"] == "limited")
    if limited and sync_health.state_row(index, account) is not None:
        return "SYNC_LIMITED_REFUSED: a sync checkpoint exists; use `mailbox sync` or a full scan (`mailbox scan --all`) instead of --limit"
    return None


def cmd_mailbox_scan(args):
    from gmail_intelligence import gmail, index as idx, oauth, scanner, sync_lease
    from gmail_intelligence.keystore import KeystoreError

    mode = "full" if args.all else "limited"
    if args.limit is not None and args.limit < 1:
        return _fail("--limit must be at least 1")
    try:
        sync_lease.guard_ok()  # D145: before the index file, a reader or any Gmail request exists
        with idx.Index() as index:
            refusal = _scan_precheck(index, args)
            if refusal:
                return _fail(refusal)
            reader, blob = _open_reader()
            profile = reader.get_profile()
            account = profile["emailAddress"].lower()
            if account != str(blob.get("account", "")).lower():
                return _fail("authenticated account differs from the stored account; run `auth logout` and `auth login`")
            if args.all or args.resume:
                est = profile.get("messagesTotal")
                print(f"Account {account}: scanning " + (f"about {est:,} messages (Gmail estimate) " if est else "")
                      + "read-only. Press Ctrl+C to stop; resume later with --resume.")
            row = scanner.run_scan(reader, index, account, mode=mode, limit=args.limit, resume=args.resume,
                                   limiter=scanner.RateLimiter(args.max_units_per_minute), progress=print,
                                   accept_count_mismatch=args.accept_count_mismatch, allow_large_prune=args.allow_large_prune)
    except scanner.ScanInterrupted as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 130
    except sync_lease.SyncError as exc:
        return _fail(f"{exc.code}: {exc}")
    except scanner.ScanError as exc:
        return _fail(exc)
    except (oauth.AuthError, gmail.GmailApiError, KeystoreError, idx.IndexProblem) as exc:
        return _fail(exc)
    print(f"Scan {row['id']} {row['status']}: listed {row['listed']:,}, indexed {row['indexed']:,}, "
          f"vanished {row['vanished']}, failed {row['failed']}, pruned {row['pruned']}")
    if row["status"] == "incomplete":
        reason = row.get("error") or ""
        if reason == "COUNT_MISMATCH":
            print("The listed message count differs from Gmail's estimate, so nothing was pruned and no checkpoint was set. "
                  "If you have reviewed the numbers, repeat with --accept-count-mismatch.")
        elif reason == "LARGE_PRUNE":
            print("Many indexed messages were not seen, so nothing was pruned. If that is expected, repeat with --allow-large-prune.")
        else:
            print("Some messages could not be indexed; the index is PARTIAL. See `mailbox status`.")
    elif mode == "limited":
        print("Limited scan: the index is PARTIAL by design. Next: mailbox report")
    return 0 if row["status"] == "completed" else 1


def cmd_mailbox_sync(args):
    from gmail_intelligence import gmail, index as idx, oauth, scanner, sync, sync_health, sync_lease
    from gmail_intelligence.keystore import KeystoreError

    if args.status:
        return _with_index(args, lambda i, a: print(sync_status_text(i, a)) or 0)
    try:
        sync_lease.guard_ok()  # D145: before the index file, a reader or any Gmail request is touched
        account_hint = _local_account(args)
        with idx.Index(create=False) as index:
            if sync_health.state_row(index, account_hint) is None:  # local refusal before any Gmail request
                return _fail("SYNC_CHECKPOINT_MISSING: there is no sync checkpoint yet; run a full scan first (mailbox scan --all)")
            reader, blob = _open_reader()
            account = str(blob.get("account", "")).lower()
            if account != account_hint:
                return _fail("authenticated account differs from the requested account; run `auth logout` and `auth login`")
            print("Syncing recent changes (read-only). Press Ctrl+C to stop; the next run replays from the saved checkpoint.")
            counts = sync.run_sync(reader, index, account, limiter=scanner.RateLimiter(args.max_units_per_minute), progress=print)
    except sync_lease.SyncError as exc:
        return _fail(f"{exc.code}: {exc}")
    except (ValueError, oauth.AuthError, gmail.GmailApiError, KeystoreError, idx.IndexProblem) as exc:
        return _fail(exc)
    print("Sync completed: " + ", ".join(f"{k} {v:,}" for k, v in counts.items()))
    return 0


def sync_status_text(index, account):
    """Aggregate, privacy-safe sync status: states, ages and counters only (no ids, labels, addresses or paths)."""
    from datetime import datetime, timezone

    from gmail_intelligence import sync_health, sync_report

    state = sync_health.state_row(index, account)
    lines = ["Sync status (local only; Gmail was not contacted)"]
    if state is None:
        lines.append("  checkpoint: none. Run a full scan first: mailbox scan --all")
    else:
        age = ""
        try:
            hours = (datetime.now(timezone.utc) - sync_health.parse(state["advanced_at"])).total_seconds() / 3600
            age = f", last advanced {hours:.1f} hours ago"
        except (ValueError, TypeError):
            pass
        status = state["status"] if state["status"] in ("OK", "IN_PROGRESS", "INTERRUPTED", "NEEDS_RECONCILE") else "UNRECOGNISED"
        reason = sync_report.safe_reason(state["reason"])
        lines.append(f"  state: {status}" + (f" ({reason})" if reason else "") + age)
    runs = index._q("SELECT kind, status, pages, records, affected, refreshed, unchanged, tombstoned, vanished, failed, error FROM sync_run WHERE account=? "
                    "ORDER BY id DESC LIMIT 3", account)
    for r in runs:
        lines.append(f"  run [{r['kind']}] {r['status']}: collected pages {r['pages']}, records {r['records']}, affected {r['affected']}; applied refreshed {r['refreshed']}, "
                     f"unchanged {r['unchanged']}, tombstoned {r['tombstoned']}, vanished {r['vanished']}, failed {r['failed']}"
                     + (f" ({sync_report.classify_note(r['error'])[0]})" if r["error"] else "") + ("" if r["status"] == "completed" else " [partial: see `mailbox changes`]"))
    codes = sync_health.problems(index, account)
    lines.append("  cleanup plan operations: " + ("allowed (index is fresh)" if not codes else "PROHIBITED until sync health is restored: " + ", ".join(codes)))
    return "\n".join(lines)


def cmd_index_upgrade(args):
    """D146: the only way an existing index is migrated to the current schema. Typed confirmation on a real terminal; a verified private backup first."""
    import sqlite3

    from gmail_intelligence import index as idx

    path = config.index_path()
    if not os.path.isfile(path):
        return _fail("no local index file exists; nothing to upgrade")
    try:
        probe = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            version = probe.execute("PRAGMA user_version").fetchone()[0]
            tables = probe.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        finally:
            probe.close()
    except sqlite3.DatabaseError:
        return _fail("the local index file is unreadable or corrupt; nothing was changed")
    if version == idx.SCHEMA_VERSION:
        print(f"The local index already uses schema v{version}; nothing to do.")
        return 0
    if version > idx.SCHEMA_VERSION or version == 0:
        return _fail(f"unsupported index schema version {version}; nothing was changed")
    print(f"Proposed upgrade: local index schema v{version} -> v{idx.SCHEMA_VERSION} ({tables} tables today).")
    print("  Additive only: new tables are added, existing data, plans, approvals and the audit log are not changed.")
    print("  A verified private backup (owner-only permissions) is created next to the index first.")
    if not sys.stdin.isatty():
        return _fail("the upgrade needs a real terminal for its typed confirmation (piped input is refused); nothing was changed")
    try:
        answer = input("Type UPGRADE to continue: ")
    except EOFError:
        return _fail("no confirmation was entered; nothing was changed")
    if answer.strip() != "UPGRADE":
        return _fail("confirmation did not match; nothing was changed")
    try:
        with idx.Index(path, create=False, allow_upgrade=True) as index:
            done = index.migrated_from
    except idx.IndexProblem as exc:
        return _fail(exc)
    print(f"Upgraded the local index from schema v{done} to v{idx.SCHEMA_VERSION}. A verified private backup was kept next to the index.")
    return 0


def _with_index(args, fn):
    from gmail_intelligence import index as idx

    try:
        account = _local_account(args)
        with idx.Index(create=False) as index:
            if index.migrated_from:
                print(f"Local index upgraded to schema v{idx.SCHEMA_VERSION} (existing data unchanged). "
                      f"Backup: {index.backup_path}", file=sys.stderr)
            return fn(index, account)
    except (ValueError, idx.IndexProblem) as exc:
        return _fail(exc)
    except sqlite3.DatabaseError:
        return _fail("the local index database reported an error (corrupt or locked); no further changes were made")


def cmd_mailbox_status(args):
    from gmail_intelligence import report
    return _with_index(args, lambda i, a: print(report.status_text(i, a)) or 0)


def cmd_mailbox_report(args):
    from gmail_intelligence import report
    return _with_index(args, lambda i, a: print(report.report_text(i, a)) or 0)


def cmd_mailbox_top_senders(args):
    from gmail_intelligence import report
    if args.limit < 1:
        return _fail("--limit must be at least 1")
    return _with_index(args, lambda i, a: print(report.senders_text(i, a, args.limit, args.unread, args.domains)) or 0)


def cmd_mailbox_purge(args):
    def purge(index, account):
        if not args.yes and input(f"Delete ALL locally indexed data for {account}? [y/N] ").strip().lower() != "y":
            return _fail("cancelled")
        index.purge(account)
        print(f"Local index data for {account} removed. (Gmail was not touched. Delete the database file "
              f"{index.path} to remove everything, including other accounts.)")
        return 0
    return _with_index(args, purge)


# ---- classification (M3): local index only, never Gmail ----
def _limit_arg(args):
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1")
    return None if getattr(args, "all", False) else args.limit


def cmd_classify_status(args):
    from gmail_intelligence import classify_report
    return _with_index(args, lambda i, a: print(classify_report.status_text(i, a)) or 0)


def _classify_pass(args, persist):
    from gmail_intelligence import ai, classifier, classify_report

    def go(index, account):
        try:
            limit = _limit_arg(args)
            backend = None
            if persist and args.ai:
                backend = ai.backend_from_config(ai.load_config())
        except (ValueError, ai.AiError) as exc:
            return _fail(exc)
        try:
            s = classifier.run(index, account, limit=limit, persist=persist, backend=backend)
        except ai.AiError as exc:
            return _fail(f"{exc}; nothing from the interrupted batch was saved")
        print(classify_report.summary_text(s, ("Classified and stored" if persist else "PREVIEW ONLY - nothing was saved")
                                            + f" ({account}; local index only, Gmail not contacted)"))
        if not persist:
            print("  (rules only; no local AI is used in preview). To save: classify run --limit N")
        elif s["selected"] == 0:
            print("Nothing to do: every indexed message already has a current result.")
        return 0
    return _with_index(args, go)


def cmd_classify_preview(args):
    return _classify_pass(args, persist=False)


def cmd_classify_run(args):
    return _classify_pass(args, persist=True)


def cmd_classify_report(args):
    from gmail_intelligence import classify_report
    return _with_index(args, lambda i, a: print(classify_report.report_text(i, a, args.show_senders)) or 0)


def cmd_classify_explain(args):
    from gmail_intelligence import classify_report
    return _with_index(args, lambda i, a: print(classify_report.explain_text(i, a, args.message_id, args.show_sender)) or 0)


def cmd_classify_clear(args):
    from gmail_intelligence import classifier

    def clear(index, account):
        if not args.yes and input(f"Delete stored classifications for {account}? Rules and the index are kept. [y/N] "
                                  ).strip().lower() != "y":
            return _fail("cancelled")
        print(f"Removed {classifier.clear(index, account):,} stored classification rows. (M2 index, rules and Gmail untouched.)")
        return 0
    return _with_index(args, clear)


def cmd_classify_rules_list(args):
    from gmail_intelligence import classify_report
    return _with_index(args, lambda i, a: print(classify_report.rules_text(i, a)) or 0)


def cmd_classify_rules_add(args):
    from gmail_intelligence import classifier
    from gmail_intelligence.classify import RuleError

    kind, value = ("type", args.type) if args.type else ("attention", args.attention)
    fields = dict(kind=kind, value=value, confidence=args.confidence, priority=args.priority, sender=args.sender,
                  domain=args.domain, label=args.label, unread=args.unread, note=args.note)

    def add(index, account):
        try:
            if args.dry_run:
                p = classifier.preview_rule(index, account, **fields)
                print(f"DRY RUN - rule not saved. It would match {p['matched']:,} of {p['messages']:,} indexed messages; "
                      f"{p['type_changes']:,} would get a different result ({p['now_unknown']:,} of the matches are "
                      f"currently UNKNOWN). Save by repeating without --dry-run, then `classify run`.")
                return 0
            rid = classifier.add_rule(index, account, **fields)
        except RuleError as exc:
            return _fail(exc)
        print(f"Rule {rid} added. Stored results are now stale; review with `classify preview`, apply with `classify run`.")
        return 0
    return _with_index(args, add)


def _rule_toggle(args, enabled):
    from gmail_intelligence import classifier

    def go(index, account):
        if not classifier.set_enabled(index, account, args.rule_id, enabled):
            return _fail(f"no such user rule: {args.rule_id} (built-in rules cannot be changed)")
        print(f"Rule {args.rule_id} {'enabled' if enabled else 'disabled'}. Run `classify run` to refresh results.")
        return 0
    return _with_index(args, go)


def cmd_classify_rules_enable(args):
    return _rule_toggle(args, True)


def cmd_classify_rules_disable(args):
    return _rule_toggle(args, False)


def cmd_classify_rules_remove(args):
    from gmail_intelligence import classifier

    def go(index, account):
        if not args.yes and input(f"Remove user rule {args.rule_id}? [y/N] ").strip().lower() != "y":
            return _fail("cancelled")
        if not classifier.remove_rule(index, account, args.rule_id):
            return _fail(f"no such user rule: {args.rule_id} (built-in rules cannot be removed)")
        print(f"Rule {args.rule_id} removed. Run `classify run` to refresh results.")
        return 0
    return _with_index(args, go)


def cmd_classify_ai_status(_args):
    from gmail_intelligence import ai
    try:
        cfg = ai.load_config()
    except ai.AiError as exc:
        return _fail(exc)
    if not cfg["enabled"]:
        print(f"Local AI: DISABLED - {cfg['reason']}. Rules work fully without it.")
        return 0
    print(f"Local AI: configured for model '{cfg['model']}' at {cfg['host']}:{cfg['port']} (loopback only). "
          "Nothing was contacted; real inference is NOT VERIFIED until you run `classify run --ai` yourself.")
    return 0


# ---- cleanup candidates (M4A): local preview only, never Gmail, never executes anything ----
def cmd_cleanup_candidates(args):
    from gmail_intelligence import cleanup_candidates, cleanup_report

    def go(index, account):
        try:
            if args.limit is not None and args.limit < 0:
                raise ValueError("--limit must not be negative")
            res = cleanup_candidates.evaluate_all(index, account, min_age_days=args.min_age_days)
        except ValueError as exc:
            return _fail(exc)
        print(cleanup_report.candidates_text(res, account, review=args.review, limit=args.limit, show_ids=args.show_ids,
                                             show_senders=args.show_senders, by_domain=args.by_domain))
        if args.export_ids:
            return _export_ids(args, res)
        return 0
    return _with_index(args, go)


def _export_ids(args, res):
    """Write up to --limit ELIGIBLE message ids (oldest first) to a new private file, as an aid for choosing plan targets."""
    from gmail_intelligence import cleanup_candidates

    path = Path(args.export_ids).expanduser()
    if args.review or args.limit < 1:
        return _fail("--export-ids needs --limit of at least 1 and cannot be combined with --review")
    if path.exists() or config.inside_git_repo(path.parent):
        return _fail("refusing to write ids: the file already exists or is inside a Git repository")
    ids = [d.message_id for d in res.decisions if d.outcome == cleanup_candidates.ELIGIBLE][:args.limit]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("# eligible archive candidates (message ids; keep private). Select explicitly, then: cleanup plan create --ids-file\n")
        fh.writelines(i + "\n" for i in ids)
    print(f"Wrote {len(ids)} eligible message id(s) to a new private file (mode 600). Nothing was selected or changed.")
    return 0


def cmd_cleanup_protect_list(args):
    from gmail_intelligence import cleanup_report
    return _with_index(args, lambda i, a: print(cleanup_report.protect_text(i, a, args.show_values)) or 0)


def cmd_cleanup_protect_add(args):
    from gmail_intelligence import cleanup_protect
    from gmail_intelligence.classify import RuleError

    def add(index, account):
        try:
            rid = cleanup_protect.add(index, account, sender=args.sender, domain=args.domain, label=args.label, note=args.note)
        except RuleError as exc:
            return _fail(exc)
        print(f"Protection rule {rid} added. Matching messages are excluded from all cleanup candidates "
              "(no Gmail change was made).")
        return 0
    return _with_index(args, add)


def _protect_toggle(args, enabled):
    from gmail_intelligence import cleanup_protect

    def go(index, account):
        if not cleanup_protect.set_enabled(index, account, args.rule_id, enabled):
            return _fail(f"no such protection rule: {args.rule_id}")
        print(f"Protection rule {args.rule_id} {'enabled' if enabled else 'DISABLED (messages it covered may become candidates again)'}.")
        return 0
    return _with_index(args, go)


def cmd_cleanup_protect_enable(args):
    return _protect_toggle(args, True)


def cmd_cleanup_protect_disable(args):
    return _protect_toggle(args, False)


def cmd_cleanup_protect_remove(args):
    from gmail_intelligence import cleanup_protect

    def go(index, account):
        try:
            answer = "y" if args.yes else input(f"Remove protection rule {args.rule_id}? Messages it covered may become "
                                                "candidates. [y/N] ").strip().lower()
        except EOFError:
            answer = ""  # no terminal input available: treat as "no"
        if answer != "y":
            return _fail("cancelled")
        if not cleanup_protect.remove(index, account, args.rule_id):
            return _fail(f"no such protection rule: {args.rule_id}")
        print(f"Protection rule {args.rule_id} removed.")
        return 0
    return _with_index(args, go)


# ---- cleanup plans and approvals (M4B): local only, no Gmail, no execution ----
def _tty_input(prompt):
    """Terminal-only confirmation: never accepts piped or scripted input, and EOF means 'no'."""
    if not sys.stdin.isatty():
        raise EOFError("interactive terminal required")
    return input(prompt)


def _plan_cmd(args, fn):
    from gmail_intelligence import cleanup_plans as cp

    def go(index, account):
        try:
            cp.expire_due(index, account)
            return fn(index, account, cp)
        except cp.PlanError as exc:
            return _fail(exc)
        except EOFError:
            return _fail("cancelled: this step needs a real interactive terminal; nothing was changed")
    return _with_index(args, go)


def _read_ids_file(path):
    p = Path(path).expanduser()
    if not p.is_file() or p.stat().st_size > 1_000_000:
        raise ValueError("ids file must be an existing text file under 1 MB")
    return [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def cmd_cleanup_plan_create(args):
    def go(index, account, cp):
        try:
            ids = list(args.message_id or []) + (_read_ids_file(args.ids_file) if args.ids_file else [])
        except (OSError, ValueError) as exc:
            return _fail(exc)
        dup = len(ids) - len(set(ids))
        plan = cp.create_plan(index, account, ids, min_age_days=args.min_age_days)
        print(f"Plan {plan['plan_id']} created as DRAFT: {plan['item_count']} explicit target(s), action {plan['action']}, "
              f"hash {cp.short(plan['plan_hash'])}" + (f" ({dup} duplicate id(s) ignored)" if dup else "") + ".")
        print("Next: cleanup plan show / review it. Nothing was approved or executed; Gmail was not contacted.")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_plan_list(args):
    from gmail_intelligence import cleanup_plan_report
    return _plan_cmd(args, lambda i, a, cp: print(cleanup_plan_report.plan_list_text(cp.list_plans(i, a))) or 0)


def cmd_cleanup_plan_show(args):
    from gmail_intelligence import cleanup_plan_report as rep

    def go(index, account, cp):
        if args.page_size < 1 or args.page_size > 200:
            return _fail("--page-size must be between 1 and 200")
        plan = cp.get_plan(index, account, args.plan_id)
        out = {}
        problems = {} if plan["state"] in cp.TERMINAL else cp.revalidate(index, account, plan, _out=out)
        print(rep.plan_show_text(plan, problems, out.get("decisions"), cp.approval_status(index, account, args.plan_id),
                                 page=args.page, page_size=args.page_size, show_ids=args.show_ids))
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_plan_review(args):
    def go(index, account, cp):
        plan = cp.get_plan(index, account, args.plan_id)
        if plan["state"] != "DRAFT":
            return _fail(f"plan is {plan['state']}; only a DRAFT plan can be reviewed")
        problems = cp.revalidate(index, account, plan)
        if problems:
            return _fail("plan is stale or inconsistent: " + cp._describe(problems) + "; create a new plan")
        size = cp.PAGE_SIZE
        pages = max(1, -(-plan["item_count"] // size))
        print(f"Reviewing plan {plan['plan_id']}: {plan['item_count']} target(s) in {pages} page(s). You will see EVERY exact "
              "message id of this plan (ids are shown because you asked to review the exact targets).")
        for n in range(1, pages + 1):
            print(f"-- page {n}/{pages}")
            for k, item in enumerate(plan["items"][(n - 1) * size:n * size], (n - 1) * size + 1):
                print(f"  {k:>4}. {item['message_id']}")
            if n < pages:
                _tty_input("Press Enter for the next page (Ctrl-D aborts) ")
        phrase = _tty_input(f"Type exactly  {cp.review_phrase(plan)}  to mark this plan REVIEWED (anything else aborts): ")
        done = cp.mark_reviewed(index, account, args.plan_id, phrase)
        print(f"Plan {done['plan_id']} is now {done['state']}. Next: cleanup approve {done['plan_id']}  (local record only).")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_plan_exclude(args):
    def go(index, account, cp):
        new = cp.revise_exclude(index, account, args.plan_id, args.message_id or [])
        print(f"Created {new['plan_id']} (version {new['version']}, DRAFT, {new['item_count']} targets, hash {cp.short(new['plan_hash'])}). "
              f"{args.plan_id} is SUPERSEDED and any approval of it is revoked. The new plan needs its own review and approval.")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_plan_cancel(args):
    def go(index, account, cp):
        try:
            answer = _tty_input(f"Cancel plan {args.plan_id}? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            return _fail("cancelled; the plan was not changed")
        cp.cancel(index, account, args.plan_id)
        print(f"Plan {args.plan_id} CANCELLED; any approval was revoked.")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_approve(args):
    from gmail_intelligence import cleanup_plan_report as rep

    def go(index, account, cp):
        plan = cp.get_plan(index, account, args.plan_id)
        print(f"Plan {plan['plan_id']}: action {plan['action']}, {plan['item_count']} target(s), hash {cp.short(plan['plan_hash'])}, "
              f"state {plan['state']}.")
        print(rep.NOT_AN_AUTH)
        phrase = _tty_input(f"Type exactly  {cp.approval_phrase(plan)}  to record a local approval (anything else aborts): ")
        st = cp.approve(index, account, args.plan_id, phrase)
        a = st["approvals"][-1]
        from gmail_intelligence import cleanup_audit
        print(f"Plan {args.plan_id} APPROVED locally (one-time; valid until {a['expires_at']}). Nothing was executed and Gmail was not contacted.")
        print(f"Audit head after this approval: {cleanup_audit.head(index, account)[1][:16]} (optional checkpoint; see `cleanup audit verify --checkpoint`).")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_approval_status(args):
    def go(index, account, cp):
        st = cp.approval_status(index, account, args.plan_id)
        print(f"Plan {st['plan_id']} is {st['plan_state']}.")
        for a in st["approvals"]:
            print(f"  approval {a['nonce']}: {a['status']}, created {a['created_at']}, expires {a['expires_at']}, "
                  f"{a['item_count']} items, hash {cp.short(a['plan_hash'])}")
        if not st["approvals"]:
            print("  no approval recorded")
        print("A local approval does not authorize Gmail access or execution.")
        return 0
    return _plan_cmd(args, go)


def cmd_cleanup_audit_verify(args):
    from gmail_intelligence import cleanup_audit

    def go(index, account, cp):
        ok, n, bad = cleanup_audit.verify_chain(index, account)
        count, head = cleanup_audit.head(index, account)
        print(f"Audit chain: {n} event(s), " + ("internally consistent." if ok else f"BROKEN at event {bad}."))
        if head:
            print(f"Head: {head[:16]}  (write this down somewhere outside this computer as a checkpoint)")
        if args.checkpoint:
            try:
                found = cleanup_audit.contains(index, account, args.checkpoint)
            except ValueError as exc:
                return _fail(exc)
            print("Checkpoint " + ("FOUND in the chain." if found else "NOT FOUND: events were removed or rewritten since you recorded it."))
            ok = ok and found
        print("Limits: deleting the newest events or the whole log is undetectable without such a checkpoint, and anyone who controls "
              "this user account can rewrite everything. The chain is tamper-evident at best, never tamper-proof.")
        return 0 if ok else 1
    return _plan_cmd(args, go)


def cmd_cleanup_audit_log(args):
    from gmail_intelligence import cleanup_audit

    def go(index, account, cp):
        if not 1 <= args.limit <= 1000:
            return _fail("--limit must be between 1 and 1000")
        for e in cleanup_audit.events(index, account, args.plan, args.limit):
            print(f"  {e['seq']:>5} {e['at']} {e['event_type']:<18} {e['plan_id'] or '-':<15} {e['meta']}")
        return 0
    return _plan_cmd(args, go)


# ---- local execution records (M4C-A): dry run and read-only listings; NO Gmail, no reservation, no execution ----
def cmd_cleanup_execute(args):
    from gmail_intelligence import cleanup_exec, cleanup_exec_report
    from gmail_intelligence import cleanup_plans as cp

    def go(index, account):
        if not args.dry_run:
            return _fail("execution is not available in this version; only `--dry-run` exists (it writes nothing and consumes no approval)")
        try:
            print(cleanup_exec_report.dry_run_text(cleanup_exec.dry_run(index, account, args.plan_id)))
        except cp.PlanError as exc:
            return _fail(exc)
        return 0
    return _with_index(args, go)


def cmd_cleanup_exec_list(args):
    from gmail_intelligence import cleanup_exec, cleanup_exec_report
    return _with_index(args, lambda i, a: print(cleanup_exec_report.list_text(cleanup_exec.list_executions(i, a))) or 0)


# ---- inbox organization (M5): label hygiene, recommendations, suggestions and label-change plans. LOCAL ONLY: no Gmail call, no credential, no mailbox change ----
def cmd_labels_recommend(args):
    from gmail_intelligence import label_report, label_suggest
    return _with_index(args, lambda i, a: print(label_report.recommend_text(i, a, label_suggest.recommend(i, a), args.show_names, args.show_senders)) or 0)


def cmd_labels_suggest_rules(args):
    from gmail_intelligence import label_report, label_suggest
    return _with_index(args, lambda i, a: print(label_report.rules_text(i, a, label_suggest.suggest_rules(i, a), args.show_senders)) or 0)


def cmd_labels_suggest_filters(args):
    from gmail_intelligence import filter_suggest, label_report
    return _with_index(args, lambda i, a: print(label_report.filters_text(i, a, filter_suggest.suggest(i, a), args.show_names, args.show_senders)) or 0)


def _label_plan_cmd(args, fn):
    from gmail_intelligence import label_plans as lp

    def go(index, account):
        try:
            lp.expire_due(index, account)
            return fn(index, account, lp)
        except lp.PlanError as exc:
            return _fail(exc)
        except EOFError:
            return _fail("cancelled: this step needs a real interactive terminal; nothing was changed")
    return _with_index(args, go)


def _split_pair(text, what):
    ref, sep, rest = text.partition("=")
    if not sep:
        raise ValueError(f"{what} takes LABEL=VALUE (use the label id if the name contains '=')")
    return ref.strip(), rest.strip()


def cmd_labels_plan_create(args):
    def go(index, account, lp):
        try:
            specs = [("CREATE", n) for n in args.create or []]
            specs += [("RENAME", *_split_pair(t, "--rename")) for t in args.rename or []]
            specs += [("NEST", *_split_pair(t, "--nest")) for t in args.nest or []]
            specs += [("MERGE", *_split_pair(t, "--merge")) for t in args.merge or []]
        except ValueError as exc:
            return _fail(exc)
        plan = lp.create_plan(index, account, specs)
        print(f"Label plan {plan['plan_id']} created as DRAFT: {plan['op_count']} operation(s), hash {lp.short(plan['plan_hash'])}. LOCAL ONLY — no Gmail changes performed.")
        print(f"Next: labels plan show {plan['plan_id']}, then labels plan review {plan['plan_id']}.")
        return 0
    return _label_plan_cmd(args, go)


def cmd_labels_plan_list(args):
    from gmail_intelligence import label_plan_report as rep
    return _label_plan_cmd(args, lambda i, a, lp: print(rep.list_text(lp.list_plans(i, a))) or 0)


def cmd_labels_plan_show(args):
    from gmail_intelligence import label_plan_report as rep
    return _label_plan_cmd(args, lambda i, a, lp: print(rep.plan_text(i, a, lp.get_plan(i, a, args.plan_id), args.show_names)) or 0)


def cmd_labels_plan_review(args):
    from gmail_intelligence import label_plan_report as rep

    def go(index, account, lp):
        plan = lp.get_plan(index, account, args.plan_id)
        if plan["state"] != "DRAFT":
            return _fail(f"plan is {plan['state']}; only a DRAFT plan can be reviewed")
        problems = lp.revalidate(index, account, plan)
        if problems:
            return _fail("label plan is stale or inconsistent: " + lp._describe(problems) + "; create a new plan")
        print(rep.plan_text(index, account, plan, args.show_names))
        phrase = _tty_input(f"Type exactly  {lp.review_phrase(plan)}  to mark this plan REVIEWED (anything else aborts): ")
        done = lp.mark_reviewed(index, account, args.plan_id, phrase)
        print(f"Label plan {done['plan_id']} is now {done['state']}. Next: labels approve {done['plan_id']}  (local record only). LOCAL ONLY — no Gmail changes performed.")
        return 0
    return _label_plan_cmd(args, go)


def cmd_labels_plan_cancel(args):
    def go(index, account, lp):
        try:
            answer = _tty_input(f"Cancel label plan {args.plan_id}? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            return _fail("cancelled; the plan was not changed")
        lp.cancel(index, account, args.plan_id)
        print(f"Label plan {args.plan_id} CANCELLED; any approval was revoked. LOCAL ONLY — no Gmail changes performed.")
        return 0
    return _label_plan_cmd(args, go)


def cmd_labels_approve(args):
    from gmail_intelligence import cleanup_audit, label_plan_report as rep

    def go(index, account, lp):
        plan = lp.get_plan(index, account, args.plan_id)
        print(f"Label plan {plan['plan_id']}: {plan['op_count']} operation(s), hash {lp.short(plan['plan_hash'])}, state {plan['state']}.")
        print(rep.NOT_AN_AUTH)
        phrase = _tty_input(f"Type exactly  {lp.approval_phrase(plan)}  to record a local approval (anything else aborts): ")
        st = lp.approve(index, account, args.plan_id, phrase)
        a = st["approvals"][-1]
        print(f"Label plan {args.plan_id} APPROVED locally (one-time; valid until {a['expires_at']}). Nothing was executed and Gmail was not contacted. LOCAL ONLY — no Gmail changes performed.")
        print(f"Audit head after this approval: {cleanup_audit.head(index, account)[1][:16]} (optional checkpoint).")
        return 0
    return _label_plan_cmd(args, go)


_REPORT_UNEXPECTED = "the report could not be produced (unexpected internal error); nothing was changed"


def _with_readonly_index(args, fn):
    """Reports that must not be able to write: the index is opened with SQLite's own `mode=ro` + `query_only` (a hidden write would fail), never upgraded, never created."""
    from gmail_intelligence import index as idx

    try:
        account = _local_account(args)
        ro = idx.ReadOnlyIndex(config.index_path())
    except (ValueError, idx.IndexProblem) as exc:
        return _fail(exc)
    except Exception:  # noqa: BLE001 - the reporting boundary (see below)
        return _fail(_REPORT_UNEXPECTED)
    try:
        return fn(ro, account)
    except sqlite3.DatabaseError:
        return _fail("the local index database reported an error (corrupt or locked); nothing was changed")
    except Exception:  # noqa: BLE001 - the reporting boundary: never a traceback, never exception text (it could carry stored data)
        return _fail(_REPORT_UNEXPECTED)
    finally:
        ro.close()


def cmd_mailbox_changes(args):
    import json

    from gmail_intelligence import sync_report
    if not 1 <= args.runs <= 50:
        return _fail("--runs must be between 1 and 50")

    def go(index, account):
        rep = sync_report.changes_report(index, account, runs=args.runs)
        print(json.dumps(rep, indent=2, sort_keys=True) if args.json else sync_report.changes_text(rep))
        return 0
    return _with_readonly_index(args, go)


def cmd_mailbox_maintenance(args):
    """M7C: local, read-only maintenance report. Does not use the writable Index class, never contacts Gmail, never repairs anything."""
    import json

    from gmail_intelligence import maintenance

    try:
        account = _local_account(args)
    except ValueError:
        account = None  # file-level checks still run
    try:
        rep = maintenance.run(config.index_path(), account, deep=args.deep)
        out = json.dumps(rep, indent=2, sort_keys=True) if args.json else maintenance.render_text(rep)  # built completely before anything is printed
    except Exception:  # noqa: BLE001 - the reporting boundary: no traceback, no exception text, a non-zero exit (never a silent "success")
        return _fail(_REPORT_UNEXPECTED)
    print(out)
    return 0


def cmd_mailbox_attention(args):
    """M8A-1: possibly-important messages from indexed metadata. Read-only; fixed-text errors; never contacts Gmail."""
    from gmail_intelligence import attention

    def go(index, account):
        try:
            res = attention.compute(index, account, limit=args.limit, cursor=args.cursor, sort=args.sort, signals=args.signal or (), min_tier=args.min_tier,
                                    sender_limit=args.sender_limit, collapse=not args.no_collapse, include_low_score=args.include_low_score,
                                    reveal_senders=args.reveal_senders)
            out = attention.as_json(res) if args.json else attention.render_text(res)  # built completely before anything is printed
        except attention.AttentionError as exc:
            return _fail(exc.message)
        except attention.ParameterError as exc:  # fixed text only; every other ValueError is internal and falls through to the generic message
            return _fail(exc)
        print(out)
        return 0
    return _with_readonly_index(args, go)


def cmd_mailbox_subscriptions(args):
    """M9A: possible low-value subscriptions from indexed metadata, for MANUAL review. Read-only; contacts nobody; fixed-text errors."""
    from gmail_intelligence import subscriptions

    def go(index, account):
        try:
            res = subscriptions.compute(index, account, by=args.by, limit=args.limit, min_messages=args.min_messages, show_all=args.all, reveal_senders=args.reveal_senders)
            out = subscriptions.as_json(res) if args.json else subscriptions.render_text(res)  # built completely before anything is printed
        except subscriptions.ParameterError as exc:  # fixed text only; every other exception is internal and ends in the generic message
            return _fail(exc)
        print(out)
        return 0
    return _with_readonly_index(args, go)


def cmd_mailbox_ask(args):
    """M11A: deterministic, allow-listed metadata question answering. Read-only; the question is never echoed or executed; fixed-text errors."""
    from gmail_intelligence import ask

    def go(index, account):
        try:
            res = ask.answer(index, account, args.question, reveal_senders=args.reveal_senders)
            out = ask.as_json(res) if args.json else ask.render_text(res)  # built completely before anything is printed
        except ask.ParameterError as exc:
            return _fail(exc)
        print(out)
        return 0
    return _with_readonly_index(args, go)


def cmd_cleanup_plan_impact(args):
    import json

    from gmail_intelligence import plan_impact

    def go(index, account):
        rep = plan_impact.impact_report(index, account)
        print(json.dumps(rep, indent=2, sort_keys=True) if args.json else plan_impact.impact_text(rep))
        return 0
    return _with_readonly_index(args, go)


def cmd_mailbox_insights(args):
    from gmail_intelligence import analytics, analytics_report

    def go(index, account):
        a = analytics.Analytics(index, account, reveal_senders=args.reveal_senders, reveal_names=args.reveal_names)
        names = list(analytics.SECTIONS) if args.section == "all" else [args.section]
        kw = {"senders": {"kind": args.kind, "limit": args.limit}, "categories": {"by": "month" if args.by_month else "total"}}
        envs = [a.section(n, **kw.get(n, {})) for n in names]
        print(analytics_report.as_json(envs[0] if len(envs) == 1 else {e["section"]: e for e in envs}) if args.json else analytics_report.text(envs))
        return 0
    return _with_index(args, go)


def cmd_dashboard_serve(args):
    from gmail_intelligence import config, dashboard_server, index as idx

    try:
        path = config.index_path()
        account = dashboard_server.detect_account(path, args.account)
        if args.port and not 1024 <= args.port <= 65535:
            raise ValueError("--port must be 0 (any free port) or between 1024 and 65535")
        return dashboard_server.serve(path, account, port=args.port, open_browser=args.open, reveal_senders=args.reveal_senders, reveal_names=args.reveal_names, verbose=args.verbose)
    except (ValueError, idx.IndexProblem, OSError) as exc:
        return _fail(exc)


def cmd_labels_report(args):
    from gmail_intelligence import label_hygiene, label_report
    return _with_index(args, lambda i, a: print(label_report.hygiene_text(i, a, label_hygiene.analyze(i, a), args.show_names)) or 0)


def cmd_cleanup_exec_show(args):
    from gmail_intelligence import cleanup_exec, cleanup_exec_report
    from gmail_intelligence import cleanup_plans as cp

    def go(index, account):
        try:
            ex = cleanup_exec.get_execution(index, account, args.exec_id)
        except cp.PlanError as exc:
            return _fail(exc)
        print(cleanup_exec_report.show_text(index, account, ex, args.show_ids))
        return 0
    return _with_index(args, go)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gmail-intelligence",
        description="Gmail Intelligence (early development). Offline: no Gmail integration yet.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{version,doctor,auth,gmail,mailbox,classify,cleanup,labels,dashboard}")
    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="check local development prerequisites (offline)").set_defaults(func=cmd_doctor)

    auth = sub.add_parser("auth", help="manage the read-only Gmail connection (and the separate, explicit write authorization)")
    asub = auth.add_subparsers(dest="auth_command", required=True, metavar="{setup,login,status,logout,setup-write,login-write,status-write,logout-write,revoke-write}")
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
    p = asub.add_parser("setup-write", help="show setup steps for, or import, the SEPARATE write OAuth client file (no network)")
    p.add_argument("--import", dest="import_file", metavar="FILE", help="validate and store the downloaded write client JSON")
    p.add_argument("--confirm-separate-project", action="store_true", help="attest that the client was created in a SEPARATE Google Cloud project (required to import)")
    p.set_defaults(func=cmd_auth_setup_write)
    p = asub.add_parser("login-write", help="authorize the broad write permission in the browser (contacts Google; explicit confirmation)")
    p.add_argument("--expect-account", metavar="EMAIL", required=True, help="fail (and store nothing) unless the authorized account matches")
    p.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser")
    p.set_defaults(func=cmd_auth_login_write)
    asub.add_parser("status-write", help="show the local write-authorization state (no network, no refresh)").set_defaults(func=cmd_auth_status_write)
    p = asub.add_parser("logout-write", help="remove the local write token only (does not revoke it at Google)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_auth_logout_write)
    p = asub.add_parser("revoke-write", help="revoke the write grant at Google, then remove the local token (contacts Google)")
    p.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    p.set_defaults(func=cmd_auth_revoke_write)

    gm = sub.add_parser("gmail", help="read-only Gmail operations")
    gsub = gm.add_subparsers(dest="gmail_command", required=True, metavar="{check}")
    gsub.add_parser("check", help="verify connectivity and identity (reads profile counts only)").set_defaults(func=cmd_gmail_check)

    def account_opt(q):
        q.add_argument("--account", metavar="EMAIL", help="account in the local index (default: the logged-in account)")
        return q

    mb = sub.add_parser("mailbox", help="read-only mailbox index and reports (M2)")
    msub = mb.add_subparsers(dest="mailbox_command", required=True, metavar="{scan,sync,changes,maintenance,attention,subscriptions,ask,status,report,insights,top-senders,purge}")
    q = account_opt(msub.add_parser("insights", help="aggregate, explainable analytics of the local index (M6A; local only, human-readable or --json)"))
    q.add_argument("section", nargs="?", default="overview", choices=("all", "freshness", "overview", "volume", "categories", "senders", "subscriptions", "cleanup-summary", "cleanup-history", "organization"))
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.add_argument("--kind", choices=("domain", "address"), default="domain", help="senders: group by domain (default) or address")
    q.add_argument("--limit", type=int, default=10, help="senders: how many to list (1-100)")
    q.add_argument("--by-month", action="store_true", help="categories: break the breakdown down by month")
    q.add_argument("--reveal-senders", action="store_true", help="show full sender addresses (private; masked by default)")
    q.add_argument("--reveal-names", action="store_true", help="include label names in the organization section (private; hidden by default)")
    q.set_defaults(func=cmd_mailbox_insights)
    p = msub.add_parser("scan", help="index message metadata into the local database (contacts Gmail, read-only)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--limit", type=int, metavar="N", help="index the newest N messages (recommended first run: 100)")
    g.add_argument("--all", action="store_true", help="index the whole mailbox (long-running; explicit intent)")
    g.add_argument("--resume", action="store_true", help="continue the last interrupted scan")
    p.add_argument("--max-units-per-minute", type=int, default=4500, metavar="U",
                   help="Gmail API quota-unit budget per minute (default 4500 of the documented 6000)")
    p.add_argument("--accept-count-mismatch", action="store_true", help="full scan: accept a reviewed difference between the listed count and Gmail's estimate")
    p.add_argument("--allow-large-prune", action="store_true", help="full scan: allow removing more than 20%% of the indexed messages (reviewed)")
    p.set_defaults(func=cmd_mailbox_scan)
    q = account_opt(msub.add_parser("changes", help="what synchronization changed: per-run counters, deletions, partial runs (M7B; local only, read-only, aggregates only)"))
    q.add_argument("--runs", type=int, default=5, metavar="N", help="how many recent runs to show (1-50)")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_mailbox_changes)
    q = account_opt(msub.add_parser("maintenance", help="local integrity checks and maintenance report (M7C; read-only, advisory, never repairs or contacts Gmail)"))
    q.add_argument("--deep", action="store_true", help="also run SQLite's full integrity_check on the index and the backups (slower)")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_mailbox_maintenance)
    q = account_opt(msub.add_parser("attention", help="messages that may deserve attention, from indexed metadata only (M8A-1; read-only, explainable, weights provisional)"))
    q.add_argument("--limit", type=int, default=25, metavar="N", help="items per page (1-100, default 25)")
    q.add_argument("--cursor", metavar="C", help="continue after the previous page (opaque; fails explicitly if the list changed)")
    q.add_argument("--sort", choices=("priority", "date", "oldest"), default="priority")
    q.add_argument("--signal", action="append", choices=("starred", "important", "unread", "rule"), metavar="SIGNAL", help="only messages with this signal (repeatable: any of)")
    q.add_argument("--min-tier", choices=("low", "medium", "high"), help="only this tier or higher")
    q.add_argument("--sender-limit", type=int, default=3, metavar="N", help="at most N items per sender (0-10, 0 = off; default 3)")
    q.add_argument("--no-collapse", action="store_true", help="one item per message instead of per thread")
    q.add_argument("--include-low-score", action="store_true", help="also show items scoring 1-14 (normally hidden)")
    q.add_argument("--reveal-senders", action="store_true", help="show full sender addresses (masked by default)")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_mailbox_attention)
    q = account_opt(msub.add_parser("subscriptions", help="possible low-value subscriptions from indexed metadata, for manual review (M9A; read-only, contacts nobody, extends top-senders)"))
    q.add_argument("--by", choices=("domain", "address"), default="domain", help="group senders by domain (default) or by address")
    q.add_argument("--limit", type=int, default=20, metavar="N", help="groups to show (1-100, default 20)")
    q.add_argument("--min-messages", type=int, default=5, metavar="N", help="a group needs at least N messages to be assessed (2-1000, default 5)")
    q.add_argument("--all", action="store_true", help="also list weak, ruled-out and not-enough-evidence groups, with the reason")
    q.add_argument("--reveal-senders", action="store_true", help="show full sender addresses with --by address (masked by default)")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_mailbox_subscriptions)
    q = account_opt(msub.add_parser("ask", help="answer an allow-listed metadata question from the local index (M11A; deterministic, no model, read-only)"))
    q.add_argument("question", help='an English question, e.g. "Which senders email me most?"')
    q.add_argument("--reveal-senders", action="store_true", help="show full sender addresses (masked by default)")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_mailbox_ask)
    p = msub.add_parser("sync", help="apply recent Gmail changes to the local index from the saved history checkpoint (contacts Gmail, read-only)")
    p.add_argument("--status", action="store_true", help="show the local sync state and exit (no Gmail contact)")
    p.add_argument("--account", metavar="EMAIL", help="account in the local index (default: the logged-in account)")
    p.add_argument("--max-units-per-minute", type=int, default=4500, metavar="U", help="Gmail API quota-unit budget per minute (default 4500 of the documented 6000)")
    p.set_defaults(func=cmd_mailbox_sync)
    for name, fn, helptext in (("status", cmd_mailbox_status, "scan history and index completeness (local only)"),
                               ("report", cmd_mailbox_report, "mailbox overview from the local index (local only)"),
                               ("top-senders", cmd_mailbox_top_senders, "top senders from the local index (local only)"),
                               ("purge", cmd_mailbox_purge, "delete this account's locally indexed data")):
        q = msub.add_parser(name, help=helptext)
        q.add_argument("--account", metavar="EMAIL", help="account in the local index (default: the logged-in account)")
        q.set_defaults(func=fn)
        if name == "top-senders":
            q.add_argument("--limit", type=int, default=20, metavar="N")
            q.add_argument("--unread", action="store_true", help="count only unread messages")
            q.add_argument("--domains", action="store_true", help="group by domain instead of showing addresses")
        if name == "purge":
            q.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ix = sub.add_parser("index", help="local index maintenance (offline)")
    isub = ix.add_subparsers(dest="index_command", required=True, metavar="{upgrade}")
    isub.add_parser("upgrade", help="upgrade an existing local index to the current schema (typed confirmation; verified private backup first)").set_defaults(func=cmd_index_upgrade)
    cl = sub.add_parser("classify", help="rules and optional local-AI classification of the local index (M3; offline)")
    csub = cl.add_subparsers(dest="classify_command", required=True,
                             metavar="{status,preview,run,report,explain,clear,rules,ai}")

    account_opt(csub.add_parser("status", help="classification coverage and staleness (local only)")).set_defaults(
        func=cmd_classify_status)
    for name, fn, helptext in (("preview", cmd_classify_preview, "show what `run` would produce; saves NOTHING"),
                               ("run", cmd_classify_run, "classify unclassified/stale messages and store results locally")):
        q = account_opt(csub.add_parser(name, help=helptext))
        g = q.add_mutually_exclusive_group(required=name == "run")
        g.add_argument("--limit", type=int, metavar="N", help="newest N messages needing work" + ("" if name == "run" else " (default 100)"))
        g.add_argument("--all", action="store_true", help="every message needing work (explicit intent)")
        if name == "preview":
            q.set_defaults(limit=100)
        else:
            q.add_argument("--ai", action="store_true", help="also ask the configured LOCAL model about weak-evidence messages")
        q.set_defaults(func=fn)
    q = account_opt(csub.add_parser("report", help="aggregate results, rule provenance, unknown groups (local only)"))
    q.add_argument("--show-senders", action="store_true", help="group unknowns by full address instead of domain")
    q.set_defaults(func=cmd_classify_report)
    q = account_opt(csub.add_parser("explain", help="show the stored results and reasons for one message id"))
    q.add_argument("message_id")
    q.add_argument("--show-sender", action="store_true", help="also print the sender address")
    q.set_defaults(func=cmd_classify_explain)
    q = account_opt(csub.add_parser("clear", help="delete stored classifications (rules and the index are kept)"))
    q.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    q.set_defaults(func=cmd_classify_clear)

    rl = csub.add_parser("rules", help="list, add, enable, disable or remove local classification rules")
    rsub = rl.add_subparsers(dest="rules_command", required=True, metavar="{list,add,enable,disable,remove}")
    account_opt(rsub.add_parser("list", help="show built-in and user rules")).set_defaults(func=cmd_classify_rules_list)
    q = account_opt(rsub.add_parser("add", help="add a user rule (matches stored metadata only)"))
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--type", metavar="TYPE", help="message type to assign (e.g. NEWSLETTER)")
    g.add_argument("--attention", metavar="SIGNAL", help="attention signal to assign (POTENTIALLY_IMPORTANT or REVIEW_NEEDED)")
    q.add_argument("--sender", metavar="ADDRESS", help="exact sender address")
    q.add_argument("--domain", metavar="DOMAIN", help="exact sender domain (subdomains are not matched)")
    q.add_argument("--label", metavar="LABEL", help="Gmail label id or name (e.g. CATEGORY_UPDATES)")
    u = q.add_mutually_exclusive_group()
    u.add_argument("--unread", dest="unread", action="store_true", default=None, help="only unread messages")
    u.add_argument("--read", dest="unread", action="store_false", help="only read messages")
    q.add_argument("--confidence", default="HIGH", metavar="LEVEL", help="LOW, MEDIUM or HIGH (default HIGH)")
    q.add_argument("--priority", type=int, default=0, metavar="N", help="higher wins among user rules (default 0)")
    q.add_argument("--note", metavar="TEXT", help="short reason shown in explanations")
    q.add_argument("--dry-run", action="store_true", help="show the impact on the local index without saving")
    q.set_defaults(func=cmd_classify_rules_add)
    for name, fn, helptext in (("enable", cmd_classify_rules_enable, "enable a user rule"),
                               ("disable", cmd_classify_rules_disable, "disable a user rule (kept, not applied)"),
                               ("remove", cmd_classify_rules_remove, "delete a user rule")):
        q = account_opt(rsub.add_parser(name, help=helptext))
        q.add_argument("rule_id", metavar="RULE_ID", help="e.g. u1")
        if name == "remove":
            q.add_argument("--yes", action="store_true", help="do not ask for confirmation")
        q.set_defaults(func=fn)

    ai_p = csub.add_parser("ai", help="optional local-AI settings (disabled by default)")
    aisub = ai_p.add_subparsers(dest="ai_command", required=True, metavar="{status}")
    aisub.add_parser("status", help="show local-AI configuration; contacts nothing").set_defaults(func=cmd_classify_ai_status)
    cu = sub.add_parser("cleanup", help="safe-cleanup candidate preview and protection rules (M4A; local, read-only)")
    cusub = cu.add_subparsers(dest="cleanup_command", required=True, metavar="{candidates,protect,plan,approve,approval,audit,execute,exec}")
    q = account_opt(cusub.add_parser("candidates", help="preview archive recommendations; changes NOTHING, contacts nothing"))
    q.add_argument("--review", action="store_true", help="show the informational REVIEW_REQUIRED view instead")
    q.add_argument("--limit", type=int, default=20, metavar="N", help="example rows to list (default 20; 0 = none)")
    q.add_argument("--min-age-days", type=int, default=90, metavar="N", help="minimum age in days (90 or more)")
    q.add_argument("--show-ids", action="store_true", help="include message ids in the example rows")
    q.add_argument("--show-senders", action="store_true", help="include sender addresses in the example rows")
    q.add_argument("--by-domain", action="store_true", help="also group by sender domain")
    q.add_argument("--export-ids", metavar="FILE", help="write up to --limit ELIGIBLE message ids to a NEW private file (never inside Git)")
    q.set_defaults(func=cmd_cleanup_candidates)
    pr = cusub.add_parser("protect", help="list, add, enable, disable or remove protection rules")
    prsub = pr.add_subparsers(dest="protect_command", required=True, metavar="{list,add,enable,disable,remove}")
    q = account_opt(prsub.add_parser("list", help="show protection rules (values masked by default)"))
    q.add_argument("--show-values", action="store_true", help="display the stored sender/domain/label values")
    q.set_defaults(func=cmd_cleanup_protect_list)
    q = account_opt(prsub.add_parser("add", help="protect messages matching ALL given conditions"))
    q.add_argument("--sender", metavar="ADDRESS", help="exact sender address")
    q.add_argument("--domain", metavar="DOMAIN", help="exact sender domain (subdomains are not matched)")
    q.add_argument("--label", metavar="LABEL", help="Gmail label id or name")
    q.add_argument("--note", metavar="TEXT", help="short reason (shown only with --show-values)")
    q.set_defaults(func=cmd_cleanup_protect_add)
    for name, fn, helptext in (("enable", cmd_cleanup_protect_enable, "enable a protection rule"),
                               ("disable", cmd_cleanup_protect_disable, "disable a protection rule (kept, not applied)"),
                               ("remove", cmd_cleanup_protect_remove, "delete a protection rule")):
        q = account_opt(prsub.add_parser(name, help=helptext))
        q.add_argument("rule_id", metavar="RULE_ID", help="e.g. p1")
        if name == "remove":
            q.add_argument("--yes", action="store_true", help="do not ask for confirmation")
        q.set_defaults(func=fn)
    plan = cusub.add_parser("plan", help="immutable cleanup plans (M4B; local only, nothing executes)")
    plsub = plan.add_subparsers(dest="plan_command", required=True, metavar="{create,list,show,review,exclude,cancel}")
    q = account_opt(plsub.add_parser("create", help="freeze an explicit set of ELIGIBLE message ids as a DRAFT plan"))
    q.add_argument("--message-id", action="append", metavar="ID", help="a target message id (repeatable)")
    q.add_argument("--ids-file", metavar="FILE", help="file with one message id per line (see cleanup candidates --export-ids)")
    q.add_argument("--min-age-days", type=int, default=90, metavar="N", help="minimum age in days (90 or more)")
    q.set_defaults(func=cmd_cleanup_plan_create)
    account_opt(plsub.add_parser("list", help="list plans")).set_defaults(func=cmd_cleanup_plan_list)
    q = account_opt(plsub.add_parser("impact", help="how the current index state affects stored plans (M7B; local, read-only, changes nothing)"))
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_cleanup_plan_impact)
    q = account_opt(plsub.add_parser("show", help="plan summary, freshness and (optionally) one page of targets"))
    q.add_argument("plan_id")
    q.add_argument("--page", type=int, metavar="N", help="show target page N")
    q.add_argument("--page-size", type=int, default=25, metavar="N")
    q.add_argument("--show-ids", action="store_true", help="print message ids on the page")
    q.set_defaults(func=cmd_cleanup_plan_show)
    q = account_opt(plsub.add_parser("review", help="walk through EVERY target (interactive terminal) and mark the plan REVIEWED"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_cleanup_plan_review)
    q = account_opt(plsub.add_parser("exclude", help="exclude messages: creates a NEW plan version and supersedes this one"))
    q.add_argument("plan_id")
    q.add_argument("--message-id", action="append", metavar="ID", required=True, help="message id to exclude (repeatable)")
    q.set_defaults(func=cmd_cleanup_plan_exclude)
    q = account_opt(plsub.add_parser("cancel", help="cancel a plan and revoke its approval"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_cleanup_plan_cancel)
    q = account_opt(cusub.add_parser("approve", help="record a LOCAL one-time approval (typed confirmation; no Gmail effect)"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_cleanup_approve)
    ap = cusub.add_parser("approval", help="inspect approvals")
    apsub = ap.add_subparsers(dest="approval_command", required=True, metavar="{status}")
    q = account_opt(apsub.add_parser("status", help="show a plan's approval records"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_cleanup_approval_status)
    au = cusub.add_parser("audit", help="local audit log of plans and approvals")
    ausub = au.add_subparsers(dest="audit_command", required=True, metavar="{verify,log}")
    q = account_opt(ausub.add_parser("verify", help="check the audit hash chain (and optionally a checkpoint you recorded earlier)"))
    q.add_argument("--checkpoint", metavar="HASH_PREFIX", help="a head hash you wrote down earlier (>= 8 hex characters)")
    q.set_defaults(func=cmd_cleanup_audit_verify)
    q = account_opt(ausub.add_parser("log", help="show recent audit events"))
    q.add_argument("--plan", metavar="PLAN_ID")
    q.add_argument("--limit", type=int, default=50, metavar="N")
    q.set_defaults(func=cmd_cleanup_audit_log)
    q = account_opt(cusub.add_parser("execute", help="dry run only (M4C-A): shows what a future execution would check; writes nothing"))
    q.add_argument("plan_id")
    q.add_argument("--dry-run", action="store_true", help="required: execution itself does not exist in this version")
    q.set_defaults(func=cmd_cleanup_execute)
    ex = cusub.add_parser("exec", help="inspect local execution records (read-only)")
    exsub = ex.add_subparsers(dest="exec_command", required=True, metavar="{list,show}")
    account_opt(exsub.add_parser("list", help="list execution records")).set_defaults(func=cmd_cleanup_exec_list)
    q = account_opt(exsub.add_parser("show", help="state, slices and item counts of one execution"))
    q.add_argument("exec_id")
    q.add_argument("--show-ids", action="store_true", help="also list message ids and item states")
    q.set_defaults(func=cmd_cleanup_exec_show)
    db = sub.add_parser("dashboard", help="local read-only dashboard (M6): serves the analytics on 127.0.0.1 only; no Gmail access, no changes")
    dbsub = db.add_subparsers(dest="dashboard_command", required=True, metavar="{serve}")
    q = dbsub.add_parser("serve", help="start the local dashboard server (loopback only, per-launch token, read-only index)")
    q.add_argument("--account", metavar="EMAIL", help="account in the local index (default: the only account in it; the Keychain is never read)")
    q.add_argument("--port", type=int, default=0, help="port (default 0: any free port)")
    q.add_argument("--open", action="store_true", help="open the dashboard link in your default browser")
    q.add_argument("--reveal-senders", action="store_true", help="show full sender addresses (private; masked by default)")
    q.add_argument("--reveal-names", action="store_true", help="show label names in the Organization screen (private; hidden by default)")
    q.add_argument("--verbose", action="store_true", help="print one line per request (method, path, status; never the token)")
    q.set_defaults(func=cmd_dashboard_serve)
    lb = sub.add_parser("labels", help="inbox organization (M5): label hygiene, recommendations, suggestions and label-change plans; LOCAL ONLY, changes nothing in Gmail",
                             description="Inbox organization (M5). LOCAL ONLY — no Gmail changes performed: these commands read the local index and never call Gmail, edit labels or create filters.")
    lbsub = lb.add_subparsers(dest="labels_command", required=True, metavar="{report,recommend,suggest-rules,suggest-filters,plan,approve}")
    q = account_opt(lbsub.add_parser("report", help="label hygiene report: duplicates, unused labels, nesting problems (local, read-only)"))
    q.add_argument("--show-names", action="store_true", help="display label names (private; hidden by default)")
    q.set_defaults(func=cmd_labels_report)
    q = account_opt(lbsub.add_parser("recommend", help="label recommendations from label usage, sender patterns and classification (local, suggestions only)"))
    q.add_argument("--show-names", action="store_true", help="display label names (private; hidden by default)")
    q.add_argument("--show-senders", action="store_true", help="display sender addresses and domains (private; hidden by default)")
    q.set_defaults(func=cmd_labels_recommend)
    q = account_opt(lbsub.add_parser("suggest-rules", help="proposed M3 classification rules with the standard preview (local; never saves a rule)"))
    q.add_argument("--show-senders", action="store_true", help="display sender addresses and domains (private; hidden by default)")
    q.set_defaults(func=cmd_labels_suggest_rules)
    q = account_opt(lbsub.add_parser("suggest-filters", help="Gmail filter suggestions (text only; creates no filter and needs no filter permission)"))
    q.add_argument("--show-names", action="store_true", help="display label names (private; hidden by default)")
    q.add_argument("--show-senders", action="store_true", help="display sender addresses and domains (private; hidden by default)")
    q.set_defaults(func=cmd_labels_suggest_filters)
    pl = lbsub.add_parser("plan", help="label-change plans (CREATE/RENAME/NEST/MERGE of user labels): offline, reviewed, never executed")
    plsub = pl.add_subparsers(dest="label_plan_command", required=True, metavar="{create,list,show,review,cancel}")
    q = account_opt(plsub.add_parser("create", help="create a DRAFT plan from explicit operations (validates names, nesting, system labels, duplicates)"))
    q.add_argument("--create", action="append", metavar="NAME", help="create a label with this full name (repeatable)")
    q.add_argument("--rename", action="append", metavar="LABEL=NEWLEAF", help="rename a label's last name segment; LABEL is an id or exact name (repeatable)")
    q.add_argument("--nest", action="append", metavar="LABEL=PARENT", help="move a label under PARENT (id or exact name), or to top level with LABEL= (repeatable)")
    q.add_argument("--merge", action="append", metavar="SOURCE=TARGET", help="merge SOURCE into TARGET (ids or exact names); may be irreversible (repeatable)")
    q.set_defaults(func=cmd_labels_plan_create)
    q = account_opt(plsub.add_parser("list", help="list label plans"))
    q.set_defaults(func=cmd_labels_plan_list)
    q = account_opt(plsub.add_parser("show", help="show one label plan"))
    q.add_argument("plan_id")
    q.add_argument("--show-names", action="store_true", help="display label names (private; hidden by default)")
    q.set_defaults(func=cmd_labels_plan_show)
    q = account_opt(plsub.add_parser("review", help="review a DRAFT plan and confirm by typing its phrase (terminal only)"))
    q.add_argument("plan_id")
    q.add_argument("--show-names", action="store_true", help="display label names (private; hidden by default)")
    q.set_defaults(func=cmd_labels_plan_review)
    q = account_opt(plsub.add_parser("cancel", help="cancel a label plan (terminal confirmation)"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_labels_plan_cancel)
    q = account_opt(lbsub.add_parser("approve", help="record a one-time LOCAL approval for a REVIEWED label plan (grants nothing; nothing executes)"))
    q.add_argument("plan_id")
    q.set_defaults(func=cmd_labels_approve)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)  # argparse exits with status 2 on usage errors
    return args.func(args)
