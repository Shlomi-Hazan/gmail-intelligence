"""Regression tests for the M4B security-audit findings (backup safety, error mapping, audit/forgery limits, clock, lockout,
corrupt snapshots) plus permanent versions of the audit's adversarial reproductions (real multi-process race, SIGKILL during a
transaction, pseudo-terminal behavior). Synthetic data only; no Gmail, network or Keychain.
"""
import contextlib
import io
import json
import os
import select
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, OTHER, Base, msg  # noqa: E402
from test_cleanup_plans import H, T0, PlanBase  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_plans as cp, cli, config  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

try:
    import pty
except ImportError:  # pragma: no cover
    pty = None


def make_v3(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript("BEGIN;" + idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + "PRAGMA user_version = 3;COMMIT;")
    conn.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", (ACCT, "m1", "t1", 1000, 10, "a@x.example.test", 0, 1))
    conn.commit()
    conn.close()


def backups(path):
    return sorted(p for p in path.parent.iterdir() if "backup" in p.name)


class BackupSafetyTests(Base):
    def setUp(self):
        super().setUp()
        self.db = self.tmp / "mig" / "index.sqlite3"
        make_v3(self.db)

    def test_backup_file_is_private_from_the_first_byte_even_with_a_permissive_umask(self):
        seen = []
        real = idx._write_backup

        def spy(conn, path, version):
            seen.append(stat.S_IMODE(os.stat(path).st_mode))  # mode BEFORE any data is written
            return real(conn, path, version)
        old = os.umask(0)
        try:
            with mock.patch.object(idx, "_write_backup", side_effect=spy):
                with idx.Index(str(self.db), allow_upgrade=True) as index:
                    final = stat.S_IMODE(os.stat(index.backup_path).st_mode)
        finally:
            os.umask(old)
        self.assertEqual(seen, [0o600])
        self.assertEqual(final, 0o600)

    def test_failed_backup_leaves_no_partial_file_and_the_database_unchanged(self):
        def boom(conn, path, version):
            Path(path).write_bytes(b"partial backup data")
            raise sqlite3.OperationalError("disk full (simulated)")
        with mock.patch.object(idx, "_write_backup", side_effect=boom):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.Index(str(self.db), allow_upgrade=True)
        self.assertEqual(backups(self.db), [])
        self.assertNotIn(str(self.tmp), str(cm.exception))  # no paths in the message
        c = sqlite3.connect(self.db)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 1)
        c.close()

    def test_existing_backup_is_never_overwritten_or_deleted(self):
        fixed = mock.Mock()
        fixed.now.return_value = __import__("datetime").datetime(2026, 1, 2, 3, 4, 5, tzinfo=__import__("datetime").timezone.utc)
        precious = Path(f"{self.db}.pre-m4b-backup-20260102T030405Z")
        precious.write_bytes(b"IRREPLACEABLE")
        os.chmod(precious, 0o600)
        with mock.patch.object(idx, "datetime", fixed):
            with idx.Index(str(self.db), allow_upgrade=True) as index:
                new = Path(index.backup_path)
        self.assertEqual(precious.read_bytes(), b"IRREPLACEABLE")
        self.assertNotEqual(new, precious)
        self.assertTrue(new.name.endswith("-1"))
        c = sqlite3.connect(new)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 3)
        c.close()

    def test_failed_upgrade_keeps_the_complete_verified_backup(self):
        with mock.patch.object(idx, "SCHEMA_V4", "CREATE TABLE a (x);CREATE TABLE a (x);"):
            with self.assertRaises(idx.IndexProblem) as cm:
                idx.Index(str(self.db), allow_upgrade=True)
        (kept,) = backups(self.db)
        self.assertEqual(stat.S_IMODE(os.stat(kept).st_mode), 0o600)
        c = sqlite3.connect(kept)
        self.assertEqual((c.execute("PRAGMA user_version").fetchone()[0], c.execute("PRAGMA quick_check").fetchone()[0]), (3, "ok"))
        c.close()
        self.assertIn("backup was kept", str(cm.exception))

    def test_unverifiable_backup_aborts_the_upgrade(self):
        def wrong_version(conn, path, version):
            raise sqlite3.DatabaseError("backup verification failed")
        with mock.patch.object(idx, "_write_backup", side_effect=wrong_version):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(self.db), allow_upgrade=True)
        self.assertEqual(backups(self.db), [])

    def test_simultaneous_upgrades_leave_a_healthy_database_and_private_backups(self):
        import threading
        out = []

        def go():
            try:
                i = idx.Index(str(self.db), allow_upgrade=True)
                out.append("ok")
                i.close()
            except idx.IndexProblem:
                out.append("problem")
        threads = [threading.Thread(target=go) for _ in range(3)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertIn("ok", out)
        c = sqlite3.connect(self.db)
        self.assertEqual((c.execute("PRAGMA user_version").fetchone()[0], c.execute("PRAGMA integrity_check").fetchone()[0]), (idx.SCHEMA_VERSION, "ok"))
        c.close()
        # the winner keeps its backup; a loser that found the upgrade already done discards only its own redundant copy
        self.assertEqual(len(backups(self.db)), 1 + out.count("problem"))
        for b in backups(self.db):
            self.assertEqual(stat.S_IMODE(os.stat(b).st_mode), 0o600)


class ErrorMappingTests(PlanBase):
    def test_unrelated_integrity_errors_are_not_reported_as_duplicate_approvals(self):
        p = self.reviewed()
        with mock.patch.object(audit, "append", side_effect=sqlite3.IntegrityError("some other constraint")):
            with self.assertRaises(cp.PlanError) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cm.exception.code, "DB_CONSTRAINT")
        self.assertNotIn("already", str(cm.exception).lower())
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")
        self.assertEqual(self.count("cleanup_approval"), 0)
        p2 = self.plan(["m4"])
        with mock.patch.object(audit, "append", side_effect=sqlite3.IntegrityError("x")):
            with self.assertRaises(cp.PlanError) as cm:
                cp.mark_reviewed(self.index, ACCT, p2["plan_id"], cp.review_phrase(p2), now=T0)
        self.assertEqual(cm.exception.code, "DB_CONSTRAINT")

    def test_a_genuine_duplicate_is_still_reported_as_such(self):
        p = self.reviewed()
        with self.index.conn:  # a VALID row is allowed while the plan is REVIEWED; the unique index then blocks the real one
            self.index.conn.execute("INSERT INTO cleanup_approval VALUES (?,?,?,?,?,?,?,?,?,?)",
                                    (ACCT, p["plan_id"], "a" * 32, p["plan_hash"], "ARCHIVE", 3, "t", "u", "VALID", "t"))
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(cm.exception.code, "ALREADY_APPROVED")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")

    def test_failure_to_write_the_rejection_audit_event_is_reported_not_hidden(self):
        p = self.reviewed()
        with mock.patch.object(cp, "_reject", return_value=False):
            with self.assertRaises(cp.PlanError) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], "wrong", now=T0)
        self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        self.assertIn("audit entry for this failure could not be written", str(cm.exception))


class AuditLimitTests(PlanBase):
    def drop_triggers(self):
        for t in ("cleanup_audit_no_update", "cleanup_audit_no_delete"):
            self.index.conn.execute(f"DROP TRIGGER {t}")

    def test_documented_limitation_deleting_the_newest_events_is_not_detectable_without_a_checkpoint(self):
        self.approved()
        _, head = audit.head(self.index, ACCT)
        self.drop_triggers()
        with self.index.conn:
            self.index.conn.execute("DELETE FROM cleanup_audit WHERE event_type='PLAN_APPROVED'")
        ok, n, bad = audit.verify_chain(self.index, ACCT)
        self.assertTrue(ok)  # LIMITATION: the shortened chain still verifies
        self.assertEqual(n, 2)
        self.assertFalse(audit.contains(self.index, ACCT, head[:12]))  # ...but an independently recorded checkpoint reveals it
        with self.index.conn:
            self.index.conn.execute("DELETE FROM cleanup_audit")
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])  # LIMITATION: even an empty log verifies
        self.assertFalse(audit.contains(self.index, ACCT, head[:12]))

    def test_middle_deletion_and_edits_are_detected(self):
        self.approved()
        self.drop_triggers()
        with self.index.conn:
            self.index.conn.execute("DELETE FROM cleanup_audit WHERE seq=2")
        self.assertFalse(audit.verify_chain(self.index, ACCT)[0])

    def test_checkpoint_helpers_validate_input(self):
        self.plan()
        _, head = audit.head(self.index, ACCT)
        self.assertTrue(audit.contains(self.index, ACCT, head[:8]))
        self.assertTrue(audit.contains(self.index, ACCT, head.upper()[:16]))
        for bad in ("", "abc", "zzzzzzzz", None):
            with self.assertRaises(ValueError):
                audit.contains(self.index, ACCT, bad)
        self.assertEqual(audit.head(self.index, OTHER), (0, None))

    def test_events_limit_is_validated(self):
        for bad in (-1, 0, 1001, "5", True, None):
            with self.assertRaises(ValueError, msg=bad):
                audit.events(self.index, ACCT, limit=bad)
        self.assertEqual(audit.events(self.index, ACCT, limit=1), [])


class ForgedStateTests(PlanBase):
    def refuse(self, sql, *params):
        with self.assertRaises(sqlite3.DatabaseError, msg=sql):
            with self.index.conn:
                self.index.conn.execute(sql, params)

    def test_database_refuses_inconsistent_states(self):
        p = self.reviewed()
        self.refuse("UPDATE cleanup_plan SET state='APPROVED' WHERE plan_id=?", p["plan_id"])  # no VALID approval row yet
        q = self.plan(["m4"])
        self.refuse("UPDATE cleanup_plan SET state='REVIEWED' WHERE plan_id=?", q["plan_id"])  # no reviewed_at
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")

    def forge(self, p, expires="2999-01-01T00:00:00Z", created="2000-01-01T00:00:00Z", log=False):
        with self.index.conn:
            self.index.conn.execute("INSERT INTO cleanup_approval VALUES (?,?,?,?,?,?,?,?,?,?)",
                                    (ACCT, p["plan_id"], "c" * 32, p["plan_hash"], "ARCHIVE", p["item_count"], created, expires, "VALID", created))
            self.index.conn.execute("UPDATE cleanup_plan SET state='APPROVED' WHERE plan_id=?", (p["plan_id"],))
        if log:
            self.index.conn.execute("BEGIN IMMEDIATE")
            audit.append(self.index, ACCT, p["plan_id"], "PLAN_APPROVED", cp._iso(T0),
                         {"items": p["item_count"], "plan_hash": p["plan_hash"], "nonce_sha256": audit.sha256("c" * 32), "expires_at": expires})
            self.index.conn.commit()

    def test_forged_approval_without_audit_trail_is_flagged(self):
        p = self.reviewed()
        self.forge(p, expires=cp._iso(T0 + 2 * H), created=cp._iso(T0))
        self.assertIn("APPROVAL_NOT_IN_AUDIT", cp.verify_approved(self.index, ACCT, p["plan_id"], T0))

    def test_forged_approval_with_impossible_times_is_flagged(self):
        p = self.reviewed()
        self.forge(p)  # created long before the plan, valid for centuries
        problems = cp.verify_approved(self.index, ACCT, p["plan_id"], T0)
        self.assertIn("APPROVAL_TIMES_INCONSISTENT", problems)

    def test_documented_limitation_a_consistent_forgery_by_a_database_writer_passes_local_checks(self):
        """Direct modification of this database by the local account is OUTSIDE the trust boundary.

        Someone who can write the file can fabricate an approval row, its state change AND a correctly chained audit event.
        verify_approved then returns no problems. That is why an executor must re-validate live Gmail state and ask the owner
        again at execution time; the local ledger alone must never be treated as authorization.
        """
        p = self.reviewed()
        self.forge(p, expires=cp._iso(T0 + 2 * H), created=cp._iso(T0), log=True)
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0 + H), {})

    def test_forgery_cannot_smuggle_an_ineligible_message_even_with_consistent_hashes(self):
        p = self.plan(["m1"])
        snap = cp.snapshot_of(p)
        with self.index.conn:
            self.index.conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCT, "m2", "STARRED"))
        snap["items"] = sorted([cp._facts(self.index, ACCT, ["m1", "m2"])[i] for i in ("m1", "m2")], key=lambda i: i["id"])
        text = audit.canonical(snap)
        for t in ("cleanup_plan_content_immutable", "cleanup_item_only_in_draft"):
            self.index.conn.execute(f"DROP TRIGGER {t}")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_plan SET snapshot=?, plan_hash=?, item_count=2 WHERE plan_id=?",
                                    (text, audit.sha256(text), p["plan_id"]))
            self.index.conn.execute("INSERT INTO cleanup_item VALUES (?,?,?,?,?)", (ACCT, p["plan_id"], "m2", "t2",
                                    audit.sha256(audit.canonical(snap["items"][1]))))
        problems = cp.revalidate(self.index, ACCT, cp.get_plan(self.index, ACCT, p["plan_id"]), T0)
        self.assertIn("ITEM_NOT_ELIGIBLE", problems)
        self.assertIn("REASON_STARRED", problems)

    def test_overlapping_plans_may_share_a_message_each_with_its_own_approval(self):
        a = self.plan(["m1", "m2"])
        b = self.plan(["m2", "m3"])
        for p in (a, b):
            self.reviewed(p)
            cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_approval WHERE status='VALID'")[0][0], 2)
        for p in (a, b):
            self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0), {})  # M4C must consume per plan


class ClockTests(PlanBase):
    def test_mutations_are_refused_when_the_clock_is_earlier_than_the_last_recorded_event(self):
        p = self.plan(now=T0)
        early = T0 - timedelta(minutes=6)
        for call in (lambda: cp.create_plan(self.index, ACCT, ["m4"], now=early),
                     lambda: cp.mark_reviewed(self.index, ACCT, p["plan_id"], cp.review_phrase(p), now=early),
                     lambda: cp.revise_exclude(self.index, ACCT, p["plan_id"], ["m1"], now=early)):
            with self.assertRaises(cp.PlanError) as cm:
                call()
            self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")
        r = self.reviewed(p, now=T0)
        with self.assertRaises(cp.PlanError) as cm:
            cp.approve(self.index, ACCT, r["plan_id"], cp.approval_phrase(r), now=early)
        self.assertEqual(cm.exception.code, "CLOCK_ROLLBACK")
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")
        self.assertEqual(self.count("cleanup_approval"), 0)
        self.assertNotIn("APPROVAL_REJECTED", self.events())  # a clock fault is reported, not logged as a bad guess

    def test_small_clock_skew_is_tolerated(self):
        p = self.reviewed(now=T0)
        st = cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=T0 - timedelta(minutes=4))
        self.assertEqual(st["plan_state"], "APPROVED")

    def test_an_approval_created_in_the_future_is_flagged_by_the_executor_side_check(self):
        p = self.approved(now=T0)
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0 - timedelta(minutes=4)), {})
        problems = cp.verify_approved(self.index, ACCT, p["plan_id"], T0 - timedelta(minutes=6))
        self.assertIn("CLOCK_BEFORE_APPROVAL", problems)
        self.assertIn("PLAN_FROM_THE_FUTURE", problems)

    def test_the_24_hour_expiry_and_fresh_clock_behavior_are_unchanged(self):
        p = self.approved(now=T0)
        self.assertEqual(cp.verify_approved(self.index, ACCT, p["plan_id"], T0 + 23 * H), {})
        self.assertIn("APPROVAL_EXPIRED", cp.verify_approved(self.index, ACCT, p["plan_id"], T0 + 24 * H))
        self.assertEqual(self.index._q("SELECT expires_at FROM cleanup_approval")[0][0], cp._iso(T0 + cp.APPROVAL_TTL))


class LockoutTests(PlanBase):
    def test_repeated_wrong_confirmations_are_bounded_and_the_lockout_is_logged_once(self):
        p = self.reviewed()
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(cp.PlanError) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], "wrong", now=T0)
            self.assertEqual(cm.exception.code, "BAD_CONFIRMATION")
        before = self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0]
        for phrase in ("wrong", cp.approval_phrase(p), "wrong"):  # even the CORRECT phrase is refused while locked out
            with self.assertRaises(cp.PlanError) as cm:
                cp.approve(self.index, ACCT, p["plan_id"], phrase, now=T0 + timedelta(minutes=1))
            self.assertEqual(cm.exception.code, "LOCKED_OUT")
        for _ in range(50):
            with self.assertRaises(cp.PlanError):
                cp.approve(self.index, ACCT, p["plan_id"], "wrong", now=T0 + timedelta(minutes=2))
        events = self.events()
        self.assertEqual(events.count("APPROVAL_REJECTED"), cp.MAX_FAILED_ATTEMPTS)
        self.assertEqual(events.count("ATTEMPTS_LOCKED_OUT"), 1)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_audit")[0][0], before + 1)  # bounded: one lockout row, nothing else
        self.assertEqual(self.count("cleanup_approval"), 0)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_lockout_expires_and_is_per_plan(self):
        p = self.reviewed()
        other = self.reviewed(self.plan(["m4", "m5"]))
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(cp.PlanError):
                cp.approve(self.index, ACCT, p["plan_id"], "wrong", now=T0)
        cp.approve(self.index, ACCT, other["plan_id"], cp.approval_phrase(other), now=T0)  # unaffected plan
        later = T0 + cp.LOCKOUT_WINDOW + timedelta(minutes=1)
        st = cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p), now=later)
        self.assertEqual(st["plan_state"], "APPROVED")

    def test_review_confirmations_are_bounded_too(self):
        p = self.plan()
        for _ in range(cp.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(cp.PlanError):
                cp.mark_reviewed(self.index, ACCT, p["plan_id"], "no", now=T0)
        with self.assertRaises(cp.PlanError) as cm:
            cp.mark_reviewed(self.index, ACCT, p["plan_id"], cp.review_phrase(p), now=T0)
        self.assertEqual(cm.exception.code, "LOCKED_OUT")


class CorruptSnapshotTests(PlanBase):
    VARIANTS = ("{broken", "", "[]", "null", "42", "{}", '{"items": 5}', json.dumps({"format": 1}),
                json.dumps({k: None for k in cp.SNAPSHOT_KEYS}))

    def corrupt(self, plan, text, rehash):
        for t in ("cleanup_plan_content_immutable",):
            self.index.conn.execute(f"DROP TRIGGER IF EXISTS {t}")
        with self.index.conn:
            self.index.conn.execute("UPDATE cleanup_plan SET snapshot=?, plan_hash=? WHERE plan_id=?",
                                    (text, audit.sha256(text) if rehash else plan["plan_hash"], plan["plan_id"]))

    def test_every_malformed_snapshot_yields_clean_errors_not_exceptions(self):
        t = T0
        for rehash in (False, True):
            for text in self.VARIANTS:
                t += timedelta(hours=1)
                plan = self.plan(["m1"], now=t)
                self.corrupt(plan, text, rehash)
                row = cp.get_plan(self.index, ACCT, plan["plan_id"])
                problems = cp.revalidate(self.index, ACCT, row, t + timedelta(minutes=10))  # must not raise
                self.assertTrue(problems, (text, rehash))
                with self.assertRaises(cp.PlanError) as cm:
                    cp.snapshot_of(row)
                self.assertEqual(cm.exception.code, "SNAPSHOT_UNREADABLE")
                if len(text) > 4:
                    self.assertNotIn(text, str(cm.exception))
                later = t + timedelta(minutes=20)
                for call in (lambda: cp.mark_reviewed(self.index, ACCT, plan["plan_id"], "x", now=later),
                             lambda: cp.revise_exclude(self.index, ACCT, plan["plan_id"], ["m1"], now=later)):
                    with self.assertRaises(cp.PlanError):
                        call()
                cp.cancel(self.index, ACCT, plan["plan_id"], now=later)  # a broken plan can always be cancelled
                self.assertEqual(cp.get_plan(self.index, ACCT, plan["plan_id"])["state"], "CANCELLED")
                t = later

    def test_cli_shows_a_clean_message_and_no_snapshot_text(self):
        import time as _t
        self.index.purge(ACCT)
        ms = int(_t.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 4)])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()):
            plan_id = None
            plan = cp.create_plan(self.index, ACCT, ["m1"])
            plan_id = plan["plan_id"]
        self.corrupt(plan, "SECRET-SNAPSHOT-TEXT {", rehash=True)
        for argv in (["cleanup", "plan", "show", plan_id], ["cleanup", "plan", "list"], ["cleanup", "approval", "status", plan_id]):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main([*argv, "--account", ACCT])
            text = out.getvalue() + err.getvalue()
            self.assertNotIn("SECRET-SNAPSHOT-TEXT", text)
            self.assertNotIn("Traceback", text)
            self.assertNotIn("Expecting", text)
            self.assertIn("<account hidden>", text) if argv[2] == "show" else None
            self.assertEqual(code, 0, text)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch.object(cli, "_tty_input", side_effect=EOFError):
            self.assertEqual(cli.main(["cleanup", "plan", "review", plan_id, "--account", ACCT]), 1)
        self.assertNotIn("SECRET-SNAPSHOT-TEXT", out.getvalue() + err.getvalue())
        self.assertIn("stale or inconsistent", err.getvalue())


class CliValidationTests(PlanBase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_audit_log_limit_is_validated(self):
        self.plan()
        for bad in ("-1", "0", "1001", "99999"):
            code, out, err = self.run_cli("cleanup", "audit", "log", "--account", ACCT, "--limit", bad)
            self.assertEqual(code, 1, bad)
            self.assertIn("between 1 and 1000", err)
            self.assertEqual(out, "")
        self.assertEqual(self.run_cli("cleanup", "audit", "log", "--account", ACCT, "--limit", "1")[0], 0)

    def test_audit_verify_checkpoint(self):
        self.plan()
        _, head = audit.head(self.index, ACCT)
        code, out, _ = self.run_cli("cleanup", "audit", "verify", "--account", ACCT, "--checkpoint", head[:12])
        self.assertEqual(code, 0, out)
        self.assertIn("FOUND", out)
        self.assertIn("never tamper-proof", out)
        code, out, _ = self.run_cli("cleanup", "audit", "verify", "--account", ACCT, "--checkpoint", "deadbeefdeadbeef")
        self.assertEqual(code, 1)
        self.assertIn("NOT FOUND", out)
        self.assertEqual(self.run_cli("cleanup", "audit", "verify", "--account", ACCT, "--checkpoint", "xyz")[0], 1)
        code, out, _ = self.run_cli("cleanup", "audit", "verify", "--account", ACCT)
        self.assertEqual(code, 0)
        self.assertIn("Head:", out)
        self.assertIn("undetectable without such a checkpoint", out)


CHILD = textwrap.dedent("""
    import sys, os, time
    sys.path.insert(0, sys.argv[1])
    os.environ["GMAIL_INTELLIGENCE_HOME"] = sys.argv[2]
    plan_id, go, mode, acct = sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
    from gmail_intelligence import index as idx, cleanup_plans as cp, cleanup_audit as au
    ix = idx.Index(create=False)
    plan = cp.get_plan(ix, acct, plan_id)
    while not os.path.exists(go):
        time.sleep(0.001)
    if mode == "slow":
        real = au.append
        def slow(*a, **k):
            r = real(*a, **k)
            open(go + ".inside", "w").close()
            time.sleep(60)
            return r
        au.append = slow
    try:
        cp.approve(ix, acct, plan_id, cp.approval_phrase(plan))
        print("OK")
    except cp.PlanError as e:
        print("ERR", e.code)
""")


class ProcessTests(PlanBase):
    """Real processes: concurrency and crashes are not simulated here."""

    def setUp(self):
        super().setUp()
        self.child = self.tmp / "child.py"
        self.child.write_text(CHILD)
        self.home = os.environ[config.HOME_ENV]
        self.index.purge(ACCT)  # child processes use the real clock, so the fixture must be relative to the real time
        ms = int(time.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 6)])

    def fresh_reviewed(self, ids):
        plan = cp.create_plan(self.index, ACCT, ids)
        plan = cp.mark_reviewed(self.index, ACCT, plan["plan_id"], cp.review_phrase(plan))
        self.index.conn.commit()
        return plan

    def spawn(self, plan_id, go, mode="fast"):
        return subprocess.Popen([sys.executable, str(self.child), str(SRC), self.home, plan_id, str(go), mode, ACCT],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_racing_processes_produce_exactly_one_approval(self):
        for n in range(3):
            p = self.fresh_reviewed([f"m{n + 1}"])
            go = self.tmp / f"go{n}"
            kids = [self.spawn(p["plan_id"], go) for _ in range(3)]
            time.sleep(0.5)
            go.write_text("go")
            outs = [k.communicate(timeout=90) for k in kids]
            results = [o[0].strip() for o in outs]
            self.assertEqual(results.count("OK"), 1, (results, [o[1][-200:] for o in outs]))
            self.assertTrue(all(r in ("OK", "ERR ALREADY_APPROVED") for r in results), results)
            self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_approval WHERE plan_id=? AND status='VALID'", p["plan_id"])[0][0], 1)
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_killing_a_process_mid_transaction_leaves_no_partial_approval(self):
        p = self.fresh_reviewed(["m1", "m2"])
        go = self.tmp / "go-kill"
        kid = self.spawn(p["plan_id"], go, mode="slow")
        time.sleep(0.5)
        go.write_text("go")
        for _ in range(600):
            if Path(str(go) + ".inside").exists():
                break
            time.sleep(0.05)
        else:
            kid.kill()
            self.fail("child never reached the transaction")
        os.kill(kid.pid, signal.SIGKILL)
        kid.wait()
        kid.stdout.close()
        kid.stderr.close()
        self.assertEqual(cp.get_plan(self.index, ACCT, p["plan_id"])["state"], "REVIEWED")
        self.assertEqual(self.count("cleanup_approval"), 0)
        self.assertNotIn("PLAN_APPROVED", self.events())
        self.assertEqual(self.index._q("PRAGMA integrity_check")[0][0], "ok")
        self.assertEqual(cp.approve(self.index, ACCT, p["plan_id"], cp.approval_phrase(p))["plan_state"], "APPROVED")


@unittest.skipIf(pty is None, "pseudo-terminals unavailable")
class TerminalTests(PlanBase):
    """The installed-style CLI on a real pseudo-terminal: EOF, wrong phrases and piped input."""

    def setUp(self):
        super().setUp()
        self.home = os.environ[config.HOME_ENV]
        self.index.purge(ACCT)
        ms = int(time.time() * 1000) - 200 * 86_400_000
        self.seed([msg(i, sender=f"s{i}@shop.example.test", ms=ms + i) for i in range(1, 4)])
        self.plan_row = cp.create_plan(self.index, ACCT, ["m1", "m2"])
        self.index.conn.commit()
        self.env = dict(os.environ, GMAIL_INTELLIGENCE_HOME=self.home, PYTHONPATH=str(SRC), TERM="dumb")

    def argv(self, *a):
        return [sys.executable, "-m", "gmail_intelligence", *a, "--account", ACCT]

    def on_tty(self, args, keys):
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(sys.executable, self.argv(*args), self.env)
        out, keys, deadline = b"", list(keys), time.time() + 60
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.3)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            elif keys and out:
                os.write(fd, keys.pop(0))
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status), out.decode(errors="replace")

    def state(self):
        return cp.get_plan(self.index, ACCT, self.plan_row["plan_id"])["state"]

    def test_eof_and_wrong_phrases_on_a_terminal_change_nothing(self):
        pid = self.plan_row["plan_id"]
        for keys in ([b"\x04"], [b"yes\n"], [b"REVIEWED 2 00000000\n"]):
            code, _ = self.on_tty(["cleanup", "plan", "review", pid], keys)
            self.assertEqual((code, self.state()), (1, "DRAFT"), keys)

    def test_piped_input_never_confirms_even_with_the_correct_phrase(self):
        pid = self.plan_row["plan_id"]
        for stdin in (cp.review_phrase(self.plan_row) + "\n", ""):
            r = subprocess.run(self.argv("cleanup", "plan", "review", pid), input=stdin, capture_output=True, text=True, env=self.env)
            self.assertEqual(r.returncode, 1)
            self.assertIn("interactive terminal", r.stderr)
            self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(self.state(), "DRAFT")

    def test_documented_limitation_a_program_driving_a_pty_can_confirm(self):
        """Same-user automation is not prevented: the typed phrase is friction and intent, not authentication."""
        pid = self.plan_row["plan_id"]
        code, _ = self.on_tty(["cleanup", "plan", "review", pid], [(cp.review_phrase(self.plan_row) + "\n").encode()])
        self.assertEqual((code, self.state()), (0, "REVIEWED"))


if __name__ == "__main__":
    unittest.main()
