"""Offline tests for M4A: candidate engine, protection rules, schema v3 migration and the cleanup CLI.

Synthetic data only (reserved example domains), temporary SQLite files, no Gmail, no network, no Keychain. A socket guard
and "bomb" replacements for the Gmail reader and the Keychain fail any attempt to use them.
"""
import contextlib
import io
import os
import re
import socket
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from gmail_intelligence import classifier, cleanup_candidates as cc, cleanup_protect, cleanup_report, cli, config  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402
from gmail_intelligence.classify import RuleError  # noqa: E402

ACCT, OTHER = "owner@example.invalid", "other@example.invalid"
NOW = 1_800_000_000_000
DAY = cc.DAY_MS
SENDER_SENTINEL = "secret.sender@sentinel.example.invalid"
LABEL_SENTINEL = "SentinelPrivateLabel"


def msg(i, days=200, sender="promo@shop.example.test", labels=("INBOX", "CATEGORY_PROMOTIONS"), thread=None, **kw):
    ms = kw.get("ms", NOW - days * DAY)
    return {"id": f"m{i}", "thread_id": thread if thread is not None else f"t{i}", "internal_ms": ms, "size": 10,
            "sender": sender, "label_ids": list(labels)}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        patcher = mock.patch.dict(os.environ, {config.HOME_ENV: str(self.tmp / "home")})
        patcher.start()
        self.addCleanup(patcher.stop)
        guard = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used"))
        guard.start()
        self.addCleanup(guard.stop)
        self.index = idx.Index()
        self.addCleanup(self.index.close)

    def seed(self, messages, account=ACCT, complete=True, labels=None, classify=True):
        scan = self.index.start_scan(account, "full" if complete else "limited", None if complete else 5)
        self.index.save_batch(account, scan, messages)
        if labels:
            self.index.save_labels(account, labels)
        self.index.finish_scan(scan, "completed")
        if classify:
            classifier.run(self.index, account, persist=True)
        return scan

    def decide(self, **kw):
        res = cc.evaluate_all(self.index, kw.pop("account", ACCT), now_ms=NOW, **kw)
        return {d.message_id: d for d in res.decisions}, res

    def one(self, m, **kw):
        self.seed([m])
        d, _ = self.decide(**kw)
        return d[m["id"]]


class PolicyTests(Base):
    def test_eligible_promotional_and_social_with_provenance(self):
        self.seed([msg(1), msg(2, labels=("INBOX", "CATEGORY_SOCIAL"))])
        d, res = self.decide()
        for mid, t in (("m1", "PROMOTIONAL"), ("m2", "SOCIAL")):
            self.assertEqual(d[mid].outcome, cc.ELIGIBLE, d[mid].codes)
            self.assertEqual(d[mid].evidence[0][:2], (t, "MEDIUM"))
        self.assertEqual(res.summary["trash_recommendations"], 0)

    def test_newsletter_needs_a_user_rule_and_works_with_it(self):
        self.seed([msg(1, sender="news@letters.example.test", labels=("INBOX",))])
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.REVIEW)  # unknown without evidence
        classifier.add_rule(self.index, ACCT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0,
                            domain="letters.example.test")
        self.assertIn("CLASSIFICATION_STALE", self.decide()[0]["m1"].codes)  # rules changed -> must reclassify first
        classifier.run(self.index, ACCT, persist=True)
        d = self.decide()[0]["m1"]
        self.assertEqual((d.outcome, d.evidence[0][:2]), (cc.ELIGIBLE, ("NEWSLETTER", "HIGH")))

    def test_hard_exclusions(self):
        for lab in ("STARRED", "SENT", "DRAFT", "TRASH", "SPAM"):
            d = self.one(msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", lab)))
            self.assertEqual(d.outcome, cc.EXCLUDED, lab)
            self.assertIn(lab, d.codes)
            self.tearDownIndex()

    def tearDownIndex(self):
        self.index.purge(ACCT)

    def test_review_required_conditions_are_never_eligible(self):
        cases = {
            "IMPORTANT_LABEL": msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT")),
            "UNREAD": msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "UNREAD")),
            "USER_LABEL": msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "Label_9")),
            "WEAK_EVIDENCE": msg(1, labels=("INBOX", "CATEGORY_FORUMS")),
            "TYPE_NOT_APPROVED": msg(1, labels=("INBOX", "CATEGORY_UPDATES")),
            "UNKNOWN_TYPE": msg(1, labels=("INBOX",)),
        }
        for code, m in cases.items():
            self.tearDownIndex()
            d = self.one(m)
            self.assertEqual(d.outcome, cc.REVIEW, (code, d.codes))
            self.assertIn(code, d.codes)

    def test_personal_and_financial_types_and_attention_need_review(self):
        self.seed([msg(1, labels=("INBOX", "CATEGORY_PERSONAL")), msg(2, sender="bank@fin.example.test"),
                   msg(3, labels=("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT"))])
        classifier.add_rule(self.index, ACCT, kind="type", value="FINANCIAL", confidence="HIGH", priority=0, domain="fin.example.test")
        classifier.run(self.index, ACCT, persist=True)
        d, _ = self.decide()
        self.assertIn("RISKY_TYPE", d["m2"].codes)
        self.assertEqual(d["m1"].outcome, cc.REVIEW)
        self.assertIn("ATTENTION_SIGNAL", d["m3"].codes)
        self.assertTrue(all(x.outcome == cc.REVIEW for x in d.values()))

    def test_ai_origin_evidence_never_grants_eligibility(self):
        self.seed([msg(1, labels=("INBOX",)), msg(2)])
        with self.index.conn:
            self.index.conn.execute("UPDATE message_class SET source='ai' WHERE message_id='m2' AND kind='type'")
            row = self.index._q("SELECT * FROM message_class WHERE message_id='m1'")[0]
            self.index.conn.execute("DELETE FROM message_class WHERE message_id='m1'")
            self.index.conn.execute("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                    (ACCT, "m1", "type", "PROMOTIONAL", "MEDIUM", "ai", "ai.local", "x",
                                     row["ruleset_hash"], row["msg_scan_id"], row["classified_at"]))
        d, _ = self.decide()
        for mid in ("m1", "m2"):
            self.assertEqual(d[mid].outcome, cc.REVIEW, mid)
            self.assertIn("AI_EVIDENCE", d[mid].codes)

    def test_compatible_and_incompatible_types(self):
        self.seed([msg(1, sender="a@x.example.test"), msg(2, sender="b@y.example.test")])
        classifier.add_rule(self.index, ACCT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=0, domain="x.example.test")
        classifier.add_rule(self.index, ACCT, kind="type", value="PERSONAL", confidence="HIGH", priority=0, domain="y.example.test")
        classifier.add_rule(self.index, ACCT, kind="type", value="SOCIAL", confidence="HIGH", priority=0, domain="y.example.test")
        classifier.run(self.index, ACCT, persist=True)
        d, _ = self.decide()
        self.assertEqual(d["m1"].outcome, cc.ELIGIBLE)  # PROMOTIONAL(MEDIUM) overridden by user NEWSLETTER: compatible
        self.assertEqual(d["m2"].outcome, cc.REVIEW)  # PERSONAL+SOCIAL conflict
        self.assertTrue({"RISKY_TYPE"} & set(d["m2"].codes))

    def test_automated_companion_allowed_but_not_alone(self):
        d = self.one(msg(1, sender="noreply@shop.example.test"))
        self.assertEqual(d.outcome, cc.ELIGIBLE)
        self.tearDownIndex()
        d = self.one(msg(2, sender="noreply@shop.example.test", labels=("INBOX",)))
        self.assertEqual((d.outcome, "TYPE_NOT_APPROVED" in d.codes), (cc.REVIEW, True))

    def test_inbox_requirement_and_age_boundaries(self):
        self.seed([msg(1, labels=("CATEGORY_PROMOTIONS",)), msg(2, ms=NOW - 90 * DAY), msg(3, ms=NOW - 90 * DAY + 1),
                   msg(4, ms=NOW + DAY), msg(5, ms=NOW - 89 * DAY - 1)])
        d, _ = self.decide()
        self.assertEqual((d["m1"].outcome, "NOT_IN_INBOX" in d["m1"].codes), (cc.EXCLUDED, True))
        self.assertEqual(d["m2"].outcome, cc.ELIGIBLE)  # exactly 90 days
        for mid in ("m3", "m4", "m5"):
            self.assertEqual((d[mid].outcome, "TOO_RECENT" in d[mid].codes), (cc.EXCLUDED, True), mid)

    def test_stricter_age_only(self):
        self.seed([msg(1, days=100), msg(2, days=130)])
        d, _ = self.decide(min_age_days=120)
        self.assertEqual((d["m1"].outcome, d["m2"].outcome), (cc.EXCLUDED, cc.ELIGIBLE))
        with self.assertRaises(ValueError):
            cc.evaluate_all(self.index, ACCT, now_ms=NOW, min_age_days=89)

    def test_unsafe_metadata_is_excluded(self):
        self.seed([msg(1), msg(2), msg(3), msg(4)])
        with self.index.conn:
            self.index.conn.execute("UPDATE messages SET thread_id=NULL WHERE id='m1'")
            self.index.conn.execute("UPDATE messages SET internal_ms=NULL WHERE id='m2'")
            self.index.conn.execute("UPDATE messages SET sender=NULL WHERE id='m3'")
            self.index.conn.execute("UPDATE messages SET unread=1 WHERE id='m4'")  # no UNREAD label -> inconsistent
        d, _ = self.decide()
        want = {"m1": "MISSING_THREAD_ID", "m2": "MISSING_DATE", "m3": "MISSING_SENDER", "m4": "UNREAD_FLAG_MISMATCH"}
        for mid, code in want.items():
            self.assertEqual(d[mid].outcome, cc.EXCLUDED, mid)
            self.assertIn(code, d[mid].codes)

    def test_missing_and_stale_classification_are_excluded(self):
        self.seed([msg(1)], classify=False)
        d, _ = self.decide()
        self.assertEqual((d["m1"].outcome, "CLASSIFICATION_MISSING" in d["m1"].codes), (cc.EXCLUDED, True))
        classifier.run(self.index, ACCT, persist=True)
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.ELIGIBLE)
        scan2 = self.index.start_scan(ACCT, "limited", 1)
        self.index.save_batch(ACCT, scan2, [msg(1)])  # rescanned -> classification no longer current
        self.assertIn("CLASSIFICATION_STALE", self.decide()[0]["m1"].codes)


class SummaryTests(Base):
    def test_decisive_and_accompanying_reasons_keep_all_underlying_codes(self):
        self.seed([msg(1, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED", "UNREAD")),  # excluded + review signal
                   msg(2, labels=("INBOX", "CATEGORY_PROMOTIONS", "UNREAD")),  # review only
                   msg(3)])
        d, res = self.decide()
        self.assertEqual((d["m1"].outcome, d["m2"].outcome, d["m3"].outcome), (cc.EXCLUDED, cc.REVIEW, cc.ELIGIBLE))
        self.assertIn("UNREAD", d["m1"].codes)  # underlying codes untouched
        self.assertIn("STARRED", d["m1"].codes)
        sm = res.summary
        self.assertEqual(sm["decisive"][cc.EXCLUDED], {"STARRED": 1})
        self.assertEqual(sm["accompanying"], {"UNREAD": 1, "ATTENTION_SIGNAL": 1})  # starring also raises an attention signal
        self.assertEqual(sm["decisive"][cc.REVIEW], {"UNREAD": 1})
        self.assertEqual(sm["reasons"][cc.EXCLUDED], {"STARRED": 1, "UNREAD": 1, "ATTENTION_SIGNAL": 1})  # legacy view intact


class ThreadTests(Base):
    def test_homogeneous_thread_is_eligible(self):
        self.seed([msg(1, thread="T"), msg(2, thread="T")])
        d, res = self.decide()
        self.assertEqual({d["m1"].outcome, d["m2"].outcome}, {cc.ELIGIBLE})
        self.assertEqual(res.summary["mixed_threads"], 0)

    def test_risky_sibling_blocks_eligibility_without_promoting_anyone(self):
        kinds = {
            "starred": dict(labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED")),
            "important": dict(labels=("INBOX", "CATEGORY_PROMOTIONS", "IMPORTANT")),
            "unread": dict(labels=("INBOX", "CATEGORY_PROMOTIONS", "UNREAD")),
            "sent": dict(labels=("SENT",)),
            "personal-type": dict(labels=("INBOX", "CATEGORY_PERSONAL")),
        }
        for name, kw in kinds.items():
            self.index.purge(ACCT)
            self.seed([msg(1, thread="T"), msg(2, thread="T", **kw)])
            d, res = self.decide()
            self.assertEqual(d["m1"].outcome, cc.REVIEW, name)
            self.assertIn("MIXED_THREAD", d["m1"].codes, name)
            self.assertNotEqual(d["m2"].outcome, cc.ELIGIBLE, name)
            self.assertEqual(res.summary["mixed_threads"], 1)

    def test_protected_unclassified_and_stale_siblings_block(self):
        self.seed([msg(1, thread="T"), msg(2, thread="T", sender="vip@keep.example.test")])
        cleanup_protect.add(self.index, ACCT, domain="keep.example.test")
        d, _ = self.decide()
        self.assertEqual((d["m1"].outcome, d["m2"].outcome), (cc.REVIEW, cc.EXCLUDED))
        self.index.purge(ACCT)
        self.seed([msg(1, thread="T")])
        scan = self.index.start_scan(ACCT, "limited", 1)
        self.index.save_batch(ACCT, scan, [msg(2, thread="T")])  # unclassified sibling
        self.assertIn("MIXED_THREAD", self.decide()[0]["m1"].codes)

    def test_benign_siblings_do_not_block(self):
        self.seed([msg(1, thread="T"), msg(2, thread="T", days=5), msg(3, thread="T", labels=("CATEGORY_PROMOTIONS",))])
        d, _ = self.decide()
        self.assertEqual(d["m1"].outcome, cc.ELIGIBLE)  # recent / already archived promotional siblings are harmless

    def test_partial_index_fails_conservatively(self):
        self.seed([msg(1)], complete=False)
        d, res = self.decide()
        self.assertEqual(d["m1"].outcome, cc.REVIEW)
        self.assertIn("INDEX_PARTIAL", d["m1"].codes)
        self.assertEqual(res.summary["outcomes"][cc.ELIGIBLE], 0)

    def test_threads_are_per_account(self):
        self.seed([msg(1, thread="T")])
        self.seed([msg(2, thread="T", labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))], account=OTHER)
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.ELIGIBLE)


class ProtectionTests(Base):
    def test_protection_by_sender_domain_and_label_incl_name(self):
        self.seed([msg(1, sender="a@p.example.test"), msg(2, sender="b@q.example.test"),
                   msg(3, labels=("INBOX", "CATEGORY_PROMOTIONS", "Label_4")), msg(4), msg(5, sender="a@q.example.test")],
                  labels=[{"id": "Label_4", "name": "Keep", "type": "user"}])
        cleanup_protect.add(self.index, ACCT, sender="a@p.example.test")
        cleanup_protect.add(self.index, ACCT, domain="q.example.test")
        cleanup_protect.add(self.index, ACCT, label="keep")
        d, _ = self.decide()
        for mid in ("m1", "m2", "m3", "m5"):
            self.assertEqual(d[mid].outcome, cc.EXCLUDED, mid)
            self.assertIn("USER_PROTECTED", d[mid].codes)
        self.assertEqual(d["m4"].outcome, cc.ELIGIBLE)

    def test_all_conditions_of_one_rule_must_match_and_rules_or(self):
        self.seed([msg(1, sender="a@p.example.test"), msg(2, sender="b@p.example.test")])
        cleanup_protect.add(self.index, ACCT, sender="a@p.example.test", label="CATEGORY_SOCIAL")
        self.assertEqual({x.outcome for x in self.decide()[0].values()}, {cc.ELIGIBLE})
        cleanup_protect.add(self.index, ACCT, sender="b@p.example.test")
        d, _ = self.decide()
        self.assertEqual((d["m1"].outcome, d["m2"].outcome), (cc.ELIGIBLE, cc.EXCLUDED))

    def test_protection_cannot_be_overridden_by_classification_rules(self):
        self.seed([msg(1, sender="a@p.example.test")])
        cleanup_protect.add(self.index, ACCT, sender="a@p.example.test")
        classifier.add_rule(self.index, ACCT, kind="type", value="NEWSLETTER", confidence="HIGH", priority=1000, sender="a@p.example.test")
        classifier.run(self.index, ACCT, persist=True)
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.EXCLUDED)

    def test_crud_invalidation_and_fingerprint(self):
        self.seed([msg(1, sender="a@p.example.test")])
        _, r0 = self.decide()
        rid = cleanup_protect.add(self.index, ACCT, domain="p.example.test", note="synthetic")
        self.assertEqual(rid, "p1")
        d, r1 = self.decide()
        self.assertEqual(d["m1"].outcome, cc.EXCLUDED)
        self.assertNotEqual(r0.summary["protection_fingerprint"], r1.summary["protection_fingerprint"])
        self.assertTrue(cleanup_protect.set_enabled(self.index, ACCT, rid, False))
        d, r2 = self.decide()
        self.assertEqual(d["m1"].outcome, cc.ELIGIBLE)
        self.assertEqual(r0.summary["protection_fingerprint"], r2.summary["protection_fingerprint"])
        self.assertTrue(cleanup_protect.set_enabled(self.index, ACCT, rid, True))
        self.assertTrue(cleanup_protect.remove(self.index, ACCT, rid))
        self.assertFalse(cleanup_protect.remove(self.index, ACCT, rid))
        self.assertFalse(cleanup_protect.set_enabled(self.index, ACCT, "p9", True))
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.ELIGIBLE)
        self.assertEqual(cleanup_protect.add(self.index, ACCT, domain="p.example.test"), "p1")

    def test_account_isolation(self):
        self.seed([msg(1, sender="a@p.example.test")])
        self.seed([msg(1, sender="a@p.example.test")], account=OTHER)
        cleanup_protect.add(self.index, OTHER, domain="p.example.test")
        self.assertEqual(self.decide()[0]["m1"].outcome, cc.ELIGIBLE)
        self.assertEqual(self.decide(account=OTHER)[0]["m1"].outcome, cc.EXCLUDED)
        self.assertEqual(cleanup_protect.rows(self.index, ACCT), [])

    def test_validation(self):
        bad = [dict(), dict(sender="nope"), dict(sender="*@x.example.test"), dict(domain="*.example.test"),
               dict(domain="a@b.example.test"), dict(label=""), dict(label="a\nb"), dict(domain="p.example.test", note="x\x00")]
        for kw in bad:
            with self.assertRaises(RuleError, msg=kw):
                cleanup_protect.add(self.index, ACCT, **kw)
        self.assertEqual(cleanup_protect.rows(self.index, ACCT), [])

    def test_purge_keeps_protection_rules(self):
        self.seed([msg(1)])
        cleanup_protect.add(self.index, ACCT, domain="p.example.test")
        self.index.purge(ACCT)
        self.assertEqual(len(cleanup_protect.rows(self.index, ACCT)), 1)


class NoSideEffectTests(Base):
    def test_candidate_preview_persists_nothing_and_leaves_m3_untouched(self):
        self.seed([msg(1), msg(2, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED"))])
        before_rows = self.index._q("SELECT * FROM message_class ORDER BY 1,2,3,4")
        before_changes = self.index.conn.total_changes
        self.decide()
        cc.evaluate_all(self.index, ACCT, now_ms=NOW)
        self.assertEqual(self.index.conn.total_changes, before_changes)
        self.assertEqual([tuple(r) for r in self.index._q("SELECT * FROM message_class ORDER BY 1,2,3,4")],
                         [tuple(r) for r in before_rows])
        tables = {r[0] for r in self.index._q("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertFalse({t for t in tables if "candidate" in t})  # candidate results are never stored (plans are M4B)

    def test_empty_account(self):
        _, res = self.decide()
        self.assertEqual(res.summary["total"], 0)
        self.assertIn("Evaluated 0", cleanup_report.candidates_text(res, ACCT))


class MigrationTests(Base):
    def make_db(self, version):
        path = self.tmp / f"v{version}" / "index.sqlite3"
        path.parent.mkdir(mode=0o700, parents=True)
        conn = sqlite3.connect(path)
        script = idx.SCHEMA + (idx.SCHEMA_V2 if version >= 2 else "")
        conn.executescript("BEGIN;" + script + f"PRAGMA user_version = {version};COMMIT;")
        conn.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", (ACCT, "m1", "t1", 1000, 10, "a@x.example.test", 1, 1))
        conn.execute("INSERT INTO message_labels VALUES (?,?,?)", (ACCT, "m1", "INBOX"))
        if version >= 2:
            conn.execute("INSERT INTO class_rules (account,id,kind,value,c_domain,confidence,priority,enabled,created_at) "
                         "VALUES (?,?,?,?,?,?,?,?,?)", (ACCT, "u1", "type", "NEWSLETTER", "x.example.test", "HIGH", 0, 1, "t"))
            conn.execute("INSERT INTO message_class VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (ACCT, "m1", "type", "UNKNOWN", "LOW", "rules", "engine.no-match", "x", "h", 1, "t"))
        conn.commit()
        conn.close()
        return path

    def test_v2_upgrade_preserves_m2_and_m3_data_with_backup(self):
        path = self.make_db(2)
        with idx.Index(str(path)) as index:
            self.assertEqual((index.migrated_from, index.conn.execute("PRAGMA user_version").fetchone()[0]), (2, idx.SCHEMA_VERSION))
            self.assertEqual(index.overview(ACCT)["n"], 1)
            self.assertEqual(index._q("SELECT id FROM class_rules")[0][0], "u1")
            self.assertEqual(index._q("SELECT COUNT(*) FROM message_class")[0][0], 1)
            self.assertEqual(index._q("SELECT COUNT(*) FROM protect_rules")[0][0], 0)
            backup = Path(index.backup_path)
        self.assertIn("pre-m4a-backup", backup.name)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        b = sqlite3.connect(backup)
        self.assertEqual(b.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(b.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='protect_rules'").fetchone()[0], 0)
        b.close()
        with idx.Index(str(path)) as again:  # idempotent: no second migration, no second backup
            self.assertIsNone(again.migrated_from)
        self.assertEqual(len(list(path.parent.glob("*backup*"))), 1)

    def test_v1_jumps_to_latest_in_one_step(self):
        path = self.make_db(1)
        with idx.Index(str(path)) as index:
            self.assertEqual(index.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)
            self.assertEqual(index._q("SELECT COUNT(*) FROM class_rules")[0][0], 0)
            self.assertIn("pre-m3-backup", Path(index.backup_path).name)

    def test_failed_upgrade_leaves_v2_intact(self):
        path = self.make_db(2)
        with mock.patch.object(idx, "SCHEMA_V3", "CREATE TABLE protect_rules (x);CREATE TABLE protect_rules (x);"):
            with self.assertRaises(idx.IndexProblem):
                idx.Index(str(path))
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM message_class").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='protect_rules'").fetchone()[0], 0)
        conn.close()

    def test_corrupt_index_is_a_clean_cli_error(self):
        home = self.tmp / "badhome"
        home.mkdir(mode=0o700)
        (home / "index.sqlite3").write_bytes(b"garbage garbage garbage")
        with mock.patch.dict(os.environ, {config.HOME_ENV: str(home)}):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(["cleanup", "candidates", "--account", ACCT]), 1)
            self.assertIn("corrupt", err.getvalue())
        self.assertEqual((home / "index.sqlite3").read_bytes(), b"garbage garbage garbage")


class CliTests(Base):
    def cli(self, *argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)), \
                mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), \
                mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")):
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        super().setUp()
        self.seed([msg(1, sender=SENDER_SENTINEL), msg(2, labels=("INBOX", "CATEGORY_PROMOTIONS", "STARRED")),
                   msg(3, labels=("INBOX", "CATEGORY_PROMOTIONS", "UNREAD")), msg(4, days=3)],
                  labels=[{"id": "Label_7", "name": LABEL_SENTINEL, "type": "user"}])
        self.a = ("--account", ACCT)

    def test_candidates_summary_and_privacy_defaults(self):
        c, o, _ = self.cli("cleanup", "candidates", *self.a)
        self.assertEqual(c, 0, o)
        for needle in ("EXCLUDED", "REVIEW_REQUIRED", "ELIGIBLE", "RECOMMENDATIONS ONLY", "Gmail was not contacted"):
            self.assertIn(needle, o)
        self.assertIn("Evaluated 4 messages", o)
        for secret in (SENDER_SENTINEL, ACCT, "sentinel.example.invalid", "m1", LABEL_SENTINEL):
            self.assertNotIn(secret, o)
        self.assertIn("<account hidden>", o)
        self.assertNotIn("example.invalid", o)  # not even the domain of the account
        c, o, _ = self.cli("cleanup", "candidates", *self.a, "--show-ids", "--show-senders", "--by-domain")
        self.assertIn("id=m1", o)
        self.assertIn(SENDER_SENTINEL, o)
        self.assertIn("sentinel.example.invalid", o)

    def test_protect_list_hides_every_value_by_default(self):
        self.cli("cleanup", "protect", "add", *self.a, "--sender", SENDER_SENTINEL, "--note", "n1")
        self.cli("cleanup", "protect", "add", *self.a, "--domain", "sentinel.example.invalid")
        self.cli("cleanup", "protect", "add", *self.a, "--label", LABEL_SENTINEL)
        listing = self.cli("cleanup", "protect", "list", *self.a)[1]
        for secret in (SENDER_SENTINEL, "sentinel.example.invalid", LABEL_SENTINEL, "SentinelPriv", "Se...", "se...", "n1", ACCT):
            self.assertNotIn(secret, listing)
        shown = self.cli("cleanup", "protect", "list", *self.a, "--show-values")[1]
        for value in (SENDER_SENTINEL, "sentinel.example.invalid", LABEL_SENTINEL):
            self.assertIn(value, shown)

    def test_reason_summaries_separate_decisive_from_accompanying(self):
        o = self.cli("cleanup", "candidates", *self.a)[1]
        self.assertIn("decisive reasons", o)
        self.assertIn("accompanying review signals; NOT the reason for exclusion", o)
        excl = o.split("Why messages were EXCLUDED")[1].split("Also present on excluded")[0]
        acc = o.split("Also present on excluded")[1].split("Why messages need REVIEW")[0]
        self.assertIn("STARRED", excl)
        self.assertIn("TOO_RECENT", excl)
        self.assertNotIn("UNREAD", excl)  # review-type signals never listed as decisive exclusion reasons
        self.assertNotIn("STARRED", acc)

    def test_protect_remove_without_terminal_input_is_cancelled_not_a_traceback(self):
        self.cli("cleanup", "protect", "add", *self.a, "--domain", "shop.example.test")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("builtins.input", side_effect=EOFError):
            self.assertEqual(cli.main(["cleanup", "protect", "remove", "p1", *self.a]), 1)
        self.assertIn("cancelled", err.getvalue())
        self.assertEqual(len(cleanup_protect.rows(self.index, ACCT)), 1)

    def test_review_view_is_informational(self):
        c, o, _ = self.cli("cleanup", "candidates", *self.a, "--review")
        self.assertEqual(c, 0)
        self.assertIn("NOT actionable", o)
        self.assertIn("UNREAD", o)
        self.assertEqual(self.cli("cleanup", "candidates", *self.a, "--min-age-days", "30")[0], 1)
        self.assertEqual(self.cli("cleanup", "candidates", *self.a, "--limit", "-1")[0], 1)
        self.assertEqual(self.cli("cleanup", "candidates", *self.a, "--limit", "0")[0], 0)

    def test_protect_flow_changes_output(self):
        before = self.cli("cleanup", "candidates", *self.a)[1]
        c, o, _ = self.cli("cleanup", "protect", "add", *self.a, "--domain", "shop.example.test", "--note", "keep")
        self.assertEqual(c, 0, o)
        after = self.cli("cleanup", "candidates", *self.a)[1]
        self.assertNotEqual(before, after)
        self.assertIn("1 active protection rule", after)
        listing = self.cli("cleanup", "protect", "list", *self.a)[1]
        self.assertIn("p1", listing)
        self.assertIn("values are hidden", listing)
        self.assertNotIn("shop.example.test", listing)
        self.assertNotIn("example.invalid", listing)
        self.assertIn("<hidden>", listing)
        self.assertIn("shop.example.test", self.cli("cleanup", "protect", "list", *self.a, "--show-values")[1])
        self.assertEqual(self.cli("cleanup", "protect", "disable", "p1", *self.a)[0], 0)
        self.assertIn("OFF", self.cli("cleanup", "protect", "list", *self.a)[1])
        self.assertEqual(self.cli("cleanup", "protect", "enable", "p1", *self.a)[0], 0)
        self.assertEqual(self.cli("cleanup", "protect", "remove", "p1", *self.a, stdin="n")[0], 1)
        self.assertEqual(self.cli("cleanup", "protect", "remove", "p1", "--yes", *self.a)[0], 0)
        self.assertEqual(self.cli("cleanup", "protect", "remove", "p1", "--yes", *self.a)[0], 1)
        self.assertEqual(self.cli("cleanup", "protect", "enable", "p9", *self.a)[0], 1)
        self.assertEqual(self.cli("cleanup", "protect", "add", *self.a)[0], 1)
        self.assertEqual(self.cli("cleanup", "protect", "add", *self.a, "--domain", "*.example.test")[0], 1)

    def test_no_gmail_keychain_or_network_and_nothing_persisted(self):
        before = self.index.conn.total_changes
        for argv in (("candidates",), ("candidates", "--review"), ("protect", "list")):
            self.assertEqual(self.cli("cleanup", *argv, *self.a)[0], 0, argv)  # bombs inside self.cli() prove it
        class NoToken:
            def load(self):
                return None
        with mock.patch.object(cli, "_store", return_value=NoToken()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["cleanup", "candidates"]), 1)  # without --account the stored login is the only source
        self.assertEqual(self.index.conn.total_changes, before)

    def test_no_missing_index(self):
        home = self.tmp / "empty"
        with mock.patch.dict(os.environ, {config.HOME_ENV: str(home)}):
            self.assertEqual(self.cli("cleanup", "candidates", *self.a)[0], 1)


class SourceGuards(unittest.TestCase):
    MODULES = ("cleanup_candidates.py", "cleanup_protect.py", "cleanup_report.py")

    def test_modules_have_no_gmail_network_or_write_capability(self):
        for name in self.MODULES:
            text = (SRC / "gmail_intelligence" / name).read_text()
            for banned in ("googleapiclient", "google.oauth2", "from gmail_intelligence import gmail", "keystore", "oauth",
                           "urllib", "socket", "requests", "subprocess", "gmail.modify", "ai_http"):
                self.assertNotIn(banned, text, (name, banned))
            self.assertIsNone(re.search(r"\b(eval|exec|compile|__import__)\(", text), name)
            self.assertIsNone(re.search(r"\.(send|modify|batchModify|trash|untrash|delete|drafts)\(", text), name)
            self.assertNotRegex(text, r"execute\(\s*f[\"']")

    def test_write_scope_is_not_requested_anywhere(self):
        # M4C-B1: the write scope is defined in exactly ONE module (oauth_write.py) and nowhere else.
        offenders = [p.name for p in SRC.rglob("*.py") if p.name != "oauth_write.py"
                     and re.search(r"auth/gmail\.(modify|compose|send|insert|labels|settings)|mail\.google\.com", p.read_text())]
        self.assertEqual(offenders, [])
        from gmail_intelligence import oauth
        self.assertEqual(sorted(oauth.EXPECTED_SCOPES), ["https://www.googleapis.com/auth/gmail.readonly"])


if __name__ == "__main__":
    unittest.main()
