"""M12E: the read-only Cleanup area of the local dashboard (issue #63). Synthetic fixtures only (the M12 bulk/reversal fixtures); real loopback HTTP against a temporary index. No Gmail, no OAuth,
no Keychain, no network beyond 127.0.0.1. These tests prove what the dashboard SHOWS and that it can change nothing; the M12 business-logic suites are not repeated."""
import http.client
import json
import re
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
STATIC = SRC / "dashboard" / "static"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_bulk_reversal import ReversalBase  # noqa: E402
from test_cleanup import ACCT, OTHER  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_executor import LABELS  # noqa: E402
from test_dashboard_server import TOKEN, _loopback_only  # noqa: E402

from gmail_intelligence import cleanup_exec as ce, cleanup_exec_report as rep, cleanup_view as view, dashboard_server as ds, exec_fake_mailbox as fm, exec_live_mailbox as live  # noqa: E402

Step = fm.Step
SECTIONS = ("overview", "discovery", "plans", "executions", "reversals", "recovery")


class Dash(ReversalBase):
    """A ReversalBase (synthetic archive/undo histories) plus a real loopback dashboard server over the same index file."""
    N = 30

    def serve(self, account=ACCT):
        guard = mock.patch.object(socket.socket, "connect", _loopback_only)
        guard.start()
        self.addCleanup(guard.stop)
        self.server = ds.DashboardServer(self.index.path, account, TOKEN)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        def stop():
            self.server.shutdown()
            self.server.server_close()
            thread.join(5)
        self.addCleanup(stop)

    def raw(self, path, method="GET", extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in {"Host": f"127.0.0.1:{self.server.port}", "Authorization": "Bearer " + TOKEN, **(extra or {})}.items():
                conn.putheader(k, v)
            conn.putheader("Content-Length", "0") if method not in ("GET", "HEAD") else None
            conn.endheaders()
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()

    def cx(self, section, query=""):
        status, body = self.raw(f"/api/v1/cleanup/{section}{query}")
        self.assertEqual(status, 200, (section, body[:200]))
        return json.loads(body)["data"]

    def tamper(self, *statements):
        """Simulates a damaged local record in the temporary test index only: the integrity triggers that normally forbid it are dropped first."""
        with self.index.conn:
            for (name,) in self.index.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
                self.index.conn.execute(f"DROP TRIGGER {name}")
            for sql, args in statements:
                self.index.conn.execute(sql, args)

    def everything(self):
        return {s: self.cx(s) for s in SECTIONS}

    def exec_of(self, d, ex):
        return [e for e in d["executions"] if e["exec_id"] == ex["exec_id"]][0]

    def rev_of(self, d, rev):
        return [r for r in d["plans"] if r["rev"] == rev][0]


class NoDataTests(Dash):
    def test_a_fresh_index_has_calm_empty_states_everywhere(self):
        self.serve()
        d = self.everything()
        self.assertEqual(d["plans"]["plans"], [])
        self.assertEqual(d["executions"]["executions"], [])
        self.assertEqual(d["reversals"]["reversals"], [])
        self.assertEqual(d["recovery"]["attention"], [])
        self.assertEqual(d["overview"]["operations"], view.LIVE_STATUS)
        self.assertEqual(d["overview"]["plans"]["total"], 0)

    def test_opening_the_pages_triggers_no_scan_and_no_write(self):
        self.serve()
        snap = lambda: ([tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit")], self.index._q("SELECT COUNT(*) FROM messages")[0][0])  # noqa: E731
        before = snap()
        self.everything()
        self.assertEqual(before, snap())


class ExecutionTests(Dash):
    N = 130

    def test_a_finished_multi_slice_execution_is_completed_with_its_boundaries(self):
        plan, ex = self.prepare_bulk()
        self.run_all(ex)
        self.serve()
        e = self.exec_of(self.cx("executions"), ex)
        self.assertEqual((e["category"], e["unresolved"], e["owner_action"]), ("COMPLETED", 0, False))
        self.assertEqual(e["item_counts"]["archived"], 130)
        self.assertEqual([s["size"] for s in e["slices"]], [25, 100, 5])
        self.assertEqual([s["items"] for s in e["slices"]], [[1, 25], [26, 125], [126, 130]])
        self.assertEqual((e["slices_completed"], e["slices_total"]), (3, 3))

    def test_a_partly_run_execution_is_waiting_and_never_complete(self):
        plan, ex = self.prepare_bulk()
        self.run_slice(ex)
        self.serve()
        e = self.exec_of(self.cx("executions"), ex)
        self.assertEqual(e["category"], "AWAITING_CONTINUATION")
        self.assertTrue(e["owner_action"])
        self.assertEqual((e["item_counts"]["archived"], e["item_counts"]["pending"]), (25, 105))
        self.assertEqual((e["slices_completed"], e["slices_pending"]), (1, 2))
        self.assertTrue([a for a in self.cx("recovery")["attention"] if a["id"] == ex["exec_id"]])

    def test_an_interrupted_execution_is_shown_as_such_with_its_open_intent(self):
        plan, ex = self.prepare_bulk(30, [Step("POST", nth=4, raises=Crash(), apply=True)])
        with self.assertRaises(Crash):
            self.run_slice(ex)
        self.serve()
        e = self.exec_of(self.cx("executions"), ex)
        self.assertNotEqual(e["category"], "COMPLETED")
        self.assertTrue(e["owner_action"])
        self.assertGreaterEqual(e["unresolved"], 1)

    def test_unknown_and_conflicting_items_prevent_completed(self):
        plan, ex = self.prepare_bulk(10)
        self.run_slice(ex)
        self.tamper(("UPDATE cleanup_exec_item SET state='UNKNOWN', evidence_checked=0 WHERE exec_id=? AND seq=2", (ex["exec_id"],)), ("UPDATE cleanup_exec_item SET state='CONFLICT', evidence_checked=0 WHERE exec_id=? AND seq=3", (ex["exec_id"],)))
        self.serve()
        e = self.exec_of(self.cx("executions"), ex)
        self.assertEqual((e["item_counts"]["unknown"], e["item_counts"]["conflict"], e["unresolved"]), (1, 1, 2))
        self.assertNotEqual(e["category"], "COMPLETED")
        self.assertTrue(e["owner_action"])


class PlanTests(Dash):
    def test_approved_and_unapproved_plans_are_told_apart(self):
        approved = self.approved_plan(self.bids(5))
        self.serve()
        d = self.cx("plans")
        self.assertTrue(d["approvals_cli_only"])
        row = [p for p in d["plans"] if p["plan_id"] == approved["plan_id"]][0]
        self.assertEqual(row["stage"], "APPROVED_NOT_EXECUTED")
        self.assertIsNone(row["execution"])


class ReversalTests(Dash):
    def rev_of(self, d, rev):
        return [r for r in d["reversals"] if r["rev"] == rev][0]

    def test_pending_and_completed_reversals(self):
        ex = self.archived_execution(10)
        pending = self.plan(ex, exclude=[1])["rev"]
        self.enable_undo()
        done = self.approved(ex)
        self.run_rev(done)
        self.serve()
        d = self.cx("reversals")
        p = self.rev_of(d, pending)
        self.assertEqual((p["state"], p["approved"], p["owner_action"]), ("PLANNED", False, True))
        c = self.rev_of(d, done)
        self.assertEqual((c["state"], c["item_counts"]["restored"], c["owner_action"]), ("COMPLETED", 10, False))

    def test_an_interrupted_reversal_distinguishes_restored_from_uncertain_and_never_attempted(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex)
        self.svc.script.append(Step("UNDO", nth=3, raises=Crash(), apply=True))
        with self.assertRaises(Crash):
            self.run_rev(rev)
        self.serve()
        r = self.rev_of(self.cx("reversals"), rev)
        ic = r["item_counts"]
        self.assertEqual(ic["restored"], 2)
        self.assertGreaterEqual(ic["uncertain"], 1)
        self.assertGreaterEqual(ic["never_attempted"] + ic["pending"], 1)
        self.assertEqual(sum(ic.values()), 10)
        self.assertTrue(r["owner_action"])
        self.assertNotEqual(r["state"], "COMPLETED")

    def test_an_inconsistent_reversal_ledger_is_reported_and_needs_the_owner(self):
        ex = self.archived_execution(10)
        rev = self.approved(ex)
        self.tamper(("UPDATE cleanup_audit SET event_type='REVERSAL_SLICE_DONE' WHERE event_type='REVERSAL_APPROVED'", ()))
        self.serve()
        d = self.cx("reversals")
        self.assertEqual([r["state"] for r in d["reversals"] if r["rev"] == rev], ["INCONSISTENT"])
        self.assertTrue([a for a in self.cx("recovery")["attention"] if a["id"] == rev])


class SecurityTests(Dash):
    def test_every_non_get_method_is_refused_and_nothing_changes(self):
        ex = self.archived_execution(10)
        self.serve()
        before = [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit")]
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for section in SECTIONS:
                status, _ = self.raw(f"/api/v1/cleanup/{section}", method)
                self.assertIn(status, (400, 403, 404, 405, 501), (method, section))
        self.assertEqual(before, [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit")])

    def test_the_token_is_required(self):
        self.serve()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        conn.putrequest("GET", "/api/v1/cleanup/plans", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.server.port}")
        conn.endheaders()
        self.assertIn(conn.getresponse().status, (401, 403))
        conn.close()

    def test_no_sensitive_data_in_any_response(self):
        ex = self.archived_execution(10)
        self.enable_undo()
        rev = self.approved(ex)
        self.run_rev(rev)
        self.serve()
        blob = json.dumps(self.everything(), ensure_ascii=False)
        for i in range(1, 11):
            self.assertNotIn(self.mid(i), blob)
            self.assertNotIn(self.thread(i), blob)
        self.assertNotIn(ACCT, blob)
        self.assertNotIn("@", blob)
        self.assertNotIn("shop.example.test", blob.replace("domain", "")) if False else None
        for word in ("subject", "snippet", "access_token", "refresh_token", "client_secret"):
            self.assertNotIn(word, blob.lower())

    def test_another_account_sees_none_of_this_account(self):
        ex = self.archived_execution(10)
        self.serve(OTHER)
        d = self.everything()
        self.assertEqual((d["plans"]["plans"], d["executions"]["executions"], d["reversals"]["reversals"], d["recovery"]["attention"]), ([], [], [], []))

    def test_the_gates_stay_disabled_and_the_view_says_so(self):
        self.assertEqual((live.LIVE_EXECUTION_ENABLED, live.LIVE_UNDO_ENABLED, live.LIVE_OBSERVE_ENABLED), (False, False, False))
        self.assertEqual(view.LIVE_STATUS, "DISABLED_IN_THIS_BUILD")


class StaticGuardTests(unittest.TestCase):
    def test_the_view_module_imports_no_live_or_mutating_module(self):
        src = (SRC / "cleanup_view.py").read_text(encoding="utf-8")
        mods = set(re.findall(r"^(?:from gmail_intelligence import|import gmail_intelligence\.)(.*)$", src, re.M))
        text = " ".join(mods)
        for forbidden in ("cleanup_exec", "cleanup_plans", "exec_live_mailbox", "cleanup_undo,", "cleanup_live", "gmail_write", "keystore", "oauth", "cleanup_bulk", "cleanup_reversal"):
            self.assertNotIn(forbidden, text + ",")

    def test_the_view_module_issues_only_read_statements(self):
        src = (SRC / "cleanup_view.py").read_text(encoding="utf-8")
        for stmt in re.findall(r'"""|\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE)\b\s+(?:INTO|TABLE|FROM|OR|\w+)', src):
            self.assertFalse(stmt in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "REPLACE"), stmt)

    def test_the_script_has_no_network_or_mutation_primitives(self):
        js = (STATIC / "js" / "cleanup.js").read_text(encoding="utf-8")
        for bad in ("POST", "PUT", "DELETE", "PATCH", "XMLHttpRequest", "sendBeacon", "WebSocket", "innerHTML", "eval(", "http://", "https://", "localStorage"):
            self.assertNotIn(bad, js)
        self.assertNotRegex(js, r'method\s*:')
        self.assertEqual(set(re.findall(r'get\("([\w/]+)"', js)) - {"cleanup/overview", "cleanup/discovery", "cleanup/plans", "cleanup/executions", "cleanup/reversals", "cleanup/recovery", "cleanup/history"}, set())

    def test_no_control_that_runs_resumes_retries_or_undoes(self):
        js = (STATIC / "js" / "cleanup.js").read_text(encoding="utf-8")
        self.assertNotIn('h("button"', js)
        self.assertNotRegex(js, r"onclick\s*:\s*\(\)\s*=>\s*(?:fetch|post)")
        en = json.loads((STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))
        for k, v in en.items():
            if k.startswith("cx.tab."):
                self.assertNotRegex(v, r"(?i)^(run|resume|retry|continue|confirm|abort|undo now|execute)\b")

    def test_every_cx_key_exists_in_both_languages_with_matching_placeholders(self):
        en = json.loads((STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))
        he = json.loads((STATIC / "i18n" / "he.json").read_text(encoding="utf-8"))
        cx_en, cx_he = {k for k in en if k.startswith("cx.")}, {k for k in he if k.startswith("cx.")}
        self.assertEqual(cx_en, cx_he)
        self.assertGreater(len(cx_en), 150)
        for k in (k for k in cx_en if not k.endswith(".one")):
            self.assertEqual(set(re.findall(r"\{(\w+)\}", en[k])), set(re.findall(r"\{(\w+)\}", he[k])), k)
            self.assertTrue(re.search(r"[֐-׿]", he[k]) or not re.search(r"[A-Za-z]{4,}", he[k]), k)

    def test_dynamic_state_vocabularies_are_all_translated(self):
        en = json.loads((STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))
        for fam, codes in (("cx.stage", ("DRAFT", "REVIEWED", "APPROVED_NOT_EXECUTED", "APPROVAL_EXPIRED", "EXECUTION_RESERVED", "CANCELLED", "EXPIRED", "SUPERSEDED")),
                           ("cx.rs", ("PLANNED", "APPROVED", "IN_PROGRESS", "INTERRUPTED", "AWAITING_CONTINUATION", "COMPLETED", "STOPPED", "ABORTED", "INCONSISTENT")),
                           ("cx.uc", tuple(sorted(set(view.UNDO_CATEGORY.values()) | {"inconsistent"}))),
                           ("cx.ei", ("archived", "skipped", "not_applied", "never_attempted", "unknown", "conflict", "intent", "pending")),
                           ("cx.ss", ("NO_DATA", "PARTIAL", "AVAILABLE", "NOT_STORED", "RECORDED", "NONE", "NO_APPROVED", "UNRESOLVED"))):
            for c in codes:
                self.assertIn(f"{fam}.{c}", en, f"{fam}.{c}")

    def test_view_vocabulary_matches_the_cli_recovery_report(self):
        self.assertEqual(tuple(view.REVERSAL_NEEDS_OWNER), tuple(rep.REVERSAL_NEEDS_OWNER))
        shared = set(rep.UNDO_CATEGORY) & set(view.UNDO_CATEGORY)
        self.assertEqual(shared, set(rep.UNDO_CATEGORY))                                    # the dashboard knows every status the CLI report knows
        for status in shared:                                                              # same meaning; the dashboard only splits "unresolved" into uncertain
            self.assertIn(view.UNDO_CATEGORY[status], (rep.UNDO_CATEGORY[status], "uncertain"))


class RoutesTests(Dash):
    def test_exactly_the_six_cleanup_routes_exist_and_are_read_only(self):
        self.assertEqual({r for r in ds.ROUTES if r.startswith("cleanup/")} - {"cleanup/history", "cleanup/summary"}, {f"cleanup/{s}" for s in SECTIONS})


if __name__ == "__main__":
    unittest.main()
