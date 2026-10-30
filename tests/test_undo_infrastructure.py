"""M12C.3 (issues #61, #41): the complete archive-undo infrastructure, DISABLED in this build. Synthetic data, a fake Gmail wire and mocked credentials only: no Gmail, no OAuth, no Keychain,
no network. Every live gate is patched on for the duration of one test and nothing else.

Covers: the exact write-policy allowlist, archive/undo capability separation, both live gates, unauthorized and disabled operations failing closed, the real adapter + policy over the fake wire,
context-bound observations, drift refusal, success, timeout/ambiguity, interruption, reconciliation without mutation, duplicates and expiry, append-only audit, read-only visibility and the CLI."""
import ast
import contextlib
import io
import json
import re
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_write_transport as TWT  # noqa: E402
from test_cleanup import ACCT  # noqa: E402
from test_cleanup_batch import Crash  # noqa: E402
from test_cleanup_executor import AFTER, HEX, LABELS, StepClock, THREADS, gerr  # noqa: E402
from test_cleanup_recovery import UndoBase  # noqa: E402

from gmail_intelligence import cleanup_audit as audit, cleanup_exec as ce, cleanup_exec_report as rep, cleanup_executor as cx, cleanup_live as cl, cleanup_plans as cp  # noqa: E402
from gmail_intelligence import cleanup_recovery as cr, cleanup_undo as cu, cli, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw, gmail_write_policy as pol  # noqa: E402
from gmail_intelligence import index as idx, keystore_write, undo_cli  # noqa: E402

Step = fm.Step
H = {"content-type": "application/json"}


class PolicyTests(unittest.TestCase):
    def test_exactly_two_fixed_modify_bodies_are_allowed_and_nothing_else(self):
        self.assertEqual(pol.check_request("POST", TWT.MODIFY, H, pol.MODIFY_BODY), "MESSAGE_MODIFY")
        self.assertEqual(pol.check_request("POST", TWT.MODIFY, H, pol.UNDO_BODY), "MESSAGE_MODIFY_UNDO")
        self.assertEqual(pol.UNDO_BODY, b'{"addLabelIds":["INBOX"]}')
        bad = (b'{"addLabelIds":["INBOX","UNREAD"]}', b'{"addLabelIds":["INBOX","TRASH"]}', b'{"addLabelIds":["TRASH"]}', b'{"addLabelIds":["inbox"]}', b'{"addLabelIds":[]}',
               b'{"addLabelIds":"INBOX"}', b'{"addLabelIds":["INBOX"],"removeLabelIds":["INBOX"]}', b'{"removeLabelIds":["INBOX"],"addLabelIds":["INBOX"]}',
               b'{"addLabelIds":["INBOX"],"x":1}', b'{"addLabelIds": ["INBOX"]}', b'{"addLabelIds":["INBOX"]}\n', b' {"addLabelIds":["INBOX"]}', b'{"addLabelIds":["\\u0049NBOX"]}',
               b'{"addLabelIds":["INBOX"],"addLabelIds":["INBOX"]}', b'[{"addLabelIds":["INBOX"]}]', b'{"addLabelIds":["INBOX"]}' * 2, bytearray(pol.UNDO_BODY), pol.UNDO_BODY.decode(),
               b"", None, b"{}")
        for body in bad:
            with self.assertRaises(pol.Denied, msg=body):
                pol.check_request("POST", TWT.MODIFY, H, body)

    def test_no_new_route_method_header_or_endpoint_appeared(self):
        self.assertEqual([(k, m) for k, m, _ in pol._ROUTES], [("PROFILE", "GET"), ("MESSAGE_GET", "GET"), ("THREAD_GET", "GET"), ("MESSAGE_MODIFY", "POST")])
        for method, url, body in (("GET", TWT.MODIFY, None), ("PUT", TWT.MODIFY, pol.UNDO_BODY), ("DELETE", TWT.MODIFY, None), ("POST", f"{TWT.B}/messages/{TWT.MID}/trash", b""),
                                  ("POST", f"{TWT.B}/messages/{TWT.MID}/untrash", b""), ("POST", f"{TWT.B}/messages/batchModify", pol.UNDO_BODY),
                                  ("POST", f"{TWT.B}/messages/send", pol.UNDO_BODY), ("POST", f"{TWT.B}/drafts", pol.UNDO_BODY), ("POST", f"{TWT.B}/messages/{TWT.MID}", pol.UNDO_BODY),
                                  ("POST", f"{TWT.B}/threads/{TWT.TID}/modify", pol.UNDO_BODY), ("POST", TWT.MODIFY.replace("?fields=id,threadId,labelIds", ""), pol.UNDO_BODY),
                                  ("POST", TWT.MODIFY.replace("labelIds", "labelIds,snippet"), pol.UNDO_BODY)):
            with self.assertRaises(pol.Denied, msg=(method, url)):
                pol.check_request(method, url, H, body)
        with self.assertRaises(pol.Denied):                      # the undo body is not accepted on a read request either
            pol.check_request("GET", TWT.PROFILE, None, pol.UNDO_BODY)
        self.assertEqual(pol.MUTATIONS, ("MESSAGE_MODIFY", "MESSAGE_MODIFY_UNDO"))


class CapabilityTests(unittest.TestCase):
    def adapter(self, net, caps):
        a = gw.ArchiveAdapter(gw._Transport(TWT.WCreds(), net, capabilities=caps), TWT.ACCOUNT)
        a._verified = True
        return a

    def test_a_transport_holds_exactly_the_capabilities_it_was_built_with(self):
        for bad in ((), ("DELETE",), ("ARCHIVE", "TRASH"), ("",)):
            with self.assertRaises(ValueError):
                gw._Transport(TWT.WCreds(), None, capabilities=bad)
        self.assertEqual(gw._Transport(TWT.WCreds(), None)._caps, frozenset({"ARCHIVE"}))   # the default stays archive-only

    def test_an_archive_adapter_cannot_undo_and_an_undo_adapter_cannot_archive_before_any_dispatch(self):
        net = TWT.Net()
        for caps, call in ((("ARCHIVE",), lambda a: a.restore_inbox(TWT.MID)), (("UNDO",), lambda a: a.archive_message(TWT.MID))):
            with self.assertRaises(pol.Denied) as ctx:
                call(self.adapter(net, caps))
            self.assertEqual(ctx.exception.code, "DENIED_CAPABILITY")
            self.assertTrue(gw.definitely_not_dispatched(ctx.exception))
        for caps, body in ((("ARCHIVE",), pol.UNDO_BODY), (("UNDO",), pol.MODIFY_BODY)):   # the transport itself refuses, even bypassing the adapter methods
            with self.assertRaises(pol.Denied) as ctx:
                self.adapter(net, caps)._t.perform("POST", TWT.MODIFY, body)
            self.assertEqual(ctx.exception.code, "DENIED_CAPABILITY")
        self.assertEqual((net.opened, net.log), (0, []))

    def test_the_undo_adapter_sends_one_post_with_the_exact_undo_body(self):
        net = TWT.Net(TWT.ok(id=TWT.MID, threadId=TWT.TID, labelIds=["INBOX", "Label_9"]))
        res = self.adapter(net, ("UNDO",)).restore_inbox(TWT.MID)
        self.assertEqual(res.label_ids, ("INBOX", "Label_9"))
        self.assertEqual((net.opened, len(net.log)), (1, 1))
        sent = net.log[0]
        self.assertEqual((sent["method"], sent["body"], sent["target"].split("?")[0].endswith("/modify")), ("POST", pol.UNDO_BODY, True))

    def test_the_undo_adapter_refuses_before_the_account_is_verified(self):
        net = TWT.Net()
        a = gw.ArchiveAdapter(gw._Transport(TWT.WCreds(), net, capabilities=("UNDO",)), TWT.ACCOUNT)
        with self.assertRaises(gw.AccountNotVerified) as ctx:
            a.restore_inbox(TWT.MID)
        self.assertTrue(gw.definitely_not_dispatched(ctx.exception))
        self.assertEqual(net.opened, 0)


class LiveUndoBase(UndoBase):
    def enable_undo(self):
        """Switch the live-UNDO gate on for THIS test only (the archive gate stays off) and put the controlled clock under the live mailbox and the adapter."""
        for target, name, value in ((live, "LIVE_UNDO_ENABLED", True), (live, "_utcnow", self.uc), (gw, "_utcnow", self.uc)):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def live_undo(self, mb, script=(), state=None):
        st = state if state is not None else {m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}
        svc = fm._Service(ACCT, st, tuple(script))
        factory = fm._Factory(svc)
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, factory, capabilities=("UNDO",)), ACCT, _clock=self.uc)
        return live._wrap_undo(adapter, ACCT, factory), svc

    def current(self, svc):
        return {m: (t, list(l)) for m, (t, l) in svc.messages.items()}

    def prepared(self, script=(), seq=1):
        ex, mb = self.archived()
        self.enable_undo()
        lm, svc = self.live_undo(mb, script)
        self.authorize(ex, seq)
        return ex, mb, lm, svc

    def rows(self):
        return [tuple(r) for r in self.index._q("SELECT * FROM cleanup_audit ORDER BY seq")]


class GateTests(LiveUndoBase):
    def test_both_gates_are_false_source_constants_and_no_environment_or_option_changes_them(self):
        self.assertIs(live.LIVE_EXECUTION_ENABLED, False)
        self.assertIs(live.LIVE_UNDO_ENABLED, False)
        assigned = []
        for path in SRC.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []):
                    if (isinstance(t, ast.Name) and t.id in ("LIVE_UNDO_ENABLED", "LIVE_EXECUTION_ENABLED")) or (isinstance(t, ast.Attribute) and t.attr in ("LIVE_UNDO_ENABLED", "LIVE_EXECUTION_ENABLED")):
                        assigned.append((path.name, t.id if isinstance(t, ast.Name) else t.attr, getattr(node.value, "value", None)))
        self.assertEqual(sorted(assigned), [("exec_live_mailbox.py", "LIVE_EXECUTION_ENABLED", False), ("exec_live_mailbox.py", "LIVE_UNDO_ENABLED", False)])
        for name in ("exec_live_mailbox.py", "cleanup_live.py", "undo_cli.py", "cleanup_undo.py"):
            self.assertNotRegex((SRC / name).read_text(), r"os\.environ|getenv|environ\[")

    def test_the_gates_are_independent(self):
        ex, mb = self.archived()
        self.enable_undo()
        with mock.patch.object(live, "LIVE_EXECUTION_ENABLED", False):
            lm, svc = self.live_undo(mb)                       # undo works with the archive gate off
        self.authorize(ex, 1)
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "RESTORED")
        with mock.patch.object(live, "LIVE_EXECUTION_ENABLED", True), mock.patch.object(live, "LIVE_UNDO_ENABLED", False):
            with self.assertRaises(live.LiveUndoDisabled):      # archive gate on does NOT enable undo
                self.live_undo(mb)
            with self.assertRaises(live.LiveUndoDisabled):
                lm.restore_inbox(self.mid(2))
            with self.assertRaises(ce.ExecError) as ctx:
                cl.undo_live(self.index, ACCT, ex["exec_id"], 2, lm)
            self.assertEqual(ctx.exception.code, "LIVE_UNDO_DISABLED")

    def test_a_disabled_or_unauthorized_undo_fails_closed_before_any_request(self):
        ex, mb, lm, svc = self.prepared()
        with mock.patch.object(live, "LIVE_UNDO_ENABLED", False):
            with self.assertRaises(ce.ExecError) as ctx:
                cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
            self.assertEqual(ctx.exception.code, "LIVE_UNDO_DISABLED")
            with self.assertRaises(ce.ExecError) as ctx:
                cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
            self.assertEqual(ctx.exception.code, "LIVE_UNDO_DISABLED")
        with self.assertRaises(ce.ExecError) as ctx:            # enabled, but item 2 was never authorized: the archive approval authorizes nothing here
            cl.undo_live(self.index, ACCT, ex["exec_id"], 2, lm)
        self.assertEqual(ctx.exception.code, "UNDO_NOT_AUTHORIZED")
        self.assertEqual((svc.log, cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), ([], "AUTHORIZED"))

    def test_nothing_is_built_or_read_while_undo_is_disabled(self):
        store = mock.MagicMock()
        with self.assertRaises(live.LiveUndoDisabled):
            live.open_live_undo_mailbox(ACCT, store, "x")
        store.load.assert_not_called()
        ex, mb = self.archived()
        svc = fm._Service(ACCT, {m: (t, list(l)) for m, (t, l) in mb.service.messages.items()}, ())
        adapter = gw.ArchiveAdapter(gw._Transport(svc.creds, fm._Factory(svc), capabilities=("UNDO",)), ACCT)
        with self.assertRaises(live.LiveUndoDisabled):
            live._wrap_undo(adapter, ACCT, fm._Factory(svc))

    def test_each_entry_point_accepts_only_its_own_mailbox_type(self):
        ex, mb, lm, svc = self.prepared()
        self.assertFalse(hasattr(lm, "archive_message"))
        self.assertTrue(live.live_undo_wiring_ok(lm))
        for call in (lambda: cu.undo_item(self.index, ACCT, ex["exec_id"], 1, lm), lambda: cu.reconcile_undo(self.index, ACCT, ex["exec_id"], 1, lm),
                     lambda: cl.undo_live(self.index, ACCT, ex["exec_id"], 1, self.umb(mb)), lambda: cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, self.umb(mb)),
                     lambda: cl.execute_live_batch(self.index, ACCT, ex["exec_id"], self.token, lm), lambda: cl.recover_live(self.index, ACCT, lm)):
            with self.assertRaises(ce.ExecError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, "MAILBOX_NOT_ALLOWED")
        self.assertEqual(svc.log, [])
        archive_box_src = (SRC / "exec_live_mailbox.py").read_text()
        self.assertEqual(archive_box_src.count("def archive_message"), 1)                    # only the archive LiveMailbox has it
        rewired = lm
        object.__getattribute__(rewired, "_adapter")._t._caps = frozenset({"ARCHIVE", "UNDO"})   # a widened transport is no longer an accepted wiring
        self.assertFalse(live.live_undo_wiring_ok(lm))


class EngineTests(LiveUndoBase):
    def test_a_successful_live_undo_restores_only_inbox_through_the_real_adapter_and_policy(self):
        ex, mb, lm, svc = self.prepared()
        history, rows = self.history(), self.rows()
        before = {m: set(l) for m, (t, l) in svc.messages.items()}
        res = cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
        self.assertEqual((res.status, res.mutations, svc.undos(), svc.posts()), ("RESTORED", 1, 1, 0))
        mid = self.mid(1)
        self.assertEqual(svc.messages[mid][1], set(LABELS))                           # INBOX is back and the unrelated label is preserved
        self.assertEqual(svc.messages[self.mid(2)][1], before[self.mid(2)])             # nothing else was touched
        self.assertEqual([k for k, _ in svc.log], ["PROFILE", "GET_MESSAGE", "GET_THREAD", "UNDO", "GET_MESSAGE"])   # preflight, ONE mutation, independent post-read
        self.assertEqual(self.history(), history)                                       # archive history untouched
        self.assertEqual(self.rows()[:len(rows)], rows)                                 # append-only
        self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_AUTHORIZED", "UNDO_INTENT", "UNDO_RESULT"])
        self.assertTrue(audit.verify_chain(self.index, ACCT)[0])

    def test_drift_and_protected_state_are_refused_before_any_mutation(self):
        cases = (("labels changed", lambda f: f.set_labels(self.mid(1), list(AFTER) + ["STARRED"])), ("already back in the inbox", lambda f: f.set_labels(self.mid(1), list(LABELS))),
                 ("a new message joined the thread", lambda f: f.add_message(HEX[6], THREADS[0], ["INBOX"])), ("the message is gone", lambda f: f.remove_message(self.mid(1))))
        for label, change in cases:
            with self.subTest(label):
                self.setUp()
                ex, mb = self.archived()
                self.enable_undo()
                lm, svc = self.live_undo(mb, [Step("GET_MESSAGE", before=change)])
                self.authorize(ex, 1)
                with self.assertRaises(ce.ExecError) as ctx:
                    cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
                self.assertIn(ctx.exception.code, ("UNDO_DRIFT", "UNDO_PREFLIGHT_FAILED"))
                self.assertEqual((svc.undos(), cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), (0, "AUTHORIZED"))
                self.assertNotIn("UNDO_INTENT", [t for t, _ in self.undo_events()])

    def test_ineligible_items_are_refused_without_any_request(self):
        ex, mb = self.archived()
        self.enable_undo()
        lm, svc = self.live_undo(mb)
        with self.assertRaises(ce.ExecError) as ctx:
            cl.undo_live(self.index, ACCT, ex["exec_id"], 99, lm)                     # no such item
        self.assertEqual(ctx.exception.code, "NO_SUCH_ITEM")
        self.assertEqual(svc.log, [])

    def test_ambiguous_outcomes_are_unknown_never_retried_and_reconcile_without_mutation(self):
        cases = ((Step("UNDO", raises=TimeoutError(), apply=True), "TIMEOUT", "RESTORED"), (Step("UNDO", raises=ConnectionResetError(), apply=False), "NETWORK_ERROR", "NOT_RESTORED"),
                 (Step("UNDO", status=503, body=b"x", apply=True), "SERVER_ERROR", "RESTORED"), (Step("UNDO", status=429, body=gerr(429)[1], apply=False), "AMBIGUOUS_RESULT", "NOT_RESTORED"),
                 (Step("UNDO", status=200, body=b"not json", apply=True), "AMBIGUOUS_RESULT", "RESTORED"))
        for step, code, final in cases:
            with self.subTest(step.status or step.raises):
                self.setUp()
                ex, mb, lm, svc = self.prepared([step])
                res = cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
                self.assertEqual((res.status, res.code, res.mutations, svc.undos()), ("UNKNOWN", code, 1, 1))
                for again in (lambda: cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm), lambda: self.authorize(ex, 1)):
                    with self.assertRaises(ce.ExecError):
                        again()                                                         # no automatic retry, no new authorization while UNKNOWN
                self.assertEqual(svc.undos(), 1)
                lm2, svc2 = self.live_undo(mb, state=self.current(svc))
                res2 = cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, lm2)
                self.assertEqual((res2.status, res2.mutations, svc2.undos(), svc2.posts()), (final, 0, 0, 0))   # reads only
                self.assertTrue({k for k, _ in svc2.log} <= {"PROFILE", "GET_MESSAGE"})

    def test_an_http_success_does_not_prove_restoration(self):
        # Gmail "answers 200 with INBOX" but the independent post-read shows the message still archived (or changed): UNKNOWN, never RESTORED
        lying = json.dumps({"id": self.mid_hex(1), "threadId": THREADS[0], "labelIds": sorted(LABELS)}).encode()
        for step in (Step("UNDO", status=200, body=lying, apply=False), Step("GET_MESSAGE", nth=2, before=lambda f: f.set_labels(self.mid_hex(1), list(LABELS) + ["STARRED"]))):
            with self.subTest(step.request):
                self.setUp()
                ex, mb, lm, svc = self.prepared([step])
                res = cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
                self.assertEqual((res.status, svc.undos()), ("UNKNOWN", 1))
                self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "UNKNOWN")

    def mid_hex(self, seq):
        return self.mid(seq)

    def test_no_usable_observation_keeps_unknown_and_a_conflicting_one_is_final(self):
        ex, mb, lm, svc = self.prepared([Step("GET_MESSAGE", nth=2, raises=TimeoutError())])
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "UNKNOWN")
        lm2, svc2 = self.live_undo(mb, [Step("GET_MESSAGE", raises=TimeoutError())], state=self.current(svc))
        with self.assertRaises(ce.ExecError) as ctx:
            cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, lm2)
        self.assertEqual((ctx.exception.code, cu.undo_status(self.index, ACCT, ex["exec_id"], 1)), ("NO_EVIDENCE", "UNKNOWN"))
        st = self.current(svc)
        st[self.mid(1)] = (st[self.mid(1)][0], list(LABELS) + ["STARRED"])             # someone else changed the message meanwhile
        lm3, svc3 = self.live_undo(mb, state=st)
        res = cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, lm3)
        self.assertEqual((res.status, res.mutations, svc3.undos()), ("CONFLICT", 0, 0))
        self.assertEqual(cu.undo_status(self.index, ACCT, ex["exec_id"], 1), "CONFLICT")   # manual owner attention: final, never presented as a restoration

    def test_an_interrupted_undo_is_open_and_resolved_by_observation_only(self):
        ex, mb, lm, svc = self.prepared([Step("UNDO", raises=Crash(), apply=True)])
        with self.assertRaises(Crash):
            cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
        self.assertEqual((cu.undo_status(self.index, ACCT, ex["exec_id"], 1), svc.undos()), ("OPEN", 1))
        self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_AUTHORIZED", "UNDO_INTENT"])   # the durable intent was written first
        lm2, svc2 = self.live_undo(mb, state=self.current(svc))
        with self.assertRaises(ce.ExecError):                   # an open intent blocks any second attempt
            cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm2)
        self.assertEqual(svc2.undos(), 0)
        res = cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 1, lm2)
        self.assertEqual((res.status, res.mutations, svc2.undos()), ("RESTORED", 0, 0))

    def test_observations_are_bound_to_their_phase_and_item(self):
        ex, mb, lm, svc = self.prepared()
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "RESTORED")
        row = dict(ce.get_execution(self.index, ACCT, ex["exec_id"]))
        item = cu._item_by_seq(self.index, ACCT, ex["exec_id"], 1)
        lm.verify_account()
        for context in (ce._context(row, self.mid(1), "POSTREAD", "x"), ce._context(row, self.mid(1), "UNDO_RECONCILE", "0" * 64), ce._context(row, self.mid(2), "UNDO_POSTREAD", "0" * 64)):
            obs = lm.observe(self.mid(1), context=context)
            with self.assertRaises(ce.ExecError) as ctx:
                cu._validated(obs, item, "2000-01-01T00:00:00.000000Z", "a-different-context", ACCT, lm)
            self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")

    def test_duplicates_and_expired_authorizations_change_nothing(self):
        ex, mb, lm, svc = self.prepared()
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "RESTORED")
        for again in (lambda: cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm), lambda: self.authorize(ex, 1)):
            with self.assertRaises(ce.ExecError):
                again()
        self.assertEqual(svc.undos(), 1)
        self.authorize(ex, 2)                                    # item 2: authorized, then too late
        later = StepClock(self.uc.at + cu.UNDO_AUTH_TTL + timedelta(minutes=5))
        with mock.patch.object(live, "_utcnow", later), mock.patch.object(gw, "_utcnow", later):
            lm2, svc2 = self.live_undo(mb)
            with self.assertRaises(ce.ExecError) as ctx:
                cl.undo_live(self.index, ACCT, ex["exec_id"], 2, lm2)
        self.assertEqual((ctx.exception.code, svc2.undos()), ("UNDO_AUTH_EXPIRED", 0))


class VisibilityTests(LiveUndoBase):
    def test_the_recovery_status_reports_every_undo_state_without_gmail_or_identifiers(self):
        ex, mb = self.archived(ids=__import__("test_cleanup_batch").IDS[:3])
        self.enable_undo()
        lm, svc = self.live_undo(mb, [Step("UNDO", nth=2, raises=TimeoutError(), apply=True)])
        before = self.snapshot()
        self.assertEqual(rep.recovery_data(self.index, ACCT, self.uc())["undos"], [])
        for seq in (1, 2):
            self.authorize(ex, seq)
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm).status, "RESTORED")
        self.assertEqual(cl.undo_live(self.index, ACCT, ex["exec_id"], 2, lm).status, "UNKNOWN")
        self.authorize(ex, 3)                                    # authorized, not run
        data = rep.recovery_data(self.index, ACCT, self.uc())
        self.assertEqual({(u["item"], u["status"], u["category"]) for u in data["undos"]},
                         {(1, "RESTORED", "restored"), (2, "UNKNOWN", "unresolved"), (3, "AUTHORIZED", "pending")})
        self.assertTrue(data["needs_owner"])
        text = rep.recovery_text(data)
        for private in (ACCT, "example", "INBOX", *HEX, *THREADS, ex["plan_id"]):
            self.assertNotIn(private, text + json.dumps(data))
        self.assertIn("UNRESOLVED", text)
        self.assertIn("restored (confirmed by a fresh observation)", text)
        self.assertTrue(data["read_only"] and data["gmail_contacted"] is False)
        self.assertEqual((svc.undos(), self.snapshot()[3] > before[3]), (2, True))   # only the undo steps above wrote anything; the status call wrote nothing
        audit_rows = len(self.rows())
        rep.recovery_data(self.index, ACCT, self.uc())
        self.assertEqual(len(self.rows()), audit_rows)
        # a conflict and a settled restoration are visible and no longer "unresolved"
        st = self.current(svc)
        st[self.mid(2)] = (st[self.mid(2)][0], list(LABELS) + ["STARRED"])
        lm2, _ = self.live_undo(mb, state=st)
        self.assertEqual(cl.reconcile_undo_live(self.index, ACCT, ex["exec_id"], 2, lm2).status, "CONFLICT")
        cats = {u["item"]: u["category"] for u in rep.recovery_data(self.index, ACCT, self.uc())["undos"]}
        self.assertEqual((cats[1], cats[2], cats[3]), ("restored", "conflict", "pending"))
        self.assertIn("CONFLICT", rep.recovery_text(rep.recovery_data(self.index, ACCT, self.uc())))

    def test_a_restored_undo_alone_does_not_demand_the_owner(self):
        ex, mb, lm, svc = self.prepared()
        cl.undo_live(self.index, ACCT, ex["exec_id"], 1, lm)
        data = rep.recovery_data(self.index, ACCT, self.uc())
        self.assertFalse(data["needs_owner"])
        self.assertIn("finished undos remain", rep.recovery_text(data))
        # the library report of the M4D recovery engine and the CLI-safe ledger module agree
        self.assertEqual(cr.status_report(self.index, ACCT).undos, ())


class CliTests(LiveUndoBase):
    def run_cmd(self, *argv, typed=(), live_mailbox=None):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(typed)
        now = lambda n=None: n if n is not None else self.uc()  # noqa: E731
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")), mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")),
                   mock.patch.object(cli, "_write_store", side_effect=AssertionError("write Keychain used")), mock.patch.object(cp, "_utc", side_effect=now),
                   mock.patch.object(cli, "_tty_input", side_effect=lambda prompt: next(feed)),
                   mock.patch.object(keystore_write, "WriteTokenStore", mock.MagicMock(name="WriteTokenStore"))]
        if live_mailbox is not None:
            patches.append(mock.patch.object(live, "open_live_undo_mailbox", return_value=live_mailbox))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(["cleanup", "undo", *argv, "--account", ACCT])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_status_and_preview_are_local_and_read_only_and_the_live_commands_refuse_first(self):
        ex, mb = self.archived()
        before = self.snapshot()
        for argv in (("status",), ("status", "--exec-id", ex["exec_id"]), ("status", "--json"), ("preview", ex["exec_id"], "1")):
            code, out, err = self.run_cmd(*argv)
            self.assertEqual((code, err), (0, ""), argv)
            for private in (ACCT, "example", *HEX, *THREADS, ex["plan_id"]):
                self.assertNotIn(private, out)
        self.assertIn("UNDO 1 " + ex["exec_id"], self.run_cmd("preview", ex["exec_id"], "1")[1])
        self.assertIn("DISABLED", self.run_cmd("preview", ex["exec_id"], "1")[1])
        with mock.patch.object(idx, "Index", side_effect=AssertionError("the index must not be opened")):
            for cmd in ("authorize", "run", "reconcile"):
                code, out, err = self.run_cmd(cmd, ex["exec_id"], "1")
                self.assertEqual((code, out, err), (2, undo_cli.DISABLED + "\n", ""), cmd)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.undo_events(), [])

    def test_the_complete_owner_workflow_with_the_gate_enabled_over_the_fake_wire(self):
        ex, mb = self.archived()
        self.enable_undo()
        lm, svc = self.live_undo(mb)
        phrase = self.phrase(ex, 1)
        code, out, err = self.run_cmd("authorize", ex["exec_id"], "1", typed=["wrong phrase"])
        self.assertEqual(code, 1)
        self.assertEqual([t for t, _ in self.undo_events()], ["UNDO_REJECTED"])                  # a wrong phrase authorizes nothing (and is recorded)
        code, out, err = self.run_cmd("authorize", ex["exec_id"], "1", typed=[phrase])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Nothing was changed and Gmail was not contacted", out)
        code, out, err = self.run_cmd("run", ex["exec_id"], "1", live_mailbox=lm)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("undo result: RESTORED", out)
        self.assertEqual((svc.undos(), svc.posts()), (1, 0))
        code, out, err = self.run_cmd("status", "--exec-id", ex["exec_id"])
        self.assertIn("item 1: eligible", out)
        self.assertIn("undo state RESTORED", out)
        code, out, err = self.run_cmd("run", ex["exec_id"], "1", live_mailbox=lm)                 # a second attempt is refused
        self.assertEqual(code, 1)
        self.assertEqual(svc.undos(), 1)
        self.assertNotRegex(out + err, r"Traceback|https?://")

    def test_cli_reconcile_is_read_only_and_ambiguity_is_reported(self):
        ex, mb = self.archived()
        self.enable_undo()
        lm, svc = self.live_undo(mb, [Step("UNDO", raises=TimeoutError(), apply=True)])
        self.run_cmd("authorize", ex["exec_id"], "1", typed=[self.phrase(ex, 1)])
        code, out, err = self.run_cmd("run", ex["exec_id"], "1", live_mailbox=lm)
        self.assertEqual(code, 1)
        self.assertIn("UNKNOWN", out)
        self.assertIn("Nothing is retried", out)
        lm2, svc2 = self.live_undo(mb, state=self.current(svc))
        code, out, err = self.run_cmd("reconcile", ex["exec_id"], "1", live_mailbox=lm2)
        self.assertEqual(code, 0)
        self.assertIn("RESTORED", out)
        self.assertIn("read-only", out)
        self.assertEqual(svc2.undos(), 0)

    def test_bad_input_has_fixed_messages(self):
        ex, mb = self.archived()
        for argv in (("preview", "exec-nope", "1"), ("preview", ex["exec_id"], "99"), ("status", "--exec-id", "exec-nope")):
            code, out, err = self.run_cmd(*argv)
            self.assertEqual((code, out), (1, ""), argv)
            self.assertNotIn("Traceback", err)
        self.assertEqual(self.run_cmd("preview", ex["exec_id"], "x")[0], 2)                  # argparse: the item must be an integer

    def test_the_ordinary_cli_reaches_the_undo_path_only_through_the_gated_entry_module(self):
        src = (SRC / "cli.py").read_text()
        for name in ("cleanup_undo", "cleanup_live", "exec_live_mailbox", "LiveUndoMailbox", "LIVE_UNDO_ENABLED", "open_live_undo_mailbox", "undo_live", "reconcile_undo_live",
                     "authorize_undo", "undo_item", "reconcile_undo", "restore_inbox", "FakeMailbox"):
            self.assertNotIn(name, src)
        self.assertEqual(len(re.findall(r"undo_cli\.dispatch\(", src)), 1)
        body = (SRC / "undo_cli.py").read_text()
        self.assertLess(body.index("live.LIVE_UNDO_ENABLED is not True"), body.index("with_readonly(args, go_status)"))   # the gate is checked before the index is opened


if __name__ == "__main__":
    unittest.main()
