"""Contract tests for M4C-C1: trusted observations, dispatch metadata and their use by the execution state (fake data only).

Everything here is synthetic: fake credentials, a recording fake HTTPS connection, a fake clock and temporary SQLite databases. Sockets are
blocked by the base classes. Tests that must build a TrustedObservation without an adapter use the module-private mint on purpose, to prove
what a FORGED observation does; production code never does that (a static test enforces it).
"""
import ast
import copy
import json
import pickle
import re
import sqlite3
import subprocess
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_exec as TCE  # noqa: E402
import test_write_auth as TWA  # noqa: E402
import test_write_transport as TWT  # noqa: E402
from test_auth import A_TOK, Base as AuthBase  # noqa: E402
from test_cleanup import ACCT, OTHER, msg  # noqa: E402

from gmail_intelligence import cleanup_exec as ce, cleanup_exec_report, cleanup_plans as cp, exec_evidence as ee, gmail_write as gw  # noqa: E402
from gmail_intelligence import gmail_write_policy as pol, index as idx  # noqa: E402

CTX = "c" * 32
HEX = [f"18c0ffee0000{i:04x}" for i in range(1, 6)]
THREADS = [f"28c0ffee0000{i:04x}" for i in range(1, 6)]
NOT_FOUND = (404, json.dumps({"error": {"code": 404, "message": "Requested entity was not found.", "errors": [{"reason": "notFound"}], "status": "NOT_FOUND"}}).encode())


class FakeClock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at


def make_adapter(net, account=ACCT, clock=None, verify=True, creds=None):
    ad = gw.ArchiveAdapter(gw._Transport(creds or TWA.WCreds(), net), account, _clock=clock)
    if verify:
        ad.verify_account()
    return ad


def present_answer(i, labels):
    body = {"id": HEX[i], "threadId": THREADS[i]}
    if labels:  # Gmail omits labelIds when a message has none
        body["labelIds"] = list(labels)
    return TWT.ok(**body)


# ====================================================================== the neutral capability module
class ContractTests(AuthBase):
    def issuer(self):
        return make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT)), clock=lambda: datetime(2027, 1, 1, tzinfo=timezone.utc))._issuer

    def test_a_trusted_observation_cannot_be_built_without_the_private_mint(self):
        issuer = self.issuer()
        kwargs = dict(account=ACCT.lower(), message_id=HEX[0], present=True, labels=(), observed_at=datetime(2027, 1, 1, tzinfo=timezone.utc), context=CTX, issuer=issuer, nonce="n" * 32)
        with self.assertRaises(TypeError):
            ee.TrustedObservation(**kwargs)
        with self.assertRaises(TypeError):
            ee.TrustedObservation(_mint=object(), **kwargs)
        with self.assertRaises(TypeError):
            ee.ObservationIssuer(account=ACCT, clock=lambda: None)
        with self.assertRaises(TypeError):
            ee.ObservationIssuer(_mint=object(), account=ACCT, clock=lambda: None)

    def test_the_type_is_final_immutable_uncopyable_and_leaks_nothing_in_its_repr(self):
        with self.assertRaises(TypeError):
            type("Impostor", (ee.TrustedObservation,), {})
        obs = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(0, ["INBOX"])), clock=lambda: datetime.now(timezone.utc)).observe(HEX[0], context=CTX)
        for name in ("labels", "present", "message_id", "account", "observed_at", "_nonce"):
            with self.assertRaises(AttributeError):
                setattr(obs, name, "x")
        with self.assertRaises(AttributeError):
            del obs.labels
        for bad in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(TypeError):
                bad(obs)
        self.assertEqual((repr(obs), repr(obs._issuer)), ("<TrustedObservation>", "<ObservationIssuer>"))
        self.assertFalse(hasattr(obs, "__dict__"))

    def test_field_rules_for_present_absent_and_malformed_observations(self):
        issuer = self.issuer()
        at = datetime(2027, 1, 1, tzinfo=timezone.utc)

        def build(**over):
            kw = dict(account=ACCT.lower(), message_id=HEX[0], present=True, labels=("INBOX",), observed_at=at, context=CTX, issuer=issuer, nonce="n" * 32)
            kw.update(over)
            return ee.TrustedObservation(_mint=ee._MINT, **kw)
        build()
        build(labels=())  # an explicit empty tuple is a valid PRESENT state
        build(present=False, labels=None)
        for bad in (dict(present=True, labels=None), dict(present=True, labels=["INBOX"]), dict(present=True, labels="INBOX"), dict(present=False, labels=()),
                    dict(present=False, labels=("X",)), dict(labels=(5,)), dict(labels=("",)), dict(labels=("é",)), dict(labels=tuple("L%d" % i for i in range(101))),
                    dict(present=1), dict(present=None), dict(observed_at=datetime(2027, 1, 1)), dict(observed_at="2027-01-01T00:00:00Z"), dict(account=""),
                    dict(account=None), dict(message_id=""), dict(message_id=5), dict(nonce=5), dict(issuer=object()), dict(issuer=None)):
            with self.assertRaises(ee.ObservationError, msg=bad):
                build(**bad)

    def test_the_issuer_needs_the_adapter_seal_an_aware_clock_and_an_account(self):
        with self.assertRaises(TypeError):
            ee.new_issuer(ACCT, lambda: datetime.now(timezone.utc))  # the seal is a required keyword
        with self.assertRaises(ee.ObservationError):
            ee.new_issuer(ACCT, lambda: datetime.now(timezone.utc), seal=object())
        with self.assertRaises(ee.ObservationError):
            ee.new_issuer(ACCT, lambda: datetime.now(timezone.utc), seal=None)
        with self.assertRaises(ee.ObservationError):
            ee.claim_adapter_seal()  # already claimed by gmail_write at import time
        ad = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(0, ["INBOX"])), clock=lambda: datetime(2027, 1, 1))  # naive clock
        with self.assertRaises(gw.ReadFailure):
            ad.observe(HEX[0], context=CTX)  # the issuer refuses a naive clock; the adapter reports an unusable read, never an observation

    def test_the_first_claimant_of_the_seal_makes_the_adapter_module_refuse_to_load(self):
        code = (f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
                "from gmail_intelligence import exec_evidence as e\n"
                "e.claim_adapter_seal()\n"
                "try:\n    import gmail_intelligence.gmail_write\n    print('LOADED')\nexcept e.ObservationError:\n    print('REFUSED')\n")
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, "REFUSED")

    def test_a_token_is_used_exactly_once_even_under_concurrent_attempts(self):
        obs = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(0, ["INBOX"])), clock=lambda: datetime.now(timezone.utc)).observe(HEX[0], context=CTX)
        self.assertTrue(ee.is_pending(obs))
        wins, barrier = [], threading.Barrier(16)

        def attempt():
            barrier.wait()
            wins.append(ee.consume(obs))
        threads = [threading.Thread(target=attempt) for _ in range(16)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sum(wins), 1)
        self.assertFalse(ee.is_pending(obs))
        self.assertFalse(ee.consume(obs))

    def test_look_alikes_are_never_pending_or_consumable(self):
        for fake in (None, "x", {"labels": ()}, mock.MagicMock(), object(), TCE.ce.Evidence("LABEL_OBSERVATION", HEX[0], ("X",), "2027-01-01T00:00:00Z", "TRUSTED_ADAPTER")):
            self.assertFalse(ee.is_trusted(fake))
            self.assertFalse(ee.is_pending(fake))
            self.assertFalse(ee.consume(fake))

    def test_an_observation_from_an_unregistered_issuer_or_with_a_forged_token_is_not_pending(self):
        stranger = ee.ObservationIssuer(_mint=ee._MINT, account=ACCT.lower(), clock=lambda: datetime.now(timezone.utc))  # not created through the sealed path
        forged = ee.TrustedObservation(_mint=ee._MINT, account=ACCT.lower(), message_id=HEX[0], present=True, labels=("INBOX",),
                                       observed_at=datetime.now(timezone.utc), context=CTX, issuer=stranger, nonce="f" * 32)
        self.assertFalse(ee.is_pending(forged))
        self.assertFalse(ee.consume(forged))
        real = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(0, ["INBOX"])), clock=lambda: datetime.now(timezone.utc)).observe(HEX[0], context=CTX)
        object.__setattr__(real, "_nonce", "0" * 32)  # tampering with the token of a genuine observation
        self.assertFalse(ee.is_pending(real))
        self.assertFalse(ee.consume(real))

    def test_the_pending_set_is_bounded(self):
        issuer = self.issuer()
        for _ in range(ee.MAX_PENDING):
            issuer.issue(HEX[0], True, (), CTX)
        with self.assertRaises(ee.ObservationError):
            issuer.issue(HEX[0], True, (), CTX)


# ====================================================================== the adapter's observe()
class ObserveTests(AuthBase):
    def setUp(self):
        super().setUp()
        self.now = datetime(2027, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

    def adapter(self, *answers, verify=True, account=ACCT):
        net = TWT.Net(*([TWT.ok(emailAddress=account)] if verify else []), *answers)
        return make_adapter(net, account=account, clock=FakeClock(self.now), verify=verify), net

    def test_an_unverified_adapter_cannot_observe_and_nothing_is_sent(self):
        net = TWT.Net()
        with self.assertRaises(gw.AccountNotVerified) as ctx:
            make_adapter(net, verify=False).observe(HEX[0], context=CTX)
        self.assertTrue(gw.definitely_not_dispatched(ctx.exception))
        net_none = TWT.Net()
        no_account = make_adapter(net_none, account=None, verify=False)  # an adapter with no expected account has no issuer and can never observe
        no_account._verified = True
        with self.assertRaises(gw.AccountNotVerified):
            no_account.observe(HEX[0], context=CTX)
        self.assertEqual((net.opened, net.log, net_none.opened, net_none.log), (0, [], 0, []))

    def test_a_present_message_yields_an_explicit_sorted_labels_tuple_stamped_by_the_clock_after_the_read(self):
        ad, net = self.adapter(TWT.ok(id=HEX[0], threadId=THREADS[0], labelIds=["Label_9", "INBOX", "Label_9"]))
        obs = ad.observe(HEX[0], context=CTX)
        self.assertEqual((obs.present, obs.labels, obs.message_id, obs.account, obs.observed_at), (True, ("INBOX", "Label_9"), HEX[0], ACCT.lower(), self.now))
        self.assertEqual([(r["method"], r["target"]) for r in net.log][1:], [("GET", f"/gmail/v1/users/me/messages/{HEX[0]}?format=minimal&fields=id,threadId,labelIds")])
        self.assertEqual(pol.check_request("GET", f"{pol.BASE}/gmail/v1/users/me/messages/{HEX[0]}?format=minimal&fields=id,threadId,labelIds"), "MESSAGE_GET")  # the existing GET

    def test_omitted_label_ids_in_a_complete_answer_is_the_explicit_empty_tuple(self):
        obs = self.adapter(present_answer(0, ()))[0].observe(HEX[0], context=CTX)
        self.assertEqual((obs.present, obs.labels), (True, ()))

    def test_incomplete_or_contradictory_answers_are_errors_never_observations(self):
        cases = (TWT.ok(id=HEX[1], threadId=THREADS[0], labelIds=["INBOX"]), TWT.ok(id=HEX[0], labelIds=["INBOX"]), TWT.ok(id=HEX[0], threadId="", labelIds=["INBOX"]),
                 TWT.ok(id=HEX[0], threadId=5, labelIds=["INBOX"]), TWT.ok(id=HEX[0], threadId=THREADS[0], labelIds="INBOX"), TWT.ok(id=HEX[0], threadId=THREADS[0], labelIds=[5]),
                 TWT.ok(), (200, b"junk"), (200, b"[]"), (204, b""))
        for answer in cases:
            ad, _ = self.adapter(answer)
            with self.assertRaises(gw.ReadFailure, msg=answer):
                ad.observe(HEX[0], context=CTX)
            self.assertEqual(ad._issuer._pending, set())

    def test_a_404_is_absence_only_when_the_body_unambiguously_says_not_found(self):
        obs = self.adapter(NOT_FOUND)[0].observe(HEX[0], context=CTX)
        self.assertEqual((obs.present, obs.labels), (False, None))
        alt = (404, json.dumps({"error": {"code": 404, "message": "x", "status": "NOT_FOUND"}}).encode())
        self.assertFalse(self.adapter(alt)[0].observe(HEX[0], context=CTX).present)
        for answer in (TWT.gerr(404), (404, b"<html>not found</html>"), (404, b""), (404, b"{}"), (404, json.dumps({"error": {"code": 500, "message": "x", "status": "NOT_FOUND"}}).encode()),
                       (404, json.dumps({"error": {"code": 404, "message": "x", "errors": [{"reason": "other"}]}}).encode()), (404, b'{"error":"not found"}')):
            ad, _ = self.adapter(answer)
            with self.assertRaises(gw.ReadFailure, msg=answer):
                ad.observe(HEX[0], context=CTX)
            self.assertEqual(ad._issuer._pending, set())

    def test_other_errors_produce_typed_errors_and_no_observation(self):
        for answer, cls in ((TWT.gerr(401), gw.WriteAuthError), (TWT.gerr(403), gw.WriteAuthError), (TWT.gerr(429), gw.RateLimited), (TWT.gerr(400), gw.RequestRejected),
                            ((500, b"{}"), gw.ReadFailure)):
            ad, _ = self.adapter(answer)
            with self.assertRaises(cls):
                ad.observe(HEX[0], context=CTX)
            self.assertEqual(ad._issuer._pending, set())
        ad, _ = self.adapter(TWT.gerr(401), present_answer(0, ["INBOX"]))
        with self.assertRaises(gw.WriteAuthError):
            ad.observe(HEX[0], context=CTX)
        with self.assertRaises(gw.AccountNotVerified):  # an authorization problem also removed the verification
            ad.observe(HEX[0], context=CTX)

    def test_losing_the_verification_invalidates_every_unused_observation(self):
        ad, _ = self.adapter(present_answer(0, ["INBOX"]), present_answer(1, ["INBOX"]))
        first, second = ad.observe(HEX[0], context=CTX), ad.observe(HEX[1], context=CTX)
        self.assertTrue(ee.is_pending(first) and ee.is_pending(second))
        ad._verified = False
        self.assertFalse(ee.is_pending(first) or ee.is_pending(second))
        self.assertFalse(ee.consume(first))
        with self.assertRaises(gw.AccountNotVerified):  # a verification lost while an answer was being read
            ad._issue(HEX[0], True, (), CTX)

    def test_invalid_ids_are_refused_before_any_request_and_are_marked_not_dispatched(self):
        net = TWT.Net()
        ad = make_adapter(net, clock=FakeClock(self.now), verify=False)
        ad._verified = True  # skip the profile read to prove no request is made for a bad id
        for bad in ("", "../x", HEX[0].upper(), None, 5, "g" * 5):
            with self.assertRaises(pol.Denied) as ctx:
                ad.observe(bad, context=CTX)
            self.assertTrue(gw.definitely_not_dispatched(ctx.exception))
        self.assertEqual((net.opened, net.log), (0, []))

    def test_the_default_clock_is_aware_utc_and_the_adapter_surface_is_still_narrow(self):
        ad = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(0, ["INBOX"])))
        obs = ad.observe(HEX[0], context=CTX)
        self.assertIsNotNone(obs.observed_at.tzinfo)
        self.assertLess(abs(datetime.now(timezone.utc) - obs.observed_at), timedelta(seconds=30))
        self.assertEqual({n for n in dir(gw.ArchiveAdapter) if not n.startswith("_")}, {"verify_account", "message_state", "thread_state", "observe", "archive_message"})

    def test_no_new_endpoint_scope_or_network(self):
        self.assertEqual([(k, m) for k, m, _ in pol._ROUTES], [("PROFILE", "GET"), ("MESSAGE_GET", "GET"), ("THREAD_GET", "GET"), ("MESSAGE_MODIFY", "POST")])
        ad, net = self.adapter(present_answer(0, ["INBOX"]))
        ad.observe(HEX[0], context=CTX)
        self.assertEqual({r["method"] for r in net.log}, {"GET"})
        with mock.patch.object(gw, "_default_connection", side_effect=AssertionError("real connection")):
            self.adapter(present_answer(0, ["INBOX"]))[0].observe(HEX[0], context=CTX)


# ====================================================================== dispatch metadata on the transport's outcomes
class DispatchMetadataTests(AuthBase):
    def setUp(self):
        super().setUp()
        self.now = datetime(2027, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

    def verified(self, *script, creds=None):
        net = TWT.Net(TWT.ok(emailAddress=ACCT), *script)
        return make_adapter(net, clock=FakeClock(self.now), creds=creds), net

    def archive_error(self, ad):
        with self.assertRaises((gw.WriteTransportError, pol.Denied)) as ctx:
            ad.archive_message(HEX[0])
        return ctx.exception

    def test_refusals_before_any_transmission_are_marked_not_dispatched_and_open_no_connection(self):
        cases = []
        net = TWT.Net()
        ad = make_adapter(net, clock=FakeClock(self.now), verify=False)
        cases.append(("unverified adapter", ad, net, lambda a: a.archive_message(HEX[0]), gw.AccountNotVerified))
        net = TWT.Net(TWT.ok(emailAddress=ACCT))
        ad = make_adapter(net, clock=FakeClock(self.now))
        cases.append(("invalid id", ad, net, lambda a: a.archive_message("../x"), pol.Denied))
        cases.append(("policy refuses the body", ad, net, lambda a: a._t.perform("POST", f"{pol.BASE}/gmail/v1/users/me/messages/{HEX[0]}/modify?fields=id,threadId,labelIds", b'{"addLabelIds":["TRASH"]}'), pol.Denied))
        cases.append(("policy refuses an endpoint", ad, net, lambda a: a._t.perform("POST", f"{pol.BASE}/gmail/v1/users/me/messages/{HEX[0]}/trash", b"{}"), pol.Denied))
        net2 = TWT.Net(TWT.ok(emailAddress=ACCT))
        ad2 = make_adapter(net2, clock=FakeClock(self.now), creds=TWA.WCreds(minutes=-5), verify=False)
        ad2._verified = True
        cases.append(("expired credentials", ad2, net2, lambda a: a.archive_message(HEX[0]), gw.WriteAuthError))
        for label, a, n, call, cls in cases:
            before = n.opened
            with self.assertRaises(cls, msg=label) as ctx:
                call(a)
            self.assertIs(ctx.exception.dispatched, False, label)
            self.assertTrue(gw.definitely_not_dispatched(ctx.exception), label)
            self.assertEqual(n.opened, before, label)

    def test_an_exhausted_budget_is_a_pre_dispatch_refusal_whatever_the_counter_says(self):
        ad, net = self.verified()
        with mock.patch.object(pol, "MAX_REQUESTS", 1):
            exc = self.archive_error(ad)  # the profile read already used the budget
        self.assertEqual(exc.code, "DENIED_BUDGET")
        self.assertTrue(gw.definitely_not_dispatched(exc))
        self.assertEqual(net.opened, 1)

    def test_a_direct_wire_level_call_with_the_gate_closed_is_also_marked_not_dispatched(self):
        net = TWT.Net()
        ad = make_adapter(net, clock=FakeClock(self.now), verify=False)
        with self.assertRaises(gw.AccountNotVerified) as ctx:
            ad._t._dispatch("POST", f"{pol.BASE}/gmail/v1/users/me/messages/{HEX[0]}/modify?fields=id,threadId,labelIds", pol.MODIFY_BODY,
                            {"authorization": "Bearer " + A_TOK, "accept": "application/json", "user-agent": "x", "content-type": "application/json"})
        self.assertTrue(gw.definitely_not_dispatched(ctx.exception))
        self.assertEqual(net.opened, 0)

    def test_the_same_exception_class_can_be_either_and_the_mark_decides(self):
        creds = TWA.WCreds()
        pre, _ = self.verified(creds=creds)
        creds.expiry = creds.expiry - timedelta(hours=2)  # verified while valid; the token expired before the POST
        net_ok = TWT.Net(TWT.ok(emailAddress=ACCT), TWT.gerr(401))
        post = make_adapter(net_ok, clock=FakeClock(self.now))
        a, b = self.archive_error(pre), self.archive_error(post)
        self.assertIsInstance(a, gw.WriteAuthError)
        self.assertIsInstance(b, gw.WriteAuthError)
        self.assertEqual((a.dispatched, b.dispatched), (False, True))
        self.assertTrue(gw.definitely_not_dispatched(a))
        self.assertFalse(gw.definitely_not_dispatched(b))

    def test_nothing_that_follows_an_attempted_transmission_is_ever_marked_not_dispatched(self):
        class Boom(Exception):
            pass
        scripts = {
            "connection cannot be created": TWT.BreakNet("connect", OSError("x")),
            "request raises": TWT.BreakNet("request", ConnectionResetError()),
            "headers raise": TWT.BreakNet("getresponse", TimeoutError()),
            "body read raises": TWT.BreakNet("read", OSError()),
            "unexpected exception": TWT.BreakNet("request", Boom()),
            "validated 400": TWT.Net(TWT.gerr(400)), "validated 401": TWT.Net(TWT.gerr(401)), "validated 403": TWT.Net(TWT.gerr(403)),
            "validated 404": TWT.Net(TWT.gerr(404)), "validated 429": TWT.Net(TWT.gerr(429)), "validated 403 rate": TWT.Net(TWT.gerr(403, "rateLimitExceeded")),
            "server error": TWT.Net((503, b"")), "redirect": TWT.Net((307, b"")), "malformed 200": TWT.Net((200, b"junk")),
            "wrong id": TWT.Net(TWT.ok(id=HEX[1], threadId=THREADS[0], labelIds=[])), "oversized": TWT.Net((200, b"x" * (pol.MAX_RESPONSE + 1))),
            "html error page": TWT.Net((502, b"<html>")),
        }
        for label, net in scripts.items():
            ad = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT)), clock=FakeClock(self.now))
            ad._t._factory = net  # same verified adapter, the mutation goes to the scripted connection
            exc = self.archive_error(ad)
            self.assertIsNot(exc.dispatched, False, label)
            self.assertFalse(gw.definitely_not_dispatched(exc), label)
            self.assertEqual(net.opened, 1, label)  # exactly one connection attempt, no retry
            self.assertLessEqual(len(net.log), 1, label)

    def test_dispatch_marks_never_depend_on_the_request_counter(self):
        ad, net = self.verified(present_answer(0, ["INBOX"]), present_answer(1, ["INBOX"]))
        ad.message_state(HEX[0])
        ad.message_state(HEX[1])
        self.assertGreater(ad._t._sent, 2)
        ad._verified = False
        exc = self.archive_error(ad)
        self.assertTrue(gw.definitely_not_dispatched(exc))  # still a pre-dispatch refusal with a high counter
        fresh = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), TWT.gerr(404)), clock=FakeClock(self.now))
        self.assertEqual(fresh._t._sent, 1)
        exc = self.archive_error(fresh)
        self.assertFalse(gw.definitely_not_dispatched(exc))  # a low counter does not make a received answer "not sent"

    def test_unmarked_and_foreign_exceptions_are_treated_as_possibly_dispatched(self):
        self.assertIsNone(gw.WriteTransportError().dispatched)
        for exc in (gw.WriteTransportError(), gw.WriteAuthError(), gw.ReadFailure(), Exception("x"), pol.Denied("DENIED_PATH"), None, "x"):
            self.assertFalse(gw.definitely_not_dispatched(exc))
        self.assertTrue(gw.UncertainOutcome().dispatched)

    def test_a_successful_archive_is_unchanged_and_sends_exactly_one_post(self):
        ad, net = self.verified(TWT.ok(id=HEX[0], threadId=THREADS[0], labelIds=["Label_9"]))
        result = ad.archive_message(HEX[0])
        self.assertEqual((result.label_ids, result.inbox_removed), (("Label_9",), True))
        self.assertEqual([r["method"] for r in net.log], ["GET", "POST"])


# ====================================================================== how the execution state uses trusted evidence
class TrustedEvidenceTests(TCE.ExecBase):
    sql = TCE.HardeningTests.sql
    refused = TCE.HardeningTests.refused
    LABELS = ["INBOX", "CATEGORY_PROMOTIONS", "Label_9"]
    AFTER = ("CATEGORY_PROMOTIONS", "Label_9")

    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed([dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(1, 6)])
        self.ids = list(HEX)

    def intent(self, labels=None):
        ex = self.started(self.approved_plan(HEX[:2]))
        a = self.ids_of(ex["exec_id"])[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, labels or self.LABELS, now=self.tick())
        return ex, a

    def ctx_for(self, mid):
        """The context the state machine expects for the latest execution: reconciliation if the item is UNKNOWN, otherwise the post-read."""
        exec_id = self.index._q("SELECT exec_id FROM cleanup_execution ORDER BY created_at DESC, exec_id DESC LIMIT 1")[0][0]
        if self.index._q("SELECT state FROM cleanup_exec_item WHERE exec_id=? AND message_id=?", exec_id, mid)[0][0] == "UNKNOWN":
            return ce.reconcile_context(self.index, ACCT, exec_id, mid)
        return ce.postread_context(self.index, ACCT, exec_id, self.token, mid)

    def observe(self, mid, labels=None, absent=False, at=None, account=ACCT):
        i = HEX.index(mid)
        net = TWT.Net(TWT.ok(emailAddress=account), NOT_FOUND if absent else present_answer(i, labels if labels is not None else self.AFTER))
        ad = make_adapter(net, account=account, clock=FakeClock(at if at is not None else self.t))
        return ad.observe(mid, context=self.ctx_for(mid)), ad

    def last_item_meta(self):
        row = self.index._q("SELECT meta FROM cleanup_audit WHERE event_type='ITEM_TRANSITION' ORDER BY seq DESC LIMIT 1")[0]
        return json.loads(row["meta"])

    def snapshot(self):
        q = self.index._q
        return ([tuple(r) for r in q("SELECT * FROM cleanup_exec_item ORDER BY message_id")], [tuple(r) for r in q("SELECT * FROM cleanup_execution")],
                q("SELECT COUNT(*) FROM cleanup_audit")[0][0])

    def unknown_item(self):
        ex, a = self.intent()
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "UNKNOWN", code="TIMEOUT", now=self.tick())
        ce.stop_execution(self.index, ACCT, ex["exec_id"], self.token, "AMBIGUOUS_RESULT", now=self.tick())
        self.assertEqual(self.exec_state(ex["exec_id"]), "RECONCILIATION_REQUIRED")
        return ex, a

    def test_these_tests_use_a_temporary_synthetic_home_never_the_real_index(self):
        from gmail_intelligence import config
        self.assertTrue(str(config.index_path()).startswith(str(self.tmp)))
        self.assertTrue(str(self.index.path).startswith(str(self.tmp)))
        self.assertEqual(self.index.conn.execute("PRAGMA user_version").fetchone()[0], idx.SCHEMA_VERSION)

    # ---- acceptance
    def test_a_genuine_observation_is_persisted_with_the_trusted_source(self):
        ex, a = self.intent()
        obs, _ = self.observe(a)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        row = self.index._q("SELECT state, evidence_checked, evidence_source, evidence_observed_at, error_code FROM cleanup_exec_item WHERE message_id=?", a)[0]
        self.assertEqual(tuple(row)[:3], ("APPLIED", 1, "TRUSTED_ADAPTER"))
        self.assertEqual(row["evidence_observed_at"], ce._us(obs.observed_at))
        self.assertFalse(ee.is_pending(obs))

    def test_ordinary_evidence_cannot_claim_the_trusted_source_in_any_way(self):
        self.assertEqual(ce.ACCEPTED_EVIDENCE_SOURCES, ("CALLER_SUPPLIED",))
        self.assertEqual(ce.TRUSTED_EVIDENCE_SOURCE, "TRUSTED_ADAPTER")
        ex, a = self.intent()
        before = self.snapshot()

        class Sub(ce.Evidence):
            pass
        fake_obs = mock.MagicMock(account=ACCT.lower(), message_id=a, present=True, labels=self.AFTER, observed_at=self.t, source="TRUSTED_ADAPTER")
        candidates = (self.ev(a, self.AFTER, source="TRUSTED_ADAPTER"), Sub("LABEL_OBSERVATION", a, self.AFTER, ce.cp._iso(self.t), "TRUSTED_ADAPTER"),
                      self.ev(a, self.AFTER, source="trusted_adapter"), self.ev(a, self.AFTER, source="CALLER_SUPPLIED ".strip() + "x"), fake_obs, {"labels": self.AFTER},
                      "APPLIED", None, object())
        for candidate in candidates:
            with self.assertRaises(ce.ExecError, msg=type(candidate)) as ctx:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=candidate, now=self.tick())
            self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE evidence_source='TRUSTED_ADAPTER'")[0][0], 0)

    def test_a_forged_observation_from_an_unregistered_issuer_is_refused(self):
        ex, a = self.intent()
        stranger = ee.ObservationIssuer(_mint=ee._MINT, account=ACCT.lower(), clock=lambda: self.t)
        forged = stranger.issue(a, True, self.AFTER, CTX)  # structurally perfect, but its issuer was never sealed to an adapter... and it is "pending" in its own set
        object.__setattr__(forged, "_issuer", ee.ObservationIssuer(_mint=ee._MINT, account=ACCT.lower(), clock=lambda: self.t))  # swap in an issuer that never issued it
        before = self.snapshot()
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=forged, now=self.tick())
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)

    def test_account_message_and_issuer_bindings(self):
        ex, a = self.intent()
        b = self.ids_of(ex["exec_id"])[1]
        other_account, _ = self.observe(a, account=OTHER)
        wrong_message, _ = self.observe(b)
        for label, obs in (("another account", other_account), ("another message", wrong_message)):
            before = self.snapshot()
            with self.assertRaises(ce.ExecError, msg=label) as ctx:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick())
            self.assertEqual(ctx.exception.code, "BAD_EVIDENCE", label)
            self.assertEqual(self.snapshot(), before, label)
            self.assertTrue(ee.is_pending(obs), label + ": a refused observation is not consumed")
        good, _ = self.observe(a, account=ACCT.upper())  # case does not matter
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=good, now=self.tick())

    def test_an_unverified_or_unverifiable_adapter_issues_nothing_usable(self):
        ex, a = self.intent()
        obs, ad = self.observe(a)
        ad._verified = False  # the adapter lost its verification after issuing
        before = self.snapshot()
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick())
        self.assertEqual(self.snapshot(), before)

    # ---- replay and persistence failure
    def test_an_observation_works_once_and_a_replay_is_refused(self):
        ex, a = self.unknown_item()
        obs, _ = self.observe(a, labels=self.AFTER, at=self.t + timedelta(seconds=1))
        ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        with self.assertRaises(ce.ExecError) as ctx:
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, obs, now=self.tick())
        self.assertIn(ctx.exception.code, ("BAD_EVIDENCE", "BAD_STATE", "BAD_ITEM_STATE"))
        self.assertFalse(ee.is_pending(obs))

    def test_after_a_database_failure_the_observation_stays_consumed_and_a_new_one_is_needed(self):
        ex, a = self.intent()
        obs, _ = self.observe(a)
        before = self.snapshot()
        with mock.patch.object(ce, "_set_item", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(sqlite3.OperationalError):
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick())
        self.assertEqual(self.snapshot(), before)  # the transaction rolled back completely
        self.assertFalse(ee.is_pending(obs))  # but the in-memory token is spent: nothing claims it survives a restart
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick())
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)
        fresh, _ = self.observe(a)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=fresh, now=self.tick())
        self.assertEqual(self.index._q("SELECT state FROM cleanup_exec_item WHERE message_id=?", a)[0][0], "APPLIED")

    def test_validation_failures_do_not_consume_the_observation(self):
        ex, a = self.intent()
        wrong_state, _ = self.observe(a, labels=("INBOX", "CATEGORY_PROMOTIONS", "Label_9"))  # still in the inbox: not the archived state
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=wrong_state, now=self.tick())
        self.assertEqual(ctx.exception.code, "EVIDENCE_MISMATCH")
        self.assertTrue(ee.is_pending(wrong_state))

    # ---- chronology and age
    def test_strict_chronology_age_and_future_bounds(self):
        ex, a = self.intent()
        intent_at = ce._parse_us(self.index._q("SELECT intent_at FROM cleanup_exec_item WHERE message_id=?", a)[0][0])
        now = intent_at + timedelta(minutes=1)
        for label, at in (("1 microsecond before the intent", intent_at - timedelta(microseconds=1)), ("4 minutes before", intent_at - timedelta(minutes=4)),
                          ("beyond the clock tolerance in the future", now + cp.CLOCK_TOLERANCE + timedelta(microseconds=1))):
            obs, _ = self.observe(a, at=at)
            before = self.snapshot()
            with self.assertRaises(ce.ExecError, msg=label) as ctx:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=now)
            self.assertEqual((ctx.exception.code, self.snapshot()), ("BAD_EVIDENCE", before), label)
            self.assertTrue(ee.is_pending(obs), label)
        ce.renew_lease(self.index, ACCT, ex["exec_id"], self.token, now=intent_at + timedelta(minutes=4))  # keep the lease alive for the age checks
        stale, _ = self.observe(a, at=intent_at)  # exactly at the intent is fine for chronology ...
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=stale, now=intent_at + ee.MAX_AGE + timedelta(microseconds=1))  # ... but too old to use
        ok_edge, _ = self.observe(a, at=intent_at)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=ok_edge, now=intent_at + ee.MAX_AGE)  # exactly at the maximum age

    def test_reconciliation_chronology_follows_the_unknown_transition(self):
        ex, a = self.unknown_item()
        unknown_at = ce._parse_us(self.index._q("SELECT result_at FROM cleanup_exec_item WHERE message_id=?", a)[0][0])
        early, _ = self.observe(a, at=unknown_at - timedelta(microseconds=1))
        with self.assertRaises(ce.ExecError) as ctx:
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, early, now=unknown_at + timedelta(seconds=30))
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        on_time, _ = self.observe(a, at=unknown_at)
        done = ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, on_time, now=unknown_at + timedelta(seconds=30))
        self.assertNotEqual(done["state"], "RECONCILIATION_REQUIRED")

    # ---- missing versus empty, absence
    def test_empty_versus_missing_label_sets(self):
        ex, a = self.intent(["INBOX"])  # the message had no other labels
        absent, _ = self.observe(a, absent=True)
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=absent, now=self.tick())
        self.assertEqual(ctx.exception.code, "EVIDENCE_MISMATCH")  # absence is never "archived"
        self.assertTrue(ee.is_pending(absent))
        nonempty, _ = self.observe(a, labels=("Label_9",))
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=nonempty, now=self.tick())
        empty, _ = self.observe(a, labels=())  # an explicit empty tuple (Gmail omitted labelIds in a complete answer)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=empty, now=self.tick())
        self.assertEqual(self.index._q("SELECT state, evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0][:], ("APPLIED", "TRUSTED_ADAPTER"))

    def test_an_empty_observation_is_refused_when_other_labels_were_expected(self):
        ex, a = self.intent()  # expected archived state: ("CATEGORY_PROMOTIONS", "Label_9")
        empty, _ = self.observe(a, labels=())
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=empty, now=self.tick())
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")

    def test_a_trusted_absence_reconciles_to_conflict_and_never_to_applied(self):
        ex, a = self.unknown_item()
        absent, _ = self.observe(a, absent=True, at=self.t + timedelta(seconds=1))
        done = ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, absent, now=self.tick(), require_source="TRUSTED_ADAPTER")
        row = self.index._q("SELECT state, error_code, evidence_checked, evidence_source, evidence_observed_at FROM cleanup_exec_item WHERE message_id=?", a)[0]
        self.assertEqual(tuple(row)[:4], ("CONFLICT", "RECONCILED_CONFLICT", 0, "TRUSTED_ADAPTER"))  # source and time are kept; the checked flag stays 0
        self.assertEqual(row["evidence_observed_at"], ce._us(absent.observed_at))
        self.assertEqual(self.last_item_meta()["obs"], "ABSENT")
        self.assertIn(done["state"], ("FAILED", "PARTIAL"))
        self.assertNotEqual(done["state"], "EXECUTED")
        self.assertFalse(ee.is_pending(absent))

    def test_reconciliation_derives_the_outcome_from_a_trusted_observation(self):
        expected = (("archived", None, "APPLIED", "RECONCILED_OBSERVED_ARCHIVED", "TRUSTED_ADAPTER"), ("before", self.LABELS, "NOT_APPLIED", "RECONCILED_UNMODIFIED", "TRUSTED_ADAPTER"),
                    ("other", ("Label_77",), "CONFLICT", "RECONCILED_CONFLICT", "TRUSTED_ADAPTER"))
        for label, labels, state, code, source in expected:
            self.setUp()
            ex, a = self.unknown_item()
            obs, _ = self.observe(a, labels=labels, at=self.t + timedelta(seconds=1))
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, obs, now=self.tick())
            row = self.index._q("SELECT state, error_code, evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0]
            self.assertEqual(tuple(row), (state, code, source), label)

    # ---- audit correction (P1: source spoofing through a stateful Evidence subclass; P2: what each reconciliation outcome keeps)
    def stateful_variants(self, a):
        """Ordinary-Python subclasses of Evidence whose `source` (or other fields) change between reads. None of them uses reflection."""
        at = ce.cp._iso(self.t)

        class Flip(ce.Evidence):  # first read says TRUSTED_ADAPTER, every later read says CALLER_SUPPLIED
            def __init__(self, *args):
                self.__dict__.update(_a=args, _n=0)
            kind = "LABEL_OBSERVATION"
            message_id = property(lambda s: s._a[0])
            labels = property(lambda s: s._a[1])
            observed_at = property(lambda s: s._a[2])

            @property
            def source(self):
                self._n += 1
                return "TRUSTED_ADAPTER" if self._n == 1 else "CALLER_SUPPLIED"

        class FlipBack(Flip):  # first read looks ordinary, later reads say TRUSTED_ADAPTER
            @property
            def source(self):
                self._n += 1
                return "CALLER_SUPPLIED" if self._n == 1 else "TRUSTED_ADAPTER"

        class Plain(ce.Evidence):  # a harmless subclass with honest values is still not the exact type
            pass
        return (Flip(a, self.AFTER, at), FlipBack(a, self.AFTER, at), Plain("LABEL_OBSERVATION", a, self.AFTER, at, "CALLER_SUPPLIED"))

    def test_p1_a_stateful_source_subclass_is_rejected_everywhere(self):
        for require in (None, "TRUSTED_ADAPTER", "CALLER_SUPPLIED"):
            self.setUp()
            ex, a = self.intent()
            before = self.snapshot()
            for ev in self.stateful_variants(a):
                with self.assertRaises(ce.ExecError, msg=(type(ev).__name__, require)) as ctx:
                    ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=ev, now=self.tick(), require_source=require)
                self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE evidence_source='TRUSTED_ADAPTER'")[0][0], 0)

    def test_p1_the_same_subclasses_cannot_reconcile_an_unknown_item(self):
        ex, a = self.unknown_item()
        before = self.snapshot()
        for ev in self.stateful_variants(a):
            for require in (None, "TRUSTED_ADAPTER"):
                with self.assertRaises(ce.ExecError, msg=type(ev).__name__) as ctx:
                    ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, ev, now=self.tick(), require_source=require)
                self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        self.assertEqual(self.snapshot(), before)

    def test_p1_ordinary_evidence_is_always_stored_with_the_constant_caller_source(self):
        self.assertEqual(ce.ACCEPTED_EVIDENCE_SOURCES, ("CALLER_SUPPLIED",))
        self.assertEqual(ce.CALLER_EVIDENCE_SOURCE, "CALLER_SUPPLIED")
        ex, a = self.intent()
        labels = list(self.AFTER)  # a list is accepted and snapshotted once
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=ce.Evidence("LABEL_OBSERVATION", a, labels, ce.cp._iso(self.t)), now=self.tick())
        self.assertEqual(self.index._q("SELECT evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0][0], "CALLER_SUPPLIED")
        self.assertEqual(self.index._q("SELECT COUNT(*) FROM cleanup_exec_item WHERE evidence_source='TRUSTED_ADAPTER'")[0][0], 0)
        self.assertEqual(self.last_item_meta().get("src"), None)  # historical shape of the audit event for caller-supplied evidence

    def test_p1_require_trusted_accepts_only_a_valid_unused_observation(self):
        ex, a = self.intent()
        for bad in (self.ev(a, self.AFTER), *self.stateful_variants(a)):
            with self.assertRaises(ce.ExecError):
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=bad, now=self.tick(), require_source="TRUSTED_ADAPTER")
        obs, _ = self.observe(a)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(self.index._q("SELECT evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0][0], "TRUSTED_ADAPTER")
        self.assertFalse(ee.is_pending(obs))  # used; replay is covered by test_an_observation_works_once_and_a_replay_is_refused

    def test_p1_invalid_ordinary_evidence_never_consumes_a_trusted_nonce(self):
        ex, a = self.intent()
        obs, _ = self.observe(a)
        for bad in (self.ev(a, ("Label_77",)), *self.stateful_variants(a)):
            with self.assertRaises(ce.ExecError):
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=bad, now=self.tick(), require_source="TRUSTED_ADAPTER")
            self.assertTrue(ee.is_pending(obs))
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertFalse(ee.is_pending(obs))

    def test_p2_every_trusted_reconciliation_outcome_keeps_its_source_time_and_observed_kind(self):
        cases = (("ARCHIVED", None, "APPLIED", 1), ("PREVIOUS", self.LABELS, "NOT_APPLIED", 0), ("OTHER_LABELS", ("Label_77",), "CONFLICT", 0), ("ABSENT", "absent", "CONFLICT", 0))
        seen_codes = set()
        for kind, labels, state, checked in cases:
            self.setUp()
            ex, a = self.unknown_item()
            obs, _ = self.observe(a, labels=None if labels == "absent" else labels, absent=labels == "absent", at=self.t + timedelta(seconds=1))
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
            row = self.index._q("SELECT state, error_code, evidence_checked, evidence_source, evidence_observed_at FROM cleanup_exec_item WHERE message_id=?", a)[0]
            self.assertEqual((row["state"], row["evidence_checked"], row["evidence_source"], row["evidence_observed_at"]), (state, checked, "TRUSTED_ADAPTER", ce._us(obs.observed_at)), kind)
            meta = self.last_item_meta()
            self.assertEqual((meta["obs"], meta["src"], meta["seen"]), (kind, "TRUSTED_ADAPTER", ce._us(obs.observed_at)))
            self.assertNotIn(a, json.dumps(meta))  # no message id; no label names either
            self.assertTrue(ce.audit.verify_chain(self.index, ACCT)[0])
            seen_codes.add((kind, meta["obs"]))
        self.assertEqual(len(seen_codes), 4)  # absence and conflicting labels are distinguishable in the audit event even though the item code is shared

    def test_p2_a_trusted_applied_outcome_records_the_archived_observation_in_the_audit_event(self):
        ex, a = self.intent()
        obs, _ = self.observe(a)
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=obs, now=self.tick(), require_source="TRUSTED_ADAPTER")
        meta = self.last_item_meta()
        self.assertEqual((meta["obs"], meta["src"], meta["seen"]), ("ARCHIVED", "TRUSTED_ADAPTER", ce._us(obs.observed_at)))

    def test_p2_caller_supplied_reconciliation_keeps_its_historical_storage(self):
        for labels, state in ((self.AFTER, "APPLIED"), (self.LABELS, "NOT_APPLIED"), (("Label_77",), "CONFLICT")):
            self.setUp()
            ex, a = self.unknown_item()
            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a, labels, when=ce.cp._iso(self.t + timedelta(seconds=1))), now=self.tick())
            row = self.index._q("SELECT state, evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0]
            self.assertEqual(tuple(row), (state, "CALLER_SUPPLIED" if state == "APPLIED" else None))
            self.assertNotIn("obs", self.last_item_meta())

    def test_a_malformed_uninitialised_observation_is_bad_evidence_and_changes_nothing(self):
        for mode in ("record_outcome", "reconcile_item"):
            self.setUp()
            ex, a = self.intent() if mode == "record_outcome" else self.unknown_item()
            real, _ = self.observe(a, at=self.t + timedelta(seconds=1))
            raw = ee.TrustedObservation.__new__(ee.TrustedObservation)  # no __init__: every slot unset
            half = ee.TrustedObservation.__new__(ee.TrustedObservation)  # some slots set, the issuer and nonce missing
            for name in ("account", "message_id", "present", "labels", "observed_at"):
                object.__setattr__(half, name, getattr(real, name))
            before = self.snapshot()
            for bad in (raw, half):
                for require in (None, "TRUSTED_ADAPTER"):
                    with self.assertRaises(ce.ExecError, msg=(mode, require)) as ctx:
                        if mode == "record_outcome":
                            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=bad, now=self.tick(), require_source=require)
                        else:
                            ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, bad, now=self.tick(), require_source=require)
                    self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
                    self.assertNotIn("Trusted", str(ctx.exception))
            self.assertEqual(self.snapshot(), before)
            self.assertTrue(ee.is_pending(real))  # no genuine token was touched; and none was consumed
            self.assertFalse(ee.consume(raw))

    # ---- require_source and compatibility
    def test_require_source_only_restricts_and_never_selects_the_stored_source(self):
        ex, a = self.intent()
        caller = self.ev(a, self.AFTER)
        with self.assertRaises(ce.ExecError) as ctx:
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=caller, now=self.tick(), require_source="TRUSTED_ADAPTER")
        self.assertEqual(ctx.exception.code, "BAD_EVIDENCE")
        trusted, _ = self.observe(a)
        with self.assertRaises(ce.ExecError):
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=trusted, now=self.tick(), require_source="CALLER_SUPPLIED")
        self.assertTrue(ee.is_pending(trusted))
        for bad in ("trusted_adapter", "", "ANY", 5, ["TRUSTED_ADAPTER"], b"TRUSTED_ADAPTER"):
            with self.assertRaises(ce.ExecError, msg=bad) as ctx:
                ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=caller, now=self.tick(), require_source=bad)
            self.assertEqual(ctx.exception.code, "BAD_INPUT")
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=caller, now=self.tick(), require_source="CALLER_SUPPLIED")
        self.assertEqual(self.index._q("SELECT evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0][0], "CALLER_SUPPLIED")

    def test_existing_caller_supplied_behaviour_is_unchanged(self):
        ex, a = self.intent()
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "APPLIED", evidence=self.ev(a, self.AFTER), now=self.tick())  # no require_source
        self.assertEqual(self.index._q("SELECT state, evidence_checked, evidence_source FROM cleanup_exec_item WHERE message_id=?", a)[0][:], ("APPLIED", 1, "CALLER_SUPPLIED"))

    def test_caller_supplied_reconciliation_still_works_and_cannot_express_absence(self):
        ex, a = self.unknown_item()
        done = ce.reconcile_item(self.index, ACCT, ex["exec_id"], a, self.ev(a, self.AFTER, when=ce.cp._iso(self.t + timedelta(seconds=1))), now=self.tick())
        self.assertEqual(self.index._q("SELECT error_code FROM cleanup_exec_item WHERE message_id=?", a)[0][0], "RECONCILED_OBSERVED_ARCHIVED")
        self.assertNotEqual(done["state"], "RECONCILIATION_REQUIRED")
        item = {"message_id": a, "prev_label_ids": json.dumps(self.LABELS), "intent_at": ce._us(self.t), "result_at": ce._us(self.t), "state": "UNKNOWN"}
        with self.assertRaises(ce.ExecError):  # a caller cannot express "absent": an empty tuple is only valid when an empty archived state was expected
            ce._check_evidence(self.ev(a, ()), item, self.t, ACCT)
        self.assertEqual(str(ce.cp._iso(self.t))[:4], "2027")  # the synthetic clock of the shared test base


# ====================================================================== reports and historical meaning
class ReportTests(TCE.ExecBase):
    LABELS = ["INBOX", "CATEGORY_PROMOTIONS", "Label_9"]
    AFTER = ("CATEGORY_PROMOTIONS", "Label_9")

    def setUp(self):
        super().setUp()
        self.index.purge(ACCT)
        self.seed([dict(msg(i, sender=f"s{i}@shop.example.test"), id=HEX[i - 1], thread_id=THREADS[i - 1]) for i in range(1, 6)])
        self.ids = list(HEX)

    def text(self, ex):
        return cleanup_exec_report.show_text(self.index, ACCT, ce.get_execution(self.index, ACCT, ex["exec_id"]), False)

    def two_item_execution(self, sources):
        ex = self.started(self.approved_plan(HEX[:2]))
        for mid, source in zip(self.ids_of(ex["exec_id"]), sources):
            ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, mid, self.LABELS, now=self.tick())
            if source == "CALLER":
                evidence = self.ev(mid, self.AFTER)
            else:
                i = HEX.index(mid)
                evidence = make_adapter(TWT.Net(TWT.ok(emailAddress=ACCT), present_answer(i, self.AFTER)), clock=FakeClock(self.t)).observe(mid, context=ce.postread_context(self.index, ACCT, ex["exec_id"], self.token, mid))
            ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, mid, "APPLIED", evidence=evidence, now=self.tick())
        return ex

    def test_the_report_distinguishes_caller_supplied_from_trusted_observations(self):
        caller = self.text(self.two_item_execution(["CALLER", "CALLER"]))
        self.assertIn("caller-supplied", caller)
        self.assertIn("not authenticated", caller)
        self.assertNotIn("trusted-adapter observation", caller)
        self.setUp()
        trusted = self.text(self.two_item_execution(["TRUSTED", "TRUSTED"]))
        self.assertIn("2 item(s) were recorded from a trusted-adapter observation", trusted)
        self.assertIn("does not prove that this tool made the change", trusted)
        self.assertNotIn("not authenticated", trusted)
        self.assertNotIn("cryptographic proof of", trusted.replace("not a cryptographic proof", ""))  # never claims cryptographic proof
        self.setUp()
        mixed = self.text(self.two_item_execution(["CALLER", "TRUSTED"]))
        self.assertIn("1 item(s) were recorded with caller-supplied evidence", mixed)
        self.assertIn("1 item(s) were recorded from a trusted-adapter observation", mixed)
        for private in (*HEX, *THREADS, ACCT, "owner@"):
            self.assertNotIn(private, mixed)

    def test_no_evidence_note_without_applied_items(self):
        ex = self.started(self.approved_plan(HEX[:2]))
        self.assertEqual(cleanup_exec_report.evidence_notes(self.index, ACCT, ex["exec_id"]), [])

    def test_a_recorded_rejection_keeps_its_code_and_its_uncertainty(self):
        self.assertEqual(ce.OUTCOME_CODES["NOT_APPLIED"], ("REJECTED",))  # the vocabulary is unchanged
        self.assertIn("REJECTED", idx.EXEC_ITEM_CODES)
        ex = self.started(self.approved_plan(HEX[:2]))
        a = self.ids_of(ex["exec_id"])[0]
        ce.record_intent(self.index, ACCT, ex["exec_id"], self.token, a, self.LABELS, now=self.tick())
        ce.record_outcome(self.index, ACCT, ex["exec_id"], self.token, a, "NOT_APPLIED", now=self.tick())
        self.assertEqual(self.index._q("SELECT state, error_code FROM cleanup_exec_item WHERE message_id=?", a)[0][:], ("NOT_APPLIED", "REJECTED"))
        meaning = ce.CODE_MEANING["REJECTED"]
        self.assertNotIn("rejected by Gmail", meaning)  # it never asserts that Gmail answered
        self.assertIn("assertion", meaning)
        self.assertIn("cannot show whether anything was sent", meaning)
        text = self.text(ex)
        self.assertIn("REJECTED", text)
        self.assertIn("cannot show whether anything was sent", text)

    def test_the_schema_and_vocabularies_are_untouched(self):
        self.assertEqual(idx.SCHEMA_VERSION, 5)
        self.assertIn("evidence_source IN ('CALLER_SUPPLIED','TRUSTED_ADAPTER')", idx.SCHEMA_V5)
        self.assertEqual(ce.EVIDENCE_SOURCES, ("CALLER_SUPPLIED", "TRUSTED_ADAPTER"))
        self.assertEqual(sorted(ce.STOP_REASONS), sorted(("CIRCUIT_BREAKER", "AMBIGUOUS_RESULT", "AUTH_PROBLEM", "ACCOUNT_MISMATCH", "RATE_LIMITED", "OWNER_REQUEST", "OWNER_ABORT", "INTERRUPTED")))
        self.assertEqual(self.index.conn.execute("PRAGMA user_version").fetchone()[0], 5)


# ====================================================================== static boundaries
class BoundaryTests(unittest.TestCase):
    def sources(self):
        return {p.name: p.read_text() for p in (SRC / "gmail_intelligence").glob("*.py")}

    def calls(self, name):
        found = set()
        for fname, text in self.sources().items():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Call):
                    f = node.func
                    if (isinstance(f, ast.Name) and f.id == name) or (isinstance(f, ast.Attribute) and f.attr == name):
                        found.add(fname)
        return found

    def test_only_the_neutral_module_builds_observations_and_only_the_adapter_creates_issuers(self):
        self.assertEqual(self.calls("TrustedObservation") - {"exec_evidence.py"}, set())
        self.assertEqual(self.calls("ObservationIssuer") - {"exec_evidence.py"}, set())
        self.assertEqual(self.calls("new_issuer"), {"gmail_write.py"})
        self.assertEqual(self.calls("claim_adapter_seal"), {"gmail_write.py"})

    def test_the_trusted_source_string_is_a_constant_never_taken_from_input(self):
        for fname, text in self.sources().items():
            if fname in ("cleanup_exec.py", "cleanup_exec_report.py", "index.py", "exec_evidence.py"):
                continue
            self.assertNotIn("TRUSTED_ADAPTER", text, fname)
        text = self.sources()["cleanup_exec.py"]
        literals = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and n.value == "TRUSTED_ADAPTER"]
        self.assertEqual(len(literals), 2)  # exactly: the EVIDENCE_SOURCES tuple and the TRUSTED_EVIDENCE_SOURCE constant
        self.assertNotRegex(text, r'ACCEPTED_EVIDENCE_SOURCES\s*=\s*\([^)]*TRUSTED')

    def test_exec_evidence_is_stdlib_only_and_the_state_machine_still_imports_no_write_module(self):
        tree = ast.parse(self.sources()["exec_evidence.py"])
        stdlib = set(sys.stdlib_module_names)
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
            for n in names:
                self.assertIn(n.split(".")[0], stdlib, n)
        text = self.sources()["cleanup_exec.py"]
        for banned in ("gmail_write", "oauth_write", "keystore_write", "googleapiclient", "httplib2"):
            self.assertNotIn(banned, text)

    def test_production_execution_is_still_unreachable(self):
        cli = self.sources()["cli.py"]
        self.assertIn("execution is not available in this version", cli)
        for name in ("record_outcome", "reconcile_item", "observe", "TrustedObservation", "exec_evidence", "reserve_execution", "archive_message"):
            self.assertNotIn(name, cli)
        for fname, text in self.sources().items():
            if fname not in ("gmail_write.py", "cli.py", "gmail_write_policy.py", "oauth_write.py", "keystore_write.py", "cleanup_executor.py", "exec_fake_mailbox.py"):
                self.assertNotIn("archive_message", text, fname)

    def test_no_new_scope_and_the_real_index_is_not_touched(self):
        holders = sorted(n for n, t in self.sources().items() if "gmail.modify" in t)
        self.assertEqual(holders, ["oauth_write.py"])


if __name__ == "__main__":
    unittest.main()
