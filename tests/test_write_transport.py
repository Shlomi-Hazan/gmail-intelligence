"""Offline tests for the write request policy, the thin transport and the narrow archive adapter (M4C-B1).

Fake connections only: a recording factory replaces the HTTPS connection, so no socket is ever opened (sockets are also blocked).
All ids, tokens and accounts are synthetic.
"""
import http.client
import json
import ssl
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_auth import A_TOK, ACCOUNT, Base, R_TOK, utcnow  # noqa: E402
from test_write_auth import ACCOUNT_OTHER, WCreds, WBase, write_client_config  # noqa: E402

from gmail_intelligence import cleanup_exec, gmail_write as gw, gmail_write_policy as pol, oauth, oauth_write  # noqa: E402

MID, TID = "18c0ffee00112233", "18c0ffee00112299"
B = pol.BASE + "/gmail/v1/users/me"
MODIFY_PATH = f"{B}/messages/{MID}/modify"
MODIFY = MODIFY_PATH + "?fields=id,threadId,labelIds"
PROFILE = f"{B}/profile?fields=emailAddress"
MSG_MIN = "?format=minimal&fields=id,threadId,labelIds"
MSG_HDR = "?format=metadata&metadataHeaders=From&fields=id,threadId,internalDate,labelIds,sizeEstimate,payload/headers"
THR_MIN = "?format=minimal&fields=id,messages/id,messages/labelIds"
PRIVATE = (A_TOK, R_TOK, MID, TID, ACCOUNT, "Bearer")


class FakeConn:
    def __init__(self, net):
        self.net, self.item = net, None

    def request(self, method, target, body=None, headers=None):
        self.net.log.append({"method": method, "target": target, "body": body, "headers": dict(headers or {})})
        if not self.net.script:
            raise AssertionError("unscripted request reached the (fake) wire")
        self.item = self.net.script.pop(0)
        if isinstance(self.item, BaseException):
            raise self.item

    def getresponse(self):
        status, body = self.item

        class R:
            length = 0  # a fully delivered, Content-Length framed body

            def __init__(s):
                s.status = status

            def read(s, n=-1):
                return body if n < 0 else body[:n]

            def getheaders(s):
                return [("Content-Length", str(len(body)))] if len(body) <= 999_999 else []

            def isclosed(s):
                return True
        return R()

    def close(self):
        self.net.closed += 1


class Net:
    """Connection factory that records every request and plays back scripted (status, body) pairs or exceptions."""
    def __init__(self, *script):
        self.script, self.log, self.opened, self.closed = list(script), [], 0, 0

    def __call__(self):
        self.opened += 1
        return FakeConn(self)


def ok(**obj):
    return 200, json.dumps(obj).encode()


def gerr(status, reason=None):
    """A well-formed Gmail error document (the only kind of answer that counts as a definite rejection)."""
    err = {"code": status, "message": "synthetic"}
    if reason:
        err["errors"] = [{"reason": reason}]
    return status, json.dumps({"error": err}).encode()


def adapter(net, creds=None, expected=ACCOUNT, verified=True):
    a = gw.ArchiveAdapter(gw._Transport(creds or WCreds(), net), expected)
    a._verified = verified  # tests that are not about verification start from the verified state
    return a


class PolicyAllowlistTests(unittest.TestCase):
    def test_exactly_four_request_families_are_allowed(self):
        self.assertEqual(pol.check_request("GET", PROFILE), "PROFILE")
        self.assertEqual(pol.check_request("GET", f"{B}/messages/{MID}{MSG_MIN}"), "MESSAGE_GET")
        self.assertEqual(pol.check_request("GET", f"{B}/messages/{MID}{MSG_HDR}"), "MESSAGE_GET")
        self.assertEqual(pol.check_request("GET", f"{B}/threads/{TID}{THR_MIN}"), "THREAD_GET")
        self.assertEqual(pol.check_request("POST", MODIFY, {"content-type": "application/json"}, pol.MODIFY_BODY), "MESSAGE_MODIFY")
        self.assertEqual(pol.check_request("POST", MODIFY, {"Content-Type": "application/json", "Accept": "application/json"}, pol.MODIFY_BODY), "MESSAGE_MODIFY")
        self.assertEqual(sorted(k for k, _, _ in pol._ROUTES), sorted(pol.KINDS))
        self.assertEqual(len(pol._ROUTES), 4)

    def test_every_other_endpoint_is_denied(self):
        urls = (f"{B}/messages", f"{B}/messages?q=in:inbox", f"{B}/messages/send", f"{B}/messages/{MID}/trash", f"{B}/messages/{MID}/untrash",
                f"{B}/messages/batchModify", f"{B}/messages/batchDelete", f"{B}/messages/insert", f"{B}/messages/import", f"{B}/messages/{MID}/attachments/{MID}",
                f"{B}/drafts", f"{B}/drafts/{MID}", f"{B}/drafts/send", f"{B}/threads", f"{B}/threads/{TID}/modify", f"{B}/threads/{TID}/trash",
                f"{B}/threads/{TID}/untrash", f"{B}/labels", f"{B}/labels/Label_1", f"{B}/history", f"{B}/watch", f"{B}/stop", f"{B}/settings/filters",
                f"{B}/settings/forwardingAddresses", f"{pol.BASE}/batch/gmail/v1", f"{pol.BASE}/upload/gmail/v1/users/me/messages/send",
                f"{pol.BASE}/gmail/v1/users/someone/profile", f"{pol.BASE}/gmail/v1/users/me", f"{pol.BASE}/gmail/v1/users/me/", f"{pol.BASE}/gmail/v1/",
                f"{pol.BASE}/", f"{pol.BASE}", f"{pol.BASE}/gmail/v1/users/me/profile/extra", f"{pol.BASE}/$discovery/rest", f"{pol.BASE}/gmail/v2/users/me/profile")
        for url in urls:
            for method in ("GET", "POST"):
                with self.assertRaises(pol.Denied, msg=(method, url)):
                    pol.check_request(method, url, None, pol.MODIFY_BODY if method == "POST" else None)

    def test_hosts_schemes_ports_and_userinfo_are_exact(self):
        tail = "/gmail/v1/users/me/profile?fields=emailAddress"
        for url in ("http://gmail.googleapis.com" + tail, "HTTPS://gmail.googleapis.com" + tail, "https://GMAIL.googleapis.com" + tail,
                    "https://gmail.googleapis.com:443" + tail, "https://gmail.googleapis.com:8443" + tail, "https://gmail.googleapis.com." + tail,
                    "https://www.googleapis.com" + tail, "https://gmail.googleapis.com.evil.example.invalid" + tail, "https://evil.example.invalid" + tail,
                    "https://user@gmail.googleapis.com" + tail, "https://gmail.googleapis.com@evil.example.invalid" + tail, "//gmail.googleapis.com" + tail,
                    tail, "ftp://gmail.googleapis.com" + tail, "https://127.0.0.1" + tail, "https://[::1]" + tail, "", None, 12, b"https://gmail.googleapis.com" + tail.encode()):
            with self.assertRaises(pol.Denied, msg=url):
                pol.check_request("GET", url)

    def test_ambiguous_encodings_and_path_tricks_are_denied(self):
        tricks = (f"{B}/messages/{MID}%2Fmodify", f"{B}/messages/%31{MID[1:]}", f"{B}/messages/{MID}%00", f"{B}/messages/..%2Fmessages/{MID}", f"{B}/messages/{MID}/../{MID}",
                  f"{B}/messages/./{MID}", f"{B}/messages//{MID}", f"{B}//messages/{MID}", f"{B}/messages/{MID}/", f"{B}/messages/{MID};x=1", f"{B}/messages/{MID}\\modify",
                  f"{B}/messages/{MID}#frag", f"{B}/messages/{MID.upper()}", f"{B}/messages/", f"{B}/messages/{'a' * 33}", f"{B}/messages/not-hex", f"{B}/messages/{MID}%252e",
                  f"{B}/messages/{MID}\n", f"{B}/messages/{MID} ", f"{B}/messages/١{MID}", f"{B}/messages/{MID}\x00", f"{B}/Messages/{MID}", f"{B}/messages/{MID}?format=minimal%26fields=x",
                  f"{B}/messages/{MID}+x", pol.BASE + "/gmail/v1/users/me/messages/" + "a" * 400)
        for url in tricks:
            with self.assertRaises(pol.Denied, msg=repr(url)):
                pol.check_request("GET", url)

    def test_query_parameters_are_endpoint_specific_and_never_carry_tokens(self):
        base = f"{B}/messages/{MID}"
        for q in ("", "?", "?format=full", "?format=raw", "?format=FULL", "?format=minimal&format=metadata", "?format=minimal&access_token=x", "?access_token=x&format=minimal",
                  "?format=minimal&key=x", "?format=minimal&alt=media", "?format=minimal&prettyPrint=true", "?format=minimal&metadataHeaders=From",
                  "?format=metadata&metadataHeaders=Subject", "?format=metadata&metadataHeaders=From&metadataHeaders=To", "?format=minimal&fields=*", "?format=minimal&fields=payload",
                  "?format=minimal&fields=id,threadId,labelIds,snippet", "?format=minimal&fields=id threadId", "?format=minimal&&", "?=minimal", "?format=", "?format", "?format=minimal?x",
                  "?format=minimal&q=in:inbox", "?userId=other&format=minimal", "?format=minimal&$.xgafv=2"):
            with self.assertRaises(pol.Denied, msg=q):
                pol.check_request("GET", base + q)
        for q in ("?format=minimal", "?format=metadata", "?format=metadata&metadataHeaders=From", "?fields=id,threadId,labelIds", "?format=metadata&fields=id,threadId,labelIds",
                  "?format=minimal&fields=id,threadId,internalDate,labelIds,sizeEstimate,payload/headers", "?format=minimal&metadataHeaders=From&fields=id,threadId,labelIds",
                  "?format=metadata&fields=id,threadId,internalDate,labelIds,sizeEstimate,payload/headers", "?format=metadata&metadataHeaders=Subject&fields=id,threadId,internalDate,labelIds,sizeEstimate,payload/headers",
                  "?format=metadata&metadataHeaders=From&fields=id,threadId,labelIds"):
            with self.assertRaises(pol.Denied, msg=q):  # every GET needs one of the two fixed projections, paired with its own format/header settings
                pol.check_request("GET", base + q)
        for url in (f"{B}/profile", f"{B}/profile?fields=emailAddress,messagesTotal", f"{B}/profile?fields=*", f"{B}/profile?fields=historyId", f"{B}/profile?format=minimal",
                    f"{B}/profile?fields=emailAddress&fields=emailAddress"):
            with self.assertRaises(pol.Denied, msg=url):
                pol.check_request("GET", url)
        for q in ("", "?format=metadata", "?format=full", "?format=minimal&metadataHeaders=From", "?format=minimal", "?fields=id,messages/id,messages/labelIds",
                  "?format=minimal&fields=id,messages/id,messages/labelIds,messages/snippet", "?format=minimal&fields=id,messages/snippet"):
            with self.assertRaises(pol.Denied, msg=q):
                pol.check_request("GET", f"{B}/threads/{TID}{q}")
        for q in ("", "?access_token=x", "?fields=id", "?alt=json", "?format=minimal", "?fields=id,threadId,labelIds,snippet", "?fields=id,threadId,labelIds&fields=id"):
            with self.assertRaises(pol.Denied, msg=q):
                pol.check_request("POST", MODIFY_PATH + q, {"content-type": "application/json"}, pol.MODIFY_BODY)

    def test_exact_immutable_argument_types_are_required(self):
        class S(str):
            pass

        class By(bytes):
            pass
        h = {"content-type": "application/json"}
        for body in (bytearray(pol.MODIFY_BODY), By(pol.MODIFY_BODY), pol.MODIFY_BODY.decode(), memoryview(pol.MODIFY_BODY), list(pol.MODIFY_BODY)):
            with self.assertRaises(pol.Denied, msg=type(body)):
                pol.check_request("POST", MODIFY, h, body)
        for call in (lambda: pol.check_request("POST", S(MODIFY), h, pol.MODIFY_BODY), lambda: pol.check_request(S("POST"), MODIFY, h, pol.MODIFY_BODY),
                     lambda: pol.check_request("GET", S(PROFILE)), lambda: pol.check_request("GET", PROFILE, {S("accept"): "application/json"}),
                     lambda: pol.check_request("GET", PROFILE, {"accept": S("application/json")}), lambda: pol.check_request("GET", PROFILE, {}.items()),
                     lambda: pol.check_request("GET", PROFILE, None, bytearray(b"")), lambda: pol.check_request("GET", PROFILE, None, By(b"")),
                     lambda: pol.valid_id(S(MID)), lambda: pol.check_response(True, 0), lambda: pol.check_response(200, "5")):
            with self.assertRaises(pol.Denied):
                call()
        self.assertEqual(pol.check_request("POST", MODIFY, h, bytes(pol.MODIFY_BODY)), "MESSAGE_MODIFY")  # all permitted forms still pass
        self.assertEqual(pol.check_request("GET", PROFILE, None, b""), "PROFILE")

    def test_method_confusion_is_denied(self):
        for method, url, body in (("POST", PROFILE, None), ("POST", f"{B}/messages/{MID}{MSG_MIN}", None), ("GET", MODIFY, None), ("PUT", MODIFY, pol.MODIFY_BODY),
                                  ("DELETE", f"{B}/messages/{MID}{MSG_MIN}", None), ("PATCH", MODIFY, pol.MODIFY_BODY), ("HEAD", PROFILE, None), ("get", PROFILE, None),
                                  ("post", MODIFY, pol.MODIFY_BODY), ("GET ", PROFILE, None), ("OPTIONS", PROFILE, None), (None, PROFILE, None), (b"GET", PROFILE, None)):
            with self.assertRaises(pol.Denied, msg=method):
                pol.check_request(method, url, {"content-type": "application/json"} if body else None, body)

    def test_headers_cannot_override_the_method_carry_credentials_or_change_the_target(self):
        good = {"content-type": "application/json"}
        for headers in ({"X-HTTP-Method-Override": "DELETE"}, {"X-HTTP-Method": "DELETE"}, {"X-Method-Override": "GET"}, {"Authorization": "Bearer SYNTH-ACCESS-1"},
                        {"Host": "evil.example.invalid"}, {"Transfer-Encoding": "chunked"}, {"Content-Length": "5"}, {"X-Goog-Api-Key": "k"}, {"Cookie": "a=b"},
                        {"Content-Type": "text/plain"}, {"content-type": "application/json", "Content-Type": "application/json"}, {"Accept": "text/html"},
                        {"User-Agent": "bad\r\nX: y"}, {"User-Agent": "x" * 200}, {"content-type": "application/json\r\n"}, {"content-type": 5}, {5: "x"}, "headers", ["a"]):
            with self.assertRaises(pol.Denied, msg=headers):
                pol.check_request("POST", MODIFY, headers if isinstance(headers, dict) and "content-type" in {k.lower() for k in headers if isinstance(k, str)} else {**good, **headers} if isinstance(headers, dict) else headers, pol.MODIFY_BODY)
        with self.assertRaises(pol.Denied):  # the mutation must declare its content type
            pol.check_request("POST", MODIFY, {}, pol.MODIFY_BODY)
        with self.assertRaises(pol.Denied):  # a read must not
            pol.check_request("GET", PROFILE, {"content-type": "application/json"})
        with self.assertRaises(pol.Denied):  # a caller can never supply the credential header
            pol.check_request("GET", PROFILE, {"authorization": "Bearer SYNTH-ACCESS-1"})
        pol.check_request("GET", PROFILE, {"authorization": "Bearer SYNTH-ACCESS-1"}, allow_authorization=True)  # only the transport may
        for token in ("Basic abc", "Bearer ", "Bearer a b", "bearer SYNTH-ACCESS-1", "Bearer short", "Bearer x\r\nHost: y"):
            with self.assertRaises(pol.Denied, msg=token):
                pol.check_request("GET", PROFILE, {"authorization": token}, allow_authorization=True)

    def test_the_only_mutation_is_removing_inbox_from_one_message(self):
        h = {"content-type": "application/json"}
        bad_bodies = (b"", None, b"{}", b'{"removeLabelIds": ["INBOX"]}', b'{"removeLabelIds":["INBOX"] }', b'{"removeLabelIds":["INBOX","UNREAD"]}', b'{"removeLabelIds":["UNREAD"]}',
                      b'{"removeLabelIds":["inbox"]}', b'{"removeLabelIds":[]}', b'{"removeLabelIds":"INBOX"}', b'{"addLabelIds":["INBOX"]}', b'{"addLabelIds":["TRASH"],"removeLabelIds":["INBOX"]}',
                      b'{"removeLabelIds":["INBOX"],"addLabelIds":["Label_1"]}', b'{"removeLabelIds":["INBOX"],"addLabelIds":[]}', b'{"removeLabelIds":["INBOX"],"x":1}',
                      b'{"removeLabelIds":["\\u0049NBOX"]}', b'{"removeLabelIds":["INBOX"],"removeLabelIds":["INBOX"]}', b'[{"removeLabelIds":["INBOX"]}]', b'{"removeLabelIds":["SPAM"]}',
                      b'{"addLabelIds":["CATEGORY_PROMOTIONS"]}', b'{"removeLabelIds":["INBOX"]}\n', b' {"removeLabelIds":["INBOX"]}', b'{"removeLabelIds":["INBOX"]}' * 2, 5, "{", ["x"],
                      b'{"removeLabelIds":["TRASH"]}', b'{"addLabelIds":["TRASH"]}')
        for body in bad_bodies:
            with self.assertRaises(pol.Denied, msg=body):
                pol.check_request("POST", MODIFY, h, body)
        for body in (b"x", "x", {}, b"{}"):
            with self.assertRaises(pol.Denied):  # reads never carry a body
                pol.check_request("GET", PROFILE, None, body)

    def test_responses_redirects_and_size(self):
        pol.check_response(200, 10)
        pol.check_response(404, 10)
        for status in (301, 302, 303, 307, 308, 399):
            with self.assertRaises(pol.Denied) as ctx:
                pol.check_response(status, 0)
            self.assertEqual(ctx.exception.code, "DENIED_REDIRECT")
        with self.assertRaises(pol.Denied):
            pol.check_response(200, pol.MAX_RESPONSE + 1)

    def test_denials_never_echo_the_request(self):
        marker = "PATH-MARKER-SYNTH"
        for call in (lambda: pol.check_request("GET", f"{B}/messages/{marker}"), lambda: pol.check_request("GET", f"https://{marker}.example.invalid/x"),
                     lambda: pol.check_request(marker, PROFILE), lambda: pol.check_request("POST", MODIFY, {"content-type": "application/json"}, marker.encode()),
                     lambda: pol.check_request("GET", f"{B}/profile?{marker}=1"), lambda: pol.check_request("GET", PROFILE, {marker: "x"})):
            with self.assertRaises(pol.Denied) as ctx:
                call()
            self.assertNotIn(marker, str(ctx.exception) + repr(ctx.exception) + ctx.exception.code)
        self.assertEqual(set(pol._MESSAGES), {"DENIED_HOST", "DENIED_PATH", "DENIED_METHOD", "DENIED_QUERY", "DENIED_BODY", "DENIED_HEADER", "DENIED_REDIRECT", "DENIED_SIZE", "DENIED_BUDGET"})

    def test_strict_response_json(self):
        self.assertEqual(pol.parse_json(b'{"a":1}'), {"a": 1})
        for raw in (b"", b"[]", b"1", b"not json", b'{"a":1,"a":2}', b"\xff\xfe", b"null"):
            self.assertIsNone(pol.parse_json(raw), raw)


class TransportTests(Base):
    def test_archive_sends_exactly_one_bounded_post_and_reports_the_labels_after(self):
        net = Net(ok(id=MID, threadId=TID, labelIds=["Label_9"]))
        result = adapter(net).archive_message(MID)
        self.assertEqual(result.label_ids, ("Label_9",))
        self.assertTrue(result.inbox_removed)
        self.assertEqual(len(net.log), 1)
        sent = net.log[0]
        self.assertEqual((sent["method"], sent["body"]), ("POST", pol.MODIFY_BODY))
        self.assertEqual(sent["target"], f"/gmail/v1/users/me/messages/{MID}/modify?fields=id,threadId,labelIds")
        self.assertEqual(sent["headers"]["authorization"], "Bearer " + A_TOK)
        self.assertEqual(sent["headers"]["content-type"], "application/json")
        self.assertEqual(net.opened, net.closed, "the connection is always closed")
        self.assertNotIn("INBOX", result.label_ids)

    def test_a_still_present_inbox_is_reported_not_hidden(self):
        r = adapter(Net(ok(id=MID, threadId=TID, labelIds=["INBOX", "Label_9"]))).archive_message(MID)
        self.assertFalse(r.inbox_removed)

    def test_a_missing_label_list_means_an_empty_set_only_in_an_otherwise_complete_answer(self):
        r = adapter(Net(ok(id=MID, threadId=TID))).archive_message(MID)
        self.assertEqual((r.label_ids, r.inbox_removed), ((), True))
        with self.assertRaises(gw.UncertainOutcome):  # wrong id: not "complete", so never success
            adapter(Net(ok(id="18c0ffee0000ffff", threadId=TID))).archive_message(MID)
        with self.assertRaises(gw.ReadFailure):
            adapter(Net(ok(id=MID))).message_state(MID)  # no threadId

    def test_reads_use_only_allowed_get_requests(self):
        net = Net(ok(emailAddress=ACCOUNT), ok(id=MID, threadId=TID, labelIds=["INBOX", "Label_9"]), ok(id=TID, messages=[{"id": MID, "labelIds": ["INBOX"]}, {"id": "18c0ffee0000aaaa"}]))
        a = adapter(net)
        self.assertEqual(a._profile_email(), ACCOUNT)
        st = a.message_state(MID)
        self.assertEqual((st.thread_id, st.label_ids), (TID, ("INBOX", "Label_9")))
        self.assertEqual(a.thread_state(TID), ((MID, ("INBOX",)), ("18c0ffee0000aaaa", ())))
        self.assertEqual([r["method"] for r in net.log], ["GET", "GET", "GET"])
        self.assertTrue(all(r["body"] is None for r in net.log))
        self.assertEqual([r["target"] for r in net.log], ["/gmail/v1/users/me/profile?fields=emailAddress", f"/gmail/v1/users/me/messages/{MID}?format=minimal&fields=id,threadId,labelIds",
                                                           f"/gmail/v1/users/me/threads/{TID}?format=minimal&fields=id,messages/id,messages/labelIds"])

    def test_forbidden_requests_are_denied_before_any_connection_is_opened(self):
        net = Net()
        t = gw._Transport(WCreds(), net)
        for method, url, body in (("POST", f"{B}/messages/{MID}/trash", b"{}"), ("POST", f"{B}/messages/batchModify", b"{}"), ("POST", f"{B}/messages/send", b"{}"),
                                  ("POST", f"{B}/drafts", b"{}"), ("POST", f"{B}/threads/{TID}/modify", pol.MODIFY_BODY), ("POST", f"{B}/messages/{MID}/untrash", None),
                                  ("POST", f"{B}/messages/batchDelete", b"{}"), ("POST", f"{B}/messages/insert", b"{}"), ("DELETE", f"{B}/messages/{MID}{MSG_MIN}", None),
                                  ("POST", MODIFY, b'{"addLabelIds":["TRASH"],"removeLabelIds":["INBOX"]}'), ("POST", MODIFY, b'{"removeLabelIds":["UNREAD"]}'),
                                  ("GET", f"{B}/messages/{MID}?format=full", None), ("GET", f"{B}/messages/{MID}/attachments/{MID}", None),
                                  ("POST", pol.BASE + "/batch/gmail/v1", b"--b"), ("GET", "https://evil.example.invalid/gmail/v1/users/me/profile", None)):
            with self.assertRaises(pol.Denied, msg=(method, url)):
                t.perform(method, url, body)
        self.assertEqual((net.opened, net.log), (0, []))

    def test_the_wire_level_guard_stops_an_internal_bypass(self):
        net = Net()
        t = gw._Transport(WCreds(), net)
        headers = {"authorization": "Bearer " + A_TOK, "accept": "application/json"}
        for method, url, body in (("POST", f"{B}/messages/{MID}/trash", b"{}"), ("GET", f"{B}/messages/{MID}?format=raw", None),
                                  ("POST", MODIFY, b'{"addLabelIds":["TRASH"]}')):
            with self.assertRaises(pol.Denied):
                t._dispatch(method, url, body, dict(headers, **({"content-type": "application/json"} if body else {})))
        with self.assertRaises(pol.Denied):  # even a valid request with a smuggled override header
            t._dispatch("GET", PROFILE, None, dict(headers, **{"x-http-method-override": "DELETE"}))
        self.assertEqual((net.opened, net.log), (0, []))

    def test_redirects_are_never_followed_and_nothing_is_resent(self):
        net = Net((302, b""), ok(emailAddress=ACCOUNT))
        with self.assertRaises(pol.Denied) as ctx:  # a read: refused, never followed
            adapter(net)._profile_email()
        self.assertEqual((ctx.exception.code, len(net.log)), ("DENIED_REDIRECT", 1))
        for status in (301, 302, 303, 307, 308):  # the MUTATION was sent: a redirect says nothing about whether it happened
            net = Net((status, b""), ok(id=MID, threadId=TID, labelIds=[]))
            with self.assertRaises(gw.UncertainOutcome) as ctx:
                adapter(net).archive_message(MID)
            self.assertEqual((ctx.exception.code, len(net.log), net.opened), ("AMBIGUOUS_RESULT", 1, 1), status)  # the scripted success was never requested

    def test_no_automatic_retry_of_a_mutation_and_every_failure_has_a_closed_code(self):
        unknown = set(cleanup_exec.OUTCOME_CODES["UNKNOWN"])
        cases = ((TimeoutError("t"), "TIMEOUT"), (ConnectionResetError("r"), "NETWORK_ERROR"), (OSError("o"), "NETWORK_ERROR"), (ssl.SSLError("s"), "NETWORK_ERROR"),
                 (http.client.RemoteDisconnected("d"), "NETWORK_ERROR"), ((500, b"{}"), "SERVER_ERROR"), ((503, b"x"), "SERVER_ERROR"), ((200, b"garbage"), "AMBIGUOUS_RESULT"),
                 ((200, b"[]"), "AMBIGUOUS_RESULT"), ((204, b""), "AMBIGUOUS_RESULT"), ((418, b"{}"), "AMBIGUOUS_RESULT"), (ok(id=MID, threadId=TID, labelIds="INBOX"), "AMBIGUOUS_RESULT"))
        for item, code in cases:
            net = Net(item, ok(id=MID, threadId=TID, labelIds=[]))  # a second scripted success would reveal a retry
            with self.assertRaises(gw.UncertainOutcome, msg=item) as ctx:
                adapter(net).archive_message(MID)
            self.assertEqual((ctx.exception.code, len(net.log), net.opened), (code, 1, 1), item)
            self.assertIn(ctx.exception.code, unknown)
            self.assertEqual(net.opened, net.closed)

    def test_definite_rejections_are_not_uncertain(self):
        cases = ((gerr(400), gw.RequestRejected, "REJECTED"), (gerr(401), gw.WriteAuthError, "AUTH_PROBLEM"), (gerr(403), gw.WriteAuthError, "AUTH_PROBLEM"),
                 (gerr(404), gw.MessageNotFound, "NOT_FOUND"), (gerr(429), gw.RateLimited, "RATE_LIMITED"), (gerr(403, "rateLimitExceeded"), gw.RateLimited, "RATE_LIMITED"),
                 (gerr(403, "userRateLimitExceeded"), gw.RateLimited, "RATE_LIMITED"))
        for item, cls, code in cases:
            net = Net(item, ok(id=MID, threadId=TID, labelIds=[]))
            with self.assertRaises(cls, msg=item) as ctx:
                adapter(net).archive_message(MID)
            self.assertEqual((ctx.exception.code, len(net.log)), (code, 1))
            self.assertNotIsInstance(ctx.exception, gw.UncertainOutcome)
        self.assertIn("REJECTED", cleanup_exec.OUTCOME_CODES["NOT_APPLIED"])

    def test_an_unvalidated_error_answer_to_the_mutation_is_uncertain_not_a_rejection(self):
        wrong_code = json.dumps({"error": {"code": 500, "message": "x"}}).encode()
        for item in ((400, b"{}"), (404, b"<html>portal</html>"), (403, b""), (401, b"not json"), (429, b"[]"), (404, wrong_code), (400, b'{"error":"invalid_request"}'),
                     (403, json.dumps({"error": {"code": 403}}).encode()), (409, b"{}"), (410, gerr(410)[1]), (204, b""), (100, b"")):
            net = Net(item, ok(id=MID, threadId=TID, labelIds=[]))
            with self.assertRaises(gw.UncertainOutcome, msg=item) as ctx:
                adapter(net).archive_message(MID)
            self.assertEqual((ctx.exception.code, len(net.log)), ("AMBIGUOUS_RESULT", 1))

    def test_reads_fail_with_read_errors_not_outcome_codes(self):
        with self.assertRaises(gw.ReadFailure) as ctx:
            adapter(Net((500, b"{}")))._profile_email()
        self.assertEqual(ctx.exception.code, "SERVER_ERROR")
        for exc, code in ((OSError("x"), "NETWORK_ERROR"), (TimeoutError("t"), "TIMEOUT"), (ValueError("v"), "READ_FAILED")):
            with self.assertRaises(gw.ReadFailure) as ctx:  # reads never claim an uncertain MUTATION; they may simply be repeated
                adapter(Net(exc))._profile_email()
            self.assertEqual(ctx.exception.code, code)
        with self.assertRaises(gw.MessageNotFound):
            adapter(Net(gerr(404))).message_state(MID)
        with self.assertRaises(gw.ReadFailure):  # a 404 that is not a Gmail error document is not trusted either
            adapter(Net((404, b"<html>"))).message_state(MID)

    def test_an_expired_token_stops_the_call_with_no_refresh_and_no_connection(self):
        net = Net()
        creds = WCreds(minutes=-5)
        creds.refresh = mock.Mock(side_effect=AssertionError("the transport must never refresh"))
        for call in (lambda a: a._profile_email(), lambda a: a.message_state(MID), lambda a: a.archive_message(MID)):
            with self.assertRaises(gw.WriteAuthError):
                call(adapter(net, creds))
        self.assertEqual((net.opened, creds.refresh.call_count), (0, 0))

    def test_oversized_responses_and_the_request_budget_are_enforced(self):
        with self.assertRaises(pol.Denied) as ctx:
            adapter(Net((200, b"x" * (pol.MAX_RESPONSE + 5))))._profile_email()
        self.assertEqual(ctx.exception.code, "DENIED_SIZE")
        net = Net(ok(emailAddress=ACCOUNT), ok(emailAddress=ACCOUNT))
        with mock.patch.object(pol, "MAX_REQUESTS", 1):
            a = adapter(net)
            a._profile_email()
            with self.assertRaises(pol.Denied) as ctx:
                a._profile_email()
        self.assertEqual((ctx.exception.code, len(net.log)), ("DENIED_BUDGET", 1))

    def test_ids_must_be_lowercase_hex_before_any_request(self):
        net = Net()
        a = adapter(net)
        for bad in ("", "../x", MID.upper(), MID + "/modify", "g" * 5, None, 5, MID + "%2F", "a" * 40):
            for call in (a.message_state, a.thread_state, a.archive_message):
                with self.assertRaises(pol.Denied):
                    call(bad)
        self.assertEqual(net.opened, 0)

    def test_errors_and_reprs_never_leak_tokens_ids_accounts_or_urls(self):
        outputs = []
        for item in (TimeoutError(A_TOK + MID), (500, (A_TOK + MID).encode()), (401, b"{}"), (404, b"{}"), (200, (A_TOK + MID).encode()), (307, b"")):
            try:
                adapter(Net(item)).archive_message(MID)
            except Exception as exc:  # noqa: BLE001
                outputs += [str(exc), repr(exc), getattr(exc, "code", "")]
        a = adapter(Net())
        outputs += [repr(a), repr(adapter(Net(ok(id=MID, threadId=TID, labelIds=["Label_9"]))).archive_message(MID)), repr(adapter(Net(ok(id=MID, threadId=TID, labelIds=[]))).message_state(MID))]
        for text in outputs:
            for private in PRIVATE:
                self.assertNotIn(private, text, text)
            self.assertNotIn("googleapis", text)

    def test_the_adapter_exposes_no_http_client_token_credentials_or_generic_service(self):
        public = {n for n in dir(gw.ArchiveAdapter) if not n.startswith("_")}
        self.assertEqual(public, {"verify_account", "message_state", "thread_state", "observe", "archive_message"})
        a = adapter(Net())
        self.assertFalse(hasattr(a, "__dict__"))
        self.assertEqual(gw.ArchiveAdapter.__slots__, ("_t", "_expected", "_issuer"))
        for banned in ("service", "http", "creds", "credentials", "token", "request", "execute", "users", "messages", "modify", "trash", "send", "batch_modify", "transport"):
            self.assertFalse(hasattr(a, banned), banned)
        for bad_class in (gw.MessageState, gw.ArchiveResult):
            self.assertFalse(hasattr(bad_class(*(["t", ()] if bad_class is gw.MessageState else [()])), "__dict__"))

    def test_account_verification_is_an_explicit_live_step_that_fails_closed(self):
        a = adapter(Net(ok(emailAddress=ACCOUNT.upper())))
        a.verify_account()  # case-insensitive match
        with self.assertRaises(gw.AccountMismatch) as ctx:
            adapter(Net(ok(emailAddress=ACCOUNT_OTHER))).verify_account()
        self.assertEqual(ctx.exception.code, "ACCOUNT_MISMATCH")
        self.assertNotIn(ACCOUNT_OTHER, str(ctx.exception))
        with self.assertRaises(gw.ReadFailure):
            adapter(Net(ok(emailAddress=""))).verify_account()

    def test_the_default_connection_is_plain_verified_tls_to_the_gmail_host_only(self):
        with mock.patch.object(http.client, "HTTPSConnection") as conn:
            gw._default_connection()
        args, kwargs = conn.call_args
        self.assertEqual(args, (pol.HOST,))
        self.assertEqual(kwargs["timeout"], gw.TIMEOUT)
        ctx = kwargs["context"]
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_REQUIRED, True))
        self.assertNotIn("proxy", " ".join(kwargs))
        with self.assertRaises(AssertionError):  # sanity: the base class blocks real sockets
            import socket
            with socket.socket() as sock:
                sock.connect(("127.0.0.1", 9))

    def test_no_test_in_this_module_uses_the_default_connection(self):
        with mock.patch.object(gw, "_default_connection", side_effect=AssertionError("real connection")):
            self.assertEqual(adapter(Net(ok(emailAddress=ACCOUNT)))._profile_email(), ACCOUNT)


class BrokenConn:
    """Connection that fails at a chosen step; records which steps were reached."""
    def __init__(self, net, step, exc):
        self.net, self.step, self.exc = net, step, exc

    def request(self, method, target, body=None, headers=None):
        self.net.log.append({"method": method, "target": target})
        if self.step == "request":
            raise self.exc

    def getresponse(self):
        if self.step == "getresponse":
            raise self.exc

        class R:
            status, length = 200, 0

            def __init__(s, step, exc):
                s.step, s.exc = step, exc

            def read(s, n=-1):
                if s.step == "read":
                    raise s.exc
                return b"{}"

            def getheaders(s):
                return [("Content-Length", "2")]
        if self.step == "status":
            class Bad:
                length = 0

                @property
                def status(s):
                    raise self.exc

                def read(s, n=-1):
                    return b"{}"

                def getheaders(s):
                    return []
            return Bad()
        return R(self.step, self.exc)

    def close(self):
        self.net.closed += 1


class BreakNet(Net):
    def __init__(self, step, exc):
        super().__init__()
        self.step, self.exc = step, exc

    def __call__(self):
        self.opened += 1
        if self.step == "connect":
            raise self.exc
        return BrokenConn(self, self.step, self.exc)


class MutationUncertaintyTests(Base):
    def test_refusals_before_any_connection_are_definite_and_never_uncertain(self):
        net = Net()
        for call, cls in ((lambda: gw._Transport(WCreds(), net).perform("POST", f"{B}/messages/{MID}/trash", b"{}"), pol.Denied),
                          (lambda: gw._Transport(WCreds(), net).perform("POST", MODIFY, b'{"addLabelIds":["TRASH"]}'), pol.Denied),
                          (lambda: adapter(net, WCreds(minutes=-5)).archive_message(MID), gw.WriteAuthError),
                          (lambda: adapter(net).archive_message("../x"), pol.Denied)):
            with self.assertRaises(cls) as ctx:
                call()
            self.assertNotIsInstance(ctx.exception, gw.UncertainOutcome)
        with mock.patch.object(pol, "MAX_REQUESTS", 0):
            with self.assertRaises(pol.Denied) as ctx:
                adapter(net).archive_message(MID)
            self.assertEqual(ctx.exception.code, "DENIED_BUDGET")
        self.assertEqual((net.opened, net.log), (0, []))  # no connection was even created

    def test_every_failure_after_dispatch_began_is_uncertain_even_creating_the_connection(self):
        boom = (RuntimeError("secret " + A_TOK), KeyError(MID), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"), http.client.IncompleteRead(b"x"),
                BrokenPipeError(), ConnectionResetError(), TimeoutError(), ssl.SSLError("x"), OSError(), ValueError("v"), http.client.BadStatusLine("x"))
        for step in ("connect", "request", "getresponse", "read", "status"):
            for exc in boom:
                net = BreakNet(step, exc)
                with self.assertRaises(gw.UncertainOutcome, msg=(step, exc)) as ctx:
                    adapter(net).archive_message(MID)
                self.assertIn(ctx.exception.code, ("TIMEOUT", "NETWORK_ERROR", "AMBIGUOUS_RESULT"))
                self.assertNotIn(A_TOK, str(ctx.exception) + repr(ctx.exception))
                self.assertEqual(net.opened, 1, "no retry")
                if step != "connect":
                    self.assertEqual(net.opened, net.closed, "connection closed on the failure path")

    def test_post_dispatch_oversized_malformed_and_wrong_answers_are_uncertain_never_denied_or_rejected(self):
        for item in ((200, b"x" * (pol.MAX_RESPONSE + 1)), (302, b""), (200, b""), (200, b"{"), (200, b'{"id":"%s"' % MID.encode()), (200, b'{"id":"%s","id":"%s"}' % (MID.encode(), MID.encode())),
                     (200, json.dumps({"id": "18c0ffee0000ffff"}).encode()), (200, json.dumps({"id": MID, "threadId": TID, "labelIds": [5]}).encode()),
                     (200, json.dumps({"id": MID, "labelIds": ["x" * 80]}).encode()), (500, b""), (502, b"<html>"), (301, b"x")):
            net = Net(item, ok(id=MID, threadId=TID, labelIds=[]))
            with self.assertRaises(gw.UncertainOutcome, msg=item[0]) as ctx:
                adapter(net).archive_message(MID)
            self.assertNotIsInstance(ctx.exception, (pol.Denied, gw.RequestRejected))
            self.assertEqual((len(net.log), net.opened), (1, 1))

    def test_the_uncertain_codes_are_stable_and_usable_for_reconciliation(self):
        unknown = set(cleanup_exec.OUTCOME_CODES["UNKNOWN"])
        seen = set()
        for item in (TimeoutError(), OSError(), (500, b""), (302, b""), (200, b"junk")):
            with self.assertRaises(gw.UncertainOutcome) as ctx:
                adapter(Net(item)).archive_message(MID)
            seen.add(ctx.exception.code)
        self.assertTrue(seen <= unknown, seen)
        self.assertEqual(seen, {"TIMEOUT", "NETWORK_ERROR", "SERVER_ERROR", "AMBIGUOUS_RESULT"})
        self.assertNotIn("NOT_APPLIED", seen | unknown)

    def test_a_genuine_inbox_removal_is_still_reported_deterministically(self):
        r = adapter(Net(ok(id=MID, threadId=TID, labelIds=["Label_9"]))).archive_message(MID)
        self.assertEqual((r.label_ids, r.inbox_removed), (("Label_9",), True))


class AccountGateTests(Base):
    def test_a_new_adapter_cannot_archive_until_the_live_account_is_verified(self):
        net = Net(ok(id=MID, threadId=TID, labelIds=[]))
        a = adapter(net, verified=False)
        with self.assertRaises(gw.AccountNotVerified) as ctx:
            a.archive_message(MID)
        self.assertEqual((ctx.exception.code, net.opened), ("ACCOUNT_NOT_VERIFIED", 0))
        net = Net(ok(emailAddress=ACCOUNT), ok(id=MID, threadId=TID, labelIds=[]))
        a = adapter(net, verified=False)
        a.verify_account()
        self.assertTrue(a.archive_message(MID).inbox_removed)
        self.assertEqual([r["method"] for r in net.log], ["GET", "POST"])

    def test_mismatch_malformed_or_failed_lookups_lock_modification(self):
        for lookup in (ok(emailAddress=ACCOUNT_OTHER), ok(emailAddress=""), ok(emailAddress=5), ok(emailAddress=None), ok(), (200, b"junk"), (500, b"{}"), (404, b"{}"),
                       gerr(401), OSError("x"), TimeoutError()):
            net = Net(lookup, ok(id=MID, threadId=TID, labelIds=[]))
            a = adapter(net, verified=False)
            with self.assertRaises(gw.WriteTransportError):
                a.verify_account()
            with self.assertRaises(gw.AccountNotVerified):
                a.archive_message(MID)
            self.assertEqual([r["method"] for r in net.log], ["GET"], lookup)  # the mutation was never sent

    def test_a_verified_adapter_loses_its_state_after_a_later_identity_or_authorization_problem(self):
        ok_profile = ok(emailAddress=ACCOUNT)
        a = adapter(Net(ok_profile, ok(emailAddress=ACCOUNT_OTHER), ok(id=MID, threadId=TID, labelIds=[])), verified=False)
        a.verify_account()
        with self.assertRaises(gw.AccountMismatch):  # a later check finds another account
            a.verify_account()
        with self.assertRaises(gw.AccountNotVerified):
            a.archive_message(MID)
        a = adapter(Net(ok_profile, gerr(401), ok(id=MID, threadId=TID, labelIds=[])), verified=False)
        a.verify_account()
        with self.assertRaises(gw.WriteAuthError):  # any authorization problem on a later call
            a.message_state(MID)
        with self.assertRaises(gw.AccountNotVerified):
            a.archive_message(MID)
        a = adapter(Net(ok_profile, OSError("x"), ok(id=MID, threadId=TID, labelIds=[])), verified=False)
        a.verify_account()
        with self.assertRaises(gw.ReadFailure):  # a failed re-verification also locks
            a.verify_account()
        with self.assertRaises(gw.AccountNotVerified):
            a.archive_message(MID)

    def test_the_expected_account_must_be_real_and_is_checked_against_the_live_profile_only(self):
        for expected in (None, "", "  ", 5):
            a = adapter(Net(ok(emailAddress=ACCOUNT)), expected=expected, verified=False)
            with self.assertRaises(gw.AccountMismatch):
                a.verify_account()
        a = adapter(Net(ok(emailAddress=" " + ACCOUNT.upper() + " ")), verified=False)
        a.verify_account()  # case and surrounding whitespace do not matter, nothing else does

    def test_internal_paths_cannot_bypass_the_verification_gate(self):
        url = MODIFY
        for label, call in (("private _call", lambda a: a._call("POST", url, pol.MODIFY_BODY)), ("transport.perform", lambda a: a._t.perform("POST", url, pol.MODIFY_BODY)),
                            ("transport._dispatch", lambda a: a._t._dispatch("POST", url, pol.MODIFY_BODY, {"authorization": "Bearer " + A_TOK, "accept": "application/json", "content-type": "application/json"}))):
            net = Net(ok(id=MID, threadId=TID, labelIds=[]))
            a = adapter(net, verified=False)
            with self.assertRaises(gw.AccountNotVerified, msg=label):
                call(a)
            self.assertEqual((net.opened, net.log), (0, []), label)  # refused before any connection exists
        # reads are not gated, and the allowlist still applies to everything
        net = Net(ok(id=MID, threadId=TID, labelIds=[]))
        a = adapter(net, verified=False)
        self.assertEqual(a.message_state(MID).label_ids, ())
        net = Net(ok(emailAddress=ACCOUNT), ok(id=MID, threadId=TID, labelIds=[]))
        a = adapter(net, verified=False)
        a.verify_account()
        self.assertTrue(a._call("POST", MODIFY, pol.MODIFY_BODY))  # after verification the private path works - and is still allowlisted
        for url2, body in ((f"{B}/messages/{MID}/trash", b"{}"), (MODIFY, b'{"addLabelIds":["TRASH"]}')):
            with self.assertRaises(pol.Denied):
                a._call("POST", url2, body)

    def test_the_gate_state_lives_in_the_transport_and_a_transport_serves_one_adapter(self):
        net = Net(ok(emailAddress=ACCOUNT), ok(id=MID, threadId=TID, labelIds=[]))
        a = adapter(net, verified=False)
        a.verify_account()
        self.assertTrue(a._t._allowed)
        with self.assertRaises(ValueError):  # a second adapter (another expected account) cannot ride on a verified transport
            gw.ArchiveAdapter(a._t, ACCOUNT_OTHER)
        b = adapter(Net(), verified=False, expected=ACCOUNT_OTHER)  # its own transport: starts locked
        with self.assertRaises(gw.AccountNotVerified):
            b.archive_message(MID)
        a._verified = False
        with self.assertRaises(gw.AccountNotVerified):
            a._t.perform("POST", MODIFY, pol.MODIFY_BODY)


class WireSock:
    """Fake socket under the REAL http.client: records the bytes written and replays a canned response."""
    def __init__(self, response=b"", fail_send=None):
        import io

        class Reader(io.BytesIO):
            def close(self):  # the HTTPResponse closes its file object; keep the synthetic bytes inspectable and silent
                pass
        self.sent, self.closed, self.fail_send, self.resp = b"", False, fail_send, Reader(response)

    def sendall(self, data):
        if self.fail_send:
            raise self.fail_send
        self.sent += data

    def makefile(self, mode="r", bufsize=None):
        return self.resp

    def close(self):
        self.closed = True

    def settimeout(self, value):
        pass


def wire(status_line, headers, body):
    return status_line + b"\r\n" + b"".join(h + b"\r\n" for h in headers) + b"\r\n" + body


def framed(body, *headers, status=b"HTTP/1.1 200 OK"):
    return wire(status, [b"Content-Length: %d" % len(body), *headers], body)


GOOD = json.dumps({"id": MID, "threadId": TID, "labelIds": ["Label_9"]}).encode()
GOOD_STATE = json.dumps({"id": MID, "threadId": TID, "labelIds": ["INBOX"]}).encode()


class HttpFramingTests(Base):
    """The lowest-level reader, exercised with the real http.client over fake sockets."""

    def run_case(self, raw, op):
        sock = WireSock(raw)
        box = {"opened": 0}

        def factory():
            box["opened"] += 1
            c = http.client.HTTPSConnection(pol.HOST, timeout=30, context=ssl.create_default_context())
            c.sock = sock
            return c
        a = adapter(Net())
        a._t._factory = factory
        try:
            result = op(a)
            error = None
        except Exception as exc:  # noqa: BLE001
            result, error = None, exc
        self.assertEqual(box["opened"], 1, "exactly one connection, no retry")
        self.assertTrue(sock.closed, "the connection is closed on every path")
        self.assertLessEqual(sock.sent.count(b"POST "), 1)
        return result, error

    archive = staticmethod(lambda a: a.archive_message(MID))
    read = staticmethod(lambda a: a.message_state(MID))

    def test_well_framed_responses_are_accepted(self):
        for label, raw in (("content-length", framed(GOOD)), ("chunked", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked"], b"%x\r\n" % len(GOOD) + GOOD + b"\r\n0\r\n\r\n")),
                           ("close-delimited", wire(b"HTTP/1.1 200 OK", [b"Connection: close"], GOOD)), ("identity coding", framed(GOOD, b"Content-Encoding: identity")),
                           ("extra bytes after the announced length", framed(GOOD) + b"EXTRA")):
            result, error = self.run_case(raw, self.archive)
            self.assertIsNone(error, label)
            self.assertEqual(result.label_ids, ("Label_9",), label)

    def bad_framing(self):
        long_body = json.dumps({"id": MID, "threadId": TID, "labelIds": []}).encode()
        chunk = lambda b: b"%x\r\n" % len(b) + b + b"\r\n0\r\n\r\n"  # noqa: E731
        return (("short body", wire(b"HTTP/1.1 200 OK", [b"Content-Length: %d" % (len(GOOD) + 400)], GOOD)),
                ("empty body for a positive length", wire(b"HTTP/1.1 200 OK", [b"Content-Length: 60"], b"")),
                ("truncated chunk", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked"], b"%x\r\n" % len(GOOD) + GOOD[:10])),
                ("missing terminating chunk", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked"], b"%x\r\n" % len(GOOD) + GOOD + b"\r\n")),
                ("bad chunk size", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked"], b"zz\r\n" + GOOD + b"\r\n0\r\n\r\n")),
                ("length and chunked together", wire(b"HTTP/1.1 200 OK", [b"Content-Length: %d" % len(GOOD), b"Transfer-Encoding: chunked"], chunk(GOOD))),
                ("two identical lengths", wire(b"HTTP/1.1 200 OK", [b"Content-Length: %d" % len(GOOD), b"Content-Length: %d" % len(GOOD)], GOOD)),
                ("two different lengths", wire(b"HTTP/1.1 200 OK", [b"Content-Length: 5", b"Content-Length: %d" % len(GOOD)], GOOD)),
                ("non numeric length", wire(b"HTTP/1.1 200 OK", [b"Content-Length: abc"], GOOD)),
                ("signed length", wire(b"HTTP/1.1 200 OK", [b"Content-Length: +%d" % len(GOOD)], GOOD)),
                ("negative length", wire(b"HTTP/1.1 200 OK", [b"Content-Length: -1"], GOOD)),
                ("gzip transfer coding", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: gzip"], GOOD)),
                ("chunked plus gzip", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked, gzip"], chunk(GOOD))),
                ("two transfer codings", wire(b"HTTP/1.1 200 OK", [b"Transfer-Encoding: chunked", b"Transfer-Encoding: chunked"], chunk(GOOD))),
                ("gzip content coding", framed(GOOD, b"Content-Encoding: gzip")),
                ("two content codings", framed(GOOD, b"Content-Encoding: identity", b"Content-Encoding: identity")),
                ("garbage status line", b"garbage\r\n\r\n"), ("empty answer", b""), ("html body", framed(b"<html>")),
                ("redirect", wire(b"HTTP/1.1 307 Temporary Redirect", [b"Location: https://evil.invalid/", b"Content-Length: 0"], b"")),
                ("oversized declared and delivered", wire(b"HTTP/1.1 200 OK", [b"Content-Length: %d" % (pol.MAX_RESPONSE + 50)], b"x" * (pol.MAX_RESPONSE + 50))),
                ("oversized announced, short delivered", wire(b"HTTP/1.1 200 OK", [b"Content-Length: %d" % (pol.MAX_RESPONSE + 50)], b"x" * 10)),
                ("valid json different id", framed(long_body.replace(MID.encode(), b"18c0ffee0000ffff"))))

    def test_ambiguous_framing_of_the_mutation_response_is_uncertain_never_success(self):
        for label, raw in self.bad_framing():
            result, error = self.run_case(raw, self.archive)
            self.assertIsNone(result, label)
            self.assertIsInstance(error, gw.UncertainOutcome, label)
            self.assertIn(error.code, set(cleanup_exec.OUTCOME_CODES["UNKNOWN"]), label)
            for private in (A_TOK, MID, TID, "googleapis"):
                self.assertNotIn(private, str(error) + repr(error), label)

    def test_ambiguous_framing_of_a_read_is_a_safe_read_error(self):
        for label, raw in self.bad_framing():
            if label in ("valid json different id", "redirect", "oversized declared and delivered"):
                continue  # id mismatch / policy refusals (Denied) are asserted separately below
            raw = raw.replace(GOOD, GOOD_STATE) if GOOD in raw else raw
            result, error = self.run_case(raw, self.read)
            self.assertIsNone(result, label)
            self.assertIsInstance(error, gw.ReadFailure, label)
        result, error = self.run_case(wire(b"HTTP/1.1 302 Found", [b"Location: https://evil.invalid/", b"Content-Length: 0"], b""), self.read)
        self.assertIsInstance(error, pol.Denied)
        self.assertEqual(error.code, "DENIED_REDIRECT")

    def test_a_well_framed_read_is_accepted_and_the_wire_request_is_exactly_one_get(self):
        sock = WireSock(framed(GOOD_STATE))
        a = adapter(Net())
        a._t._factory = lambda: _preset(sock)
        st = a.message_state(MID)
        self.assertEqual(st.label_ids, ("INBOX",))
        line = sock.sent.split(b"\r\n")[0]
        self.assertEqual(line, b"GET /gmail/v1/users/me/messages/%s?format=minimal&fields=id,threadId,labelIds HTTP/1.1" % MID.encode())
        self.assertNotIn(b"Transfer-Encoding", sock.sent)

    def test_non_bytes_bodies_never_escape_as_raw_errors(self):
        for body in (None, "str", [1], 5, bytearray(b"{}"), object()):
            class Resp:
                status, length = 200, 0

                def read(self, n=-1, body=body):
                    return body

                def getheaders(self):
                    return []

                def isclosed(self):
                    return True

            class Conn:
                def request(self, *a, **k):
                    pass

                def getresponse(self):
                    return Resp()

                def close(self):
                    pass
            for op, cls in ((self.archive, gw.UncertainOutcome), (self.read, gw.ReadFailure)):
                a = adapter(Net())
                a._t._factory = Conn
                with self.assertRaises(cls, msg=type(body)):
                    op(a)

    def test_a_failure_while_transmitting_the_request_is_uncertain_for_the_mutation(self):
        sock = WireSock(fail_send=BrokenPipeError())
        a = adapter(Net())
        a._t._factory = lambda: _preset(sock)
        with self.assertRaises(gw.UncertainOutcome) as ctx:
            a.archive_message(MID)
        self.assertEqual(ctx.exception.code, "NETWORK_ERROR")
        self.assertTrue(sock.closed)


def _preset(sock):
    c = http.client.HTTPSConnection(pol.HOST, timeout=30, context=ssl.create_default_context())
    c.sock = sock
    return c


class OpenAdapterTests(WBase):
    def setUp(self):
        super().setUp()
        self.path = self.write_client_file()

    def test_builds_from_local_state_only_without_refresh_network_or_prompt(self):
        self.write_blob()
        net = Net()
        with mock.patch("builtins.input", side_effect=AssertionError("prompt")), mock.patch.object(oauth_write, "refresh_write_credentials", side_effect=AssertionError("refresh")):
            a = gw.open_archive_adapter(ACCOUNT, self.wstore, self.path, connection_factory=net)
        self.assertIsInstance(a, gw.ArchiveAdapter)
        self.assertEqual((net.opened, net.log), (0, []))  # nothing is verified with Google until the separately approved live step
        with self.assertRaises(gw.AccountNotVerified):  # and until then the adapter cannot modify anything
            a.archive_message(MID)
        self.assertEqual(net.opened, 0)

    def test_refuses_without_a_record_on_account_client_or_validity_problems(self):
        with self.assertRaisesRegex(oauth.AuthError, "no write authorization"):
            gw.open_archive_adapter(ACCOUNT, self.wstore, self.path)
        self.write_blob()
        with self.assertRaises(gw.AccountMismatch):
            gw.open_archive_adapter(ACCOUNT_OTHER, self.wstore, self.path)
        other = self.write_client_file(client_id="400000000004-othersynth03.apps.googleusercontent.com")
        with self.assertRaisesRegex(oauth.AuthError, "different OAuth client"):
            gw.open_archive_adapter(ACCOUNT, self.wstore, other)
        self.wstore.delete()
        self.write_client_file()  # restore the matching client file
        short = oauth_write.write_blob(WCreds(minutes=5), ACCOUNT, [oauth_write.WRITE_SCOPE], write_client_config())
        self.wstore.save(short)
        with self.assertRaisesRegex(oauth.AuthError, "10 minutes"):
            gw.open_archive_adapter(ACCOUNT, self.wstore, self.path)

    def test_never_falls_back_to_the_read_only_token(self):
        self.stored_blob()  # only a read-only token exists
        with self.assertRaisesRegex(oauth.AuthError, "no write authorization"):
            gw.open_archive_adapter(ACCOUNT, self.wstore, self.path)

    def test_fetch_profile_email_is_a_single_allowed_read(self):
        net = Net(ok(emailAddress=ACCOUNT))
        self.assertEqual(gw.fetch_profile_email(WCreds(), net), ACCOUNT)
        self.assertEqual([(r["method"], r["target"]) for r in net.log], [("GET", "/gmail/v1/users/me/profile?fields=emailAddress")])


if __name__ == "__main__":
    unittest.main()
