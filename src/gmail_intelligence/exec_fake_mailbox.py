"""FAKE-ONLY synthetic Gmail mailbox for the M4C-C2 executor. It contacts nothing: no socket, no credential, no Keychain, no Google service.

`FakeMailbox` is the only mailbox type the C2 executor accepts. It cannot be given credentials, a connection factory or a transport: its constructor takes
a synthetic account, plain message data, a clock and an optional fault script, and it builds its own in-memory "Gmail" and a connection class that answers
from that memory. The real `ArchiveAdapter` code (policy checks, framing checks, dispatch markers, observations) runs on top of it, so the executor is
exercised against the genuine error behaviour, but every byte stays in this process.

This is test infrastructure shipped in `src` only so that the executor can check the exact type of its mailbox. It is not a production component.
"""
import json
import re
from dataclasses import dataclass
from datetime import datetime

from gmail_intelligence import gmail_write as gw, gmail_write_policy as pol

FAKE_ONLY = True
_NOT_FOUND = (404, json.dumps({"error": {"code": 404, "message": "Requested entity was not found.", "errors": [{"reason": "notFound"}],
                                         "status": "NOT_FOUND"}}).encode())
_ROUTES = ((re.compile(r"^/gmail/v1/users/me/profile$"), "PROFILE"),
           (re.compile(r"^/gmail/v1/users/me/messages/([0-9a-f]+)/modify$"), "POST"),
           (re.compile(r"^/gmail/v1/users/me/messages/([0-9a-f]+)$"), "GET_MESSAGE"),
           (re.compile(r"^/gmail/v1/users/me/threads/([0-9a-f]+)$"), "GET_THREAD"))


@dataclass(frozen=True)
class Step:
    """One scripted deviation for the `nth` request of a kind (PROFILE, GET_MESSAGE, GET_THREAD or POST).

    `before(fake)` runs before the request is answered (a concurrent change by someone else); `after(fake)` runs after it was answered normally.
    `raises` makes the fake wire raise that exception; `status`/`body` make it answer something else. For a POST, `apply=True` means that the mutation
    DID happen before the failure (the ambiguous case the executor must treat as possibly dispatched).
    """
    request: str
    nth: int = 1
    before: object = None
    after: object = None
    raises: object = None
    status: object = None
    body: bytes = b""
    apply: bool = False


class _FakeCreds:
    """Not a credential: a stand-in object with the two attributes the transport reads."""
    token = "synthetic-placeholder"

    def __init__(self):
        self.live = True

    @property
    def valid(self):
        return self.live


class _Service:
    def __init__(self, account, messages, script):
        self.account = account
        self.messages = {mid: [tid, set(labels)] for mid, (tid, labels) in messages.items()}
        self.script, self.counts, self.log = list(script), {}, []
        self.creds = _FakeCreds()

    # ---- helpers for tests that play "someone else" changing the mailbox
    def set_labels(self, mid, labels):
        self.messages[mid][1] = set(labels)

    def add_message(self, mid, tid, labels):
        self.messages[mid] = [tid, set(labels)]

    def remove_message(self, mid):
        self.messages.pop(mid, None)

    def posts(self):
        return sum(1 for kind, _ in self.log if kind == "POST")

    def undos(self):
        return sum(1 for kind, _ in self.log if kind == "UNDO")

    def undo(self, key):
        """The in-memory service's answer to the undo request (POST .../modify with the fixed undo body): put INBOX back on one message. It is reached through the real adapter and
        the real request policy; only the Gmail side is simulated."""
        self.counts["UNDO"] = n = self.counts.get("UNDO", 0) + 1
        self.log.append(("UNDO", key))
        step = next((s for s in self.script if s.request == "UNDO" and s.nth == n), None)
        if step is not None and step.before:
            step.before(self)
        if step is not None and (step.raises is not None or step.status is not None):
            if step.apply and key in self.messages:
                self.messages[key][1].add("INBOX")
            if step.raises is not None:
                raise step.raises
            return step.status, step.body
        if key not in self.messages:
            return _NOT_FOUND
        self.messages[key][1].add("INBOX")
        answer = self._json(200, self._message(key))
        if step is not None and step.after:
            step.after(self)
        return answer

    def _json(self, status, obj):
        return status, json.dumps(obj).encode()

    def _message(self, mid):
        tid, labels = self.messages[mid]
        obj = {"id": mid, "threadId": tid}
        if labels:
            obj["labelIds"] = sorted(labels)
        return obj

    def _normal(self, kind, key):
        if kind == "PROFILE":
            return self._json(200, {"emailAddress": self.account})
        if kind in ("GET_MESSAGE", "POST") and key not in self.messages:
            return _NOT_FOUND
        if kind == "GET_MESSAGE":
            return self._json(200, self._message(key))
        if kind == "POST":
            self.messages[key][1].discard("INBOX")
            return self._json(200, self._message(key))
        members = sorted(m for m, (tid, _) in self.messages.items() if tid == key)
        if not members:
            return _NOT_FOUND
        return self._json(200, {"id": key, "messages": [dict(id=m, **({"labelIds": sorted(self.messages[m][1])} if self.messages[m][1] else {})) for m in members]})

    def handle(self, method, target, body):
        path = target.split("?", 1)[0]
        for rx, kind in _ROUTES:
            m = rx.match(path)
            if m:
                break
        else:
            raise AssertionError("the fake mailbox does not serve this request")
        key = m.group(1) if m.groups() else None
        if kind == "POST" and method == "POST" and body == pol.UNDO_BODY:
            return self.undo(key)  # the one undo mutation: its own counter, log entry and fault-script kind ("UNDO")
        self.counts[kind] = n = self.counts.get(kind, 0) + 1
        self.log.append((kind, key))
        if kind == "POST" and (method != "POST" or body != pol.MODIFY_BODY):
            raise AssertionError("unexpected mutation request")  # (an undo request is dispatched before this point)
        step = next((s for s in self.script if s.request == kind and s.nth == n), None)
        if step is None:
            return self._normal(kind, key)
        if step.before:
            step.before(self)
        if step.raises is not None or step.status is not None:
            if kind == "POST" and step.apply and key in self.messages:
                self.messages[key][1].discard("INBOX")
            if step.raises is not None:
                raise step.raises
            return step.status, step.body
        answer = self._normal(kind, key)
        if step.after:
            step.after(self)
        return answer


class _Response:
    length = 0

    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def getheaders(self):
        return [("Content-Length", str(len(self._body)))]

    def isclosed(self):
        return True


class _Connection:
    def __init__(self, service):
        self._service, self._answer = service, None

    def request(self, method, target, body=None, headers=None):
        self._answer = self._service.handle(method, target, body)

    def getresponse(self):
        return _Response(*self._answer)

    def close(self):
        pass


class _Factory:
    def __init__(self, service):
        self._service = service

    def __call__(self):
        return _Connection(self._service)


def wiring_is_fake(mailbox):
    """True only if this FakeMailbox still routes every request to its own in-memory service: the exact adapter, transport, credentials and connection
    factory types it was built with, all pointing at its own service. The executor checks this at the start and again right before the archive POST.
    Defence in depth against a swapped inner object; it is NOT a guarantee against deliberate reflection by code in the same process."""
    try:
        adapter = mailbox._adapter
        transport = adapter._t
        factory = transport._factory
        return (type(mailbox) is FakeMailbox and type(adapter) is gw.ArchiveAdapter and type(transport) is gw._Transport and type(factory) is _Factory
                and type(transport._creds) is _FakeCreds and factory._service is mailbox._service and transport._creds is mailbox._service.creds)
    except AttributeError:
        return False


class FakeMailbox:
    """The one mailbox type the C2 executor accepts. Final and immutable; no credential, factory or transport can be supplied or replaced by assignment."""
    __slots__ = ("_service", "_adapter", "_clock")
    FAKE_ONLY = True

    def __init_subclass__(cls, **kwargs):
        raise TypeError("FakeMailbox is final")

    def __init__(self, account, messages, *, clock, script=()):
        if type(account) is not str or not account.strip() or not callable(clock):
            raise ValueError("a fake mailbox needs a synthetic account and a clock")
        if not isinstance(messages, dict) or not all(re.fullmatch(r"[0-9a-f]{1,32}", str(mid)) and re.fullmatch(r"[0-9a-f]{1,32}", str(v[0]))
                                                       for mid, v in messages.items()):
            raise ValueError("messages must map hex message ids to (hex thread id, labels)")
        service = _Service(account.strip(), messages, tuple(script))
        for name, value in (("_service", service), ("_clock", clock),
                            ("_adapter", gw.ArchiveAdapter(gw._Transport(service.creds, _Factory(service), capabilities=("ARCHIVE", "UNDO")), account.strip(), _clock=clock))):  # test infrastructure: both
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("a FakeMailbox is immutable: its adapter, service and clock cannot be replaced")

    def __delattr__(self, name):
        raise AttributeError("a FakeMailbox is immutable")

    def __repr__(self):
        return "<FakeMailbox>"

    # ---- the port the executor uses
    def clock(self):
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("the clock must return an aware datetime")
        return value

    @property
    def account(self):
        return self._service.account

    def verify_account(self):
        return self._adapter.verify_account()

    def message_state(self, message_id):
        return self._adapter.message_state(message_id)

    def thread_state(self, thread_id):
        return self._adapter.thread_state(thread_id)

    def archive_message(self, message_id):
        return self._adapter.archive_message(message_id)

    def observe(self, message_id, *, context):
        return self._adapter.observe(message_id, context=context)

    def restore_inbox(self, message_id):
        """Undo of an archive through the REAL adapter code and request policy (the fixed undo body), answered by the in-memory service. Returns the labels Gmail's answer reported.
        Failures carry the adapter's dispatch markers: `dispatched=False` only for refusals proven to be before any transmission."""
        return self._adapter.restore_inbox(message_id).label_ids

    # ---- inspection and "someone else" controls for tests
    @property
    def service(self):
        return self._service
