"""Synthetic fake Gmail for the M7 sync tests: a ground-truth mailbox with a monotonic history log. No network, no real data (.test addresses only).

The reader API matches `gmail.GmailReader` (get_profile, list_label_details, list_message_ids, get_message_metadata, list_history). Faults, reordering,
duplicates, token expiry and history expiry are injectable. Every call is recorded in `calls`; a tripwire fails any write-capable attribute.
"""
import random

from gmail_intelligence import gmail

ACCOUNT = "owner@example.test"
BASE_MS = 1_700_000_000_000


class FakeHistoryMailbox:
    WRITE_NAMES = ("send", "modify", "batchModify", "trash", "untrash", "delete", "insert", "import_", "drafts", "create", "update", "patch")

    def __init__(self, account=ACCOUNT, seed=1):
        self.account = account
        self.msgs = {}
        self.hid = 100
        self.events = []  # {"id": int, "type": "added"|"deleted"|"labels", "m": message id}
        self.labels = [{"id": "INBOX", "name": "INBOX", "type": "system"}, {"id": "UNREAD", "name": "UNREAD", "type": "system"},
                       {"id": "Label_1", "name": "Private Label Name", "type": "user"}]
        self.expired_before = 0
        self.calls = []
        self.faults = {}            # method name -> list of exceptions raised (and popped) on successive calls
        self.shuffle = False
        self.duplicate = False
        self.expire_tokens = set()  # history page tokens that raise 404 once
        self.truncate_history_after = None  # silently drop nextPageToken after this many pages (an undetectable fault)
        self.profile_total = None   # override messagesTotal
        self.profile_history_id = None
        self.hooks = {}             # call count of a method -> callable run BEFORE the call is served: {("get_message_metadata", 3): fn}
        self.rng = random.Random(seed)
        self.counts = {}
        self._n = 0

    # ---- ground-truth mutations (each is one history event with a fresh history id) ----
    def _event(self, kind, mid):
        self.hid += 1
        self.events.append({"id": self.hid, "type": kind, "m": mid})

    def add(self, mid, labels=("INBOX",), sender=None, thread=None, size=1000):
        self._n += 1
        self.msgs[mid] = {"id": mid, "thread_id": thread or f"t-{mid}", "internal_ms": BASE_MS + self._n * 1000, "size": size,
                          "sender": sender or f"{mid}@sender.example.test", "label_ids": sorted(set(labels))}
        self._event("added", mid)

    def labels_change(self, mid, add=(), remove=()):
        cur = set(self.msgs[mid]["label_ids"])
        cur |= set(add)
        cur -= set(remove)
        self.msgs[mid]["label_ids"] = sorted(cur)
        self._event("labels", mid)

    def delete(self, mid):
        del self.msgs[mid]
        self._event("deleted", mid)

    def script(self, ops):
        """Apply a serializable list of operations: ["add", id, [labels]], ["labels", id, [add], [remove]], ["delete", id]."""
        for op in ops:
            if op[0] == "add":
                self.add(op[1], tuple(op[2]) if len(op) > 2 else ("INBOX",))
            elif op[0] == "labels":
                self.labels_change(op[1], op[2], op[3])
            elif op[0] == "delete":
                self.delete(op[1])

    # ---- reader API ----
    def _tick(self, name):
        self.calls.append(name)
        self.counts[name] = self.counts.get(name, 0) + 1
        fn = self.hooks.pop((name, self.counts[name]), None)
        if fn:
            fn()
        queue = self.faults.get(name)
        if queue:
            raise queue.pop(0)

    def get_profile(self):
        self._tick("get_profile")
        total = len(self.msgs) if self.profile_total is None else self.profile_total
        hid = self.hid if self.profile_history_id is None else self.profile_history_id
        return {"emailAddress": self.account, "messagesTotal": total, "threadsTotal": total, "historyId": str(hid)}

    def list_label_details(self):
        self._tick("list_label_details")
        return [dict(x) for x in self.labels]

    def list_message_ids(self, page_token=None, max_results=500):
        self._tick("list_message_ids")
        ids = [m["id"] for m in sorted(self.msgs.values(), key=lambda m: (-m["internal_ms"], m["id"]))]
        start = int(page_token[1:]) if page_token else 0
        nxt = f"o{start + max_results}" if start + max_results < len(ids) else None
        return ids[start:start + max_results], nxt

    def get_message_metadata(self, message_id):
        self._tick("get_message_metadata")
        if message_id not in self.msgs:
            raise gmail.GmailNotFoundError("gone", 404)
        return dict(self.msgs[message_id], label_ids=list(self.msgs[message_id]["label_ids"]))

    def list_history(self, start_history_id, page_token=None, max_results=100):
        self._tick("list_history")
        start = int(start_history_id)
        if start < self.expired_before:
            raise gmail.GmailHistoryNotFoundError("expired", 404)
        if page_token in self.expire_tokens:
            self.expire_tokens.discard(page_token)
            raise gmail.GmailHistoryNotFoundError("token expired", 404)
        evs = [e for e in self.events if e["id"] > start]
        pages = [evs[i:i + max_results] for i in range(0, len(evs), max_results)] or [[]]
        n = int(page_token[1:]) if page_token else 0
        chunk = list(pages[n])
        if self.shuffle:
            self.rng.shuffle(chunk)
        records = []
        for e in chunk:
            rec = {"id": str(e["id"]), "added": [], "deleted": [], "labels": []}
            rec[{"added": "added", "deleted": "deleted", "labels": "labels"}[e["type"]]] = [e["m"]]
            records.append(rec)
            if self.duplicate:
                records.append(dict(rec))
        nxt = f"h{n + 1}" if n + 1 < len(pages) else None
        if self.truncate_history_after is not None and n + 1 >= self.truncate_history_after:
            nxt = None
        return {"records": records, "next": nxt, "history_id": str(self.hid)}

    def __getattr__(self, name):  # tripwire: no write-capable method exists
        if name in self.WRITE_NAMES or name.startswith("_write"):
            raise AssertionError(f"write-capable call attempted: {name}")
        raise AttributeError(name)


def standard_mailbox(n=12, account=ACCOUNT):
    m = FakeHistoryMailbox(account)
    for i in range(n):
        m.add(f"m{i:03d}", ("INBOX", "UNREAD") if i % 3 == 0 else ("INBOX",))
    return m
