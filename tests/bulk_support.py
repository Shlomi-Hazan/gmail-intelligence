"""Shared synthetic infrastructure for the M12D bulk archive / bulk reversal tests (not a test module). Fake Gmail wire, mocked credentials, a controlled step clock: no Gmail, no OAuth, no
Keychain, no network. The live gates are patched on for one test at a time."""
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cleanup_canary as TC  # noqa: E402
from test_cleanup import ACCT, msg  # noqa: E402
from test_cleanup_executor import LABELS  # noqa: E402

from gmail_intelligence import cleanup_bulk as bulk, cleanup_exec as ce, cleanup_plans as cp, exec_fake_mailbox as fm, exec_live_mailbox as live, gmail_write as gw  # noqa: E402


class BulkBase(TC.CanaryBase):
    """N synthetic promotional messages (`N`, default 130 -> slices [25, 100, 5]); `SHARED` maps a message number to the thread of another message (siblings in one thread)."""
    N = 130
    SHARED = {}

    def mid(self, i):
        return f"18c0ffee{i:08x}"

    def thread(self, i):
        return f"28c0ffee{self.SHARED.get(i, i):08x}"

    def bids(self, n=None):
        return [self.mid(i) for i in range(1, (n or self.N) + 1)]

    def messages(self):
        return [dict(msg(i, sender=f"s{i}@shop.example.test"), id=self.mid(i), thread_id=self.thread(i)) for i in range(1, self.N + 1)]

    def fake_state(self, extra=None):
        state = {self.mid(i): (self.thread(i), list(LABELS)) for i in range(1, self.N + 1)}
        state.update(extra or {})
        return state

    # ---- archive side
    def prepare_bulk(self, n=None, script=()):
        """An APPROVED plan of n messages, RESERVED (typed phrase) but not started; live execution switched on; the adapter's default connection replaced by the fake wire."""
        plan = self.approved_plan(self.bids(n))
        self.enable()
        self.svc = fm._Service(ACCT, self.fake_state(), tuple(script))
        patcher = mock.patch.object(gw, "_default_connection", fm._Factory(self.svc))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = TC.RecordingStore(self.blob())
        ex = ce.reserve_execution(self.index, ACCT, plan["plan_id"], ce.execution_phrase(plan, ce.plan_slices(plan["item_count"])[0]), now=self.clk())
        return plan, ex

    def confirmed_slice(self, ex):
        (sl,) = [s for s in ce.slices(self.index, ACCT, ex["exec_id"]) if s["state"] == "CONFIRMED"]
        return sl

    def run_phrase(self, ex):
        plan = cp.get_plan(self.index, ACCT, ex["plan_id"])
        confirmed = [s for s in ce.slices(self.index, ACCT, ex["exec_id"]) if s["state"] == "CONFIRMED"]
        if len(confirmed) != 1:
            return "RUN (no slice is confirmed)"
        return bulk.run_phrase(plan, ex["exec_id"], confirmed[0]["slice_no"], confirmed[0]["size"])

    def run_slice(self, ex, phrase=None):
        return bulk.run_bulk_slice(self.index, ACCT, ex["exec_id"], self.run_phrase(ex) if phrase is None else phrase, self.store, self.client_path)

    def confirm_next(self, ex, phrase=None):
        plan = cp.get_plan(self.index, ACCT, ex["plan_id"])
        sl = [s for s in ce.slices(self.index, ACCT, ex["exec_id"]) if s["state"] == "PENDING"][0]
        ce.confirm_slice(self.index, ACCT, ex["exec_id"], sl["slice_no"], ce.continuation_phrase(plan, sl["slice_no"], sl["size"]) if phrase is None else phrase, now=self.clk())
        return sl["slice_no"]

    def run_all(self, ex):
        """Every slice with its own confirmations, as an owner would (used by tests that need a finished execution)."""
        out = [self.run_slice(ex)]
        while ce.get_execution(self.index, ACCT, ex["exec_id"])["state"] == "AWAITING_CONTINUATION":
            self.confirm_next(ex)
            out.append(self.run_slice(ex))
        return out

    def exec_row(self, ex):
        return ce.get_execution(self.index, ACCT, ex["exec_id"])

    def archived_ids(self):
        return sorted(m for m, (t, labels) in self.svc.messages.items() if "INBOX" not in labels)
