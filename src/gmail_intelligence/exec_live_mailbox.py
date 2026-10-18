"""The REAL-execution boundary (M4 live-integration preparation): DISABLED, with no entry point. Nothing here is enabled, reachable from the CLI or exercised against Gmail.

`LiveMailbox` is the only object the live entry points of the executor accept. It wraps a genuine `gmail_write.ArchiveAdapter` (archive-only policy: remove INBOX from one
message; profile, message and thread reads) and exposes exactly the port the executor already uses: `clock`, `account`, `verify_account`, `message_state`, `thread_state`,
`archive_message`, `observe`. It deliberately has NO undo, no label creation, no delete, no send and no other Gmail operation.

What keeps it safe, in order of strength:
  * `LIVE_EXECUTION_ENABLED` is a constant in this source file and is `False`. Nothing in the program changes it; enabling live execution is a source change that needs the
    owner's separate approval. Every construction and every live executor step re-reads it, so disabling it stops a run before its next request.
  * There is no production entry point: the CLI never imports this module (a static test enforces it), and `cleanup execute` stays disabled.
  * The mailbox has no clock parameter (time is the controlled UTC clock of this process) and no connection-factory or transport parameter on the public constructor
    `open_live_mailbox`; the HTTPS transport is the adapter's own default (host-pinned by the request policy, no redirects, no proxy, no retry, no refresh).
  * `LiveMailbox` is final and immutable, and its wiring is re-verified before every item and right before every POST.
The fake-only APIs and the `FakeMailbox` restrictions are unchanged; a live mailbox is refused by them and a fake mailbox is refused by the live entry points.

Like every in-process guard this is a barrier against mistakes and ordinary callers, not against deliberate reflection by code running in the same process.
"""
from datetime import datetime, timezone

from gmail_intelligence import gmail_write as gw

LIVE_EXECUTION_ENABLED = False


class LiveExecutionDisabled(Exception):
    """Live execution is switched off in this build. Fixed message; never ids, accounts or tokens."""
    code = "LIVE_DISABLED"

    def __init__(self):
        super().__init__("live Gmail execution is disabled in this build")


def _utcnow():
    return datetime.now(timezone.utc)


def _require_enabled():
    if LIVE_EXECUTION_ENABLED is not True:
        raise LiveExecutionDisabled()


class LiveMailbox:
    """Final, immutable port over a real archive adapter. Build it only with `open_live_mailbox`."""
    __slots__ = ("_adapter", "_account", "_test_factory")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("LiveMailbox is final")

    def __init__(self, *, _adapter, _account, _test_factory=None):
        for name, value in (("_adapter", _adapter), ("_account", _account), ("_test_factory", _test_factory)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("a LiveMailbox is immutable")

    def __delattr__(self, name):
        raise AttributeError("a LiveMailbox is immutable")

    def __repr__(self):
        return "<LiveMailbox>"

    # ---- the port the executor uses (nothing else is exposed: no undo, no other Gmail operation)
    def clock(self):
        return _utcnow()

    @property
    def account(self):
        return self._account

    def verify_account(self):
        return self._adapter.verify_account()

    def message_state(self, message_id):
        return self._adapter.message_state(message_id)

    def thread_state(self, thread_id):
        return self._adapter.thread_state(thread_id)

    def archive_message(self, message_id):
        _require_enabled()
        return self._adapter.archive_message(message_id)

    def observe(self, message_id, *, context):
        return self._adapter.observe(message_id, context=context)


def live_wiring_ok(mailbox):
    """True only if the mailbox still wraps the adapter it was built with: exact adapter and transport types, the adapter's own default HTTPS connection (or, for offline
    tests only, the one fake factory it was built with), and the expected account. Does not check the enabled switch."""
    try:
        adapter = mailbox._adapter
        transport = adapter._t
        factory = transport._factory
        expected_factory = mailbox._test_factory if mailbox._test_factory is not None else gw._default_connection
        return (type(mailbox) is LiveMailbox and type(adapter) is gw.ArchiveAdapter and type(transport) is gw._Transport and factory is expected_factory
                and isinstance(mailbox._account, str) and adapter._expected == mailbox._account)
    except AttributeError:
        return False


def _wrap(adapter, expected_account, test_factory=None):
    """Wrap a genuine adapter. `test_factory` exists only so offline tests can put a recording fake wire under the real adapter code; no production caller passes it."""
    _require_enabled()
    if type(adapter) is not gw.ArchiveAdapter or not isinstance(expected_account, str) or not expected_account.strip() or adapter._expected != expected_account:
        raise ValueError("a live mailbox needs a genuine archive adapter for the expected account")
    box = LiveMailbox(_adapter=adapter, _account=expected_account, _test_factory=test_factory)
    if not live_wiring_ok(box):
        raise ValueError("the archive adapter is not wired to the default transport")
    return box


def open_live_mailbox(expected_account, store, client_path):
    """Build the live mailbox from the stored WRITE authorization (local checks only: no refresh, no network, no prompt). Raises LiveExecutionDisabled first, before the
    store is touched. There is no clock, connection-factory or transport parameter. Nothing in this build calls it."""
    _require_enabled()
    adapter = gw.open_archive_adapter(expected_account, store, client_path)
    return _wrap(adapter, expected_account)
