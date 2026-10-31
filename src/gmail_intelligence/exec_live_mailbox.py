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

M12C.3 adds a SECOND, independent final type, `LiveUndoMailbox`, behind its own constant `LIVE_UNDO_ENABLED` (also False, also a source constant that nothing changes, also never
read from the environment). It wraps an adapter whose transport holds the UNDO capability only and exposes `restore_inbox` (and the same reads) but NO `archive_message`; `LiveMailbox`
wraps an ARCHIVE-only adapter and has no `restore_inbox`. Neither switch enables the other: archive execution never authorizes undo and undo never authorizes archive.

M12C.4 adds a THIRD final type, `LiveObserveMailbox`, behind `LIVE_OBSERVE_ENABLED` (False): a READ-ONLY port (account verification, message and thread labels, trusted execution-bound observations) over
an adapter whose transport holds the OBSERVE capability only. It is what a future live recovery / reconciliation uses; it cannot archive or undo and neither mutation switch enables it (nor it them).

Like every in-process guard this is a barrier against mistakes and ordinary callers, not against deliberate reflection by code running in the same process.
"""
from datetime import datetime, timezone

from gmail_intelligence import exec_fake_mailbox as fm, gmail_write as gw

LIVE_EXECUTION_ENABLED = False
LIVE_OBSERVE_ENABLED = False  # M12C.4: the switch of LIVE read-only observation (recovery / reconciliation); independent of both mutation switches; same rules: a source constant, False, nothing flips it
LIVE_UNDO_ENABLED = False  # M12C.3: the independent switch of the live archive-undo path; same rules as above (a source constant, False in this build, nothing flips it)
_BULK_PERMIT = object()  # module-private capability: only `cleanup_bulk.run_bulk_slice` passes it to the live slice entry point (a static test enforces it)
_CANARY_PERMIT = object()  # module-private capability: only `cleanup_canary.run_canary` passes it to the live batch entry point (a static test enforces it)
_MINT = object()  # module-private: only `_wrap` holds it, so an ordinary caller cannot construct a LiveMailbox directly (and so cannot choose its wiring)


class LiveExecutionDisabled(Exception):
    """Live execution is switched off in this build. Fixed message; never ids, accounts or tokens."""
    code = "LIVE_DISABLED"

    def __init__(self):
        super().__init__("live Gmail execution is disabled in this build")


class LiveObserveDisabled(Exception):
    """Live read-only observation is switched off in this build. Fixed message; never ids, accounts or tokens."""
    code = "LIVE_OBSERVE_DISABLED"

    def __init__(self):
        super().__init__("live Gmail observation is disabled in this build")


class LiveUndoDisabled(Exception):
    """Live archive undo is switched off in this build. Fixed message; never ids, accounts or tokens."""
    code = "LIVE_UNDO_DISABLED"

    def __init__(self):
        super().__init__("live Gmail archive undo is disabled in this build")


def _utcnow():
    return datetime.now(timezone.utc)


def _require_enabled():
    if LIVE_EXECUTION_ENABLED is not True:
        raise LiveExecutionDisabled()


def _require_observe_enabled():
    if LIVE_OBSERVE_ENABLED is not True:
        raise LiveObserveDisabled()


def _require_undo_enabled():
    if LIVE_UNDO_ENABLED is not True:
        raise LiveUndoDisabled()


class LiveMailbox:
    """Final, immutable port over a real archive adapter. Build it only with `open_live_mailbox`."""
    __slots__ = ("_adapter", "_account", "_test_factory")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("LiveMailbox is final")

    def __init__(self, *, _mint, _adapter, _account, _test_factory=None):
        if _mint is not _MINT:
            raise TypeError("a LiveMailbox can only be built by open_live_mailbox")
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
        _require_enabled()
        return self._adapter.verify_account()

    def message_state(self, message_id):
        _require_enabled()
        return self._adapter.message_state(message_id)

    def thread_state(self, thread_id):
        _require_enabled()
        return self._adapter.thread_state(thread_id)

    def archive_message(self, message_id):
        _require_enabled()
        return self._adapter.archive_message(message_id)

    def observe(self, message_id, *, context):
        _require_enabled()
        return self._adapter.observe(message_id, context=context)


def live_wiring_ok(mailbox):
    """True only if the mailbox still wraps the adapter it was built with: exact adapter and transport types, the adapter's own default HTTPS connection (or, for offline
    tests only, the in-memory fake wire `exec_fake_mailbox._Factory` it was built with: a factory of any other type is never accepted, so a real connection cannot be
    substituted through the test seam), and the expected account. Does not check the enabled switch."""
    try:
        adapter = mailbox._adapter
        transport = adapter._t
        factory = transport._factory
        expected_factory = mailbox._test_factory if mailbox._test_factory is not None else gw._default_connection
        if mailbox._test_factory is not None and type(mailbox._test_factory) is not fm._Factory:
            return False
        return (type(mailbox) is LiveMailbox and type(adapter) is gw.ArchiveAdapter and type(transport) is gw._Transport and factory is expected_factory
                and transport._caps == frozenset({"ARCHIVE"}) and isinstance(mailbox._account, str) and adapter._expected == mailbox._account)
    except AttributeError:
        return False


def _wrap(adapter, expected_account, test_factory=None):
    """Wrap a genuine adapter. `test_factory` exists only so offline tests can put a recording fake wire under the real adapter code; no production caller passes it."""
    _require_enabled()
    if type(adapter) is not gw.ArchiveAdapter or not isinstance(expected_account, str) or not expected_account.strip() or adapter._expected != expected_account:
        raise ValueError("a live mailbox needs a genuine archive adapter for the expected account")
    box = LiveMailbox(_mint=_MINT, _adapter=adapter, _account=expected_account, _test_factory=test_factory)
    if not live_wiring_ok(box):
        raise ValueError("the archive adapter is not wired to the default transport (or, in offline tests, the in-memory fake wire)")
    return box


def open_live_mailbox(expected_account, store, client_path):
    """Build the live mailbox from the stored WRITE authorization (local checks only: no refresh, no network, no prompt). Raises LiveExecutionDisabled first, before the
    store is touched. There is no clock, connection-factory or transport parameter. Nothing in this build calls it."""
    _require_enabled()
    adapter = gw.open_archive_adapter(expected_account, store, client_path)
    return _wrap(adapter, expected_account)


class LiveUndoMailbox:
    """Final, immutable port over a real adapter holding the UNDO capability only (M12C.3). Build it only with `open_live_undo_mailbox`. Every method re-reads LIVE_UNDO_ENABLED.

    It exposes the reads the undo engine needs and `restore_inbox`; it has NO `archive_message`, and its transport refuses the archive request before any dispatch."""
    __slots__ = ("_adapter", "_account", "_test_factory")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("LiveUndoMailbox is final")

    def __init__(self, *, _mint, _adapter, _account, _test_factory=None):
        if _mint is not _MINT_UNDO:
            raise TypeError("a LiveUndoMailbox can only be built by open_live_undo_mailbox")
        for name, value in (("_adapter", _adapter), ("_account", _account), ("_test_factory", _test_factory)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("a LiveUndoMailbox is immutable")

    def __delattr__(self, name):
        raise AttributeError("a LiveUndoMailbox is immutable")

    def __repr__(self):
        return "<LiveUndoMailbox>"

    def clock(self):
        return _utcnow()

    @property
    def account(self):
        return self._account

    def verify_account(self):
        _require_undo_enabled()
        return self._adapter.verify_account()

    def message_state(self, message_id):
        _require_undo_enabled()
        return self._adapter.message_state(message_id)

    def thread_state(self, thread_id):
        _require_undo_enabled()
        return self._adapter.thread_state(thread_id)

    def restore_inbox(self, message_id):
        _require_undo_enabled()
        return self._adapter.restore_inbox(message_id).label_ids

    def observe(self, message_id, *, context):
        _require_undo_enabled()
        return self._adapter.observe(message_id, context=context)


_MINT_UNDO = object()  # module-private: only `_wrap_undo` holds it


def live_undo_wiring_ok(mailbox):
    """True only if the undo mailbox still wraps the adapter it was built with: exact adapter and transport types, the adapter's own default HTTPS connection (or, for offline tests
    only, the in-memory fake wire it was built with), the UNDO capability and nothing else, and the expected account. Does not check the enabled switch."""
    try:
        adapter = mailbox._adapter
        transport = adapter._t
        factory = transport._factory
        expected_factory = mailbox._test_factory if mailbox._test_factory is not None else gw._default_connection
        if mailbox._test_factory is not None and type(mailbox._test_factory) is not fm._Factory:
            return False
        return (type(mailbox) is LiveUndoMailbox and type(adapter) is gw.ArchiveAdapter and type(transport) is gw._Transport and factory is expected_factory
                and transport._caps == frozenset({"UNDO"}) and isinstance(mailbox._account, str) and adapter._expected == mailbox._account)
    except AttributeError:
        return False


def _wrap_undo(adapter, expected_account, test_factory=None):
    """Wrap a genuine UNDO-capable adapter. `test_factory` exists only so offline tests can put a recording fake wire under the real adapter code; no production caller passes it."""
    _require_undo_enabled()
    if type(adapter) is not gw.ArchiveAdapter or not isinstance(expected_account, str) or not expected_account.strip() or adapter._expected != expected_account:
        raise ValueError("a live undo mailbox needs a genuine adapter for the expected account")
    box = LiveUndoMailbox(_mint=_MINT_UNDO, _adapter=adapter, _account=expected_account, _test_factory=test_factory)
    if not live_undo_wiring_ok(box):
        raise ValueError("the adapter is not an undo-only adapter wired to the default transport (or, in offline tests, the in-memory fake wire)")
    return box


def open_live_undo_mailbox(expected_account, store, client_path):
    """Build the live undo mailbox from the stored WRITE authorization (local checks only: no refresh, no network, no prompt). Raises LiveUndoDisabled first, before the store is
    touched. There is no clock, connection-factory or transport parameter. Nothing in this build calls it successfully: the switch is False."""
    _require_undo_enabled()
    adapter = gw.open_undo_adapter(expected_account, store, client_path)
    return _wrap_undo(adapter, expected_account)


class LiveObserveMailbox:
    """Final, immutable READ-ONLY port over a real adapter holding the OBSERVE capability only (M12C.4). Build it only with `open_live_observe_mailbox`. Every method re-reads
    LIVE_OBSERVE_ENABLED (independent of the archive and undo switches).

    It exposes `verify_account`, `message_state`, `thread_state` and `observe`: no archive, no undo, no other Gmail operation; its transport refuses both modify requests."""
    __slots__ = ("_adapter", "_account", "_test_factory")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("LiveObserveMailbox is final")

    def __init__(self, *, _mint, _adapter, _account, _test_factory=None):
        if _mint is not _MINT_OBSERVE:
            raise TypeError("a LiveObserveMailbox can only be built by open_live_observe_mailbox")
        for name, value in (("_adapter", _adapter), ("_account", _account), ("_test_factory", _test_factory)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("a LiveObserveMailbox is immutable")

    def __delattr__(self, name):
        raise AttributeError("a LiveObserveMailbox is immutable")

    def __repr__(self):
        return "<LiveObserveMailbox>"

    def clock(self):
        return _utcnow()

    @property
    def account(self):
        return self._account

    def verify_account(self):
        _require_observe_enabled()
        return self._adapter.verify_account()

    def message_state(self, message_id):
        _require_observe_enabled()
        return self._adapter.message_state(message_id)

    def thread_state(self, thread_id):
        _require_observe_enabled()
        return self._adapter.thread_state(thread_id)

    def observe(self, message_id, *, context):
        _require_observe_enabled()
        return self._adapter.observe(message_id, context=context)


_MINT_OBSERVE = object()  # module-private: only `_wrap_observe` holds it


def live_observe_wiring_ok(mailbox):
    """True only if the observe mailbox still wraps the adapter it was built with: exact adapter and transport types, the adapter's own default HTTPS connection (or, for offline tests
    only, the in-memory fake wire it was built with), the OBSERVE capability and nothing else, and the expected account. Does not check the enabled switch."""
    try:
        adapter = mailbox._adapter
        transport = adapter._t
        factory = transport._factory
        expected_factory = mailbox._test_factory if mailbox._test_factory is not None else gw._default_connection
        if mailbox._test_factory is not None and type(mailbox._test_factory) is not fm._Factory:
            return False
        return (type(mailbox) is LiveObserveMailbox and type(adapter) is gw.ArchiveAdapter and type(transport) is gw._Transport and factory is expected_factory
                and transport._caps == frozenset({"OBSERVE"}) and isinstance(mailbox._account, str) and adapter._expected == mailbox._account)
    except AttributeError:
        return False


def _wrap_observe(adapter, expected_account, test_factory=None):
    """Wrap a genuine OBSERVE-capable adapter. `test_factory` exists only so offline tests can put a recording fake wire under the real adapter code; no production caller passes it."""
    _require_observe_enabled()
    if type(adapter) is not gw.ArchiveAdapter or not isinstance(expected_account, str) or not expected_account.strip() or adapter._expected != expected_account:
        raise ValueError("a live observe mailbox needs a genuine adapter for the expected account")
    box = LiveObserveMailbox(_mint=_MINT_OBSERVE, _adapter=adapter, _account=expected_account, _test_factory=test_factory)
    if not live_observe_wiring_ok(box):
        raise ValueError("the adapter is not an observe-only adapter wired to the default transport (or, in offline tests, the in-memory fake wire)")
    return box


def open_live_observe_mailbox(expected_account, store, client_path):
    """Build the live observe mailbox from the stored WRITE authorization (local checks only: no refresh, no network, no prompt). Raises LiveObserveDisabled first, before the store is
    touched. There is no clock, connection-factory or transport parameter. Nothing in this build calls it successfully: the switch is False."""
    _require_observe_enabled()
    adapter = gw.open_observe_adapter(expected_account, store, client_path)
    return _wrap_observe(adapter, expected_account)
