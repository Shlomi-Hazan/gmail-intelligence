"""Trusted observations for the cleanup execution state (M4C-C1). Stdlib only; no Gmail, OAuth, Keychain, network or database code.

A `TrustedObservation` is what a designated archive adapter hands to the execution state machine as evidence of one message's label
state. What it can and cannot establish:
  * it was issued by an adapter object that had verified the account, for exactly one account and one message;
  * it is valid once (the token is consumed), for a short time, and only if the adapter still holds its verification;
  * it reports an OBSERVED state at a time T. It never proves that this application changed anything: the owner or another client could have.

The guard is an IN-PROCESS capability boundary against accidents and ordinary callers (a private mint object, a final type, per-issuer
one-time tokens). It is NOT a cryptographic guarantee: code running in the same Python process can bypass any such guard. Tokens live in
memory only; nothing here survives a restart, and a consumed token stays consumed for the life of its issuer.
"""
import secrets
import threading
from datetime import datetime, timedelta, timezone

MAX_AGE = timedelta(minutes=5)  # an observation older than this (against the caller's clock) is refused
MAX_PENDING = 1024
_MINT = object()  # module-private capability: only this module's issuer holds it, callers cannot build an observation without it
_seal_lock = threading.Lock()
_seal_claimed = False


class _AdapterSeal:
    """The one capability that lets an adapter create issuers. Handed out exactly once, to the first claimant (the Gmail write adapter module)."""
    __slots__ = ()


_THE_SEAL = _AdapterSeal()


def claim_adapter_seal():
    """Called once, at import time, by the module that implements the archive adapter. A second claim fails loudly, so a module that claimed
    the seal first (for example to mint test observations) makes the real adapter module refuse to load instead of silently sharing it."""
    global _seal_claimed
    with _seal_lock:
        if _seal_claimed:
            raise ObservationError("the adapter seal was already claimed")
        _seal_claimed = True
        return _THE_SEAL


class ObservationError(Exception):
    """Refusal with a fixed, privacy-safe message (never ids, labels or tokens)."""


def _aware(value):
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


class TrustedObservation:
    """One observed label state: `present` with an explicit `labels` tuple (possibly empty), or definitively absent (`labels` is None)."""
    __slots__ = ("account", "message_id", "present", "labels", "observed_at", "_issuer", "_nonce")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("TrustedObservation is final")

    def __init__(self, *, _mint, account, message_id, present, labels, observed_at, issuer, nonce):
        if _mint is not _MINT:
            raise TypeError("a TrustedObservation can only be issued by an adapter")
        if (type(account) is not str or not account or type(message_id) is not str or not message_id or type(present) is not bool
                or not _aware(observed_at) or type(nonce) is not str or type(issuer) is not ObservationIssuer):
            raise ObservationError("invalid observation fields")
        if present:
            if type(labels) is not tuple or len(labels) > 100 or not all(type(x) is str and 0 < len(x) <= 64 and x.isascii() for x in labels):
                raise ObservationError("a present message needs an explicit labels tuple")
        elif labels is not None:
            raise ObservationError("an absent message has no labels")
        for name, value in (("account", account), ("message_id", message_id), ("present", present), ("labels", labels),
                            ("observed_at", observed_at.astimezone(timezone.utc)), ("_issuer", issuer), ("_nonce", nonce)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("a TrustedObservation is immutable")

    def __delattr__(self, name):
        raise AttributeError("a TrustedObservation is immutable")

    def __repr__(self):
        return "<TrustedObservation>"

    def __reduce__(self):
        raise TypeError("a TrustedObservation cannot be copied or pickled")

    def __copy__(self):
        raise TypeError("a TrustedObservation cannot be copied or pickled")

    def __deepcopy__(self, memo):
        raise TypeError("a TrustedObservation cannot be copied or pickled")


class ObservationIssuer:
    """Belongs to exactly one adapter and one account; issues one-time tokens and nothing else."""
    __slots__ = ("_account", "_clock", "_pending", "_lock")

    def __init__(self, *, _mint, account, clock):
        if _mint is not _MINT:
            raise TypeError("an issuer can only be created through new_issuer()")
        self._account, self._clock, self._pending, self._lock = account, clock, set(), threading.Lock()

    def __repr__(self):
        return "<ObservationIssuer>"

    def issue(self, message_id, present, labels):
        """Mint one observation stamped by the injected clock. The caller (the adapter) must have verified the account first."""
        observed_at = self._clock()
        if not _aware(observed_at):
            raise ObservationError("the clock must return an aware datetime")
        nonce = secrets.token_hex(16)
        obs = TrustedObservation(_mint=_MINT, account=self._account, message_id=message_id, present=present, labels=labels,
                                 observed_at=observed_at, issuer=self, nonce=nonce)
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                raise ObservationError("too many unused observations")
            self._pending.add(nonce)
        return obs

    def revoke_all(self):
        """Forget every unused observation (called when the adapter loses its verification)."""
        with self._lock:
            self._pending.clear()


def new_issuer(account, clock, *, seal):
    """Create the issuer of one adapter. `account` is bound once (lower-cased); `clock` returns an aware UTC datetime; `seal` is the claimed adapter seal."""
    if seal is not _THE_SEAL:
        raise ObservationError("only the archive adapter may create an issuer")
    if type(account) is not str or not account.strip() or not callable(clock):
        raise ObservationError("an issuer needs an account and a clock")
    return ObservationIssuer(_mint=_MINT, account=account.strip().lower(), clock=clock)


def is_trusted(obj):
    """Exact-type test: subclasses (which cannot exist) and look-alikes are not trusted."""
    return type(obj) is TrustedObservation


def is_pending(obs):
    """True if this observation's token is still unused AND was minted by the issuer it names. Does not consume."""
    if type(obs) is not TrustedObservation:
        return False
    issuer, nonce = getattr(obs, "_issuer", None), getattr(obs, "_nonce", None)
    if issuer is None or nonce is None:  # an uninitialised observation (built without __init__) is never pending
        return False
    with issuer._lock:
        return nonce in issuer._pending


def consume(obs):
    """Atomically use the token once. Returns True for exactly one caller; every later or forged attempt returns False."""
    if type(obs) is not TrustedObservation:
        return False
    issuer, nonce = getattr(obs, "_issuer", None), getattr(obs, "_nonce", None)
    if issuer is None or nonce is None:
        return False
    with issuer._lock:
        if nonce not in issuer._pending:
            return False
        issuer._pending.discard(nonce)
        return True
