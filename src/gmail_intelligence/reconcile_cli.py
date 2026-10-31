"""Owner-operated LIVE recovery / reconciliation (M12C.4): the only module through which the ordinary CLI reaches live observation, and DISABLED.

  cleanup exec recovery --reconcile   observe Gmail (READ-ONLY) and reconcile interrupted / UNKNOWN archive items and open or uncertain undos
  cleanup undo reconcile EXEC SEQ     observe Gmail (READ-ONLY) and reconcile ONE open / UNKNOWN undo

Four things are kept apart: local STATUS (`cleanup exec recovery`, reads the journal only, always available), LIVE OBSERVATION (reads Gmail; this module; disabled), RECONCILIATION (compares a
trusted, execution-bound observation with the record and may append a LOCAL audit/journal result; never changes Gmail) and MUTATION (archive / undo; separate switches, not used here).
Both commands refuse right after the arguments are parsed, BEFORE the index is opened, a credential store is created or the network is touched, while
`exec_live_mailbox.LIVE_OBSERVE_ENABLED` is False (this build). No environment variable, configuration value or option enables it, and it is independent of `LIVE_EXECUTION_ENABLED` and
`LIVE_UNDO_ENABLED`. When enabled, the owner must type an explicit phrase for each invocation; nothing runs on startup, on a schedule, or repeatedly, and nothing is retried or resumed.
`mailbox_factory` exists only so offline tests can supply a mailbox over the in-memory fake wire; the ordinary CLI never passes it.
"""
from gmail_intelligence import cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, cleanup_recovery as cr, config, exec_live_mailbox as live

DISABLED = "Live Gmail observation is disabled in this build; nothing was read or changed."
OBSERVE_PHRASE = "OBSERVE GMAIL READ-ONLY"
_EXPLAIN = ("This READ-ONLY step contacts Gmail only to read message labels (no content, subjects or attachments) and compares them with the local record. It never archives, restores, "
            "retries or resumes anything and never changes Gmail; it may append local audit and journal results.")


def _mailbox(account, mailbox_factory, store_factory):
    if mailbox_factory is not None:
        return mailbox_factory()
    if store_factory is None:
        from gmail_intelligence.keystore_write import WriteTokenStore
        store_factory = WriteTokenStore
    return live.open_live_observe_mailbox(account, store_factory(), config.write_client_secret_path())


def _intent(tty_input, fail):
    typed = tty_input(f"Type exactly  {OBSERVE_PHRASE}  to start this read-only observation (anything else aborts): ")
    return None if typed.strip() == OBSERVE_PHRASE else fail("declined; nothing was read or changed")


def _run(args, with_index, tty_input, fail, mailbox_factory, store_factory, work):
    if live.LIVE_OBSERVE_ENABLED is not True:  # refuse before the index, a credential store or the network is touched
        print(DISABLED)
        return 2

    def go(index, account):
        try:
            print(_EXPLAIN)
            declined = _intent(tty_input, fail)
            if declined is not None:
                return declined
            return work(index, account, _mailbox(account, mailbox_factory, store_factory))
        except (ce.ExecError, cp.PlanError, live.LiveObserveDisabled) as exc:
            return fail(exc)
        except EOFError:
            return fail("cancelled: this step needs a real interactive terminal; nothing was read or changed")
        except Exception as exc:  # noqa: BLE001 - never print a traceback, token or identifier from an unexpected failure
            return fail(f"{type(exc).__name__}; nothing further was attempted (the local record is unchanged or was extended only with append-only results)")
    return with_index(args, go)


def dispatch_recovery(args, *, with_index, tty_input, fail, mailbox_factory=None, store_factory=None):
    """`cleanup exec recovery --reconcile`: recover interrupted executions and reconcile everything uncertain from fresh read-only observations."""
    def work(index, account, mailbox):
        print(cr.format_report(cl.recover_observed(index, account, mailbox)))
        return 0
    return _run(args, with_index, tty_input, fail, mailbox_factory, store_factory, work)


def dispatch_undo_reconcile(args, *, with_index, tty_input, fail, mailbox_factory=None, store_factory=None):
    """`cleanup undo reconcile EXEC SEQ`: settle ONE open / UNKNOWN undo from a fresh read-only observation (no mutation, ever)."""
    def work(index, account, mailbox):
        res = cl.reconcile_undo_observed(index, account, args.exec_id, args.item, mailbox)
        print(f"undo result: {res.status} ({res.code or '-'}); mutation attempts made: {res.mutations} (read-only: Gmail was not changed)")
        if res.status == "CONFLICT":
            print("CONFLICT: the mailbox shows something unexpected. This needs manual owner review and is never presented as a restoration.")
        return 0
    return _run(args, with_index, tty_input, fail, mailbox_factory, store_factory, work)
