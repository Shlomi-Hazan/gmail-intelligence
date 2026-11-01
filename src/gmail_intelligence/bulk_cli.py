"""Owner-operated BULK archive execution commands (M12D): the only module through which the ordinary CLI reaches the live bulk path, and DISABLED.

  cleanup execute PLAN_ID --reserve   consume the plan's one-time approval with the typed execution phrase and freeze the targets (slice 1 is confirmed by that same phrase)
  cleanup exec run EXEC_ID            run the ONE confirmed slice (a separate typed run phrase; one bounded slice per command)
  cleanup exec confirm EXEC_ID        give the next slice its own fresh typed continuation phrase (refused while anything uncertain or unsafe remains)
  cleanup exec abort EXEC_ID          abandon a PREPARED / AWAITING_CONTINUATION execution (local; remaining targets are never attempted; the approval stays consumed)

`reserve`, `run` and `confirm` refuse right after the arguments are parsed, BEFORE the index is opened, a credential store is created or the network is touched, while
`exec_live_mailbox.LIVE_EXECUTION_ENABLED` is False (this build): no environment variable, configuration value or option enables it. `abort` only ends an execution locally and needs no gate.
Local status and previews (`cleanup execute --dry-run`, `cleanup exec show`, `cleanup exec recovery`) never need the gate. Nothing continues automatically, nothing is retried, and an uncertain
item is only ever settled by the read-only `cleanup exec recovery --reconcile`. `store_factory` exists only so offline tests can supply a recording credential store.
"""
from gmail_intelligence import cleanup_bulk as bulk, cleanup_exec as ce, cleanup_plans as cp, config, exec_live_mailbox as live

DISABLED = "Live Gmail execution is disabled in this build; nothing was read or changed."
LIVE_COMMANDS = ("reserve", "run", "confirm")


def abort_phrase(exec_id):
    return f"ABORT EXECUTION {exec_id}"


def _progress(res):
    return (f"slice {res.slice_no} finished: {res.applied} archived (recorded), {res.skipped} skipped (changed or gone; nothing sent), {res.unknown} UNKNOWN, {res.not_applied} not applied; "
            f"{res.posts} archive request(s); execution {res.execution_state}")


def dispatch(args, *, with_index, tty_input, fail, store_factory=None):
    cmd = args.bulk_command
    if cmd in LIVE_COMMANDS and live.LIVE_EXECUTION_ENABLED is not True:  # refuse before the index, a credential store or the network is touched
        print(DISABLED)
        return 2

    def go(index, account):
        try:
            if cmd == "reserve":
                plan = cp.get_plan(index, account, args.plan_id)
                sizes = ce.plan_slices(plan["item_count"])
                print(f"This consumes the plan's one-time approval and freezes {plan['item_count']} target(s) of {plan['action']} in {len(sizes)} slice(s) {sizes}. Nothing is sent to Gmail yet.")
                typed = tty_input(f"Type exactly  {ce.execution_phrase(plan, sizes[0])}  to reserve the execution (anything else aborts): ")
                ex = ce.reserve_execution(index, account, args.plan_id, typed)
                print(f"Execution {ex['exec_id']} reserved ({ex['item_count']} targets, {ex['slice_count']} slice(s)); slice 1 is confirmed. Next: cleanup exec run {ex['exec_id']}")
                return 0
            ex = ce.get_execution(index, account, args.exec_id)
            plan = cp.get_plan(index, account, ex["plan_id"])
            if cmd == "abort":
                typed = tty_input(f"Type exactly  {abort_phrase(args.exec_id)}  to abandon this execution (remaining targets are never attempted): ")
                if typed.strip() != abort_phrase(args.exec_id):
                    return fail("declined; the execution was not changed")
                ce.abort_execution(index, account, args.exec_id)
                print(f"Execution {args.exec_id} ABORTED; the approval stays consumed and nothing further will be attempted.")
                return 0
            if cmd == "confirm":
                pending = [s for s in ce.slices(index, account, args.exec_id) if s["state"] == "PENDING"]
                if not pending:
                    return fail("no slice is waiting for a continuation confirmation")
                sl = pending[0]
                print(f"This authorizes slice {sl['slice_no']} ({sl['size']} targets) ONLY. It does not run it.")
                typed = tty_input(f"Type exactly  {ce.continuation_phrase(plan, sl['slice_no'], sl['size'])}  to confirm this slice (anything else aborts): ")
                ce.confirm_slice(index, account, args.exec_id, sl["slice_no"], typed)
                print(f"Slice {sl['slice_no']} confirmed. Next: cleanup exec run {args.exec_id}")
                return 0
            # run
            confirmed = [s for s in ce.slices(index, account, args.exec_id) if s["state"] == "CONFIRMED"]
            if len(confirmed) != 1:
                return fail("exactly one slice must be confirmed before it can run (see `cleanup exec show`)")
            sl = confirmed[0]
            print(f"This runs slice {sl['slice_no']} ({sl['size']} targets) of {plan['action']} against Gmail, one message at a time, each re-verified first. An uncertain result stops "
                  "everything and is never retried.")
            typed = tty_input(f"Type exactly  {bulk.run_phrase(plan, args.exec_id, sl['slice_no'], sl['size'])}  to run it (anything else aborts): ")
            if store_factory is None:
                from gmail_intelligence.keystore_write import WriteTokenStore
                factory = WriteTokenStore
            else:
                factory = store_factory
            res = bulk.run_bulk_slice(index, account, args.exec_id, typed, factory(), config.write_client_secret_path())
            print(_progress(res))
            if res.stopped or res.unknown:
                print("STOPPED: nothing further was attempted and nothing is retried. Settle any UNKNOWN item read-only with `cleanup exec recovery --reconcile`.")
            elif res.execution_state == "AWAITING_CONTINUATION":
                print(f"Next slice needs its own confirmation: cleanup exec confirm {args.exec_id}")
            return 1 if res.stopped else 0
        except cp.PlanError as exc:
            return fail(exc)
        except EOFError:
            return fail("cancelled: this step needs a real interactive terminal; nothing was changed")
        except Exception as exc:  # noqa: BLE001 - never print a traceback, token or identifier from an unexpected failure
            return fail(f"{type(exc).__name__}; nothing further was attempted (if a slice was started, settle it read-only with `cleanup exec recovery` before deciding anything)")
    return with_index(args, go)
