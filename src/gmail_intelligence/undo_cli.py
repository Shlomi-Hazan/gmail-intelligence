"""Owner-operated archive-undo workflow (M12C.3): the only module through which the ordinary CLI reaches the live undo path, and DISABLED for everything that can read or change Gmail.

Commands (`gmail-intelligence cleanup undo ...`, wired in `cli.py` through `dispatch`):

  status [--exec-id E] [--json]   LOCAL, read-only: which archived items of an execution could be undone and the state of every undo ledger (counts, codes, sequence numbers)
  preview EXEC_ID SEQ             LOCAL, read-only: eligibility of ONE item, its undo state, the exact typed phrase an authorization needs, and what is and is not enabled
  authorize EXEC_ID SEQ           records the owner's SEPARATE typed authorization for ONE item (a local ledger entry; valid 15 minutes; one attempt) - needs the live-undo switch
  run EXEC_ID SEQ                 the one controlled undo of that item through `cleanup_live.undo_live` - needs the live-undo switch
  reconcile EXEC_ID SEQ           READ-ONLY resolution of an open/UNKNOWN undo from a fresh observation: delegated to `reconcile_cli` (M12C.4), which needs the separate live-OBSERVE switch
                                  (not the undo switch) and an observe-only mailbox that cannot restore anything

`authorize` and `run` refuse right after the arguments are parsed, BEFORE the index is opened, a credential store is created or the network is touched, while
`exec_live_mailbox.LIVE_UNDO_ENABLED` is False (this build); `reconcile` does the same with `LIVE_OBSERVE_ENABLED`. No environment variable, configuration value or option enables it. The switch is independent of
`LIVE_EXECUTION_ENABLED`: neither authorizes the other. There is no generic Gmail operation here, no retry and no resume; everything printed is counts, codes and sequence numbers.
`mailbox_factory` exists only so offline tests can supply a mailbox over the in-memory fake wire; the ordinary CLI never passes it.
"""
import json

from gmail_intelligence import cleanup_exec as ce, cleanup_live as cl, cleanup_plans as cp, cleanup_undo as cu, config, exec_live_mailbox as live
from gmail_intelligence import cleanup_undo_ledger as ledger

DISABLED = "Live archive undo is disabled in this build; nothing was read or changed."
LIVE_COMMANDS = ("authorize", "run")  # mutation-side commands, gated by LIVE_UNDO_ENABLED; `reconcile` is read-only and gated by LIVE_OBSERVE_ENABLED (reconcile_cli)
_NOTE = ("Undo restores INBOX on ONE message that an execution archived and recorded with trusted evidence; it never touches other labels, other messages, Trash or deletion, and "
         "it is never retried. An uncertain result stays UNKNOWN until a fresh observation settles it.")


def _item_rows(index, account, exec_id):
    out = []
    for r in index._q("SELECT seq FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='APPLIED' ORDER BY seq", account, exec_id):
        try:
            cu._original(index, account, exec_id, r["seq"])
            eligible, reason = True, ""
        except ce.ExecError as exc:
            eligible, reason = False, exc.code
        out.append({"item": r["seq"], "eligible": eligible, "reason": reason, "undo": ledger.undo_status(index, account, exec_id, r["seq"])})
    return out


def status_data(index, account, exec_id=None):
    execs = [e for e in ce.list_executions(index, account) if exec_id in (None, e["exec_id"])]
    if exec_id is not None and not execs:
        raise ce.ExecError("NO_SUCH_EXECUTION", "no such execution for this account")
    rows = []
    for e in execs:
        items = _item_rows(index, account, e["exec_id"])
        rows.append({"exec_id": e["exec_id"], "state": e["state"], "applied_items": len(items), "undoable_items": sum(1 for i in items if i["eligible"]),
                     **({"items": items} if exec_id is not None else {})})
    return {"executions": rows, "undos": ledger.all_undos(index, account), "live_undo_enabled": live.LIVE_UNDO_ENABLED is True, "read_only": True, "gmail_contacted": False}


def status_text(data):
    out = [f"Archive undo status for <account hidden> (local journal only; live undo {'ENABLED' if data['live_undo_enabled'] else 'DISABLED in this build'})"]
    for e in data["executions"]:
        out.append(f"  execution {e['exec_id']}: {e['state']}; {e['applied_items']} archived item(s), {e['undoable_items']} eligible for undo")
        for i in e.get("items", []):
            out.append(f"    item {i['item']}: {'eligible' if i['eligible'] else 'NOT eligible (' + i['reason'] + ')'}; undo state {i['undo']}")
    if not data["executions"]:
        out.append("  (no executions)")
    for ex, item, st in data["undos"]:
        out.append(f"  undo ledger: execution {ex} item {item}: {st}")
    return "\n".join(out + ["", _NOTE])


def preview_data(index, account, exec_id, seq):
    ex, item, plan = cu._original(index, account, exec_id, seq)  # raises ExecError (fixed codes) when the item is not an undoable archive
    return {"exec_id": exec_id, "item": seq, "eligible": True, "undo_state": ledger.undo_status(index, account, exec_id, seq), "action": "RESTORE_INBOX",
            "phrase": cu.undo_phrase(plan, exec_id, seq), "live_undo_enabled": live.LIVE_UNDO_ENABLED is True, "read_only": True, "gmail_contacted": False}


def preview_text(d):
    return "\n".join([f"Undo preview: execution {d['exec_id']} item {d['item']} (local, read-only; nothing was sent)",
                      "  eligible: yes (recorded APPLIED with trusted evidence; intact plan and consumed approval)", f"  undo state: {d['undo_state']}",
                      "  action: add INBOX back to this ONE message (no other label, no other message)",
                      f"  a SEPARATE typed authorization is required (valid 15 minutes, one attempt): {d['phrase']}",
                      f"  live undo: {'enabled' if d['live_undo_enabled'] else 'DISABLED in this build (authorize / run / reconcile refuse)'}", "", _NOTE])


def _result_line(res):
    return f"undo result: {res.status} ({res.code or '-'}); mutation attempts made: {res.mutations}"


def dispatch(args, *, with_index, with_readonly, tty_input, fail, mailbox_factory=None, store_factory=None):
    """Run one `cleanup undo` subcommand. `with_index` / `with_readonly` are the CLI's index openers (account lookup and error handling stay there)."""
    cmd = args.undo_command
    if cmd == "reconcile":
        from gmail_intelligence import reconcile_cli
        return reconcile_cli.dispatch_undo_reconcile(args, with_index=with_index, tty_input=tty_input, fail=fail, mailbox_factory=mailbox_factory, store_factory=store_factory)
    if cmd in LIVE_COMMANDS and live.LIVE_UNDO_ENABLED is not True:  # refuse before the index, a credential store or the network is touched
        print(DISABLED)
        return 2
    if cmd == "status":
        def go_status(index, account):
            try:
                data = status_data(index, account, args.exec_id)
            except ce.ExecError as exc:
                return fail(exc)
            print(json.dumps(data, indent=2, sort_keys=True) if args.json else status_text(data))
            return 0
        return with_readonly(args, go_status)
    if cmd == "preview":
        def go_preview(index, account):
            try:
                d = preview_data(index, account, args.exec_id, args.item)
            except ce.ExecError as exc:
                return fail(exc)
            print(preview_text(d))
            return 0
        return with_readonly(args, go_preview)

    def go(index, account):
        try:
            if cmd == "authorize":
                ex = ce.get_execution(index, account, args.exec_id)
                plan = cp.get_plan(index, account, ex["plan_id"])
                phrase = cu.undo_phrase(plan, args.exec_id, args.item)
                print(f"This authorizes ONE undo of execution {args.exec_id} item {args.item}: INBOX goes back on that one message. Nothing happens until `cleanup undo run`.")
                typed = tty_input(f"Type exactly  {phrase}  to authorize (anything else aborts): ")
                cu.authorize_undo(index, account, args.exec_id, args.item, typed)
                print("Undo authorized (local record; valid 15 minutes; one attempt). Nothing was changed and Gmail was not contacted.")
                return 0
            if store_factory is None:
                from gmail_intelligence.keystore_write import WriteTokenStore
                factory = WriteTokenStore
            else:
                factory = store_factory
            mailbox = (mailbox_factory or (lambda: live.open_live_undo_mailbox(account, factory(), config.write_client_secret_path())))()
            if cmd == "run":  # (the only remaining live command after authorize)
                res = cl.undo_live(index, account, args.exec_id, args.item, mailbox)
                print(_result_line(res))
                if res.status != "RESTORED":
                    print("Not recorded as restored. Nothing is retried; if it is UNKNOWN, use `cleanup undo reconcile` (read-only) before deciding anything.")
                return 0 if res.status == "RESTORED" else 1
            return fail("internal: unreachable")
        except (ce.ExecError, cp.PlanError, live.LiveUndoDisabled) as exc:
            return fail(exc)
        except EOFError:
            return fail("cancelled: this step needs a real interactive terminal; nothing was changed")
        except Exception as exc:  # noqa: BLE001 - never print a traceback, token or identifier from an unexpected failure
            return fail(f"{type(exc).__name__}; nothing further was attempted (if an undo was started, reconcile it read-only before deciding anything)")
    return with_index(args, go)
