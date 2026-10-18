"""Owner-operated entry point for the single-message canary (M4): DISABLED, separate from the ordinary command line, never exercised against Gmail.

Run as `python -m gmail_intelligence.cleanup_canary_cli <describe|plan|run> ...`. It is NOT reachable through `gmail-intelligence cleanup execute` (which stays disabled) and the
ordinary CLI never imports it. Preparation and execution are separated:

  describe  LOCAL and read-only: how the ordinary rules and the canary exception judge ONE message (reason codes only, never ids, senders or labels)
  plan      LOCAL: creates the one-message canary plan after a typed phrase; review and approval then use the ordinary `cleanup plan review` and `cleanup approve` commands
  run       EXECUTION: reserves the approved plan (typed execution phrase), starts it, and calls `run_canary` (typed canary phrase)

`describe` and `plan` use the local index only: no Gmail call, no OAuth, no Keychain, no network and no mailbox mutation, so they work while live execution is disabled (they
change nothing that can be executed without the switch). `run` is disabled while `exec_live_mailbox.LIVE_EXECUTION_ENABLED` is False (this build): it refuses right after the
arguments are parsed (pure string handling), BEFORE the index is opened, an execution is reserved or any credential store is created. No environment variable, configuration value or
option enables it.

The account is always given explicitly (nothing is looked up in the Keychain to choose it). Everything it prints is counts and codes.
"""
import argparse
import sys

from gmail_intelligence import cleanup_canary as canary, cleanup_exec as ce, cleanup_plans as cp, config, exec_live_mailbox as live
from gmail_intelligence import index as idx


def _fail(message, out):
    out(f"error: {message}")
    return 1


def _typed(input_fn, out, what, expected):
    out(f"Type exactly this to confirm {what}:\n  {expected}")
    return input_fn("> ").strip() == expected


def main(argv=None, *, input_fn=input, out=print, store_factory=None):
    parser = argparse.ArgumentParser(prog="cleanup_canary_cli", description="owner-operated single-message canary (see the module docstring)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("describe", "plan"):
        q = sub.add_parser(name)
        q.add_argument("--account", required=True, metavar="EMAIL")
        q.add_argument("--message-id", required=True, metavar="ID")
    q = sub.add_parser("run")
    q.add_argument("--account", required=True, metavar="EMAIL")
    q.add_argument("--plan-id", required=True, metavar="PLAN_ID")
    args = parser.parse_args(argv)
    if args.command == "run" and live.LIVE_EXECUTION_ENABLED is not True:  # execution is disabled: refuse before the index, a reservation or any credential store
        out("Live execution of the single-message canary is disabled in this build; nothing was read or changed.")
        return 2
    try:
        with idx.Index(create=False) as index:
            if args.command == "describe":
                v = canary.describe_candidate(index, args.account, args.message_id)
                for name in ("ordinary", "canary"):
                    out(f"{name}: {v[name]['outcome']}; reasons: {', '.join(v[name]['reasons']) or 'none'}")
                out("SENT protection: " + ("this message carries SENT (sent from this account): the exception will NOT apply; send the test message from a different account"
                                           if v["self_sent"] else "not triggered"))
                out(f"plan phrase: {v['phrase']}")
                return 0
            if args.command == "plan":
                v = canary.describe_candidate(index, args.account, args.message_id)
                if not _typed(input_fn, out, "the canary exception for this ONE message", v["phrase"]):
                    return _fail("confirmation did not match; nothing was created", out)
                plan = canary.create_canary_plan(index, args.account, args.message_id, v["phrase"])
                out(f"Canary plan {plan['plan_id']} created (DRAFT, 1 target). Next, with the ordinary commands: `cleanup plan review {plan['plan_id']}` then `cleanup approve {plan['plan_id']}`.")
                return 0
            plan = cp.get_plan(index, args.account, args.plan_id)
            if plan["state"] != "APPROVED" or plan["item_count"] != 1:
                return _fail("the plan must be APPROVED and contain exactly one target", out)
            if not _typed(input_fn, out, "reserving this one-message execution", ce.execution_phrase(plan, 1)):
                return _fail("confirmation did not match; nothing was reserved", out)
            execution = ce.reserve_execution(index, args.account, args.plan_id, ce.execution_phrase(plan, 1), now=live._utcnow())
            token = ce.start_slice(index, args.account, execution["exec_id"], 1, now=live._utcnow())
            phrase = canary.canary_phrase(plan, execution["exec_id"])
            if not _typed(input_fn, out, "the live canary of this ONE message (it will be archived through Gmail)", phrase):
                return _fail("confirmation did not match; nothing was sent (the started execution expires and is recovered as unattempted)", out)
            if store_factory is None:
                from gmail_intelligence.keystore_write import WriteTokenStore
                store_factory = WriteTokenStore
            result = canary.run_canary(index, args.account, execution["exec_id"], token, phrase, store_factory(), config.write_client_secret_path())
            out(f"canary result: item {result.item_state} ({result.code or '-'}), execution {result.execution_state}, archive requests made: {result.posts}")
            if result.item_state != "APPLIED":
                out("Not recorded as archived. Nothing is retried; if the item is UNKNOWN, use the read-only recovery (fresh observation) before deciding anything.")
            return 0 if result.item_state == "APPLIED" else 1
    except (cp.PlanError, idx.IndexProblem, ValueError) as exc:
        return _fail(exc, out)
    except Exception as exc:  # noqa: BLE001 - never print a traceback, token or identifier from an unexpected failure
        return _fail(f"{type(exc).__name__}; nothing further was attempted (if an execution was started, recover it read-only before deciding anything)", out)


if __name__ == "__main__":
    sys.exit(main())
