"""Recovery workflow for interrupted and uncertain executions (M4D): library only, FAKE MAILBOX ONLY. Not reachable from the CLI.

It only COMPOSES the existing primitives, it adds no state machine:
  1. `cleanup_exec.recover_interrupted` turns executions whose lease expired into UNKNOWN work (never resumed);
  2. every UNKNOWN item is reconciled with `cleanup_exec.reconcile_item` from a FRESH trusted observation bound to that item's UNKNOWN episode;
  3. every uncertain undo is reconciled with `cleanup_undo.reconcile_undo` the same way.
Nothing here performs a mutation: no archive, no undo, no retry. Whatever cannot be resolved from evidence stays unresolved and is reported as needing the owner. It fails
closed: another account, an unverifiable account, a failed read or a database error never produces a guess. The report contains counts and sequence numbers only.
"""
import sqlite3
from dataclasses import dataclass
from datetime import timezone

from gmail_intelligence import cleanup_exec as ce, cleanup_plans as cp, cleanup_undo as cu
from gmail_intelligence.exec_fake_mailbox import FakeMailbox, wiring_is_fake

_STOP_CODES = ("AUTH_PROBLEM", "ACCOUNT_MISMATCH", "ACCOUNT_NOT_VERIFIED")


@dataclass(frozen=True)
class ExecutionReport:
    exec_id: str
    state: str
    counts: tuple  # ((name, n), ...): APPLIED, NOT_APPLIED, NEVER_ATTEMPTED, SKIPPED, CONFLICT, UNKNOWN, PENDING, INTENT (zero counts omitted)
    resolved_now: int  # UNKNOWN items resolved by this call
    unresolved: tuple  # sequence numbers of items that still need the owner (UNKNOWN or CONFLICT)
    notes: tuple


@dataclass(frozen=True)
class RecoveryReport:
    interrupted: tuple  # execution ids turned from EXECUTING to needing reconciliation by this call
    executions: tuple  # ExecutionReport, oldest first
    undos: tuple  # ((exec_id, item seq, status), ...) for undos that are still open after this call
    undos_resolved: int
    stopped: str  # '' or the closed reason the call stopped early
    needs_owner: bool


def _counts(index, account, exec_id):
    names = {"APPLIED": "APPLIED", "CONFLICT": "CONFLICT", "UNKNOWN": "UNKNOWN", "PENDING": "PENDING", "INTENT": "INTENT"}
    out = {}
    for r in index._q("SELECT state, error_code, COUNT(*) n FROM cleanup_exec_item WHERE account=? AND exec_id=? GROUP BY state, error_code", account, exec_id):
        if r["state"] in names:
            key = names[r["state"]]
        elif r["state"] in ("SKIPPED_DRIFT", "SKIPPED_GONE"):
            key = "SKIPPED"
        else:
            key = "NEVER_ATTEMPTED" if r["error_code"] == "NEVER_ATTEMPTED" else "NOT_APPLIED"
        out[key] = out.get(key, 0) + r["n"]
    return tuple(sorted(out.items()))


def _execution_report(index, account, exec_id, resolved, notes):
    ex = ce.get_execution(index, account, exec_id)
    unresolved = tuple(r["seq"] for r in index._q("SELECT seq FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state IN ('UNKNOWN','CONFLICT','INTENT') ORDER BY seq",
                                                  account, exec_id))
    notes = list(notes)
    if ex["state"] == "EXECUTING":
        notes.append("in progress: a live lease holds this execution; it was not touched")
    if any(r["state"] == "CONFLICT" for r in index._q("SELECT state FROM cleanup_exec_item WHERE account=? AND exec_id=?", account, exec_id)):
        notes.append("a conflicting observation needs the owner; nothing is retried")
    return ExecutionReport(exec_id, ex["state"], _counts(index, account, exec_id), resolved, unresolved, tuple(notes))


def _relevant(index, account):
    """Executions that are not finished, plus finished ones that still hold an UNKNOWN or CONFLICT item."""
    return [r["exec_id"] for r in index._q(
        "SELECT e.exec_id FROM cleanup_execution e WHERE e.account=? AND (e.state IN ('PREPARED','EXECUTING','AWAITING_CONTINUATION','RECONCILIATION_REQUIRED') "
        "OR EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account=e.account AND i.exec_id=e.exec_id AND i.state IN ('UNKNOWN','CONFLICT'))) ORDER BY e.created_at, e.exec_id", account)]


def status_report(index, account):
    """Read-only snapshot: what is open or uncertain right now. Changes nothing and needs no mailbox."""
    execs = tuple(_execution_report(index, account, e, 0, ()) for e in _relevant(index, account))
    undos = tuple(cu.open_undos(index, account))
    return RecoveryReport((), execs, undos, 0, "", any(x.unresolved for x in execs) or bool(undos))


def recover(index, account, mailbox):
    """Recover and reconcile everything that can be resolved from fresh evidence. See the module docstring. Raises ExecError (and changes nothing) only for a refused
    mailbox or another account; every other failure is reported and leaves the item unresolved. When anything needs recovery the account is verified BEFORE any local
    transition is made, so an unverifiable account changes nothing."""
    if type(mailbox) is not FakeMailbox or not wiring_is_fake(mailbox):
        raise ce.ExecError("MAILBOX_NOT_ALLOWED", "only the fake test mailbox is accepted in this version; nothing was read or changed")
    if mailbox.account.strip().lower() != account.strip().lower():
        raise ce.ExecError("ACCOUNT_MISMATCH", "the mailbox belongs to another account; nothing was changed")
    stopped, interrupted, resolved, notes, undos_resolved = "", [], {}, {}, 0
    cp_iso = cp._iso
    pending_exec, undo_open = [], []
    try:
        # Verify the account FIRST whenever there is anything to recover or reconcile: an unverifiable account must not leave even a local recovery transition behind.
        now = mailbox.clock().astimezone(timezone.utc)
        stale = index._q("SELECT 1 FROM cleanup_execution WHERE account=? AND state='EXECUTING' AND (lease_expires_at IS NULL OR lease_expires_at <= ?) LIMIT 1",
                         account, cp_iso(now))
        unknown = index._q("SELECT 1 FROM cleanup_exec_item i JOIN cleanup_execution e ON e.account=i.account AND e.exec_id=i.exec_id "
                           "WHERE i.account=? AND i.state='UNKNOWN' AND e.state='RECONCILIATION_REQUIRED' LIMIT 1", account)
        if stale or unknown or cu.open_undos(index, account):
            try:
                mailbox.verify_account()
            except Exception:  # noqa: BLE001 - an unverifiable account is never a reason to guess
                stopped = "ACCOUNT_NOT_VERIFIED"
        if not stopped:
            interrupted = ce.recover_interrupted(index, account, now=now)
            pending_exec = [e for e in _relevant(index, account)
                            if ce.get_execution(index, account, e)["state"] == "RECONCILIATION_REQUIRED"
                            and index._q("SELECT 1 FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='UNKNOWN' LIMIT 1", account, e)]
            undo_open = cu.open_undos(index, account)
        if not stopped:
            for exec_id in pending_exec:
                for r in index._q("SELECT message_id, seq FROM cleanup_exec_item WHERE account=? AND exec_id=? AND state='UNKNOWN' ORDER BY seq", account, exec_id):
                    try:
                        obs = mailbox.observe(r["message_id"], context=ce.reconcile_context(index, account, exec_id, r["message_id"]))
                        ce.reconcile_item(index, account, exec_id, r["message_id"], obs, now=mailbox.clock().astimezone(timezone.utc), require_source=ce.TRUSTED_EVIDENCE_SOURCE)
                        resolved[exec_id] = resolved.get(exec_id, 0) + 1
                    except sqlite3.Error:
                        stopped = "DATABASE_ERROR"
                        break
                    except Exception as exc:  # noqa: BLE001 - no usable evidence for this item: it stays UNKNOWN
                        code = getattr(exc, "code", "")
                        notes.setdefault(exec_id, []).append(f"item {r['seq']}: no usable fresh observation ({code or 'read failed'}); still unresolved")
                        if code in _STOP_CODES:
                            stopped = code
                            break
                if stopped:
                    break
        if not stopped:
            for exec_id, seq, _ in undo_open:
                try:
                    cu.reconcile_undo(index, account, exec_id, seq, mailbox)
                    undos_resolved += 1
                except sqlite3.Error:
                    stopped = "DATABASE_ERROR"
                    break
                except ce.ExecError:
                    continue  # stays open and is reported
    except sqlite3.Error:
        stopped = "DATABASE_ERROR"
    try:
        touched = list(dict.fromkeys(_relevant(index, account) + [e for e in list(interrupted) + list(resolved) if e not in _relevant(index, account)]))
        execs = tuple(_execution_report(index, account, e, resolved.get(e, 0), notes.get(e, ())) for e in touched)
        undos = tuple(cu.open_undos(index, account))
    except sqlite3.Error:
        return RecoveryReport(tuple(interrupted), (), (), undos_resolved, "DATABASE_ERROR", True)
    return RecoveryReport(tuple(interrupted), execs, undos, undos_resolved, stopped, bool(stopped) or any(x.unresolved for x in execs) or bool(undos))


def format_report(report):
    """Plain text for the owner: states, counts, sequence numbers and codes. Never message ids, labels, senders or credentials."""
    lines = ["Recovery report"]
    if report.interrupted:
        lines.append(f"  interrupted executions turned into reconciliation work: {len(report.interrupted)}")
    if report.stopped:
        lines.append(f"  STOPPED EARLY: {report.stopped} (nothing was guessed; unresolved items are listed below)")
    for ex in report.executions:
        counts = ", ".join(f"{k}={n}" for k, n in ex.counts) or "no items"
        lines.append(f"  execution {ex.exec_id}: {ex.state}; {counts}; resolved now: {ex.resolved_now}")
        if ex.unresolved:
            lines.append("    needs the owner: items " + ", ".join(str(s) for s in ex.unresolved))
        lines += [f"    note: {n}" for n in ex.notes]
    for exec_id, seq, status in report.undos:
        lines.append(f"  undo of item {seq} in {exec_id}: {status} (needs the owner; the undo is never repeated automatically)")
    if report.undos_resolved:
        lines.append(f"  uncertain undos resolved now: {report.undos_resolved}")
    lines.append("  OWNER ACTION REQUIRED" if report.needs_owner else "  nothing needs the owner")
    lines.append("  Nothing was retried, archived or restored by this recovery; it only compared fresh observations with the recorded state.")
    return "\n".join(lines)
