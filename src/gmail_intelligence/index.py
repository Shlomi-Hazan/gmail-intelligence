"""Local SQLite metadata index (stdlib only). Stores no bodies, snippets, subjects or credentials.

All data is keyed by account, so one account's rows are never mixed with another's. Schema version is
kept in `PRAGMA user_version`. There is no migration framework: older versions are upgraded by additive scripts (v2 = M3
classification tables, v3 = M4A protection rules, v4 = M4B plans/approvals/audit, v5 = M4C-A local execution state) in ONE transaction, after an automatic backup copy of the database file.
"""
import os
import sqlite3
from datetime import datetime, timezone

from gmail_intelligence import config

SCHEMA_VERSION = 5
SCHEMA = """
CREATE TABLE messages (
  account TEXT NOT NULL, id TEXT NOT NULL, thread_id TEXT, internal_ms INTEGER, size INTEGER,
  sender TEXT, unread INTEGER NOT NULL DEFAULT 0, scan_id INTEGER NOT NULL,
  PRIMARY KEY (account, id)) WITHOUT ROWID;
CREATE INDEX messages_sender ON messages (account, sender);
CREATE INDEX messages_date ON messages (account, internal_ms);
CREATE TABLE message_labels (
  account TEXT NOT NULL, message_id TEXT NOT NULL, label_id TEXT NOT NULL,
  PRIMARY KEY (account, message_id, label_id)) WITHOUT ROWID;
CREATE INDEX message_labels_label ON message_labels (account, label_id);
CREATE TABLE labels (
  account TEXT NOT NULL, id TEXT NOT NULL, name TEXT, type TEXT, PRIMARY KEY (account, id)) WITHOUT ROWID;
CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, mode TEXT NOT NULL, limit_n INTEGER,
  status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, page_token TEXT,
  listed INTEGER NOT NULL DEFAULT 0, indexed INTEGER NOT NULL DEFAULT 0, vanished INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0, pruned INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE INDEX scans_account ON scans (account, id);
"""
# Version 2 (M3): purely additive, so M2 data is never rewritten. See docs/CLASSIFICATION.md.
SCHEMA_V2 = """
CREATE TABLE class_rules (
  account TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  c_sender TEXT, c_domain TEXT, c_label TEXT, c_unread INTEGER,
  confidence TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT, created_at TEXT NOT NULL, PRIMARY KEY (account, id)) WITHOUT ROWID;
CREATE TABLE message_class (
  account TEXT NOT NULL, message_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  confidence TEXT NOT NULL, source TEXT NOT NULL, rule_id TEXT NOT NULL, explanation TEXT NOT NULL,
  ruleset_hash TEXT NOT NULL, msg_scan_id INTEGER NOT NULL, classified_at TEXT NOT NULL,
  PRIMARY KEY (account, message_id, kind, value)) WITHOUT ROWID;
CREATE INDEX message_class_value ON message_class (account, kind, value);
"""
# Version 3 (M4A): user protection rules only. Candidate results are never stored (computed on demand).
SCHEMA_V3 = """
CREATE TABLE protect_rules (
  account TEXT NOT NULL, id TEXT NOT NULL, c_sender TEXT, c_domain TEXT, c_label TEXT,
  enabled INTEGER NOT NULL DEFAULT 1, note TEXT, created_at TEXT NOT NULL,
  PRIMARY KEY (account, id)) WITHOUT ROWID;
"""

# Version 4 (M4B): immutable cleanup plans, approvals and a hash-chained audit log. Purely local; nothing here talks to Gmail.
# Triggers make plan content, plan items, approvals and audit rows immutable and allow only forward state transitions.
# They protect against bugs and accidents, NOT against someone who controls this database file (they can drop triggers).
SCHEMA_V4 = """
CREATE TABLE cleanup_plan (
  account TEXT NOT NULL, plan_id TEXT NOT NULL, version INTEGER NOT NULL CHECK (version >= 1), parent_id TEXT,
  action TEXT NOT NULL CHECK (action IN ('ARCHIVE')),
  state TEXT NOT NULL CHECK (state IN ('DRAFT','REVIEWED','APPROVED','CANCELLED','EXPIRED','SUPERSEDED')),
  plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64), snapshot TEXT NOT NULL,
  item_count INTEGER NOT NULL CHECK (item_count >= 1), created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  reviewed_at TEXT, state_changed_at TEXT NOT NULL,
  PRIMARY KEY (account, plan_id),
  FOREIGN KEY (account, parent_id) REFERENCES cleanup_plan (account, plan_id)) WITHOUT ROWID;
CREATE TABLE cleanup_item (
  account TEXT NOT NULL, plan_id TEXT NOT NULL, message_id TEXT NOT NULL, thread_id TEXT NOT NULL, item_digest TEXT NOT NULL,
  PRIMARY KEY (account, plan_id, message_id),
  FOREIGN KEY (account, plan_id) REFERENCES cleanup_plan (account, plan_id)) WITHOUT ROWID;
CREATE TABLE cleanup_approval (
  account TEXT NOT NULL, plan_id TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, plan_hash TEXT NOT NULL, action TEXT NOT NULL,
  item_count INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('VALID','CONSUMED','REVOKED','EXPIRED')), status_changed_at TEXT NOT NULL,
  PRIMARY KEY (account, plan_id, nonce),
  FOREIGN KEY (account, plan_id) REFERENCES cleanup_plan (account, plan_id)) WITHOUT ROWID;
CREATE UNIQUE INDEX cleanup_one_valid_approval ON cleanup_approval (account, plan_id) WHERE status = 'VALID';
CREATE TABLE cleanup_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, plan_id TEXT, event_type TEXT NOT NULL, at TEXT NOT NULL,
  meta TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX cleanup_audit_account ON cleanup_audit (account, seq);
CREATE TRIGGER cleanup_plan_content_immutable BEFORE UPDATE ON cleanup_plan
WHEN NEW.account IS NOT OLD.account OR NEW.plan_id IS NOT OLD.plan_id OR NEW.version IS NOT OLD.version
  OR NEW.parent_id IS NOT OLD.parent_id OR NEW.action IS NOT OLD.action OR NEW.plan_hash IS NOT OLD.plan_hash
  OR NEW.snapshot IS NOT OLD.snapshot OR NEW.item_count IS NOT OLD.item_count OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'cleanup plan content is immutable'); END;
CREATE TRIGGER cleanup_plan_state_forward_only BEFORE UPDATE OF state ON cleanup_plan
WHEN NEW.state <> OLD.state AND NOT (
     (OLD.state = 'DRAFT' AND NEW.state IN ('REVIEWED','CANCELLED','SUPERSEDED','EXPIRED'))
  OR (OLD.state = 'REVIEWED' AND NEW.state IN ('APPROVED','CANCELLED','SUPERSEDED','EXPIRED'))
  OR (OLD.state = 'APPROVED' AND NEW.state IN ('CANCELLED','SUPERSEDED','EXPIRED')))
BEGIN SELECT RAISE(ABORT, 'illegal cleanup plan state transition'); END;
CREATE TRIGGER cleanup_plan_starts_as_draft BEFORE INSERT ON cleanup_plan WHEN NEW.state <> 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'a cleanup plan must start as DRAFT'); END;
CREATE TRIGGER cleanup_approval_only_for_reviewed BEFORE INSERT ON cleanup_approval
WHEN NEW.status <> 'VALID' OR (SELECT state FROM cleanup_plan WHERE account = NEW.account AND plan_id = NEW.plan_id)
  IS NOT 'REVIEWED'
BEGIN SELECT RAISE(ABORT, 'an approval can only be recorded for a REVIEWED plan'); END;
CREATE TRIGGER cleanup_plan_approved_needs_approval BEFORE UPDATE OF state ON cleanup_plan
WHEN NEW.state = 'APPROVED' AND NOT EXISTS (SELECT 1 FROM cleanup_approval
  WHERE account = NEW.account AND plan_id = NEW.plan_id AND status = 'VALID')
BEGIN SELECT RAISE(ABORT, 'a plan can only become APPROVED while it has a VALID approval record'); END;
CREATE TRIGGER cleanup_plan_reviewed_needs_timestamp BEFORE UPDATE OF state ON cleanup_plan
WHEN NEW.state IN ('REVIEWED','APPROVED') AND NEW.reviewed_at IS NULL
BEGIN SELECT RAISE(ABORT, 'a reviewed plan must record when it was reviewed'); END;
CREATE TRIGGER cleanup_plan_no_delete BEFORE DELETE ON cleanup_plan
BEGIN SELECT RAISE(ABORT, 'cleanup plans are never deleted'); END;
CREATE TRIGGER cleanup_item_no_update BEFORE UPDATE ON cleanup_item
BEGIN SELECT RAISE(ABORT, 'cleanup plan items are immutable'); END;
CREATE TRIGGER cleanup_item_no_delete BEFORE DELETE ON cleanup_item
BEGIN SELECT RAISE(ABORT, 'cleanup plan items are immutable'); END;
CREATE TRIGGER cleanup_item_only_in_draft BEFORE INSERT ON cleanup_item
WHEN (SELECT state FROM cleanup_plan WHERE account = NEW.account AND plan_id = NEW.plan_id) IS NOT 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'items can only be added while a plan is being created'); END;
CREATE TRIGGER cleanup_approval_content_immutable BEFORE UPDATE ON cleanup_approval
WHEN NEW.account IS NOT OLD.account OR NEW.plan_id IS NOT OLD.plan_id OR NEW.nonce IS NOT OLD.nonce
  OR NEW.plan_hash IS NOT OLD.plan_hash OR NEW.action IS NOT OLD.action OR NEW.item_count IS NOT OLD.item_count
  OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'cleanup approval content is immutable'); END;
CREATE TRIGGER cleanup_approval_forward_only BEFORE UPDATE OF status ON cleanup_approval
WHEN NEW.status <> OLD.status AND OLD.status <> 'VALID'
BEGIN SELECT RAISE(ABORT, 'a used, revoked or expired approval can never become valid again'); END;
CREATE TRIGGER cleanup_approval_no_delete BEFORE DELETE ON cleanup_approval
BEGIN SELECT RAISE(ABORT, 'cleanup approvals are never deleted'); END;
CREATE TRIGGER cleanup_audit_no_update BEFORE UPDATE ON cleanup_audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER cleanup_audit_no_delete BEFORE DELETE ON cleanup_audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
"""

# Version 5 (M4C-A): LOCAL execution state only. Nothing here talks to Gmail; the plan tables above stay untouched and immutable.
# An execution is created in the same transaction that consumes the plan's approval. Triggers keep the state machines forward-only,
# freeze the target set, lock the plan once an execution exists, and refuse contradictory terminal states (for example EXECUTED while
# items are still open, or an APPLIED item without verification and recovery metadata). Code writes related rows in a fixed safe
# order: items first, then slices, then the execution. Triggers guard against bugs, not against someone who can write the file.
EXEC_ITEM_CODES = ("NEVER_ATTEMPTED", "REJECTED", "RECONCILED_UNMODIFIED", "RECONCILED_OBSERVED_ARCHIVED", "RECONCILED_CONFLICT", "INTERRUPTED",
                   "OVERLAP_ALREADY_APPLIED", "APPLIED", "TIMEOUT", "SERVER_ERROR", "NETWORK_ERROR", "AMBIGUOUS_RESULT",
                   "LABELS_CHANGED", "STATE_CHANGED", "THREAD_CHANGED", "NOT_IN_INBOX", "NOT_FOUND")
_CODES_SQL = ",".join(f"'{c}'" for c in EXEC_ITEM_CODES)
_TS_GLOB = "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'"
_OPEN = "('PENDING','INTENT','UNKNOWN')"
_TERMINAL = "('EXECUTED','PARTIAL','FAILED','ABORTED')"
SCHEMA_V5 = f"""
CREATE TABLE cleanup_execution (
  account TEXT NOT NULL, exec_id TEXT NOT NULL, plan_id TEXT NOT NULL, plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
  approval_nonce TEXT NOT NULL UNIQUE, action TEXT NOT NULL CHECK (action IN ('ARCHIVE')),
  state TEXT NOT NULL CHECK (state IN ('PREPARED','EXECUTING','AWAITING_CONTINUATION','PARTIAL','EXECUTED','FAILED','ABORTED',
                                       'RECONCILIATION_REQUIRED')),
  item_count INTEGER NOT NULL CHECK (item_count >= 1), slice_count INTEGER NOT NULL CHECK (slice_count >= 1),
  confirmation_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, state_changed_at TEXT NOT NULL,
  lease_token TEXT CHECK (lease_token IS NULL OR length(lease_token) = 64), lease_expires_at TEXT,
  PRIMARY KEY (account, exec_id),
  FOREIGN KEY (account, plan_id) REFERENCES cleanup_plan (account, plan_id)) WITHOUT ROWID;
CREATE UNIQUE INDEX cleanup_exec_one_per_plan ON cleanup_execution (account, plan_id);
CREATE UNIQUE INDEX cleanup_exec_one_active_per_account ON cleanup_execution (account)
  WHERE state IN ('PREPARED','EXECUTING','RECONCILIATION_REQUIRED');
CREATE TABLE cleanup_exec_slice (
  account TEXT NOT NULL, exec_id TEXT NOT NULL, slice_no INTEGER NOT NULL CHECK (slice_no >= 1),
  size INTEGER NOT NULL CHECK (size >= 1),
  state TEXT NOT NULL CHECK (state IN ('PENDING','CONFIRMED','ACTIVE','COMPLETED','STOPPED')),
  confirmation_sha256 TEXT, confirmed_at TEXT, started_at TEXT, finished_at TEXT,
  PRIMARY KEY (account, exec_id, slice_no),
  FOREIGN KEY (account, exec_id) REFERENCES cleanup_execution (account, exec_id)) WITHOUT ROWID;
CREATE TABLE cleanup_exec_item (
  account TEXT NOT NULL, exec_id TEXT NOT NULL, message_id TEXT NOT NULL, seq INTEGER NOT NULL, slice_no INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('PENDING','INTENT','APPLIED','SKIPPED_DRIFT','SKIPPED_GONE','NOT_APPLIED','UNKNOWN','CONFLICT')),
  prev_label_ids TEXT CHECK (prev_label_ids IS NULL OR (substr(prev_label_ids, 1, 1) = '[' AND instr(prev_label_ids, '"INBOX"') > 0)),
  intent_at TEXT CHECK (intent_at IS NULL OR intent_at GLOB {_TS_GLOB}),
  result_at TEXT CHECK (result_at IS NULL OR result_at GLOB {_TS_GLOB}),
  error_code TEXT CHECK (error_code IS NULL OR error_code IN ({_CODES_SQL})),
  evidence_checked INTEGER NOT NULL DEFAULT 0 CHECK (evidence_checked IN (0, 1)),
  evidence_source TEXT CHECK (evidence_source IS NULL OR evidence_source IN ('CALLER_SUPPLIED','TRUSTED_ADAPTER')),
  evidence_observed_at TEXT CHECK (evidence_observed_at IS NULL OR evidence_observed_at GLOB {_TS_GLOB}),
  CHECK (evidence_checked = 0 OR (state = 'APPLIED' AND evidence_source IS NOT NULL AND evidence_observed_at IS NOT NULL)),
  CHECK (state <> 'APPLIED' OR evidence_checked = 1),
  PRIMARY KEY (account, exec_id, message_id),
  FOREIGN KEY (account, exec_id) REFERENCES cleanup_execution (account, exec_id),
  FOREIGN KEY (account, exec_id, slice_no) REFERENCES cleanup_exec_slice (account, exec_id, slice_no)) WITHOUT ROWID;
CREATE UNIQUE INDEX cleanup_exec_item_seq ON cleanup_exec_item (account, exec_id, seq);
CREATE TRIGGER cleanup_exec_insert_guard BEFORE INSERT ON cleanup_execution
WHEN NEW.state <> 'PREPARED'
  OR EXISTS (SELECT 1 FROM cleanup_execution x WHERE x.account = NEW.account AND x.exec_id = NEW.exec_id)
  OR NOT EXISTS (SELECT 1 FROM cleanup_approval a WHERE a.account = NEW.account AND a.plan_id = NEW.plan_id
      AND a.nonce = NEW.approval_nonce AND a.plan_hash = NEW.plan_hash AND a.status = 'CONSUMED')
  OR NOT EXISTS (SELECT 1 FROM cleanup_plan p WHERE p.account = NEW.account AND p.plan_id = NEW.plan_id AND p.state = 'APPROVED'
      AND p.plan_hash = NEW.plan_hash AND p.item_count = NEW.item_count AND p.action = NEW.action)
BEGIN SELECT RAISE(ABORT, 'an execution needs a CONSUMED approval of an APPROVED plan and must start PREPARED'); END;
CREATE TRIGGER cleanup_exec_content_immutable BEFORE UPDATE ON cleanup_execution
WHEN NEW.account IS NOT OLD.account OR NEW.exec_id IS NOT OLD.exec_id OR NEW.plan_id IS NOT OLD.plan_id
  OR NEW.plan_hash IS NOT OLD.plan_hash OR NEW.approval_nonce IS NOT OLD.approval_nonce OR NEW.action IS NOT OLD.action
  OR NEW.item_count IS NOT OLD.item_count OR NEW.slice_count IS NOT OLD.slice_count
  OR NEW.confirmation_sha256 IS NOT OLD.confirmation_sha256 OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'execution content is immutable'); END;
CREATE TRIGGER cleanup_exec_state_forward_only BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state <> OLD.state AND NOT (
     (OLD.state = 'PREPARED' AND NEW.state IN ('EXECUTING','ABORTED'))
  OR (OLD.state = 'EXECUTING' AND NEW.state IN ('AWAITING_CONTINUATION','PARTIAL','EXECUTED','FAILED','RECONCILIATION_REQUIRED'))
  OR (OLD.state = 'AWAITING_CONTINUATION' AND NEW.state IN ('EXECUTING','ABORTED'))
  OR (OLD.state = 'RECONCILIATION_REQUIRED' AND NEW.state IN ('PARTIAL','EXECUTED','FAILED')))
BEGIN SELECT RAISE(ABORT, 'illegal execution state transition'); END;
CREATE TRIGGER cleanup_exec_start_needs_frozen_targets BEFORE UPDATE OF state ON cleanup_execution
WHEN OLD.state = 'PREPARED' AND NEW.state = 'EXECUTING' AND (
     (SELECT COUNT(*) FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id) <> NEW.item_count
  OR (SELECT COUNT(*) FROM cleanup_exec_slice s WHERE s.account = NEW.account AND s.exec_id = NEW.exec_id) <> NEW.slice_count)
BEGIN SELECT RAISE(ABORT, 'an execution may only start with exactly its frozen targets and slices'); END;
CREATE TRIGGER cleanup_exec_terminal_has_no_open_items BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state IN {_TERMINAL} AND EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id
  AND i.state IN {_OPEN})
BEGIN SELECT RAISE(ABORT, 'a finished execution cannot contain pending, in-flight or unknown items'); END;
CREATE TRIGGER cleanup_exec_executed_means_all_evidence_checked BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'EXECUTED' AND (
     NOT EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state = 'APPLIED')
  OR EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state = 'APPLIED' AND i.evidence_checked <> 1)
  OR EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state IN ('NOT_APPLIED','CONFLICT')))
BEGIN SELECT RAISE(ABORT, 'EXECUTED needs at least one APPLIED item, all with checked evidence, and no unsuccessful items'); END;
CREATE TRIGGER cleanup_exec_running_needs_active_slice BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'EXECUTING' AND OLD.state <> 'EXECUTING' AND
     (SELECT COUNT(*) FROM cleanup_exec_slice s WHERE s.account = NEW.account AND s.exec_id = NEW.exec_id AND s.state = 'ACTIVE') <> 1
BEGIN SELECT RAISE(ABORT, 'an execution may only start running with exactly one ACTIVE slice'); END;
CREATE TRIGGER cleanup_exec_failed_means_nothing_applied BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'FAILED' AND EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state = 'APPLIED')
BEGIN SELECT RAISE(ABORT, 'FAILED means nothing was applied'); END;
CREATE TRIGGER cleanup_exec_partial_means_some_applied_some_not BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'PARTIAL' AND (
     NOT EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state = 'APPLIED')
  OR NOT EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state IN ('NOT_APPLIED','CONFLICT')))
BEGIN SELECT RAISE(ABORT, 'PARTIAL needs some applied and some unsuccessful items'); END;
CREATE TRIGGER cleanup_exec_awaiting_needs_pending_slice BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'AWAITING_CONTINUATION' AND (
     NOT EXISTS (SELECT 1 FROM cleanup_exec_slice s WHERE s.account = NEW.account AND s.exec_id = NEW.exec_id AND s.state = 'PENDING')
  OR EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state IN ('INTENT','UNKNOWN')))
BEGIN SELECT RAISE(ABORT, 'AWAITING_CONTINUATION needs a pending slice and no in-flight or unknown items'); END;
CREATE TRIGGER cleanup_exec_awaiting_needs_safe_slices BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'AWAITING_CONTINUATION' AND (
     EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id AND i.state IN ('NOT_APPLIED','CONFLICT'))
  OR EXISTS (SELECT 1 FROM cleanup_exec_slice s WHERE s.account = NEW.account AND s.exec_id = NEW.exec_id AND s.state = 'COMPLETED'
      AND NOT EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = s.account AND i.exec_id = s.exec_id AND i.slice_no = s.slice_no AND i.state = 'APPLIED')))
BEGIN SELECT RAISE(ABORT, 'no continuation after a slice with no applied item or with rejected or conflicting items'); END;
CREATE TRIGGER cleanup_exec_reconciliation_needs_unknown BEFORE UPDATE OF state ON cleanup_execution
WHEN NEW.state = 'RECONCILIATION_REQUIRED' AND NOT EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account
  AND i.exec_id = NEW.exec_id AND i.state = 'UNKNOWN')
BEGIN SELECT RAISE(ABORT, 'RECONCILIATION_REQUIRED needs at least one UNKNOWN item'); END;
CREATE TRIGGER cleanup_exec_no_delete BEFORE DELETE ON cleanup_execution
BEGIN SELECT RAISE(ABORT, 'executions are never deleted'); END;
CREATE TRIGGER cleanup_exec_slice_insert_guard BEFORE INSERT ON cleanup_exec_slice
WHEN NEW.state NOT IN ('PENDING','CONFIRMED')
  OR EXISTS (SELECT 1 FROM cleanup_exec_slice x WHERE x.account = NEW.account AND x.exec_id = NEW.exec_id AND x.slice_no = NEW.slice_no)
  OR (SELECT state FROM cleanup_execution e WHERE e.account = NEW.account AND e.exec_id = NEW.exec_id) IS NOT 'PREPARED'
BEGIN SELECT RAISE(ABORT, 'slices can only be created while the execution is being reserved'); END;
CREATE UNIQUE INDEX cleanup_exec_one_active_slice ON cleanup_exec_slice (account, exec_id) WHERE state = 'ACTIVE';
CREATE TRIGGER cleanup_exec_slice_activate_before_running BEFORE UPDATE OF state ON cleanup_exec_slice
WHEN NEW.state = 'ACTIVE' AND (SELECT state FROM cleanup_execution e WHERE e.account = NEW.account AND e.exec_id = NEW.exec_id)
     NOT IN ('PREPARED','AWAITING_CONTINUATION')
BEGIN SELECT RAISE(ABORT, 'a slice is activated before the execution starts running'); END;
CREATE TRIGGER cleanup_exec_slice_immutable BEFORE UPDATE ON cleanup_exec_slice
WHEN NEW.account IS NOT OLD.account OR NEW.exec_id IS NOT OLD.exec_id OR NEW.slice_no IS NOT OLD.slice_no OR NEW.size IS NOT OLD.size
BEGIN SELECT RAISE(ABORT, 'slice identity is immutable'); END;
CREATE TRIGGER cleanup_exec_slice_state_forward_only BEFORE UPDATE OF state ON cleanup_exec_slice
WHEN NEW.state <> OLD.state AND NOT (
     (OLD.state = 'PENDING' AND NEW.state IN ('CONFIRMED','STOPPED'))
  OR (OLD.state = 'CONFIRMED' AND NEW.state IN ('ACTIVE','STOPPED'))
  OR (OLD.state = 'ACTIVE' AND NEW.state IN ('COMPLETED','STOPPED')))
BEGIN SELECT RAISE(ABORT, 'illegal slice state transition'); END;
CREATE TRIGGER cleanup_exec_slice_completed_has_no_open_items BEFORE UPDATE OF state ON cleanup_exec_slice
WHEN NEW.state = 'COMPLETED' AND EXISTS (SELECT 1 FROM cleanup_exec_item i WHERE i.account = NEW.account AND i.exec_id = NEW.exec_id
  AND i.slice_no = NEW.slice_no AND i.state IN {_OPEN})
BEGIN SELECT RAISE(ABORT, 'a COMPLETED slice cannot contain pending, in-flight or unknown items'); END;
CREATE TRIGGER cleanup_exec_slice_frozen_when_terminal BEFORE UPDATE ON cleanup_exec_slice
WHEN (SELECT state FROM cleanup_execution e WHERE e.account = OLD.account AND e.exec_id = OLD.exec_id) IN {_TERMINAL}
BEGIN SELECT RAISE(ABORT, 'slices of a finished execution are frozen'); END;
CREATE TRIGGER cleanup_exec_slice_no_delete BEFORE DELETE ON cleanup_exec_slice
BEGIN SELECT RAISE(ABORT, 'slices are never deleted'); END;
CREATE TRIGGER cleanup_exec_item_insert_guard BEFORE INSERT ON cleanup_exec_item
WHEN NEW.state NOT IN ('PENDING','SKIPPED_DRIFT') OR NEW.evidence_checked <> 0
  OR EXISTS (SELECT 1 FROM cleanup_exec_item x WHERE x.account = NEW.account AND x.exec_id = NEW.exec_id AND x.message_id = NEW.message_id)
  OR (SELECT state FROM cleanup_execution e WHERE e.account = NEW.account AND e.exec_id = NEW.exec_id) IS NOT 'PREPARED'
  OR NOT EXISTS (SELECT 1 FROM cleanup_execution e JOIN cleanup_item ci ON ci.account = e.account AND ci.plan_id = e.plan_id
      WHERE e.account = NEW.account AND e.exec_id = NEW.exec_id AND ci.message_id = NEW.message_id)
BEGIN SELECT RAISE(ABORT, 'execution targets must be exactly items of the approved plan and are fixed at reservation'); END;
CREATE TRIGGER cleanup_exec_item_identity_immutable BEFORE UPDATE ON cleanup_exec_item
WHEN NEW.account IS NOT OLD.account OR NEW.exec_id IS NOT OLD.exec_id OR NEW.message_id IS NOT OLD.message_id
  OR NEW.seq IS NOT OLD.seq OR NEW.slice_no IS NOT OLD.slice_no
BEGIN SELECT RAISE(ABORT, 'execution item identity is immutable'); END;
CREATE TRIGGER cleanup_exec_item_recovery_metadata_immutable BEFORE UPDATE ON cleanup_exec_item
WHEN (OLD.prev_label_ids IS NOT NULL AND NEW.prev_label_ids IS NOT OLD.prev_label_ids)
  OR (OLD.intent_at IS NOT NULL AND NEW.intent_at IS NOT OLD.intent_at)
BEGIN SELECT RAISE(ABORT, 'previous label ids and the intent time are immutable once recorded'); END;
CREATE TRIGGER cleanup_exec_item_frozen_when_terminal BEFORE UPDATE ON cleanup_exec_item
WHEN (SELECT state FROM cleanup_execution e WHERE e.account = OLD.account AND e.exec_id = OLD.exec_id) IN {_TERMINAL}
BEGIN SELECT RAISE(ABORT, 'items of a finished execution are frozen'); END;
CREATE TRIGGER cleanup_exec_item_state_forward_only BEFORE UPDATE OF state ON cleanup_exec_item
WHEN NEW.state <> OLD.state AND NOT (
     (OLD.state = 'PENDING' AND NEW.state IN ('INTENT','SKIPPED_DRIFT','SKIPPED_GONE','NOT_APPLIED'))
  OR (OLD.state = 'INTENT' AND NEW.state IN ('APPLIED','NOT_APPLIED','UNKNOWN'))
  OR (OLD.state = 'UNKNOWN' AND NEW.state IN ('APPLIED','NOT_APPLIED','CONFLICT')))
BEGIN SELECT RAISE(ABORT, 'illegal execution item state transition'); END;
CREATE TRIGGER cleanup_exec_item_intent_needs_metadata BEFORE UPDATE OF state ON cleanup_exec_item
WHEN NEW.state = 'INTENT' AND (
     (SELECT state FROM cleanup_execution e WHERE e.account = NEW.account AND e.exec_id = NEW.exec_id) IS NOT 'EXECUTING'
  OR NEW.intent_at IS NULL OR NEW.prev_label_ids IS NULL OR substr(NEW.prev_label_ids, 1, 1) <> '[' OR instr(NEW.prev_label_ids, '"INBOX"') = 0)
BEGIN SELECT RAISE(ABORT, 'an intent needs the EXECUTING state, a time and the previous label ids including INBOX'); END;
CREATE TRIGGER cleanup_exec_item_applied_needs_proof BEFORE UPDATE OF state ON cleanup_exec_item
WHEN NEW.state = 'APPLIED' AND (OLD.prev_label_ids IS NULL OR OLD.intent_at IS NULL OR NEW.evidence_checked <> 1 OR NEW.result_at IS NULL
  OR NEW.evidence_source IS NULL OR NEW.evidence_observed_at IS NULL OR NEW.evidence_observed_at < OLD.intent_at
  OR (OLD.state = 'UNKNOWN' AND NEW.evidence_observed_at < OLD.result_at))
BEGIN SELECT RAISE(ABORT, 'APPLIED needs recovery metadata, a result time and evidence not earlier than the intent (or the unknown result)'); END;
CREATE TRIGGER cleanup_exec_item_evidence_only_when_applied BEFORE UPDATE OF evidence_checked ON cleanup_exec_item
WHEN NEW.evidence_checked = 1 AND NEW.state <> 'APPLIED'
BEGIN SELECT RAISE(ABORT, 'only an APPLIED item can carry checked evidence'); END;
CREATE TRIGGER cleanup_exec_item_evidence_never_downgraded BEFORE UPDATE ON cleanup_exec_item
WHEN OLD.evidence_checked = 1 AND (NEW.evidence_checked IS NOT 1 OR NEW.evidence_source IS NOT OLD.evidence_source
  OR NEW.evidence_observed_at IS NOT OLD.evidence_observed_at)
BEGIN SELECT RAISE(ABORT, 'accepted evidence can never be downgraded or altered'); END;
CREATE TRIGGER cleanup_exec_item_no_delete BEFORE DELETE ON cleanup_exec_item
BEGIN SELECT RAISE(ABORT, 'execution items are never deleted'); END;
CREATE TRIGGER cleanup_plan_locked_by_execution BEFORE UPDATE OF state ON cleanup_plan
WHEN NEW.state <> OLD.state AND EXISTS (SELECT 1 FROM cleanup_execution e WHERE e.account = OLD.account AND e.plan_id = OLD.plan_id)
BEGIN SELECT RAISE(ABORT, 'a plan that has an execution can no longer change state'); END;
"""


def _reserve_backup(base):
    """Create a NEW empty file at `base` (or `base-N`) with mode 0600. O_EXCL guarantees an existing file is never touched."""
    for n in range(100):
        path = base if n == 0 else f"{base}-{n}"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        try:
            os.fchmod(fd, 0o600)  # also correct under an unusual umask
        finally:
            os.close(fd)
        return path
    raise OSError("no free backup file name")


def _write_backup(src_conn, path, version):
    """Copy the database into the reserved file and check that the copy is complete and consistent."""
    dest = sqlite3.connect(path)
    try:
        src_conn.backup(dest)
    finally:
        dest.close()
    os.chmod(path, 0o600)
    check = sqlite3.connect(path)
    try:
        if check.execute("PRAGMA user_version").fetchone()[0] != version or check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise sqlite3.DatabaseError("backup verification failed")
    finally:
        check.close()


def _discard_partial(path):
    try:
        os.unlink(path)
    except OSError:
        pass


class IndexProblem(Exception):
    """Index problem with a user-facing message."""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Index:
    def __init__(self, path=None, create=True):
        self.path = path if path is not None else config.index_path()
        parent = os.path.dirname(self.path) or "."
        if not os.path.exists(self.path) and not create:
            raise IndexProblem("no local index yet; run `mailbox scan --limit 100` first")
        os.makedirs(parent, mode=0o700, exist_ok=True)
        os.chmod(parent, 0o700)
        self.conn = sqlite3.connect(self.path)
        os.chmod(self.path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        # PRAGMAs are per connection. Without recursive_triggers, INSERT OR REPLACE deletes the old row WITHOUT firing the BEFORE DELETE
        # (no-delete) triggers. Every production connection is opened here; the setting is verified, not assumed.
        self.conn.execute("PRAGMA recursive_triggers = ON")
        if self.conn.execute("PRAGMA recursive_triggers").fetchone()[0] != 1:
            self.conn.close()
            raise IndexProblem("could not enable recursive_triggers; refusing to open the index")
        self.migrated_from = self.backup_path = None
        try:
            version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.DatabaseError:
            self.conn.close()
            raise IndexProblem("the local index file is unreadable or corrupt; nothing was changed. Restore a backup "
                               "(e.g. index.sqlite3.pre-m3-backup-*) or remove the file and rescan") from None
        if version == 0:
            with self.conn:
                self.conn.executescript("BEGIN;" + SCHEMA + SCHEMA_V2 + SCHEMA_V3 + SCHEMA_V4 + SCHEMA_V5 + f"PRAGMA user_version = {SCHEMA_VERSION};COMMIT;")
        elif version in (1, 2, 3, 4):
            self._migrate(version)
        elif version != SCHEMA_VERSION:
            self.conn.close()
            raise IndexProblem(f"unsupported index schema version {version} (expected {SCHEMA_VERSION})")

    def _migrate(self, version):
        """Back up the database file, then add the missing tables in one transaction (all-or-nothing).

        The backup file is created exclusively (never overwriting an existing file) with mode 0600 from the first byte; a partial
        backup that WE created is removed if writing it fails; a complete, verified backup is always kept.
        """
        tag = {1: "pre-m3", 2: "pre-m4a", 3: "pre-m4b", 4: "pre-m4c"}[version]
        script = "".join([SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5][version - 1:])  # names resolved now, so tests can patch them
        base = f"{self.path}.{tag}-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        backup = None
        try:
            backup = _reserve_backup(base)
            _write_backup(self.conn, backup, version)
        except (sqlite3.Error, OSError) as exc:
            if backup:
                _discard_partial(backup)
            self.conn.close()
            raise IndexProblem(f"could not create the safety backup ({type(exc).__name__}); the index was left unchanged "
                               "and no partial backup was kept") from None
        try:
            with self.conn:
                self.conn.executescript("BEGIN;" + script + f"PRAGMA user_version = {SCHEMA_VERSION};COMMIT;")
        except sqlite3.Error as exc:
            try:
                done = self.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
            except sqlite3.Error:
                done = False
            if done:  # another process finished the same upgrade first: our redundant backup (which we created) can go
                _discard_partial(backup)
                return
            self.conn.close()
            raise IndexProblem(f"could not upgrade the index to schema version {SCHEMA_VERSION}; it was left unchanged "
                               f"({type(exc).__name__}); the verified backup was kept: {backup}") from None
        self.migrated_from = version
        self.backup_path = backup

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _q(self, sql, *params):
        return self.conn.execute(sql, params).fetchall()

    # ---- scans ----
    def start_scan(self, account, mode, limit=None):
        with self.conn:  # an old 'running' scan of this account can only be a crashed one
            self.conn.execute("UPDATE scans SET status='interrupted' WHERE account=? AND status='running'", (account,))
            cur = self.conn.execute("INSERT INTO scans (account, mode, limit_n, status, started_at) VALUES (?,?,?,?,?)",
                                    (account, mode, limit, "running", _now()))
        return cur.lastrowid

    def find_resumable(self, account):
        """Latest unfinished scan of this account (interrupted/running/incomplete after a stop), or None."""
        rows = self._q("SELECT * FROM scans WHERE account=? ORDER BY id DESC LIMIT 1", account)
        if rows and rows[0]["status"] in ("interrupted", "running", "failed"):
            return dict(rows[0])
        return None

    def reopen_scan(self, scan_id):
        with self.conn:
            self.conn.execute("UPDATE scans SET status='running', error=NULL, finished_at=NULL WHERE id=?", (scan_id,))

    def set_page_token(self, scan_id, token):
        with self.conn:
            self.conn.execute("UPDATE scans SET page_token=? WHERE id=?", (token, scan_id))

    def finish_scan(self, scan_id, status, error=None, **counters):
        with self.conn:
            self.conn.execute("UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                              (status, _now(), error, scan_id))
            for key, val in counters.items():
                assert key in ("listed", "indexed", "vanished", "failed", "pruned")
                self.conn.execute(f"UPDATE scans SET {key}=? WHERE id=?", (val, scan_id))

    def add_counters(self, scan_id, listed=0, indexed=0, vanished=0, failed=0):
        self.conn.execute("UPDATE scans SET listed=listed+?, indexed=indexed+?, vanished=vanished+?, failed=failed+? "
                          "WHERE id=?", (listed, indexed, vanished, failed, scan_id))

    def scan(self, scan_id):
        rows = self._q("SELECT * FROM scans WHERE id=?", scan_id)
        return dict(rows[0]) if rows else None

    def recent_scans(self, account, n=5):
        return [dict(r) for r in self._q("SELECT * FROM scans WHERE account=? ORDER BY id DESC LIMIT ?", account, n)]

    # ---- messages ----
    def done_ids(self, account, scan_id, ids):
        """Ids from `ids` already fetched during this scan (stamped with its id)."""
        if not ids:
            return set()
        marks = ",".join("?" * len(ids))
        rows = self._q(f"SELECT id FROM messages WHERE account=? AND scan_id=? AND id IN ({marks})",
                       account, scan_id, *ids)
        return {r["id"] for r in rows}

    def set_listed(self, scan_id, listed):
        with self.conn:
            self.conn.execute("UPDATE scans SET listed=? WHERE id=?", (listed, scan_id))

    def save_batch(self, account, scan_id, rows, vanished=0, failed=0):
        """Upsert message rows (dicts from the adapter) and bump counters in ONE transaction."""
        with self.conn:
            for r in rows:
                labels = r["label_ids"]
                self.conn.execute(
                    "INSERT INTO messages (account,id,thread_id,internal_ms,size,sender,unread,scan_id) "
                    "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(account,id) DO UPDATE SET thread_id=excluded.thread_id, "
                    "internal_ms=excluded.internal_ms, size=excluded.size, sender=excluded.sender, "
                    "unread=excluded.unread, scan_id=excluded.scan_id",
                    (account, r["id"], r["thread_id"], r["internal_ms"], r["size"], r["sender"],
                     1 if "UNREAD" in labels else 0, scan_id))
                self.conn.execute("DELETE FROM message_labels WHERE account=? AND message_id=?", (account, r["id"]))
                self.conn.executemany("INSERT OR IGNORE INTO message_labels VALUES (?,?,?)",
                                      [(account, r["id"], lab) for lab in labels])
            self.add_counters(scan_id, indexed=len(rows), vanished=vanished, failed=failed)

    def save_labels(self, account, labels):
        with self.conn:
            self.conn.execute("DELETE FROM labels WHERE account=?", (account,))
            self.conn.executemany("INSERT OR IGNORE INTO labels VALUES (?,?,?,?)",
                                  [(account, x["id"], x["name"], x["type"]) for x in labels if x.get("id")])

    def prune_unseen(self, account, scan_id):
        """After a COMPLETE full scan only: drop rows the scan did not see (no longer in Gmail)."""
        with self.conn:
            for table, col in (("message_labels", "message_id"), ("message_class", "message_id")):
                self.conn.execute(f"DELETE FROM {table} WHERE account=? AND {col} IN "
                                  "(SELECT id FROM messages WHERE account=? AND scan_id<>?)", (account, account, scan_id))
            cur = self.conn.execute("DELETE FROM messages WHERE account=? AND scan_id<>?", (account, scan_id))
        return cur.rowcount

    def purge(self, account):
        with self.conn:
            for table in ("message_class", "message_labels", "messages", "labels", "scans"):  # class_rules (user config) is kept
                self.conn.execute(f"DELETE FROM {table} WHERE account=?", (account,))

    def accounts(self):
        return [r[0] for r in self._q("SELECT DISTINCT account FROM scans UNION SELECT DISTINCT account FROM messages")]

    # ---- reporting queries (local only) ----
    def overview(self, account):
        r = self._q("SELECT COUNT(*) n, COUNT(DISTINCT thread_id) t, COALESCE(SUM(unread),0) u, "
                    "COALESCE(SUM(size),0) sz, MIN(internal_ms) lo, MAX(internal_ms) hi FROM messages WHERE account=?",
                    account)[0]
        return dict(r)

    def label_counts(self, account):
        return [dict(r) for r in self._q(
            "SELECT ml.label_id id, l.name name, l.type type, COUNT(*) n FROM message_labels ml "
            "LEFT JOIN labels l ON l.account=ml.account AND l.id=ml.label_id WHERE ml.account=? "
            "GROUP BY ml.label_id ORDER BY n DESC, ml.label_id", account)]

    def by_period(self, account, fmt):
        assert fmt in ("%Y", "%Y-%m")
        return [(r[0], r[1]) for r in self._q(
            f"SELECT strftime('{fmt}', internal_ms/1000, 'unixepoch') p, COUNT(*) FROM messages "
            "WHERE account=? AND internal_ms IS NOT NULL GROUP BY p ORDER BY p", account)]

    def top_senders(self, account, limit=20, unread_only=False, domains=False):
        key = "COALESCE(substr(sender, instr(sender,'@')+1), '(unknown)')" if domains else "COALESCE(sender,'(unknown)')"
        where = "AND unread=1" if unread_only else ""
        return [dict(r) for r in self._q(
            f"SELECT {key} who, COUNT(*) n, COALESCE(SUM(unread),0) unread, COALESCE(SUM(size),0) size "
            f"FROM messages WHERE account=? {where} GROUP BY who ORDER BY n DESC, who LIMIT ?", account, limit)]
