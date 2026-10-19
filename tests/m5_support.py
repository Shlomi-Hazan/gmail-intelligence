"""Shared synthetic-fixture helpers for the M5 tests (label hygiene, recommendations, suggestions, plans). Synthetic data only: reserved example domains, invented label names,
temporary SQLite files, a socket guard (from test_cleanup.Base) and bombs for the Gmail reader and the Keychain."""
import contextlib
import io
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cleanup import ACCT, Base, DAY, NOW, OTHER, msg  # noqa: E402

from gmail_intelligence import cli  # noqa: E402

__all__ = ["ACCT", "OTHER", "NOW", "DAY", "M5Base", "label", "mail"]


def label(id, name, type="user"):
    return {"id": id, "name": name, "type": type}


def mail(i, labels=("INBOX",), sender=None, days=200, thread=None, unread=False):
    m = msg(i, days=days, sender=sender or f"s{i}@shop.example.test", labels=tuple(labels), thread=thread)
    if unread:
        m["label_ids"] = list(labels) + ["UNREAD"]
    return m


class M5Base(Base):
    def fixture(self, labels=(), messages=(), complete=True, account=ACCT, classify=True):
        """Seed labels and messages through the real scan path (a full scan unless complete=False)."""
        self.seed(list(messages), account=account, complete=complete, labels=list(labels) or None, classify=classify)
        if not messages and labels:
            self.index.save_labels(account, list(labels))

    def run_cli(self, *argv, inputs=None, tty=True):
        out, err = io.StringIO(), io.StringIO()
        feed = iter(inputs or [])

        def fake(prompt):
            try:
                return next(feed)
            except StopIteration:
                raise EOFError from None
        patches = [mock.patch.object(cli, "_open_reader", side_effect=AssertionError("Gmail used")),
                   mock.patch.object(cli, "_store", side_effect=AssertionError("Keychain used")),
                   mock.patch.object(cli, "_write_store", side_effect=AssertionError("write Keychain used"))]
        if tty:
            patches.append(mock.patch.object(cli, "_tty_input", side_effect=fake))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                code = cli.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()
