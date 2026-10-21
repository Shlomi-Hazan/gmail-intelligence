"""Post-M7 acceptance correction: an UNEXPECTED internal error in a read-only report never prints a traceback or the exception text.

`mailbox maintenance`, `mailbox changes` and `cleanup plan impact` return a non-zero exit code with one fixed generic message, print nothing to stdout (no partial or
"successful-looking" report), never touch the database files, and keep the normal diagnostics for known errors. Text and JSON modes. Synthetic data only.
"""
import contextlib
import hashlib
import io
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from gmail_intelligence import cli, config, maintenance, plan_impact, sync_report  # noqa: E402
from gmail_intelligence import index as idx  # noqa: E402

LEAK_MARK = "SyntheticLeakMarker7731"
ACCOUNT = "owner@example.test"
GENERIC = "error: " + cli._REPORT_UNEXPECTED + "\n"


def tree(directory):
    out = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        st = os.lstat(p)
        out.append((name, st.st_size, st.st_mtime_ns, st.st_mode, hashlib.sha256(Path(p).read_bytes()).hexdigest()))
    return out


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.join(tmp.name, "home")
        patcher = mock.patch.dict(os.environ, {config.HOME_ENV: self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        idx.Index().close()
        self.dir = os.path.dirname(str(config.index_path()))

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def commands(self):
        for mode in ([], ["--json"]):
            yield ["mailbox", "maintenance", "--account", ACCOUNT] + mode
            yield ["mailbox", "changes", "--account", ACCOUNT] + mode
            yield ["cleanup", "plan", "impact", "--account", ACCOUNT] + mode

    def assertGeneric(self, argv, code, out, err):
        self.assertEqual(code, 1, argv)
        self.assertEqual(err, GENERIC, argv)
        self.assertEqual(out, "", argv)  # no partial report that could look like success
        self.assertNotIn(SECRET, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertNotIn("RuntimeError", out + err)

    def test_an_unexpected_error_in_the_report_builder_is_generic_in_text_and_json(self):
        boom = RuntimeError(f"failure containing {SECRET}")
        with mock.patch.object(maintenance, "run", side_effect=boom), mock.patch.object(sync_report, "changes_report", side_effect=boom), \
                mock.patch.object(plan_impact, "impact_report", side_effect=boom):
            before = tree(self.dir)
            for argv in self.commands():
                self.assertGeneric(argv, *self.run_cli(argv))
            self.assertEqual(tree(self.dir), before)

    def test_an_unexpected_error_while_rendering_is_generic_and_prints_nothing(self):
        boom = RuntimeError(SECRET)
        with mock.patch.object(maintenance, "render_text", side_effect=boom), mock.patch.object(sync_report, "changes_text", side_effect=boom), \
                mock.patch.object(plan_impact, "impact_text", side_effect=boom):
            before = tree(self.dir)
            for argv in self.commands():
                if "--json" not in argv:
                    self.assertGeneric(argv, *self.run_cli(argv))
            self.assertEqual(tree(self.dir), before)

    def test_unexpected_error_in_a_deep_check_and_in_the_account_lookup(self):
        with mock.patch.object(maintenance, "_audit_checks", side_effect=RuntimeError(SECRET)):
            argv = ["mailbox", "maintenance", "--account", ACCOUNT, "--json"]
            self.assertGeneric(argv, *self.run_cli(argv))
        with mock.patch.object(cli, "_local_account", side_effect=RuntimeError(SECRET)):
            argv = ["mailbox", "changes", "--json"]
            self.assertGeneric(argv, *self.run_cli(argv))

    def test_the_real_reports_still_succeed_and_print_to_stdout(self):
        for argv in self.commands():
            code, out, err = self.run_cli(argv)
            self.assertEqual(code, 0, (argv, err))
            self.assertTrue(out.strip(), argv)
            self.assertEqual(err, "", argv)

    def test_known_errors_keep_their_normal_diagnostics(self):
        os.remove(str(config.index_path()))  # no index: a known condition, not an unexpected one
        for argv in (["mailbox", "changes", "--account", ACCOUNT], ["cleanup", "plan", "impact", "--account", ACCOUNT, "--json"]):
            code, out, err = self.run_cli(argv)
            self.assertEqual(code, 1)
            self.assertIn("no local index yet", err)
            self.assertNotIn(cli._REPORT_UNEXPECTED, err)
        idx.Index().close()
        with mock.patch.object(sync_report, "changes_report", side_effect=sqlite3.DatabaseError(SECRET)):
            code, out, err = self.run_cli(["mailbox", "changes", "--account", ACCOUNT])
        self.assertEqual(code, 1)
        self.assertIn("reported an error", err)
        self.assertNotIn(SECRET, err)
        code, out, err = self.run_cli(["mailbox", "changes", "--account", ACCOUNT, "--runs", "0"])
        self.assertEqual((code, "between 1 and 50" in err), (1, True))

    def test_the_boundary_is_narrow_other_commands_are_not_wrapped(self):
        with mock.patch.object(cli, "_with_index", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(RuntimeError):
                cli.main(["mailbox", "status", "--account", ACCOUNT])


if __name__ == "__main__":
    unittest.main()
