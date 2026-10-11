"""Tests for the offline CLI and the package's no-network / no-dependency guarantees."""
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import gmail_intelligence  # noqa: E402

FORBIDDEN_IMPORTS = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "imaplib", "poplib",
                     "requests", "httpx", "googleapiclient", "google", "google_auth_oauthlib"}


def run_cli(*args, cwd=ROOT, env_extra=None):
    env = {"PATH": os.environ["PATH"], "PYTHONPATH": str(SRC), **(env_extra or {})}
    return subprocess.run([sys.executable, "-m", "gmail_intelligence", *args],
                          cwd=cwd, env=env, capture_output=True, text=True)


class CliTests(unittest.TestCase):
    def test_package_import_and_version(self):
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertIn('attr = "gmail_intelligence.__version__"', pyproject)
        self.assertRegex(gmail_intelligence.__version__, r"^\d+\.\d+\.\d+$")

    def test_help(self):
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage:", proc.stdout)
        self.assertIn("doctor", proc.stdout)

    def test_version(self):
        proc = run_cli("version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), f"gmail-intelligence {gmail_intelligence.__version__}")

    def test_doctor_in_repo(self):
        proc = run_cli("doctor")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("python", proc.stdout)
        self.assertIn("0 failed", proc.stdout)

    def test_doctor_outside_repo_skips_repo_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_cli("doctor", cwd=tmp, env_extra={"GIT_CEILING_DIRECTORIES": tmp})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("not inside a git repository", proc.stdout)

    def test_doctor_does_not_print_environment_values(self):
        marker = "synthetic-env-" + "value-12345"
        proc = run_cli("doctor", env_extra={"GMAIL_INTEL_TEST_TOKEN": marker})
        self.assertNotIn(marker, proc.stdout + proc.stderr)

    def test_invalid_command_exit_code(self):
        proc = run_cli("frobnicate")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid choice", proc.stderr)

    def test_missing_command_exit_code(self):
        self.assertEqual(run_cli().returncode, 2)


class OfflineGuarantees(unittest.TestCase):
    def test_runtime_has_no_dependencies(self):
        self.assertRegex((ROOT / "pyproject.toml").read_text(), r"(?m)^dependencies = \[\]")

    def test_source_imports_only_stdlib_and_no_network_modules(self):
        stdlib = set(sys.stdlib_module_names) | {"gmail_intelligence"}
        for path in SRC.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    self.assertIn(top, stdlib, f"{path.name}: non-stdlib import {name}")
                    self.assertNotIn(top, FORBIDDEN_IMPORTS, f"{path.name}: forbidden import {name}")

    def test_secret_scanner_compatible_with_repository(self):
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "scan_secrets.py"), "--all"],
                              cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
