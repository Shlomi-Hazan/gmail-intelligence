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


class HiddenPthTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "chflags") and hasattr(__import__("stat"), "UF_HIDDEN"), "macOS/BSD file flags only")
    def test_detects_hidden_pth_files(self):
        import stat
        from gmail_intelligence import cli
        with tempfile.TemporaryDirectory() as tmp:
            visible, hidden = Path(tmp, "a.pth"), Path(tmp, "b.pth")
            visible.write_text("x\n")
            hidden.write_text("x\n")
            os.chflags(hidden, stat.UF_HIDDEN)
            self.assertEqual(cli.hidden_pth_files([tmp]), [hidden])
            os.chflags(hidden, 0)
            self.assertEqual(cli.hidden_pth_files([tmp]), [])

    def test_no_hidden_pth_for_missing_dir(self):
        from gmail_intelligence import cli
        self.assertEqual(cli.hidden_pth_files(["/nonexistent-dir-for-test"]), [])


class OfflineGuarantees(unittest.TestCase):
    # Only these modules may import third-party / Google libraries (all lazily imported by the CLI).
    GOOGLE_MODULES = {"oauth.py", "gmail.py", "keystore.py", "oauth_write.py", "keystore_write.py"}  # scanner/index/report stay stdlib-only
    WRITE_TRANSPORT_MODULES = {"gmail_write.py"}  # M4C-B1: stdlib-only thin HTTPS transport; may import http.client and ssl, nothing broader
    LOOPBACK_AI_MODULES = {"ai_http.py"}  # M3: the only stdlib-networking module; may import urllib, nothing broader

    def test_runtime_dependencies_are_the_reviewed_set(self):
        text = (ROOT / "pyproject.toml").read_text()
        block = re.search(r"(?s)^dependencies = \[(.*?)\]", text, re.M).group(1)
        names = sorted(re.findall(r'"([A-Za-z0-9_.\-]+)', block))
        self.assertEqual(names, ["google-api-python-client", "google-auth-oauthlib", "keyring"])

    def test_only_google_modules_import_third_party_or_network_code(self):
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
                    if path.name in self.LOOPBACK_AI_MODULES:
                        self.assertNotIn(top, {"socket", "ssl", "http", "smtplib", "imaplib", "poplib", "ftplib"}, path.name)
                        continue
                    if path.name in self.WRITE_TRANSPORT_MODULES:
                        self.assertNotIn(top, {"socket", "urllib", "smtplib", "imaplib", "poplib", "ftplib", "requests", "httpx", "googleapiclient", "google"}, path.name)
                        self.assertIn(top, stdlib, path.name)
                        continue
                    if path.name in self.GOOGLE_MODULES:
                        self.assertNotIn(top, {"socket", "ssl", "http", "urllib", "smtplib", "imaplib", "poplib"}, path.name)
                        continue
                    self.assertIn(top, stdlib, f"{path.name}: non-stdlib import {name}")
                    self.assertNotIn(top, FORBIDDEN_IMPORTS, f"{path.name}: forbidden import {name}")

    def test_local_commands_do_not_load_google_libraries(self):
        code = ("import sys; from gmail_intelligence.cli import main; "
                "main(['version']); main(['doctor']); "
                "bad=[m for m in sys.modules if m.split('.')[0] in ('google','googleapiclient','keyring','requests','httplib2')]; "
                "print(bad)")
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": str(SRC)}
        proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertTrue(proc.stdout.strip().endswith("[]"), proc.stdout + proc.stderr)

    def test_secret_scanner_compatible_with_repository(self):
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "scan_secrets.py"), "--all"],
                              cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
