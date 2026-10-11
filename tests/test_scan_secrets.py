"""Regression tests for scripts/scan_secrets.py and .githooks/pre-commit.

Standard library only, no network. Every test builds a throwaway Git repository in a
temporary directory and uses synthetic credentials assembled at runtime. The scanner is
always exercised through its real staged-index path (subprocess), never via helpers.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "scripts" / "scan_secrets.py"
HOOK = ROOT / ".githooks" / "pre-commit"

# Synthetic values, assembled so this file itself contains no scannable literal.
TOKEN = "gh" + "p_" + "Q7" * 18
GENERIC_VALUE = "ABCDEFGH" + "12345678" + "_example"
KEYLINE = "-----BEGIN " + "RSA PRIVATE KEY-----"


def secret_line(value=TOKEN):
    return 'x = "' + value + '"\n'


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scan-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": self.tmp,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": self.tmp,
            "LC_ALL": "en_US.UTF-8",
        }
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")

    def git(self, *args, check=True):
        proc = subprocess.run(["git", *args], cwd=self.repo, env=self.env, capture_output=True)
        if check and proc.returncode != 0:
            self.fail(f"git {args} failed: {proc.stderr.decode(errors='replace')}")
        return proc

    def write(self, name, data, mode="w"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path

    def scan(self, *args, cwd=None):
        proc = subprocess.run(
            [sys.executable, "-I", str(SCANNER), *args],
            cwd=cwd or self.repo, env=self.env, capture_output=True,
        )
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        return proc.returncode, out, err

    def commit_unhooked(self, msg="c"):
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", msg)

    def assertClean(self, *args):
        code, out, err = self.scan(*args)
        self.assertEqual(code, 0, out + err)

    def assertFinding(self, rule=None, *args):
        code, out, err = self.scan(*args)
        self.assertEqual(code, 1, out + err)
        if rule:
            self.assertIn(f"[{rule}]", out)
        return out


class StagedScanning(RepoCase):
    def test_01_safe_file_passes(self):
        self.write("a.txt", "hello\n")
        self.git("add", "a.txt")
        self.assertClean()

    def test_02_staged_secret_detected(self):
        self.write("a.py", secret_line())
        self.git("add", "a.py")
        self.assertFinding("github-token")

    def test_03_hebrew_filename(self):
        self.write("סוד.txt", secret_line())
        self.git("add", "--all")
        out = self.assertFinding("github-token")
        self.assertNotIn("סוד", out)  # path is escaped, not echoed raw

    def test_04_filename_with_spaces(self):
        self.write("my secret file.txt", secret_line())
        self.git("add", "--all")
        self.assertFinding("github-token")

    def test_05_filename_with_quotes(self):
        self.write('we"ird\'name.txt', secret_line())
        self.git("add", "--all")
        self.assertFinding("github-token")

    def test_06_filename_with_tab_and_newline(self):
        self.write("tab\tname.txt", secret_line())
        self.write("new\nline.txt", secret_line())
        self.git("add", "--all")
        code, out, err = self.scan()
        self.assertEqual(code, 1, out + err)
        self.assertEqual(out.count("[github-token]"), 2)
        self.assertEqual(len(out.strip().splitlines()), 2)  # newline in name did not split output

    def _rename_setup(self, body):
        self.write("orig.txt", body)
        self.git("add", "orig.txt")
        self.commit_unhooked()

    def test_07_rename_with_secret(self):
        self._rename_setup("".join(f"line {i}\n" for i in range(300)))
        self.git("mv", "orig.txt", "moved.txt")
        with open(self.repo / "moved.txt", "a", encoding="utf-8") as fh:
            fh.write(secret_line())
        self.git("add", "--all")
        status = self.git("diff", "--cached", "--name-status", "-M").stdout.decode()
        self.assertTrue(status.startswith("R"), status)  # Git really sees a rename
        self.assertFinding("github-token")

    def test_08_high_similarity_rename(self):
        self._rename_setup("".join(f"line {i}\n" for i in range(2000)))
        self.git("mv", "orig.txt", "moved.txt")
        with open(self.repo / "moved.txt", "a", encoding="utf-8") as fh:
            fh.write(secret_line())
        self.git("add", "--all")
        status = self.git("diff", "--cached", "--name-status", "-M").stdout.decode()
        self.assertRegex(status, r"^R(09\d|100)\t", status)  # >=90% similarity
        self.assertFinding("github-token")

    def test_09_copy_with_secret(self):
        body = "".join(f"line {i}\n" for i in range(300)) + secret_line()
        self.write("orig.txt", body)
        self.git("add", "orig.txt")
        self.commit_unhooked()
        shutil.copy(self.repo / "orig.txt", self.repo / "copy.txt")
        self.git("add", "copy.txt")
        status = self.git("diff", "--cached", "--name-status", "-C", "--find-copies-harder").stdout.decode()
        self.assertTrue(status.startswith("C"), status)  # Git really sees a copy
        out = self.assertFinding("github-token")
        self.assertIn("copy.txt", out)  # destination path was scanned

    def test_10_deleted_file_is_not_a_finding(self):
        self.write("a.txt", "fine\n")
        self.write("b.txt", "fine\n")
        self.git("add", "--all")
        self.commit_unhooked()
        self.git("rm", "-q", "a.txt")
        self.assertClean()

    def test_11_type_change_file_to_symlink(self):
        self.write("link", "plain\n")
        self.git("add", "link")
        self.commit_unhooked()
        (self.repo / "link").unlink()
        os.symlink("/etc/hosts", self.repo / "link")  # external target must not be followed
        self.git("add", "link")
        status = self.git("diff", "--cached", "--name-status").stdout.decode()
        self.assertTrue(status.startswith("T"), status)
        self.assertClean()
        # a symlink whose *target text* looks like a secret is still inspected
        (self.repo / "link").unlink()
        os.symlink(TOKEN, self.repo / "link")
        self.git("add", "link")
        self.assertFinding("github-token")

    def test_12_safe_binary_asset(self):
        data = bytes((i * 7 + 3) % 256 for i in range(4096)) + b"\x00\xff\xfe"
        self.write("asset.bin", data)
        self.git("add", "asset.bin")
        self.assertClean()

    def test_13_suspicious_binary_content(self):
        self.write("blob.bin", b"\x00\xff\xfe\x00" + TOKEN.encode() + b"\x00\x80")
        self.git("add", "blob.bin")
        out = self.assertFinding("github-token")
        self.assertNotIn(TOKEN, out)

    def test_14_uppercase_sensitive_names(self):
        for name in (".ENV", "SERVER.PEM", "private.KEY", "Dump.MBOX", "DB.SQLITE3"):
            self.write(name, "x\n")
        self.git("add", "--all")
        out = self.assertFinding("blocked-filename")
        self.assertEqual(out.count("[blocked-filename]"), 5, out)

    def test_15_mixed_case_sensitive_names(self):
        for name in (".Env.Local", "Client_Secret_123.JSON", "Token.Json", "Id_Rsa", "Credentials.json"):
            self.write(name, "x\n")
        self.write(".env.example", "API_KEY=<set-locally>\n")  # allowed
        self.git("add", "--all")
        out = self.assertFinding("blocked-filename")
        self.assertEqual(out.count("[blocked-filename]"), 5, out)
        self.assertNotIn(".env.example", out)

    def test_16_placeholder_false_negative_attempt(self):
        self.write("cfg.txt", 'password = "' + GENERIC_VALUE + '"\n')
        self.git("add", "cfg.txt")
        out = self.assertFinding("generic-assignment")
        self.assertNotIn(GENERIC_VALUE, out)
        self.git("reset", "-q")
        self.write("cfg.txt", "API_KEY=<set-locally>\nsecret = changeme\npassword = \"" + "x" * 20 + "\"\n")
        self.git("add", "cfg.txt")
        self.assertClean()  # narrowly defined whole-value placeholders only

    def test_17_git_command_failure(self):
        elsewhere = Path(self.tmp) / "not-a-repo"
        elsewhere.mkdir()
        code, out, err = self.scan(cwd=elsewhere)
        self.assertEqual(code, 2, out + err)
        self.assertIn("SCANNER ERROR", err)

    def _break_blob(self, name):
        sha = self.git("rev-parse", f":{name}").stdout.decode().strip()
        obj = self.repo / ".git" / "objects" / sha[:2] / sha[2:]
        self.assertTrue(obj.exists())
        os.chmod(obj, 0o644)
        obj.unlink()

    def test_18_staged_blob_retrieval_failure(self):
        self.write("a.txt", "fine\n")
        self.git("add", "a.txt")
        self._break_blob("a.txt")
        code, out, err = self.scan()
        self.assertEqual(code, 2, out + err)

    def test_19_staged_content_differs_from_working_tree(self):
        self.write("a.py", secret_line())
        self.git("add", "a.py")
        self.write("a.py", "clean now\n")  # unstaged edit hides the secret on disk
        self.assertFinding("github-token")
        self.git("reset", "-q")
        self.write("b.py", "clean\n")
        self.git("add", "b.py")
        self.write("b.py", secret_line())  # only the working tree has it; commit would not
        self.assertClean()

    def test_20_unmerged_index_entry(self):
        self.write("f.txt", "base\n")
        self.git("add", "f.txt")
        self.commit_unhooked("base")
        self.git("checkout", "-q", "-b", "other")
        self.write("f.txt", "other\n")
        self.git("commit", "-qam", "o", "--no-verify")
        self.git("checkout", "-q", "main")
        self.write("f.txt", "main\n")
        self.git("commit", "-qam", "m", "--no-verify")
        self.git("merge", "other", check=False)
        self.assertTrue(self.git("ls-files", "-u").stdout)
        code, out, err = self.scan()
        self.assertEqual(code, 2, out + err)
        self.assertIn("unmerged", err)

    def test_21_oversized_blob_is_blocked(self):
        self.write("big.dat", b"a" * (5 * 1024 * 1024 + 1))
        self.git("add", "big.dat")
        self.assertFinding("oversized-blob")

    def test_25_output_never_contains_secret_values(self):
        self.write("a.py", secret_line() + 'password = "' + GENERIC_VALUE + '"\n' + KEYLINE + "\n")
        self.git("add", "a.py")
        code, out, err = self.scan()
        self.assertEqual(code, 1)
        for value in (TOKEN, GENERIC_VALUE, KEYLINE):
            self.assertNotIn(value, out + err)

    def test_all_mode_scans_index(self):
        self.write("a.py", secret_line())
        self.git("add", "a.py")
        self.commit_unhooked()
        self.assertFinding("github-token", "--all")


class HookBehaviour(RepoCase):
    def setUp(self):
        super().setUp()
        (self.repo / "scripts").mkdir()
        (self.repo / ".githooks").mkdir()
        shutil.copy(SCANNER, self.repo / "scripts" / "scan_secrets.py")
        shutil.copy(HOOK, self.repo / ".githooks" / "pre-commit")
        os.chmod(self.repo / ".githooks" / "pre-commit", 0o755)
        self.git("config", "core.hooksPath", ".githooks")

    def commit(self, msg="c"):
        return self.git("commit", "-q", "-m", msg, check=False)

    def head_exists(self):
        return self.git("rev-parse", "--verify", "-q", "HEAD", check=False).returncode == 0

    def test_22_hook_blocks_synthetic_secret(self):
        self.write("a.py", secret_line())
        self.git("add", "a.py")
        proc = self.commit()
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.head_exists())
        self.assertNotIn(TOKEN, (proc.stdout + proc.stderr).decode(errors="replace"))

    def test_23_hook_blocks_scanner_error(self):
        self.write("a.txt", "fine\n")
        self.git("add", "a.txt")
        sha = self.git("rev-parse", ":a.txt").stdout.decode().strip()
        obj = self.repo / ".git" / "objects" / sha[:2] / sha[2:]
        os.chmod(obj, 0o644)
        obj.unlink()
        proc = self.commit()
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.head_exists())
        self.assertIn(b"SCANNER ERROR", proc.stderr)

    def test_24_safe_commit_succeeds(self):
        self.write("a.txt", "fine\n")
        self.git("add", "a.txt")
        proc = self.commit()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.head_exists())

    def test_hook_uses_isolated_python(self):
        self.assertIn("python3 -I", HOOK.read_text())
        marker = Path(self.tmp) / "hijacked"
        # A module planted next to the scanner must not be importable under -I.
        self.write("scripts/json.py", f"open({str(marker)!r}, 'w').write('x')\nraise SystemExit(0)\n")
        self.write("a.txt", "fine\n")
        self.git("add", "a.txt")
        proc = self.commit()
        self.assertFalse(marker.exists(), "planted module was imported (python not isolated)")
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
