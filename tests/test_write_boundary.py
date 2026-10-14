"""Static and behavioral boundary tests for M4C-B1: who may import the write modules, where the write scope lives, what the write
code may call, and that M4C-A / the read-only paths are unchanged. No credentials, network or real database are involved."""
import ast
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gmail_intelligence"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_auth import ACCOUNT, Base  # noqa: E402

from gmail_intelligence import cleanup_exec, config, gmail_write_policy as pol, index as idx  # noqa: E402

WRITE_MODULES = {"oauth_write", "keystore_write", "gmail_write_policy", "gmail_write"}
WRITE_FILES = {n + ".py" for n in WRITE_MODULES}


def imported_names(tree):
    """(module-qualified names, is_top_level) for every import in a parsed file."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(a.name, node) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out += [(f"{node.module}.{a.name}", node) for a in node.names] + [(node.module, node)]
    return out


class ImportBoundaryTests(unittest.TestCase):
    def test_the_write_scope_string_exists_in_exactly_one_source_file(self):
        holders = sorted(p.name for p in SRC.glob("*.py") if "gmail.modify" in p.read_text())
        self.assertEqual(holders, ["oauth_write.py"])
        assigned = [p.name for p in SRC.glob("*.py") if re.search(r"^WRITE_SCOPE\s*=", p.read_text(), re.M)]
        self.assertEqual(assigned, ["oauth_write.py"])

    def test_only_cli_and_the_write_modules_import_write_modules(self):
        for path in SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            hits = {n.split(".")[-1] for n, _ in imported_names(tree) if n.split(".")[-1] in WRITE_MODULES}
            if path.name in WRITE_FILES:
                continue
            if path.name == "exec_fake_mailbox.py":  # the fake-only test mailbox wraps the real adapter CLASS over an in-memory connection (M4C-C2)
                self.assertEqual(hits, {"gmail_write", "gmail_write_policy"})
                continue
            if path.name == "cli.py":
                self.assertTrue(hits <= WRITE_MODULES)
                continue
            self.assertEqual(hits, set(), f"{path.name} imports a write module")

    def test_cli_imports_write_modules_only_inside_command_handlers(self):
        tree = ast.parse((SRC / "cli.py").read_text())
        for node in tree.body:  # module level
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
                self.assertFalse({n.split(".")[-1] for n in names if n} & WRITE_MODULES, "top-level import of a write module in cli.py")

    def callers(self, attr):
        out = set()
        for path in SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef,))]:
                for call in [c for c in ast.walk(fn) if isinstance(c, ast.Call)]:
                    f = call.func
                    if (isinstance(f, ast.Attribute) and f.attr == attr) or (isinstance(f, ast.Name) and f.id == attr):
                        out.add((path.name, fn.name))
        return out

    def test_the_authorization_flow_is_started_only_by_login_write(self):
        self.assertEqual({c for c in self.callers("run_login_write") if c[1] != "run_login_write"}, {("cli.py", "cmd_auth_login_write")})

    def test_refresh_is_never_started_by_a_command_and_no_production_code_builds_the_adapter_yet(self):
        fake_only = {"archive_message": {("cleanup_executor.py", "execute_one"), ("exec_fake_mailbox.py", "archive_message")},
                     "verify_account": {("cleanup_executor.py", "execute_one"), ("exec_fake_mailbox.py", "verify_account")}}
        for attr in ("refresh_write_credentials", "refresh_and_store", "open_archive_adapter", "archive_message", "verify_account"):
            outside = {c for c in self.callers(attr) if c[0] not in WRITE_FILES}
            # the only consumers are the single-item executor and the fake-only mailbox it accepts (M4C-C2); no production code builds a real adapter
            self.assertEqual(outside, fake_only.get(attr, set()), attr)
        self.assertEqual({c for c in self.callers("fetch_profile_email") if c[0] == "cli.py"}, {("cli.py", "cmd_auth_login_write")})

    def test_revocation_and_the_write_store_have_explicit_callers_only(self):
        self.assertEqual({c for c in self.callers("revoke_refresh_token") if c[0] == "cli.py"}, {("cli.py", "_discard_new_grant"), ("cli.py", "cmd_auth_revoke_write")})
        self.assertEqual({c for c in self.callers("_discard_new_grant")}, {("cli.py", "cmd_auth_login_write")})  # only a rejected login may discard a fresh grant
        self.assertEqual({c for c in self.callers("WriteTokenStore") if c[0] == "cli.py"}, {("cli.py", "_write_store")})
        self.assertEqual({c for c in self.callers("_write_store")}, {("cli.py", n) for n in (
            "cmd_auth_login_write", "cmd_auth_status_write", "cmd_auth_logout_write", "cmd_auth_revoke_write")})

    def test_project_isolation_is_checked_before_every_operation_that_can_create_or_revoke_a_grant(self):
        self.assertEqual({c for c in self.callers("verify_isolation") if c[0] == "cli.py"},
                         {("cli.py", n) for n in ("cmd_auth_login_write", "cmd_auth_revoke_write", "cmd_auth_status_write", "_discard_new_grant")})
        self.assertEqual({c for c in self.callers("check_project_separation") if c[0] == "cli.py"}, {("cli.py", "cmd_auth_setup_write")})
        self.assertEqual({c for c in self.callers("write_isolation_record") if c[0] == "cli.py"}, {("cli.py", "cmd_auth_setup_write")})
        # every network-capable revocation call sits in a function that verified isolation first
        for fn in ("cmd_auth_revoke_write", "_discard_new_grant"):
            tree = ast.parse((SRC / "cli.py").read_text())
            node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn)
            calls = [(c.lineno, c.func.attr) for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)]
            verify = min(l for l, a in calls if a == "verify_isolation")
            revoke = min(l for l, a in calls if a == "revoke_refresh_token")
            self.assertLess(verify, revoke, fn)

    def test_write_modules_use_only_the_reviewed_imports(self):
        stdlib = set(sys.stdlib_module_names) | {"gmail_intelligence"}
        networking = {"urllib", "socket", "httplib2", "httpx", "subprocess", "googleapiclient"}
        lazy_third_party = {"oauth_write.py": {"google", "google_auth_oauthlib", "requests"}}  # imported only inside functions
        for name in WRITE_FILES:
            tree = ast.parse((SRC / name).read_text())
            for node in tree.body:  # top level: standard library and this package only
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for m in ([a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]):
                        self.assertIn(m.split(".")[0], stdlib, f"{name}: non-stdlib top-level import {m}")
            for mod, _ in imported_names(tree):
                top = mod.split(".")[0]
                self.assertNotIn(top, networking, f"{name}: {mod}")
                if top not in stdlib:
                    self.assertIn(top, lazy_third_party.get(name, set()), f"{name}: {mod}")
        policy_imports = {m.split(".")[0] for m, _ in imported_names(ast.parse((SRC / "gmail_write_policy.py").read_text()))}
        self.assertEqual(policy_imports, {"json", "re"})  # the pure policy has no I/O capability at all
        for path in SRC.glob("*.py"):  # only the transport may speak HTTP
            if path.name != "gmail_write.py":
                self.assertNotIn("http.client", path.read_text(), path.name)

    def test_write_code_contains_no_other_gmail_operations(self):
        pattern = re.compile(r"\.(send|batchModify|trash|untrash|batchDelete|insert|import_|drafts|threads|history|attachments|settings|watch|labels)\(")
        for name in WRITE_FILES:
            text = (SRC / name).read_text()
            self.assertIsNone(pattern.search(text), name)
            for banned in ("batchModify", "batchDelete", "untrash", "addLabelIds", "/send", "/trash", "/drafts", "/batch"):
                body = text if name != "gmail_write_policy.py" else text.replace('addLabelIds', '')
                self.assertNotIn(banned, body.replace("batch support", "").replace("batch and upload", ""), (name, banned))

    def test_the_route_table_is_exactly_the_four_approved_families(self):
        self.assertEqual([(k, m) for k, m, _ in pol._ROUTES], [("PROFILE", "GET"), ("MESSAGE_GET", "GET"), ("THREAD_GET", "GET"), ("MESSAGE_MODIFY", "POST")])
        self.assertEqual(pol.MODIFY_BODY, b'{"removeLabelIds":["INBOX"]}')
        self.assertEqual(pol.HOST, "gmail.googleapis.com")


class UnchangedBehaviourTests(Base):
    def test_m4c_a_semantics_and_schema_are_untouched(self):
        self.assertEqual(idx.SCHEMA_VERSION, 5)
        self.assertEqual(cleanup_exec.ACCEPTED_EVIDENCE_SOURCES, ("CALLER_SUPPLIED",))  # TRUSTED_ADAPTER stays unavailable until M4C-C
        self.assertEqual(set(cleanup_exec.OUTCOME_CODES), {"APPLIED", "NOT_APPLIED", "UNKNOWN"})
        for module in WRITE_MODULES:
            self.assertNotIn(module, (SRC / "cleanup_exec.py").read_text())
            self.assertNotIn(module, (SRC / "cleanup_exec_report.py").read_text())

    def test_cleanup_execute_without_dry_run_is_still_unavailable(self):
        with idx.Index(config.index_path(), create=True):
            pass
        code, _, err = self.run_cli("cleanup", "execute", "plan-none", "--account", ACCOUNT)
        self.assertEqual(code, 1)
        self.assertIn("not available in this version", err)

    def test_local_commands_do_not_load_write_modules_or_google_libraries(self):
        code = ("import sys; from gmail_intelligence.cli import main; main(['version']); main(['doctor']); main(['auth','setup']); "
                "bad=[m for m in sys.modules if m.split('.')[-1] in %r or m.split('.')[0] in ('google','googleapiclient','keyring','requests','httplib2')]; print(bad)"
                % (sorted(WRITE_MODULES),))
        with tempfile.TemporaryDirectory() as home:
            env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "GMAIL_INTELLIGENCE_HOME": home, "PYTHONDONTWRITEBYTECODE": "1"}
            out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.strip().splitlines()
        self.assertEqual(out[-1], "[]")
        # the explicit `auth setup-write` help text may load oauth_write (stdlib + the read module) but never a Google library or the transport
        code2 = code.replace("main(['auth','setup']); ", "main(['auth','setup']); main(['auth','setup-write']); ")
        with tempfile.TemporaryDirectory() as home:
            env["GMAIL_INTELLIGENCE_HOME"] = home
            out2 = subprocess.run([sys.executable, "-c", code2], env=env, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
        self.assertEqual(out2, "['gmail_intelligence.oauth_write']")

    def test_runtime_dependencies_are_unchanged(self):
        block = re.search(r"(?s)^dependencies = \[(.*?)\]", (ROOT / "pyproject.toml").read_text(), re.M).group(1)
        self.assertEqual(sorted(re.findall(r'"([A-Za-z0-9_.\-]+)', block)), ["google-api-python-client", "google-auth-oauthlib", "keyring"])


if __name__ == "__main__":
    unittest.main()
