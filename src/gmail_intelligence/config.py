"""Local, non-secret configuration paths. Stdlib only; never reads or prints credentials."""
import os
import stat
from pathlib import Path

HOME_ENV = "GMAIL_INTELLIGENCE_HOME"
CLIENT_FILE = "client_secret.json"


def app_dir():
    """Directory for local application data, always outside the Git repository."""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Application Support" / "gmail-intelligence"


def client_secret_path():
    return app_dir() / CLIENT_FILE


def ensure_app_dir():
    path = app_dir()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def inside_git_repo(path):
    """True if `path` (or a parent) contains a .git entry, i.e. would be inside a repository."""
    path = Path(path).expanduser().resolve()
    return any((p / ".git").exists() for p in [path, *path.parents])


def too_permissive(path):
    """True if group/other can access the file."""
    return bool(stat.S_IMODE(os.stat(path).st_mode) & 0o077)
