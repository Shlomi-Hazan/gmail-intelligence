"""Local, read-only dashboard server (M6B). Python standard library only. LOCAL ONLY: it never contacts Gmail, never reads the Keychain or OAuth data and never writes.

Security model (every rule is enforced in code and covered by tests with real local HTTP requests):
  * It binds to 127.0.0.1 only (there is no host option) on an OS-chosen free port by default.
  * Only GET and HEAD exist. Every other method is refused with 405; request bodies are refused.
  * `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding defence: a rebound hostname fails here).
  * `Origin`, when present, must be this server's own origin. `Sec-Fetch-Site`, when present, must be same-origin (or none for the first page load); an API call may not be a navigation.
  * There is NO CORS: no `Access-Control-*` header is ever sent, so a foreign page cannot read a response, and a preflight is refused. A request without `Origin` (ordinary for a same-origin
    GET) is allowed, because the real gate is the token: every `/api/` request needs `Authorization: Bearer <token>`, compared in constant time. The token is random per launch, lives only
    in this process's memory, is printed once to the terminal as a URL fragment (`#t=...`, which browsers never send to a server) and is never logged, cached or put in a cookie.
  * The database is opened per request with `ReadOnlyIndex` (SQLite `mode=ro` + `query_only`); an index that is not at the current schema is refused and never migrated.
  * Static files come from an in-memory allowlist built at start (regular files only, no symlinks, fixed extensions); there is no path-to-file mapping at request time.
  * Every response carries a strict Content-Security-Policy, `nosniff`, `no-referrer`, `Cache-Control: no-store`, frame and cross-origin isolation headers. Nothing is fetched from the network.
  * Errors are fixed codes and messages; no path, token, account or traceback is ever sent.
"""
import hmac
import http.server
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from gmail_intelligence import analytics, config, index as idx

STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
                 ".svg": "image/svg+xml"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'; object-src 'none'; manifest-src 'none'")
SECURITY_HEADERS = (("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store"),
                    ("X-Frame-Options", "DENY"), ("Cross-Origin-Resource-Policy", "same-origin"), ("Cross-Origin-Opener-Policy", "same-origin"),
                    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"))
API_PREFIX = "/api/v1/"
# route -> (analytics section, allowed query parameters with their validators)
ROUTES = {"meta": None, "overview": ("overview", {}), "freshness": ("freshness", {}), "volume": ("volume", {}), "categories": ("categories", {"by": ("total", "month")}),
          "senders": ("senders", {"kind": ("domain", "address"), "limit": (1, 100)}), "subscriptions": ("subscriptions", {"limit": (1, 25)}),
          "cleanup/summary": ("cleanup-summary", {}), "cleanup/history": ("cleanup-history", {"recent": (1, 100)}), "organization": ("organization", {})}
ERRORS = {400: ("BAD_REQUEST", "the request is not valid"), 401: ("UNAUTHORIZED", "a valid session token is required"), 403: ("FORBIDDEN", "this request is not allowed"),
          404: ("NOT_FOUND", "not found"), 405: ("METHOD_NOT_ALLOWED", "this dashboard is read-only; only GET and HEAD are supported"), 421: ("BAD_HOST", "unexpected host"),
          500: ("INTERNAL", "an internal error occurred"), 503: ("INDEX_UNAVAILABLE", "the local index is unavailable")}


def load_static(root=STATIC_DIR):
    """{url path: (content type, bytes)} for the allowlisted files under `root`. Symlinks, dot-files and other extensions are skipped."""
    out = {}
    root = Path(root)
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if name.startswith(".") or ext not in CONTENT_TYPES or os.path.islink(full) or not os.path.isfile(full):
                continue
            with open(full, "rb") as fh:
                out["/" + os.path.relpath(full, root).replace(os.sep, "/")] = (CONTENT_TYPES[ext], fh.read())
    return out


def detect_account(db_path, wanted=None):
    """The one account in the index (read-only). With `wanted`, check that it exists. Never touches the Keychain."""
    ro = idx.ReadOnlyIndex(db_path)
    try:
        found = sorted({r[0] for r in ro._q("SELECT account FROM messages UNION SELECT account FROM scans")})
    finally:
        ro.close()
    if wanted:
        if wanted.strip().lower() not in {a.lower() for a in found}:
            raise ValueError("that account is not in the local index")
        return next(a for a in found if a.lower() == wanted.strip().lower())
    if len(found) == 1:
        return found[0]
    raise ValueError("the local index has no account yet" if not found else "the local index holds several accounts; pass --account EMAIL")


class DashboardServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, db_path, account, token, port=0, reveal_senders=False, reveal_names=False, static=None, clock=None, verbose=False, reload_static=False):
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        super().__init__(("127.0.0.1", port), Handler)  # loopback only; there is deliberately no host parameter
        self.db_path, self.account = os.fspath(db_path), account
        self.token = token.encode("utf-8")
        self.reveal_senders, self.reveal_names = bool(reveal_senders), bool(reveal_names)
        self.static = load_static() if static is None else static
        self.reload_static = bool(reload_static)  # development aid used only by the synthetic demo launcher: re-read the allowlisted files per request
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.verbose = verbose
        self.port = self.server_address[1]
        self.hosts = frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}"})
        self.origins = frozenset("http://" + h for h in self.hosts)
        self._cache, self._lock = {}, threading.Lock()

    def url(self, token_fragment=True):
        return f"http://127.0.0.1:{self.port}/" + (f"#t={self.token.decode()}" if token_fragment else "")

    def db_signature(self):
        try:
            st = os.stat(self.db_path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def compute(self, route, params):
        """The JSON payload for an API route. Raises ValueError (bad query) or idx.IndexProblem / sqlite3.Error."""
        now = self.clock()
        if route == "meta":
            return {"app": "gmail-intelligence", "api_version": 1, "read_only": True, "schema": idx.SCHEMA_VERSION, "languages": ["en", "he"],
                    "reveal": {"senders": self.reveal_senders, "names": self.reveal_names}, "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        section, _ = ROUTES[route]
        key = (section, tuple(sorted(params.items())), self.db_signature(), now.strftime("%Y-%m-%d"), self.reveal_senders, self.reveal_names)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        ro = idx.ReadOnlyIndex(self.db_path)
        try:
            result = analytics.Analytics(ro, self.account, now=now, reveal_senders=self.reveal_senders, reveal_names=self.reveal_names).section(section, **params)
        finally:
            ro.close()
        with self._lock:
            if len(self._cache) >= 64:
                self._cache.clear()
            self._cache[key] = result
        return result


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GmailIntelligenceDashboard"
    sys_version = ""

    def log_message(self, fmt, *args):  # never log headers, queries or tokens
        if self.server.verbose:
            print(f"{self.command} {urlsplit(self.path).path} -> {args[1] if len(args) > 1 else ''}", flush=True)

    def __getattr__(self, name):  # every other HTTP method is refused, not mapped to a 501
        if name.startswith("do_"):
            return self._refuse_method
        raise AttributeError(name)

    # ---------------------------------------------------------------- responses
    def _send(self, status, body, content_type, head=False, close=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        if status == 405:
            self.send_header("Allow", "GET, HEAD")
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        if close or status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _error(self, status, head=False):
        code, message = ERRORS[status]
        self._send(status, json.dumps({"error": {"code": code, "message": message}}).encode(), "application/json; charset=utf-8", head=head, close=True)

    def _refuse_method(self):
        self._error(405)

    # ---------------------------------------------------------------- the checks
    def _headers_ok(self, path):
        srv = self.server
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0].strip().lower() not in srv.hosts:
            return 421
        origin = self.headers.get_all("Origin")
        if origin and (len(origin) != 1 or origin[0].strip().lower() not in srv.origins):
            return 403
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        is_api = path.startswith(API_PREFIX)
        if site and site not in ("same-origin", "none"):
            return 403
        if is_api and (site == "none" or (self.headers.get("Sec-Fetch-Mode") or "").strip().lower() == "navigate"):
            return 403  # an API response is never a page
        if self.headers.get("Content-Length", "0").strip() not in ("", "0") or self.headers.get("Transfer-Encoding"):
            return 400
        return 0

    def _authorized(self):
        auth = self.headers.get("Authorization") or ""
        scheme, _, value = auth.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(value.strip().encode("utf-8", "ignore"), self.server.token)

    def _path(self):
        raw = self.path
        if not raw.startswith("/") or raw.startswith("//") or "\\" in raw or "\x00" in raw:
            return None, None
        parts = urlsplit(raw)
        if parts.scheme or parts.netloc:
            return None, None
        path = unquote(parts.path)
        if "\x00" in path or "//" in path or any(seg in ("..", ".") for seg in path.split("/")):
            return None, None
        return path, parts.query

    def _query(self, spec, query):
        parsed = parse_qs(query, keep_blank_values=True, strict_parsing=bool(query), max_num_fields=8)
        params = {}
        for key, values in parsed.items():
            if key not in spec or len(values) != 1:
                raise ValueError("unknown or repeated parameter")
            rule, value = spec[key], values[0]
            if isinstance(rule[0], int):
                if not (value.isascii() and value.isdigit()) or not rule[0] <= int(value) <= rule[1]:
                    raise ValueError("number out of range")
                params[key] = int(value)
            elif value in rule:
                params[key] = value
            else:
                raise ValueError("unsupported value")
        return params

    # ---------------------------------------------------------------- GET / HEAD
    def _serve(self, head):
        path, query = self._path()
        if path is None:
            return self._error(400, head)
        status = self._headers_ok(path)
        if status:
            return self._error(status, head)
        if path.startswith(API_PREFIX):
            if not self._authorized():
                return self._error(401, head)
            route = path[len(API_PREFIX):]
            if route not in ROUTES:
                return self._error(404, head)
            try:
                params = self._query({} if ROUTES[route] is None else ROUTES[route][1], query)
                payload = self.server.compute(route, {k: v for k, v in params.items()})
            except ValueError:
                return self._error(400, head)
            except (idx.IndexProblem, sqlite3.OperationalError):
                return self._error(503, head)
            except Exception:  # noqa: BLE001 - never leak details of an unexpected failure
                return self._error(500, head)
            return self._send(200, json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"), "application/json; charset=utf-8", head=head)
        if query:
            return self._error(404, head)
        static = load_static() if self.server.reload_static else self.server.static
        entry = static.get("/index.html" if path == "/" else path)
        if entry is None:
            return self._error(404, head)
        self._send(200, entry[1], entry[0], head=head)

    def do_GET(self):
        self._serve(False)

    def do_HEAD(self):
        self._serve(True)


def serve(db_path, account, port=0, open_browser=False, reveal_senders=False, reveal_names=False, verbose=False, out=print):
    token = secrets.token_urlsafe(32)
    server = DashboardServer(db_path, account, token, port=port, reveal_senders=reveal_senders, reveal_names=reveal_names, verbose=verbose)
    out("Gmail Intelligence dashboard - LOCAL ONLY, read-only: no Gmail access, no changes, loopback address only.")
    out(f"Open this link in your browser (it holds this session's token; it stops working when you stop the server):\n  {server.url()}")
    out("Press Ctrl-C to stop.")
    if open_browser:
        import webbrowser
        webbrowser.open(server.url())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out("\nStopped.")
    finally:
        server.server_close()
    return 0
