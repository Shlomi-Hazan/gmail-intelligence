"""Pure request policy for the write transport (M4C-B1): which Gmail requests may ever be sent. Stdlib only, no I/O, no network.

An ALLOWLIST of exactly four request families (for one account, `users/me`):
  GET  /gmail/v1/users/me/profile?fields=emailAddress
  GET  /gmail/v1/users/me/messages/{id}            (one of two fixed projections: labels only, or labels plus the From header)
  GET  /gmail/v1/users/me/threads/{id}             (labels of the messages only; read-only sibling inspection)
  POST /gmail/v1/users/me/messages/{id}/modify     (body exactly: remove the INBOX label; fixed response projection)
Every GET and the POST MUST carry one of the allowlisted `fields` projections, so a direct call cannot return snippets, subject lines,
bodies or other content. Argument types are exact (`str`, `bytes`, `dict`): subclasses and mutable buffers are refused.
Everything else is denied BEFORE any network dispatch: other endpoints, hosts, ports, methods, encodings, query parameters, headers,
bodies, batch and upload endpoints. Errors carry a fixed code and message only - never the URL, ids, headers, body or tokens.
"""
import json
import re

HOST = "gmail.googleapis.com"
BASE = "https://" + HOST
MAX_URL = 400
MAX_RESPONSE = 1_000_000
MAX_REQUESTS = 500
MODIFY_BODY = b'{"removeLabelIds":["INBOX"]}'  # the only mutation: archive = remove INBOX from one message
KINDS = ("PROFILE", "MESSAGE_GET", "THREAD_GET", "MESSAGE_MODIFY")

_ID = r"[0-9a-f]{1,32}"
_ROUTES = (("PROFILE", "GET", r"/gmail/v1/users/me/profile"),
           ("MESSAGE_GET", "GET", rf"/gmail/v1/users/me/messages/{_ID}"),
           ("THREAD_GET", "GET", rf"/gmail/v1/users/me/threads/{_ID}"),
           ("MESSAGE_MODIFY", "POST", rf"/gmail/v1/users/me/messages/{_ID}/modify"))
_FIELDS = {"PROFILE": ("emailAddress",),
           "MESSAGE_GET": ("id,threadId,labelIds", "id,threadId,internalDate,labelIds,sizeEstimate,payload/headers"),
           "THREAD_GET": ("id,messages/id,messages/labelIds",),
           "MESSAGE_MODIFY": ("id,threadId,labelIds",)}
_HEADER_FIELDS = "id,threadId,internalDate,labelIds,sizeEstimate,payload/headers"  # the only projection that includes a header (From only)
_SAFE_QUERY = r"[A-Za-z0-9,/]+"
_HEADERS = {"accept", "user-agent", "content-type", "authorization"}
_MESSAGES = {
    "DENIED_HOST": "request denied: unexpected host, scheme or port",
    "DENIED_PATH": "request denied: path is not an allowed Gmail endpoint or is ambiguous",
    "DENIED_METHOD": "request denied: method is not allowed for this endpoint",
    "DENIED_QUERY": "request denied: query parameters are not allowed",
    "DENIED_BODY": "request denied: body is not allowed",
    "DENIED_HEADER": "request denied: headers are not allowed",
    "DENIED_REDIRECT": "request denied: redirects are never followed",
    "DENIED_SIZE": "request denied: size limit exceeded",
    "DENIED_BUDGET": "request denied: request budget exhausted",
}


class Denied(Exception):
    """A request the policy refuses. `code` is stable; the message never contains request data."""

    dispatched = None  # set explicitly at the raise site: False only where nothing can have been sent; None means "unknown" (treat as possibly sent)

    def __init__(self, code):
        super().__init__(_MESSAGES[code])
        self.code = code


def valid_id(value):
    """Gmail message/thread ids are lowercase hex; anything else is refused (no encoding, no path tricks)."""
    if type(value) is not str or re.fullmatch(_ID, value, re.ASCII) is None:
        raise Denied("DENIED_PATH")
    return value


def _split(url):
    if type(url) is not str or not url.isascii() or len(url) > MAX_URL:
        raise Denied("DENIED_PATH")
    if any(ord(c) <= 32 or ord(c) == 127 or c in "%#\\@+;" for c in url):
        raise Denied("DENIED_PATH")  # percent-encoding, fragments, userinfo, backslashes, parameters, whitespace: all ambiguous
    if not url.startswith(BASE + "/"):
        raise Denied("DENIED_HOST")
    rest = url[len(BASE):]
    path, mark, query = rest.partition("?")
    if mark and (not query or "?" in query):
        raise Denied("DENIED_QUERY")
    return path, query


def _parse_query(query):
    params = {}
    if not query:
        return params
    for part in query.split("&"):
        key, eq, value = part.partition("=")
        if not eq or not key or not value or "=" in value or re.fullmatch(r"[A-Za-z]+", key) is None \
                or re.fullmatch(_SAFE_QUERY, value, re.ASCII) is None or key in params:
            raise Denied("DENIED_QUERY")
        params[key] = value
    return params


def _check_query(kind, params):
    allowed = {"PROFILE": {"fields"}, "MESSAGE_GET": {"format", "metadataHeaders", "fields"}, "THREAD_GET": {"format", "fields"},
               "MESSAGE_MODIFY": {"fields"}}[kind]
    if set(params) - allowed:  # also refuses access_token / key / alt / prettyPrint and every other parameter
        raise Denied("DENIED_QUERY")
    if params.get("fields") not in _FIELDS[kind]:  # a projection is MANDATORY on every request (a missing one is None, which is never listed)
        raise Denied("DENIED_QUERY")
    if kind == "MESSAGE_GET":
        with_header = params["fields"] == _HEADER_FIELDS  # the From header may only be requested together with its fixed projection
        if params.get("format") != ("metadata" if with_header else "minimal") or ("metadataHeaders" in params) != with_header \
                or (with_header and params["metadataHeaders"] != "From"):
            raise Denied("DENIED_QUERY")
    if kind == "THREAD_GET" and params.get("format") != "minimal":
        raise Denied("DENIED_QUERY")


def _check_headers(headers, kind, allow_authorization):
    if headers is None:
        headers = {}
    if type(headers) is not dict:
        raise Denied("DENIED_HEADER")
    seen = set()
    for key, value in headers.items():
        if type(key) is not str or type(value) is not str or not key.isascii() or not value.isascii():
            raise Denied("DENIED_HEADER")
        name = key.lower()
        if name in seen or name not in _HEADERS or len(value) > 3000 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise Denied("DENIED_HEADER")  # includes X-HTTP-Method-Override, Host, Transfer-Encoding, X-* and duplicates
        seen.add(name)
        if name == "authorization" and (not allow_authorization or re.fullmatch(r"Bearer [A-Za-z0-9._~+/=-]{8,2048}", value) is None):
            raise Denied("DENIED_HEADER")
        if name == "content-type" and (kind != "MESSAGE_MODIFY" or value != "application/json"):
            raise Denied("DENIED_HEADER")
        if name == "accept" and value != "application/json":
            raise Denied("DENIED_HEADER")
        if name == "user-agent" and (len(value) > 100 or re.fullmatch(r"[A-Za-z0-9._/ ()-]+", value) is None):
            raise Denied("DENIED_HEADER")
    if kind == "MESSAGE_MODIFY" and "content-type" not in seen:
        raise Denied("DENIED_HEADER")


def check_request(method, url, headers=None, body=None, *, allow_authorization=False):
    """Return the allowed request KIND or raise Denied. Pure; called before building AND again immediately before dispatch."""
    path, query = _split(url)
    kind = None
    for name, verb, pattern in _ROUTES:
        if re.fullmatch(pattern, path, re.ASCII):
            kind = name
            if type(method) is not str or method != verb:
                raise Denied("DENIED_METHOD")
            break
    if kind is None:
        raise Denied("DENIED_PATH")
    _check_query(kind, _parse_query(query))
    _check_headers(headers, kind, allow_authorization)
    if kind == "MESSAGE_MODIFY":
        if type(body) is not bytes or body != MODIFY_BODY:  # exact immutable bytes: no bytearray/subclass/str, no extra fields, labels or escapes
            raise Denied("DENIED_BODY")
    elif body is not None and not (type(body) is bytes and body == b""):
        raise Denied("DENIED_BODY")
    return kind


def check_response(status, length=0):
    """Redirects are never followed or trusted; oversized responses are refused."""
    if type(status) is not int:
        raise Denied("DENIED_BODY")  # an unreadable status line is never trusted
    if 300 <= status < 400:
        raise Denied("DENIED_REDIRECT")
    if type(length) is not int or length > MAX_RESPONSE:
        raise Denied("DENIED_SIZE")


def parse_json(data):
    """Strict JSON object parse of a response body (no duplicate keys). Returns None when it is not a JSON object."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out
    try:
        value = json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None
