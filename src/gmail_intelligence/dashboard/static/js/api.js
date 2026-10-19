// The only way data reaches the UI: GET requests to this same origin with the session token in an Authorization header.
// The token comes from the URL fragment, is removed from the address bar immediately, and lives only in this module's memory (never in storage, cookies or the DOM).
let token = null;

export function takeTokenFromUrl() {
  const match = /^#t=([A-Za-z0-9_-]{16,128})$/.exec(window.location.hash);
  if (match) {
    token = match[1];
    window.history.replaceState(null, "", window.location.pathname + window.location.search + "#/overview");
  }
  return token !== null;
}
export function hasToken() { return token !== null; }

export class ApiError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

export async function get(route, params) {
  if (token === null) throw new ApiError(401, "UNAUTHORIZED");
  const query = params ? "?" + new URLSearchParams(params).toString() : "";
  let res;
  try {
    res = await fetch(`/api/v1/${route}${query}`, { method: "GET", headers: { Authorization: `Bearer ${token}` }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", redirect: "error" });
  } catch (e) { throw new ApiError(0, "NETWORK"); }
  let body = null;
  try { body = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new ApiError(res.status, body?.error?.code ?? "ERROR");
  return body;
}
