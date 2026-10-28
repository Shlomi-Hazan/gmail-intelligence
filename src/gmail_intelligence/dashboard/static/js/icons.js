// Hand-authored 24px stroke icons (no icon library). Each is decorative: aria-hidden, the visible label carries the meaning.
import { s } from "./util.js";

const PATHS = {
  overview: ["M4 4h7v7H4z", "M13 4h7v4h-7z", "M13 11h7v9h-7z", "M4 14h7v6H4z"],
  attention: ["M6 4v16", "M6 5h11l-2.5 3.5L17 12H6"],
  trends: ["M4 4v16h16", "M7 15l4-4 3 3 5-6"],
  senders: ["M12 11.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z", "M5 20c0-3.4 3-5.5 7-5.5s7 2.1 7 5.5"],
  cleanup: ["M4 7h16v3H4z", "M5.5 10v9h13v-9", "M10 14h4"],
  organization: ["M4 12V5h7l9 9-7 7z", "M8.5 8.5h.01"],
  data: ["M5 6c0-1.7 3.1-3 7-3s7 1.3 7 3-3.1 3-7 3-7-1.3-7-3z", "M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6", "M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"],
  settings: ["M5 7h9", "M18 7h1", "M5 17h1", "M10 17h9", "M16 4v6", "M8 14v6"],
  lock: ["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"],
  ok: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M8 12.5l2.7 2.7L16 9.8"],
  warn: ["M12 4l9 16H3z", "M12 10v4", "M12 17.2h.01"],
  error: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M9.2 9.2l5.6 5.6", "M14.8 9.2l-5.6 5.6"],
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 11v5", "M12 7.8h.01"],
  empty: ["M4 13l2.5-7h11L20 13v6H4z", "M4 13h4.5l1 2h5l1-2H20"],
};

export function icon(name, extraClass = "") {
  return s("svg", { class: `icon ${extraClass}`.trim(), viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" }, (PATHS[name] || PATHS.info).map((d) => s("path", { d })));
}
