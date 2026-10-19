// Translation catalogs (en.json, he.json), plural rules and number/date formatting. All formatting uses the browser's Intl with Latin digits in both languages.
import { clean } from "./util.js";

const catalogs = {};
let current = "en";

export function lang() { return current; }
export async function load(code) {
  for (const l of new Set(["en", code])) {
    if (!catalogs[l]) {
      const res = await fetch(`/i18n/${l}.json`, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
      catalogs[l] = res.ok ? await res.json() : {};
    }
  }
  current = code;
}

function lookup(key) { return catalogs[current]?.[key] ?? catalogs.en?.[key]; }
function fill(text, vars) { return text.replace(/\{(\w+)\}/g, (_, name) => (vars && name in vars ? String(vars[name]) : `{${name}}`)); }

/** t("key", {vars}): the translated string, or the key itself when it is missing (visible, never a silent blank). */
export function t(key, vars) { const text = lookup(key); return text === undefined ? key : fill(text, vars); }
/** tn("key", n, vars): plural form by Intl.PluralRules (Hebrew has one, two, many and other); falls back to "other". */
export function tn(key, n, vars) {
  const rule = new Intl.PluralRules(current).select(n);
  const text = lookup(`${key}.${rule}`) ?? lookup(`${key}.other`);
  return text === undefined ? key : fill(text, { n: int(n), ...vars });
}
/** A code from the server (a type, state, event or reason) shown in the user's language. Unknown codes are shown cleaned, never dropped. */
export function code(prefix, value) { const text = lookup(`${prefix}.${value}`); return text === undefined ? clean(value, 60) : text; }

const locale = () => (current === "he" ? "he-IL-u-nu-latn" : "en-US-u-nu-latn");
export const int = (n) => new Intl.NumberFormat(locale()).format(n ?? 0);
export const pct = (n) => new Intl.NumberFormat(locale(), { maximumFractionDigits: n < 10 && n % 1 ? 1 : 0 }).format(n ?? 0) + "%";
export function bytes(n) {
  const units = [["byte", 1], ["kilobyte", 1e3], ["megabyte", 1e6], ["gigabyte", 1e9]];
  let [unit, size] = units[0];
  for (const u of units) if (n >= u[1]) [unit, size] = u;
  return new Intl.NumberFormat(locale(), { style: "unit", unit, unitDisplay: "short", maximumFractionDigits: size > 1 && n / size < 10 ? 1 : 0 }).format(n / size);
}
const date = (opts) => (iso) => { const d = new Date(String(iso).length === 10 ? iso + "T00:00:00Z" : iso); return Number.isNaN(d.getTime()) ? "" : new Intl.DateTimeFormat(locale(), { timeZone: "UTC", ...opts }).format(d); };
export const day = (iso) => (iso ? date({ dateStyle: "medium" })(iso) : "—");
export const dateTime = (iso) => (iso ? date({ dateStyle: "medium", timeStyle: "short" })(iso) : "—");
export const month = (period) => date({ month: "short", year: "numeric" })(period + "-01");
export const monthLong = (period) => date({ month: "long", year: "numeric" })(period + "-01");
export const year = (period) => period.slice(0, 4);
