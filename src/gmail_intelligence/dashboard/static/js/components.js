// Shared building blocks: panels that load and fail on their own, notices, KPI lists, rank lists. Every text is translated; every piece of mailbox-derived text goes through untrusted().
import { h } from "./util.js";
import { icon } from "./icons.js";
import { t, tn, code, int, pct, day, dateTime } from "./i18n.js";
import { get, ApiError } from "./api.js";

export function skeleton() {
  return h("div", { class: "skeleton", role: "status", "aria-label": t("state.loading") }, h("i"), h("i"), h("i"));
}

export function notice(kind, title, body, ...extra) {
  const name = kind === "ok" ? "ok" : kind === "err" ? "error" : kind === "warn" ? "warn" : "info";
  return h("div", { class: `notice ${kind}`, role: kind === "err" ? "alert" : "note" }, icon(name), h("div", null, title ? h("b", null, title + " ") : null, body, extra));
}

export function empty(titleKey, bodyKey) {
  return h("div", { class: "empty" }, icon("empty"), h("strong", null, t(titleKey)), h("p", null, t(bodyKey)));
}

export function errorState(err, retry) {
  const status = err instanceof ApiError ? err.status : 0;
  const key = status === 401 ? "error.session" : status === 503 ? "error.index" : status === 0 ? "error.network" : "error.generic";
  return h("div", { class: "stack" }, notice("err", t("error.title"), t(key)), status === 401 ? null : h("div", null, h("button", { class: "btn quiet", type: "button", onclick: retry }, t("error.retry"))));
}

/** A panel that fetches its own data. A failure shows inside the panel and leaves the rest of the screen working. */
export function panel({ title, desc, load, render, wide }) {
  const body = h("div", { class: "stack" }, skeleton());
  const el = h("section", { class: `panel ${wide ? "wide" : ""}`.trim() }, h("header", null, h("h2", null, t(title)), desc ? h("p", null, t(desc)) : null), body);
  const run = async () => {
    body.replaceChildren(skeleton());
    try { body.replaceChildren(...[].concat(await render(await load())).flat(Infinity).filter(Boolean)); } catch (err) { body.replaceChildren(errorState(err, run)); }
  };
  run();
  return el;
}

export function kpis(items) {
  return h("dl", { class: "kpis" }, items.map((k) => h("div", null, h("dt", null, k.label), h("dd", null, h("bdi", { dir: "ltr" }, k.value), k.note ? h("small", null, h("bdi", { dir: "ltr" }, k.note)) : null))));
}

export function rank(items) {
  return h("ol", { class: "rank" }, items.map((it) => h("li", null, h("span", { class: "name" }, it.name), h("span", { class: "val" }, h("bdi", { dir: "ltr" }, it.value)),
    it.meta && it.meta.length ? h("span", { class: "meta" }, it.meta.map((m) => h("span", null, m))) : null, h("span", { class: "track", "aria-hidden": "true" }, (() => { const bar = h("i"); bar.style.setProperty("--w", `${Math.max(0, Math.min(100, it.share))}%`); return bar; })()))));
}

export function badge(kind, text) { return h("span", { class: `badge ${kind}`.trim() }, text); }
export const confidenceBadge = (c) => badge(c === "HIGH" ? "ok" : c === "LOW" ? "warn" : "", code("confidence", c));

/** "How is this calculated?" - the server's stable explain codes, translated. */
export function how(env) {
  return h("details", { class: "how" }, h("summary", null, t("how.title")), h("ul", { class: "list-plain" }, [...env.explain, env.basis === "INFERRED" ? "BASIS_INFERRED" : env.basis === "MIXED" ? "BASIS_MIXED" : "BASIS_OBSERVED"].map((c) => h("li", null, code("explain", c)))));
}

/** The freshness notice shown on data screens: honest about age, completeness and classification. */
export function freshnessNotice(env) {
  const idx = env.index;
  if (idx.state === "empty") return notice("warn", t("fresh.empty.title"), t("fresh.empty.body"), h("p", { class: "actions" }, h("code", null, "gmail-intelligence mailbox scan")));
  const items = [];
  if (idx.state === "partial") items.push(t("fresh.partial"));
  if (idx.stale) items.push(tn("fresh.stale", idx.age_days));
  if (idx.health === "CLASSIFICATION_STALE") items.push(t("fresh.class_stale"));
  if (idx.health === "UNCLASSIFIED") items.push(t("fresh.unclassified"));
  const sync = env.data && env.data.sync;  // only the freshness section carries it; every other envelope is unchanged
  if (sync && sync.state !== "OK") items.push(code("fresh.sync", sync.state), t("fresh.sync.hint"));
  return items.length ? notice("warn", t("fresh.title"), items.join(" "), h("p", { class: "actions" }, h("code", null, "gmail-intelligence mailbox scan"))) : null;
}

export function ageText(env) {
  const idx = env.index;
  if (env.as_of === null) return t("fresh.never");
  return idx.age_days === 0 ? t("fresh.today") : tn("fresh.ago", idx.age_days);
}
export { int, pct, day, dateTime };
