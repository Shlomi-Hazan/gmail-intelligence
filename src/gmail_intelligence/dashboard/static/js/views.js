// The six screens. Each returns a DOM element; every panel loads its own data, so one failing request never blanks a screen.
import { h, untrusted, sum } from "./util.js";
import { get, ApiError } from "./api.js";
import { t, tn, code, int, pct, bytes, day, dateTime, month, monthLong } from "./i18n.js";
import { panel, kpis, rank, notice, empty, how, freshnessNotice, ageText, skeleton, errorState, badge, confidenceBadge } from "./components.js";
import { stackedBars, shareBar, legend, miniBars, tableAlt, swatch, TYPE_ORDER } from "./charts.js";
import { icon } from "./icons.js";

const put = (el, ...children) => el.replaceChildren(...children.flat(Infinity).filter(Boolean));
const view = (...children) => h("div", { class: "view" }, children);
const link = (hash, key) => h("a", { href: hash }, t(key));

function segmented(name, labelKey, options, current, onChange) {
  const group = h("div", { class: "seg inline", role: "radiogroup", "aria-label": t(labelKey) });
  for (const [value, label] of options) {
    const input = h("input", { type: "radio", name, value, checked: value === current, onchange: () => onChange(value) });
    group.append(h("label", null, input, h("span", null, label)));
  }
  return group;
}

/** Loads one endpoint into a container; used where a whole block (not a titled panel) depends on one response. */
function block(load, render) {
  const el = h("div", { class: "stack" }, skeleton());
  const run = async () => { el.replaceChildren(skeleton()); try { el.replaceChildren(...[].concat(await render(await load())).flat(Infinity).filter(Boolean)); } catch (err) { el.replaceChildren(errorState(err, run)); } };
  run();
  return el;
}

/** Every data screen shows the same honest data note (partial, stale or unclassified) above its content, and screens that need indexed mail show ONE clear empty state when the index has no scan at all. */
function whenData(render, { gate = true } = {}) {
  const el = h("div", { class: "stack" }, skeleton());
  const run = async () => {
    el.replaceChildren(skeleton());
    try {
      const env = await get("freshness");
      put(el, gate && env.data.state === "empty" ? [empty("empty.title", "empty.body"), freshnessNotice(env)] : [freshnessNotice(env), render()]);
    } catch (err) { el.replaceChildren(errorState(err, run)); }
  };
  run();
  return el;
}

// ---------------------------------------------------------------- Overview
function ribbonPoints(volume, cats) {
  const byMonth = new Map(cats.data.by_month.map((m) => [m.period, m.counts]));
  return volume.data.points.map((p) => ({ period: p.period, total: p.messages, unread: p.unread, in_progress: p.in_progress, parts: byMonth.get(p.period) || {} }));
}

function overviewView() {
  const top = block(() => get("overview"), (env) => {
    const d = env.data;
    if (!d.messages) return empty("empty.title", "empty.body");
    return [
      h("p", { class: "lede" }, tn("ov.lede", d.messages, { from: day(d.oldest), to: day(d.newest), classified: pct(d.classified_share_pct) })),
      h("section", { class: "panel", "aria-label": t("ov.glance") }, kpis([
        { label: t("kpi.messages"), value: int(d.messages) }, { label: t("kpi.unread"), value: int(d.unread), note: pct(d.unread_share_pct) },
        { label: t("kpi.inbox"), value: int(d.in_inbox) }, { label: t("kpi.size"), value: bytes(d.size_bytes) },
        { label: t("kpi.classified"), value: pct(d.classified_share_pct) }, { label: t("kpi.attention"), value: int(sum(Object.values(d.attention))) }])),
    ];
  });
  const ribbon = panel({ title: "ov.ribbon.title", desc: "ov.ribbon.desc", wide: true,
    load: () => Promise.all([get("volume"), get("categories", { by: "month" })]),
    render: ([volume, cats]) => {
      const points = ribbonPoints(volume, cats);
      if (!points.length) return empty("empty.title", "empty.body");
      const present = cats.data.types.filter((x) => x.messages > 0).map((x) => ({ key: x.type, n: x.messages }));
      return [stackedBars(points, { label: t("ov.ribbon.aria", { n: points.length }) }), legend(present, cats.data.indexed), how(cats)];
    } });
  const categories = panel({ title: "ov.cat.title", desc: "ov.cat.desc", load: () => get("categories"), render: (env) => {
    const d = env.data;
    if (!d.indexed) return empty("empty.title", "empty.body");
    const items = d.types.filter((x) => x.messages > 0).map((x) => ({ key: x.type, n: x.messages }));
    return [shareBar(items, d.indexed, { label: t("ov.cat.aria") }), legend(items, d.indexed), how(env)];
  } });
  const senders = panel({ title: "ov.senders.title", desc: "ov.senders.desc", load: () => get("senders", { kind: "domain", limit: "5" }), render: (env) => {
    const d = env.data;
    if (!d.items.length) return empty("empty.title", "empty.body");
    return [rank(d.items.map((i) => ({ name: untrusted(i.display), value: int(i.messages), share: (i.messages / d.items[0].messages) * 100,
      meta: [pct(i.share_of_indexed_pct), tn("chart.unread", i.unread), code("type", i.dominant_type)] }))), link("#/senders", "ov.senders.all")];
  } });
  return view(top, ribbon, h("div", { class: "grid" }, categories, senders));
}

// ---------------------------------------------------------------- Trends
function trendsView() {
  const volume = panel({ title: "tr.volume.title", desc: "tr.volume.desc", wide: true, load: () => get("volume"), render: (env) => {
    const pts = env.data.points.map((p) => ({ period: p.period, total: p.messages, unread: p.unread, in_progress: p.in_progress, parts: {} }));
    if (!pts.length) return empty("empty.title", "empty.body");
    return [stackedBars(pts, { label: t("tr.volume.aria", { n: pts.length }), single: true, showUnread: true }), how(env)];
  } });
  const mix = h("section", { class: "panel" });
  let mode = "count", data = null;
  const body = h("div", { class: "stack" }, skeleton());
  const draw = () => {
    const env = data;
    const pts = ribbonPoints({ data: { points: env.volume.data.points } }, env.cats);
    body.replaceChildren(segmented("mix-mode", "tr.mix.mode", [["count", t("tr.mix.count")], ["share", t("tr.mix.share")]], mode, (v) => { mode = v; draw(); }),
      stackedBars(pts, { label: t("tr.mix.aria"), mode }), legend(env.cats.data.types.filter((x) => x.messages > 0).map((x) => ({ key: x.type, n: x.messages })), env.cats.data.indexed), how(env.cats));
  };
  const load = async () => { body.replaceChildren(skeleton()); try { const [volumeEnv, cats] = await Promise.all([get("volume"), get("categories", { by: "month" })]); data = { volume: volumeEnv, cats }; if (!volumeEnv.data.points.length) body.replaceChildren(empty("empty.title", "empty.body")); else draw(); } catch (err) { body.replaceChildren(errorState(err, load)); } };
  mix.append(h("header", null, h("h2", null, t("tr.mix.title")), h("p", null, t("tr.mix.desc"))), body);
  load();
  const subs = panel({ title: "tr.subs.title", desc: "tr.subs.desc", wide: true, load: () => get("subscriptions"), render: (env) => {
    const types = env.data.types;
    if (!types.some((x) => x.messages)) return empty("tr.subs.none.title", "tr.subs.none.body");
    const minis = h("div", { class: "minis" }, types.map((x) => {
      const peak = x.monthly.reduce((a, p) => (p.messages > a.messages ? p : a), x.monthly[0] || { messages: 0, period: "" });
      return h("div", { class: "mini-card" }, h("strong", null, code("type", x.type)), h("span", { class: "muted" }, `${tn("chart.messages", x.messages)} · ${pct(x.share_of_indexed_pct)}`),
        miniBars(x.monthly, (p) => p.messages, t("tr.subs.aria", { type: code("type", x.type), n: int(x.messages), peak: peak.period ? month(peak.period) : "—" })),
        h("span", { class: "muted" }, tn("tr.subs.domains", x.domains)));
    }));
    const periods = types[0].monthly.map((p) => p.period);
    return [minis, tableAlt("tr.subs.caption", [t("chart.month"), ...types.map((x) => code("type", x.type))], periods.map((p, i) => [month(p), ...types.map((x) => int(x.monthly[i].messages))])), how(env)];
  } });
  return view(volume, mix, subs);
}

// ---------------------------------------------------------------- Senders
function sendersView() {
  let kind = "domain";
  const holder = h("section", { class: "panel" });
  const body = h("div", { class: "stack" }, skeleton());
  const load = async () => {
    body.replaceChildren(skeleton());
    try {
      const env = await get("senders", { kind, limit: "15" });
      const d = env.data;
      const items = d.items;
      put(body,
        segmented("sender-kind", "sn.kind", [["domain", t("sn.domains")], ["address", t("sn.addresses")]], kind, (v) => { kind = v; load(); }),
        kind === "address" && !d.addresses_revealed ? notice("", t("sn.masked.title"), t("sn.masked.body")) : null,
        items.length ? rank(items.map((i) => ({ name: untrusted(i.display), value: int(i.messages), share: (i.messages / items[0].messages) * 100,
          meta: [pct(i.share_of_indexed_pct), tn("chart.unread", i.unread), `${day(i.first_seen)} – ${day(i.last_seen)}`, code("type", i.dominant_type)] }))) : empty("empty.title", "empty.body"),
        h("p", { class: "muted" }, t("sn.covered", { shown: int(d.covered_messages), total: int(d.indexed), distinct: int(d.distinct) })), how(env));
    } catch (err) { body.replaceChildren(errorState(err, load)); }
  };
  holder.append(h("header", null, h("h2", null, t("sn.title")), h("p", null, t("sn.desc"))), body);
  load();
  const patterns = panel({ title: "sn.subs.title", desc: "sn.subs.desc", load: () => get("subscriptions", { limit: "5" }), render: (env) => {
    const cols = env.data.types.map((x) => h("div", { class: "stack" }, h("div", { class: "row" }, h("strong", null, code("type", x.type)), h("span", { class: "muted" }, tn("chart.messages", x.messages))),
      x.top_domains.length ? rank(x.top_domains.map((d) => ({ name: untrusted(d.domain), value: int(d.messages), share: (d.messages / x.top_domains[0].messages) * 100, meta: [tn("chart.unread", d.unread), day(d.last_seen)] }))) : h("p", { class: "muted" }, t("sn.subs.none"))));
    return [h("div", { class: "grid three" }, cols), how(env)];
  } });
  return view(holder, patterns);
}

// ---------------------------------------------------------------- Cleanup
export function cleanup() {
  const summary = panel({ title: "cl.title", desc: "cl.desc", wide: true, load: () => get("cleanup/summary"), render: (env) => {
    const d = env.data;
    if (!d.total) return empty("empty.title", "empty.body");
    const o = d.outcomes;
    const reasons = (list) => (list.length ? h("ul", { class: "list-plain" }, list.map((r) => h("li", null, `${code("reason", r.code)}: ${int(r.messages)}`))) : h("p", { class: "muted" }, t("cl.reasons.none")));
    return [notice("ok", t("cl.only.title"), t("cl.only.body")),
      h("div", { class: "outcomes" }, ["ELIGIBLE_FOR_ARCHIVE_RECOMMENDATION", "REVIEW_REQUIRED", "EXCLUDED"].map((k) => h("div", { class: "outcome" }, h("strong", null, int(o[k] || 0)), h("span", { class: "muted" }, code("outcome", k))))),
      h("div", { class: "grid" }, h("div", { class: "stack" }, h("h3", null, t("cl.excluded")), reasons(d.excluded_reasons)), h("div", { class: "stack" }, h("h3", null, t("cl.review")), reasons(d.review_reasons))),
      h("p", { class: "muted" }, t("cl.policy", { days: int(d.min_age_days), rules: int(d.protection_rules_active) })), how(env)];
  } });
  const history = panel({ title: "ch.title", desc: "ch.desc", wide: true, load: () => get("cleanup/history"), render: (env) => {
    const d = env.data, a = d.audit;
    if (!d.plans.length && !a.events) return [empty("ch.none.title", "ch.none.body"), how(env)];
    const chain = a.chain_ok ? badge("ok", t("ch.chain.ok")) : badge("err", t("ch.chain.bad"));
    const out = [h("div", { class: "row" }, h("span", null, tn("ch.events", a.events)), chain),
      !a.chain_ok ? notice("err", t("ch.chain.bad"), t("ch.chain.bad_body")) : null];
    if (d.plans.length) out.push(tableAlt("ch.plans", [t("ch.plan"), t("ch.state"), t("ch.items"), t("ch.created")], d.plans.map((p) => [p.plan_id, code("plan", p.state), int(p.item_count), dateTime(p.created_at)])));
    if (d.executions.length) out.push(tableAlt("ch.execs", [t("ch.exec"), t("ch.state"), t("ch.items"), t("ch.outcomes")], d.executions.map((e) => [e.exec_id, code("exec", e.state), int(e.item_count), Object.entries(e.items).map(([k, v]) => `${code("item", k)} ${int(v)}`).join(" · ")])));
    out.push(h("p", { class: "muted" }, tn("ch.applied", d.items_applied)));
    if (a.recent.length) out.push(h("div", { class: "stack" }, h("h3", null, t("ch.recent")), h("ul", { class: "list-plain" }, [...a.recent].reverse().map((e) => h("li", null, `${dateTime(e.at)}: ${code("event", e.event)}`)))));
    out.push(how(env));
    return out;
  } });
  return view(summary, history);
}

// ---------------------------------------------------------------- Organization
export function organization() {
  return view(panel({ title: "og.title", desc: "og.desc", wide: true, load: () => get("organization"), render: (env) => {
    const d = env.data;
    const counts = (obj) => Object.entries(obj).map(([k, v]) => h("li", null, `${code("hyg", k)}: ${int(v)}`));
    const conf = (obj) => Object.entries(obj).map(([k, v]) => h("span", { class: "pill-row" }, confidenceBadge(k), int(v)));
    const col = (titleKey, total, by) => h("div", { class: "stack" }, h("strong", null, t(titleKey)), h("div", { class: "outcome" }, h("strong", null, int(total))), h("div", { class: "pill-row" }, conf(by)));
    const plans = Object.entries(d.label_plans);
    return [notice("", t("og.readonly.title"), t("og.readonly.body")),
      kpis([{ label: t("og.labels"), value: int(d.labels.total) }, { label: t("og.user"), value: int(d.labels.user) }, { label: t("og.inuse"), value: int(d.labels.user_in_use) }, { label: t("og.system"), value: int(d.labels.system) }]),
      h("div", { class: "grid three" }, col("og.hyg", d.hygiene.findings, d.hygiene.by_confidence), col("og.rec", d.recommendations.total, d.recommendations.by_confidence),
        col("og.rules", d.rule_proposals.total, d.rule_proposals.by_confidence)),
      h("div", { class: "grid" }, h("div", { class: "stack" }, h("h3", null, t("og.filters")), h("div", { class: "outcome" }, h("strong", null, int(d.filter_suggestions.total))), h("p", { class: "muted" }, t("og.filters.note"))),
        h("div", { class: "stack" }, h("h3", null, t("og.plans")), plans.length ? h("ul", { class: "list-plain" }, plans.map(([k, v]) => h("li", null, `${code("plan", k)}: ${int(v)}`))) : h("p", { class: "muted" }, t("og.plans.none")))),
      d.hygiene.findings ? h("div", { class: "stack" }, h("h3", null, t("og.findings")), h("ul", { class: "list-plain" }, counts(d.hygiene.by_code)),
        d.hygiene.top.length ? h("ul", { class: "list-plain" }, d.hygiene.top.map((f) => h("li", null, h("span", null, code("hyg", f.code), " · ", confidenceBadge(f.confidence), " · ", code("basis", f.basis), " · ", (f.names ? f.names.map((n) => untrusted(n)) : f.labels.map((l) => untrusted(l))).flatMap((x, i) => (i ? [", ", x] : [x])))))) : null) : empty("og.clean.title", "og.clean.body"),
      !d.names_revealed ? h("p", { class: "muted" }, t("og.names")) : null, h("p", { class: "muted" }, t("og.cli")), how(env)];
  } }));
}

// ---------------------------------------------------------------- Data
export function data() {
  return view(
    panel({ title: "dt.title", desc: "dt.desc", load: () => get("freshness"), render: (env) => {
      const f = env.data, c = f.classification;
      const issues = f.issues.length ? h("ul", { class: "list-plain" }, f.issues.map((i) => h("li", null, code("health", i)))) : h("p", null, badge("ok", code("health", "OK")));
      return [freshnessNotice(env), h("dl", { class: "facts" },
        h("dt", null, t("dt.index")), h("dd", null, code("state", f.state)), h("dt", null, t("dt.scan")), h("dd", null, f.last_full_scan ? `${dateTime(f.last_full_scan)} · ${ageText(env)}` : t("fresh.never")),
        h("dt", null, t("dt.recorded")), h("dd", null, int(f.scans_recorded)), h("dt", null, t("dt.class")), h("dd", null, t("dt.class.v", { current: int(c.current), stale: int(c.stale), unclassified: int(c.unclassified), indexed: int(c.indexed) })),
        h("dt", null, t("dt.health")), h("dd", null, issues),
        h("dt", null, t("dt.sync")), h("dd", null, f.sync.healthy ? badge("ok", code("sync", f.sync.state)) : code("sync", f.sync.state)),
        h("dt", null, t("dt.sync.checkpoint")), h("dd", null, f.sync.checkpoint === "present" ? t("dt.sync.present") : t("dt.sync.missing")),
        h("dt", null, t("dt.sync.last")), h("dd", null, f.sync.last_completed_sync_at ? `${dateTime(f.sync.last_completed_sync_at)}${f.sync.age_hours === null ? "" : " · " + t("dt.sync.hours", { n: int(Math.round(f.sync.age_hours)) })}` : t("dt.sync.never")),
        h("dt", null, t("dt.sync.note.label")), h("dd", null, t("dt.sync.note")),
        h("dt", null, t("dt.maint")), h("dd", null, h("code", null, "gmail-intelligence mailbox maintenance"), " ", t("dt.maint.hint"))), how(env)];
    } }),
    panel({ title: "dt.limits.title", desc: "dt.limits.desc", load: () => get("meta"), render: (meta) => [
      h("ul", { class: "list-plain" }, ["dt.l1", "dt.l2", "dt.l3", "dt.l4", "dt.l5"].map((k) => h("li", null, t(k)))),
      h("dl", { class: "facts" }, h("dt", null, t("dt.api")), h("dd", null, `v${meta.api_version} · ${t("dt.readonly")}`), h("dt", null, t("dt.schema")), h("dd", null, `v${meta.schema}`),
        h("dt", null, t("dt.reveal")), h("dd", null, `${t("dt.reveal.senders")}: ${meta.reveal.senders ? t("yes") : t("no")} · ${t("dt.reveal.names")}: ${meta.reveal.names ? t("yes") : t("no")}`))] }),
    panel({ title: "dt.privacy.title", desc: "dt.privacy.desc", load: async () => null, render: () => h("ul", { class: "list-plain" }, ["dt.p1", "dt.p2", "dt.p3", "dt.p4"].map((k) => h("li", null, t(k)))) }));
}

export const overview = () => whenData(overviewView);
export const trends = () => whenData(trendsView);
export const senders = () => whenData(sendersView);

export const cleanupScreen = () => whenData(cleanup, { gate: false });
export const organizationScreen = () => whenData(organization, { gate: false });

export const SCREENS = [
  { id: "overview", icon: "overview", render: overview }, { id: "trends", icon: "trends", render: trends }, { id: "senders", icon: "senders", render: senders },
  { id: "cleanup", icon: "cleanup", render: cleanupScreen }, { id: "organization", icon: "organization", render: organizationScreen }, { id: "data", icon: "data", render: data },
];
export { icon, swatch, TYPE_ORDER, month, monthLong, ApiError };
