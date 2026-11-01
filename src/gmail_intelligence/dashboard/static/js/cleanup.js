// The Cleanup area (M12E): a READ-ONLY view of the local cleanup records. Discovery -> Review -> Plan -> Approval -> Execution -> Recovery / Undo.
// Everything shown comes from GET /api/v1/cleanup/*; nothing here approves, reserves, runs, confirms, aborts, undoes or reconciles anything, and there is no control that could.
import { h, untrusted } from "./util.js";
import { get } from "./api.js";
import { t, tn, code, int, bytes, dateTime } from "./i18n.js";
import { panel, kpis, notice, empty, how, badge } from "./components.js";

const TABS = ["overview", "discovery", "plans", "executions", "undo", "recovery", "history"];
let tab = "overview";
const ltr = (value) => h("bdi", { dir: "ltr" }, value);                        // identifiers, hashes and numbers keep their direction inside right-to-left text
const mono = (value) => h("code", null, ltr(value));

/** A readable data table (visible, unlike the collapsed chart tables): the first column is the row header. */
function table(captionKey, columns, rows) {
  return h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("caption", null, t(captionKey)),
    h("thead", null, h("tr", null, columns.map((c, i) => h("th", { scope: "col", class: i ? "num" : "" }, c)))),
    h("tbody", null, rows.map((r) => h("tr", null, r.map((cell, i) => (i ? h("td", { class: "num" }, cell) : h("th", { scope: "row" }, cell))))))));
}

const KIND = { COMPLETED: "ok", RESTORED: "ok", COMPLETED_WITH_OPEN_ITEMS: "warn", INTERRUPTED: "warn", RECONCILIATION_REQUIRED: "warn", AWAITING_CONTINUATION: "warn", PREPARED: "warn", PARTIAL: "warn",
  FAILED: "err", ABORTED: "", RUNNING: "", STOPPED: "warn", PLANNED: "", APPROVED: "", IN_PROGRESS: "", INCONSISTENT: "err" };

function cliHint(text) { return h("p", { class: "muted" }, t(text)); }

// ---------------------------------------------------------------- overview
function lifecycle(d) {
  const noData = !d.discovery.indexed && !d.plans.total && !d.executions.total && !d.reversals.total;
  const bad = d.executions.owner_action + d.recovery.attention + (d.recovery.audit_chain_ok ? 0 : 1);
  const steps = [
    { id: "discovery", n: d.discovery.candidates, status: !d.discovery.indexed ? "NO_DATA" : d.discovery.index_state !== "complete" ? "PARTIAL" : "AVAILABLE" },
    { id: "review", n: null, status: "NOT_STORED" },
    { id: "plan", n: d.plans.total, status: d.plans.total ? "RECORDED" : "NONE" },
    { id: "approval", n: (d.plans.by_stage.APPROVED_NOT_EXECUTED || 0) + (d.plans.by_stage.EXECUTION_RESERVED || 0), status: (d.plans.by_stage.APPROVED_NOT_EXECUTED || 0) + (d.plans.by_stage.EXECUTION_RESERVED || 0) ? "RECORDED" : "NO_APPROVED" },
    { id: "execution", n: d.executions.total, status: !d.executions.total ? "NONE" : d.executions.owner_action ? "UNRESOLVED" : "RECORDED" },
    { id: "recovery", n: d.recovery.attention, status: bad ? "UNRESOLVED" : d.reversals.total ? "RECORDED" : "NONE" },
  ];
  return noData ? empty("cx.empty.title", "cx.empty.body") : h("ol", { class: "life", "aria-label": t("cx.life.aria") }, steps.map((s, i) => h("li", { class: `step ${s.status === "UNRESOLVED" ? "warn" : ""}`.trim() },
    h("span", { class: "step-no", "aria-hidden": "true" }, int(i + 1)), h("strong", null, t(`cx.step.${s.id}`)), h("span", { class: "step-n" }, s.n === null ? "—" : ltr(int(s.n))),
    badge(s.status === "UNRESOLVED" ? "warn" : s.status === "RECORDED" || s.status === "AVAILABLE" ? "ok" : "", code("cx.ss", s.status)))));
}

function overviewTab() {
  const head = panel({ title: "cx.life.title", desc: "cx.life.desc", wide: true, load: () => get("cleanup/overview"), render: (env) => {
    const d = env.data;
    const open = d.executions.items.unknown + d.executions.items.conflict + d.executions.items.intent;
    return [lifecycle(d), kpis([
      { label: t("cx.k.candidates"), value: int(d.discovery.candidates) }, { label: t("cx.k.groups"), value: int(d.discovery.groups) }, { label: t("cx.k.plans"), value: int(d.plans.total) },
      { label: t("cx.k.archived"), value: int(d.executions.items.archived) }, { label: t("cx.k.open"), value: int(open) }, { label: t("cx.k.restored"), value: int(d.reversals.restored) }]),
      h("p", { class: "muted" }, t("cx.k.note")), d.discovery.warnings.length ? notice("warn", t("cx.warn.title"), d.discovery.warnings.map((w) => code("cx.dw", w)).join(" ")) : null, how(env)];
  } });
  const split = panel({ title: "cx.split.title", desc: "cx.split.desc", wide: true, load: () => get("cleanup/overview"), render: (env) => {
    const d = env.data;
    const line = (titleKey, counts, prefix) => h("div", { class: "stack" }, h("h3", null, t(titleKey)), Object.keys(counts).length ?
      h("div", { class: "pill-row" }, Object.entries(counts).map(([k, v]) => h("span", null, badge(KIND[k] ?? "", code(prefix, k)), " ", ltr(int(v))))) : h("p", { class: "muted" }, t("cx.none")));
    return h("div", { class: "grid three" }, line("cx.split.plans", d.plans.by_stage, "cx.stage"), line("cx.split.exec", d.executions.by_category, "cx.cat"), line("cx.split.rev", d.reversals.by_state, "cx.rs"));
  } });
  return [h("section", { class: "panel", "aria-label": t("cx.intro.title") }, notice("ok", t("cx.intro.title"), t("cx.intro.body")), cliHint("cx.intro.cli")), head, split];
}

// ---------------------------------------------------------------- discovery
function discoveryTab() {
  const groups = panel({ title: "cx.dis.title", desc: "cx.dis.desc", wide: true, load: () => get("cleanup/discovery", { limit: "20", min_group: "5" }), render: (env) => {
    const r = env.data.discovery, tt = r.totals;
    if (!tt.indexed) return [empty("cx.dis.none.title", "cx.dis.none.body"), how(env)];
    const out = [r.warnings.length ? notice("warn", t("cx.warn.title"), r.warnings.map((w) => code("cx.dw", w)).join(" ")) : null,
      h("div", { class: "outcomes" }, [["cx.dis.eligible", tt.eligible.messages], ["cx.dis.uncertain", tt.uncertain.messages], ["cx.dis.protected", tt.protected.messages]].map(([k, n]) =>
        h("div", { class: "outcome" }, h("strong", null, int(n)), h("span", { class: "muted" }, t(k))))),
      h("p", { class: "muted" }, t("cx.dis.maybe"))];
    if (!r.groups.length) { out.push(empty("cx.dis.nogroups.title", "cx.dis.nogroups.body")); return [out, how(env)]; }
    out.push(table("cx.dis.caption", [t("cx.dis.domain"), t("cx.dis.messages"), t("cx.dis.threads"), t("cx.dis.size"), t("cx.dis.age"), t("cx.dis.rule"), t("cx.dis.context")],
      r.groups.map((g) => [untrusted(g.domain), ltr(int(g.messages)), ltr(int(g.threads)), ltr(bytes(g.bytes)), ltr(`${int(g.newest_days)}–${int(g.oldest_days)}`),
        g.evidence.map((e) => `${code("type", e.type)} (${code("confidence", e.confidence)}) ×${int(e.messages)}`).join("; ") || "—",
        g.subscription_review ? [code("cx.est", g.subscription_review.estimate), g.subscription_review.caution ? " — " + t("cx.dis.caution") : ""] : "—"])));
    out.push(h("details", { class: "how" }, h("summary", null, t("cx.dis.why.title")), h("ul", { class: "list-plain" }, [...new Set(r.groups.flatMap((g) => g.why).map((w) => w.replace(/_\d+D$/, "_DAYS")))].map((w) => h("li", null, t(`cx.why.${w}`, { days: int(r.min_age_days) }))))));
    if (r.below_min_group.groups) out.push(h("p", { class: "muted" }, t("cx.dis.small", { groups: int(r.below_min_group.groups), messages: int(r.below_min_group.messages) })));
    out.push(how(env));
    return out;
  } });
  const reasons = panel({ title: "cx.dis.reasons.title", desc: "cx.dis.reasons.desc", wide: true, load: () => get("cleanup/discovery", { limit: "1", min_group: "1000" }), render: (env) => {
    const r = env.data.discovery;
    const list = (titleKey, rows) => h("div", { class: "stack" }, h("h3", null, t(titleKey)), rows.length ? h("ul", { class: "list-plain" }, rows.map((x) => h("li", null, `${code("reason", x.code)}: ${int(x.messages)}`))) : h("p", { class: "muted" }, t("cx.none")));
    return h("div", { class: "grid" }, list("cx.dis.review", r.uncertain_reasons), list("cx.dis.protectedlist", r.protected_reasons), list("cx.dis.unsafe", r.unsafe_data_reasons), list("cx.dis.na", r.not_applicable_reasons));
  } });
  return [groups, reasons];
}

// ---------------------------------------------------------------- plans
function plansTab() {
  return [panel({ title: "cx.plans.title", desc: "cx.plans.desc", wide: true, load: () => get("cleanup/plans"), render: (env) => {
    const rows = env.data.plans;
    const body = rows.length ? table("cx.plans.caption", [t("cx.plans.id"), t("cx.plans.stage"), t("cx.plans.items"), t("cx.plans.hash"), t("cx.plans.created"), t("cx.plans.expires"), t("cx.plans.approvals"), t("cx.plans.exec")],
      [...rows].reverse().map((p) => [mono(p.plan_id), badge(p.stage === "APPROVED_NOT_EXECUTED" || p.stage === "EXECUTION_RESERVED" ? "ok" : p.stage === "APPROVAL_EXPIRED" ? "warn" : "", code("cx.stage", p.stage)),
        ltr(int(p.items)), mono(p.hash8), dateTime(p.created_at), dateTime(p.expires_at), Object.entries(p.approvals).map(([k, v]) => `${code("cx.appr", k)} ${int(v)}`).join(", ") || "—",
        p.execution ? [mono(p.execution.exec_id), " ", code("exec", p.execution.state)] : t("cx.plans.noexec")])) : empty("cx.plans.none.title", "cx.plans.none.body");
    return [notice("", t("cx.plans.info.title"), t("cx.plans.info.body")), body, cliHint("cx.plans.cli"), how(env)];
  } })];
}

// ---------------------------------------------------------------- executions
function progress(done, total) {
  const bar = h("i"); bar.style.setProperty("--w", `${total ? (100 * done) / total : 0}%`);
  return h("div", { class: "prog", role: "img", "aria-label": t("cx.ex.slices.aria", { done: int(done), total: int(total) }) }, h("span", { class: "track", "aria-hidden": "true" }, bar), h("span", { class: "muted" }, t("cx.ex.slices", { done: int(done), total: int(total) })));
}

function executionCard(e) {
  const c = e.item_counts;
  const counts = [["archived", c.archived], ["skipped", c.skipped], ["not_applied", c.not_applied], ["never_attempted", c.never_attempted], ["unknown", c.unknown], ["conflict", c.conflict], ["intent", c.intent], ["pending", c.pending]]
    .filter(([k, n]) => n || ["archived", "skipped", "unknown", "conflict"].includes(k));
  return h("article", { class: "card" }, h("header", { class: "row" }, h("h3", null, mono(e.exec_id)), badge(KIND[e.category] ?? "", code("cx.cat", e.category))),
    h("p", { class: "muted" }, t("cx.ex.of", { plan: e.plan_id, hash: e.plan_hash8 ?? "—", items: int(e.items) })), progress(e.slices_completed, e.slices_total),
    h("dl", { class: "facts" }, counts.flatMap(([k, n]) => [h("dt", null, t(`cx.ei.${k}`)), h("dd", null, ltr(int(n)))])),
    e.owner_action ? notice("warn", t("cx.ex.attention"), t(`cx.ex.next.${e.category}`)) : e.category === "COMPLETED" ? notice("ok", t("cx.ex.done.title"), t("cx.ex.done.body")) : null,
    table("cx.ex.slice.caption", [t("cx.ex.slice"), t("cx.ex.range"), t("cx.ex.size"), t("cx.ex.state"), t("cx.ex.confirmed"), t("cx.ex.finished")],
      e.slices.map((s) => [ltr(int(s.slice)), ltr(`${int(s.items[0])}–${int(s.items[1])}`), ltr(int(s.size)), code("cx.sl", s.state), dateTime(s.confirmed_at), dateTime(s.finished_at)])),
    h("p", { class: "muted" }, t("cx.ex.times", { created: dateTime(e.created_at), changed: dateTime(e.changed_at), audit: dateTime(e.last_audit_at) })));
}

function executionsTab() {
  return [panel({ title: "cx.ex.title", desc: "cx.ex.desc", wide: true, load: () => get("cleanup/executions"), render: (env) => {
    const rows = env.data.executions;
    if (!rows.length) return [empty("cx.ex.none.title", "cx.ex.none.body"), how(env)];
    return [notice("", t("cx.ex.info.title"), t("cx.ex.info.body")), h("div", { class: "stack" }, [...rows].reverse().map(executionCard)), how(env)];
  } })];
}

// ---------------------------------------------------------------- undo / reversal
function reversalCard(r) {
  if (r.state === "INCONSISTENT") return h("article", { class: "card" }, h("header", { class: "row" }, h("h3", null, mono(r.rev)), badge("err", code("cx.rs", r.state))), notice("err", t("cx.rv.bad.title"), t("cx.rv.bad.body")));
  const c = r.item_counts;
  return h("article", { class: "card" }, h("header", { class: "row" }, h("h3", null, mono(r.rev)), badge(KIND[r.state] ?? "", code("cx.rs", r.state))),
    h("p", { class: "muted" }, t("cx.rv.of", { exec: r.exec_id, items: int(r.items), done: int(r.slices_done), total: int(r.slices) })), progress(r.slices_done, r.slices),
    h("dl", { class: "facts" }, ["restored", "not_restored", "never_attempted", "pending", "uncertain", "conflict", "inconsistent"].flatMap((k) => [h("dt", null, t(`cx.uc.${k}`)), h("dd", null, ltr(int(c[k])))]),
      h("dt", null, t("cx.rv.skipped")), h("dd", null, ltr(int(r.skipped)), Object.keys(r.skip_codes).length ? " (" + Object.entries(r.skip_codes).map(([k, v]) => `${code("cx.skip", k)} ${int(v)}`).join(", ") + ")" : "")),
    r.owner_action ? notice("warn", t("cx.ex.attention"), t(`cx.rv.next.${r.state}`)) : null,
    h("p", { class: "muted" }, t("cx.rv.times", { planned: dateTime(r.planned_at), approval: r.approved ? dateTime(r.approval_expires) : "—" })));
}

function undoTab() {
  return [panel({ title: "cx.rv.title", desc: "cx.rv.desc", wide: true, load: () => get("cleanup/reversals"), render: (env) => {
    const d = env.data;
    const singles = Object.entries(d.single_undos);
    if (!d.reversals.length && !singles.length) return [empty("cx.rv.none.title", "cx.rv.none.body"), how(env)];
    return [notice("", t("cx.rv.info.title"), t("cx.rv.info.body")), h("div", { class: "stack" }, [...d.reversals].reverse().map(reversalCard)),
      singles.length ? h("div", { class: "stack" }, h("h3", null, t("cx.rv.single")), h("div", { class: "pill-row" }, singles.map(([k, v]) => h("span", null, badge(k === "restored" ? "ok" : k === "never_attempted" || k === "not_restored" ? "" : "warn", code("cx.uc", k)), " ", ltr(int(v)))))) : null,
      how(env)];
  } })];
}

// ---------------------------------------------------------------- recovery
function recoveryTab() {
  return [panel({ title: "cx.rec.title", desc: "cx.rec.desc", wide: true, load: () => get("cleanup/recovery"), render: (env) => {
    const d = env.data;
    const status = d.audit_chain_ok ? badge("ok", t("ch.chain.ok")) : badge("err", t("ch.chain.bad"));
    const chain = d.audit_chain_ok ? null : notice("err", t("cx.rec.chain.title"), t("cx.rec.chain.body"));         // an invalid audit chain is never an all-clear
    if (!d.attention.length) return [chain || notice("ok", t("cx.rec.clear.title"), t("cx.rec.clear.body")), h("div", { class: "row" }, h("span", { class: "muted" }, t("cx.rec.note")), status), how(env)];
    return [chain, notice("warn", t("cx.rec.some.title"), tn("cx.rec.some", d.attention.length)),
      table("cx.rec.caption", [t("cx.rec.what"), t("cx.rec.state"), t("cx.rec.open"), t("cx.rec.since"), t("cx.rec.next")],
        d.attention.map((a) => [a.id ? [t(`cx.rec.kind.${a.kind}`), " ", mono(a.id)] : t(`cx.rec.kind.${a.kind}`), a.kind === "execution" ? code("cx.cat", a.code) : a.kind === "reversal" ? code("cx.rs", a.code) : code("cx.uc", a.code.toLowerCase()),
          ltr(int(a.unresolved)), dateTime(a.since), t(`cx.next.${a.next}`)])),
      h("p", { class: "muted" }, t("cx.rec.note")), h("div", { class: "row" }, h("span", null, t("cx.rec.cli")), status), how(env)];
  } })];
}

// ---------------------------------------------------------------- history (the local audit chain)
function historyTab() {
  return [panel({ title: "ch.title", desc: "ch.desc", wide: true, load: () => get("cleanup/history"), render: (env) => {
    const d = env.data, a = d.audit;
    if (!d.plans.length && !a.events) return [empty("ch.none.title", "ch.none.body"), how(env)];
    const out = [h("div", { class: "row" }, h("span", null, tn("ch.events", a.events)), a.chain_ok ? badge("ok", t("ch.chain.ok")) : badge("err", t("ch.chain.bad"))),
      !a.chain_ok ? notice("err", t("ch.chain.bad"), t("ch.chain.bad_body")) : null, h("p", { class: "muted" }, tn("ch.applied", d.items_applied))];
    if (a.recent.length) out.push(h("div", { class: "stack" }, h("h3", null, t("ch.recent")), h("ul", { class: "list-plain" }, [...a.recent].reverse().map((e) => h("li", null, `${dateTime(e.at)}: ${code("event", e.event)}`)))));
    out.push(how(env));
    return out;
  } })];
}

const RENDER = { overview: overviewTab, discovery: discoveryTab, plans: plansTab, executions: executionsTab, undo: undoTab, recovery: recoveryTab, history: historyTab };

/** The screen: a labelled tab group (radios, keyboard-operable) and the selected tab's panels. Switching tabs only re-reads local records. */
export function cleanupScreen() {
  const body = h("div", { class: "view" });
  const group = h("div", { class: "seg tabs", role: "radiogroup", "aria-label": t("cx.tab.label") });
  const draw = () => body.replaceChildren(...RENDER[tab]().flat(Infinity).filter(Boolean));
  for (const id of TABS) {
    group.append(h("label", null, h("input", { type: "radio", name: "cx-tab", value: id, checked: id === tab, onchange: () => { tab = id; draw(); } }), h("span", null, t(`cx.tab.${id}`))));
  }
  draw();
  return h("div", { class: "view" }, group, body);
}
