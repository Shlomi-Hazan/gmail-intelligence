// The Action Center (M8A-3): a read-only list of messages that may deserve attention, from the server's /attention route (the same engine as `mailbox attention`).
// Text only goes through createTextNode (h / untrusted); senders arrive masked unless the server was started with --reveal-senders; there are no links and no action buttons.
import { h, untrusted } from "./util.js";
import { get } from "./api.js";
import { t, tn, code, int, day, dateTime } from "./i18n.js";
import { notice, empty, skeleton, errorState, badge } from "./components.js";

const SORTS = ["priority", "date", "oldest"];
const SIGNALS = ["all", "starred", "important", "unread", "rule"];
const TIERS = ["any", "low", "medium", "high"];
const LIMITS = ["1", "2", "3", "5", "10", "0"];
const PAGE = "25";

function select(labelKey, value, options, onChange) {
  const id = `att-${labelKey.replace(/\W/g, "-")}`;
  const el = h("select", { id, onchange: (ev) => onChange(ev.target.value) }, options.map(([v, label]) => h("option", { value: v, selected: v === value }, label)));
  return h("div", { class: "field" }, h("label", { for: id }, t(labelKey)), el);
}

function checkbox(labelKey, checked, onChange) {
  return h("label", { class: "check" }, h("input", { type: "checkbox", checked, onchange: (ev) => onChange(ev.target.checked) }), h("span", null, t(labelKey)));
}

function itemCard(it) {
  const who = it.sender.display === null ? t("att.sender.unknown") : it.sender.display;
  const meta = [it.date ? day(it.date) : t("att.nodate")];
  if (it.unread_days !== null) meta.push(tn("att.unread_days", it.unread_days));
  if (it.thread_messages > 1) meta.push(tn("att.thread", it.thread_messages));
  return h("li", { class: "att-item" },
    h("div", { class: "att-head" }, h("bdi", { dir: "ltr", class: "att-rank" }, t("att.rank", { n: int(it.rank) })),
      badge(`tier-${it.tier}`, `${code("att.tier", it.tier)} · ${t("att.score", { n: int(it.score) })}`), h("span", { class: "muted" }, code("att.evidence", it.evidence))),
    h("p", { class: "att-who" }, untrusted(who, 254)),
    h("p", { class: "att-meta" }, meta.map((m) => h("span", null, m))),
    h("ul", { class: "att-signals" }, it.signals.map((s) => h("li", null, h("span", null, code("att.sig", s.code)), " ", h("bdi", { dir: "ltr", class: "att-points" }, `${s.points >= 0 ? "+" : "−"}${int(Math.abs(s.points))}`), " ", h("small", { class: "muted" }, code("basis", s.basis))))),
    h("p", { class: "att-explain muted" }, t("att.components", { owner: int(it.components.owner), inferred: int(it.components.inferred), penalty: int(it.components.penalty) })),
    it.types.length || it.flags.length ? h("p", { class: "att-tags" }, it.types.map((ty) => badge("", code("type", ty))), it.flags.map((f) => badge("warn", code("att.flag", f)))) : null);
}

function warningsNotice(res) {
  if (!res.warnings.length || (res.warnings.length === 1 && res.warnings[0] === "INDEX_EMPTY")) return null;
  const parts = res.warnings.filter((w) => w !== "INDEX_EMPTY").map((w) => code("att.warn", w));
  if (res.warnings.includes("SYNC_NOT_HEALTHY")) parts.push(code("fresh.sync", res.freshness.sync_state));
  parts.push(res.freshness.as_of ? t("att.asof", { when: dateTime(res.freshness.as_of) }) : t("att.asof.unknown"));
  return notice("warn", t("att.warn.title"), parts.join(" "));
}

export function attentionScreen() {
  const q = { sort: "priority", signal: "all", tier: "any", sender_limit: "3", collapse: true, low: false };
  let cursor = null;
  const history = [];
  const body = h("div", { class: "stack" }, skeleton());
  let serial = 0;

  const reset = () => { cursor = null; history.length = 0; run(); };
  const restart = h("button", { class: "btn quiet", type: "button", onclick: reset }, t("att.err.restart"));

  function failure(err) {
    const c = err && err.code;
    if (c === "SNAPSHOT_CHANGED" || c === "CURSOR_INVALID") return [notice("warn", t("att.err.changed.title"), t("att.err.changed.body")), h("div", null, restart)];
    if (c === "RESULT_INCOMPLETE") return [notice("warn", t("att.err.incomplete.title"), t("att.err.incomplete.body"))];
    if (c === "INDEX_CHANGED_DURING_READ") return [notice("warn", t("att.err.busy.title"), t("att.err.busy.body")), h("div", null, h("button", { class: "btn quiet", type: "button", onclick: () => run() }, t("error.retry")))];
    return [errorState(err, () => run())];
  }

  function render(res) {
    const out = [warningsNotice(res)];
    if (!res.items.length) {
      out.push(res.warnings.includes("INDEX_EMPTY") ? empty("empty.title", "empty.body") : empty("att.empty.title", "att.empty.body"));
      if (history.length) out.push(h("div", null, restart));
      return out;
    }
    out.push(h("p", { class: "muted" }, tn("att.summary", res.totals.total, { shown: int(res.items.length) })));
    out.push(h("ol", { class: "att-list", start: res.items[0].rank }, res.items.map(itemCard)));
    out.push(h("nav", { class: "pager", "aria-label": t("att.pager.label") },
      h("button", { class: "btn quiet", type: "button", disabled: history.length === 0, onclick: () => { cursor = history.pop(); run(); } }, t("att.pager.prev")),
      h("button", { class: "btn quiet", type: "button", disabled: !res.next_cursor, onclick: () => { history.push(cursor); cursor = res.next_cursor; run(); } }, t("att.pager.next"))));
    return out;
  }

  async function run() {
    const mine = ++serial;
    body.replaceChildren(skeleton());
    const params = { limit: PAGE, sort: q.sort, signal: q.signal, tier: q.tier, sender_limit: q.sender_limit, collapse: q.collapse ? "1" : "0", low: q.low ? "1" : "0" };
    if (cursor) params.cursor = cursor;
    try {
      const res = await get("attention", params);
      if (mine === serial) body.replaceChildren(...render(res).flat(Infinity).filter(Boolean));
    } catch (err) {
      if (mine === serial) body.replaceChildren(...failure(err).flat(Infinity).filter(Boolean));
    }
  }

  const set = (key) => (value) => { q[key] = value; reset(); };
  const controls = h("div", { class: "att-controls" },
    select("att.sort.label", q.sort, SORTS.map((v) => [v, code("att.sort", v)]), set("sort")),
    select("att.signal.label", q.signal, SIGNALS.map((v) => [v, code("att.signal", v)]), set("signal")),
    select("att.mintier.label", q.tier, TIERS.map((v) => [v, code("att.mintier", v)]), set("tier")),
    select("att.senderlimit.label", q.sender_limit, LIMITS.map((v) => [v, v === "0" ? t("att.senderlimit.off") : int(Number(v))]), set("sender_limit")),
    checkbox("att.collapse", q.collapse, set("collapse")), checkbox("att.low", q.low, set("low")));
  run();
  return h("div", { class: "view" }, h("section", { class: "panel wide" }, h("header", null, h("h2", null, t("att.title")), h("p", null, t("att.desc"))),
    notice("info", t("att.note.title"), t("att.note.body")), controls, body));
}
