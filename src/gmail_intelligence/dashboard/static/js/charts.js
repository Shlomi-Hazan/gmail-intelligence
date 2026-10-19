// Hand-authored SVG charts. Time always runs left to right (the chart body is dir="ltr" in both languages); everything around it follows the page direction.
// Each chart has a text equivalent: an aria-label summary, a keyboard-operable readout, and a "view as table" alternative.
import { h, s, clean } from "./util.js";
import { t, tn, int, pct, month, monthLong, year, code } from "./i18n.js";

export const TYPE_ORDER = ["PERSONAL", "PROMOTIONAL", "NEWSLETTER", "SOCIAL", "AUTOMATED_NOTIFICATION", "TRANSACTIONAL", "FINANCIAL", "EDUCATIONAL", "UNKNOWN", "UNCLASSIFIED"];
let uid = 0;
const nextId = (name) => `${name}-${++uid}`;

function hatch(id) {
  return s("pattern", { id, width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" }, s("rect", { width: 6, height: 6, class: "hatch-bg" }), s("line", { x1: 0, y1: 0, x2: 0, y2: 6, class: "hatch-line" }));
}

export function swatch(type) {
  const id = nextId("sw");
  const unclassified = type === "UNCLASSIFIED";
  return s("svg", { class: "swatch", viewBox: "0 0 12 12", "aria-hidden": "true", focusable: "false" }, unclassified ? hatch(id) : null,
    s("rect", { width: 12, height: 12, rx: 2, class: unclassified ? "" : `f-${type}`, fill: unclassified ? `url(#${id})` : undefined }));
}

function ticks(points) {
  const out = [], n = points.length;
  const place = (i, label) => { const pos = ((i + 0.5) / n) * 100; if (!out.length || pos - out[out.length - 1].pos > 11) out.push({ pos, label }); };
  points.forEach((p, i) => { if (i === 0) place(i, month(p.period)); else if (p.period.endsWith("-01")) place(i, year(p.period)); });
  if (n > 1 && 100 - out[out.length - 1].pos > 11) out.push({ pos: ((n - 0.5) / n) * 100, label: month(points[n - 1].period) });
  return out;
}

export function tableAlt(captionKey, columns, rows) {
  return h("details", { class: "alt" }, h("summary", null, t("chart.table")), h("div", { class: "table-wrap" }, h("table", null, h("caption", null, t(captionKey)),
    h("thead", null, h("tr", null, columns.map((c, i) => h("th", { scope: "col", class: i ? "num" : "" }, c)))),
    h("tbody", null, rows.map((r) => h("tr", null, r.map((cell, i) => (i ? h("td", { class: "num" }, cell) : h("th", { scope: "row" }, cell)))))))));
}

/** Monthly stacked columns. points: [{period, parts:{TYPE:n}, total, unread, in_progress}]; mode "count" or "share". */
export function stackedBars(points, { label, mode = "count", single = false, showUnread = false }) {
  const n = points.length;
  const max = mode === "share" ? 100 : Math.max(1, ...points.map((p) => p.total));
  const unit = 10, H = 100;
  const hid = nextId("open");
  const svg = s("svg", { class: "bars", viewBox: `0 0 ${n * unit} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true", focusable: "false" }, s("defs", null, hatch(hid)));
  const sel = s("rect", { class: "sel", x: 0, y: 0, width: unit, height: H, visibility: "hidden" });
  points.forEach((p, i) => {
    let y = H;
    const total = p.total || 1;
    const keys = single ? ["single"] : TYPE_ORDER.filter((k) => p.parts[k]);
    for (const k of keys) {
      const raw = single ? p.total : p.parts[k];
      const hgt = (mode === "share" ? (raw / total) * H : (raw / max) * H);
      if (hgt <= 0) continue;
      y -= hgt;
      const unclassified = k === "UNCLASSIFIED";
      svg.append(s("rect", { class: `seg-rect ${unclassified ? "" : `f-${k}`}`, x: i * unit + 1, y, width: unit - 2, height: hgt, fill: unclassified ? `url(#${hid})` : undefined }));
    }
    if (showUnread && p.unread && mode === "count") {
      const hgt = (p.unread / max) * H;
      svg.append(s("rect", { class: "f-unread", x: i * unit + 1, y: H - hgt, width: (unit - 2) / 2.5, height: hgt }));
    }
    if (p.in_progress) svg.append(s("rect", { fill: `url(#${hid})`, opacity: 0.55, x: i * unit + 1, y: 0, width: unit - 2, height: H }));
  });
  svg.append(sel);
  const axis = h("div", { class: "axis", "aria-hidden": "true" }, ticks(points).map((tk) => { const el = h("span", null, tk.label); el.style.left = `${tk.pos}%`; return el; }));
  const readout = h("p", { class: "readout", "aria-live": "polite" }, t("chart.hint"));
  const body = h("div", { class: "chart-body", tabindex: "0", role: "group", "aria-roledescription": t("chart.role"), "aria-label": label }, svg);
  let cur = -1;
  const show = (i) => {
    cur = Math.max(0, Math.min(n - 1, i));
    const p = points[cur];
    sel.setAttribute("x", cur * unit); sel.setAttribute("visibility", "visible");
    const top = TYPE_ORDER.filter((k) => p.parts[k]).sort((a, b) => p.parts[b] - p.parts[a]).slice(0, 3).map((k) => `${code("type", k)} ${int(p.parts[k])}`).join(" · ");
    readout.replaceChildren(h("b", null, monthLong(p.period)), ": ", tn("chart.messages", p.total), p.unread != null ? ` · ${tn("chart.unread", p.unread)}` : "", top ? ` · ${top}` : "", p.in_progress ? ` · ${t("chart.in_progress")}` : "");
  };
  const at = (ev) => { const r = svg.getBoundingClientRect(); return Math.floor(((ev.clientX - r.left) / Math.max(r.width, 1)) * n); };
  body.addEventListener("pointermove", (ev) => { if (ev.pointerType === "mouse") show(at(ev)); });
  body.addEventListener("pointerdown", (ev) => show(at(ev)));
  body.addEventListener("focus", () => { if (cur < 0) show(n - 1); });
  body.addEventListener("keydown", (ev) => {
    const step = { ArrowLeft: -1, ArrowRight: 1, PageUp: -12, PageDown: 12 }[ev.key];
    if (step !== undefined) { ev.preventDefault(); show((cur < 0 ? n - 1 : cur) + step); }
    else if (ev.key === "Home") { ev.preventDefault(); show(0); } else if (ev.key === "End") { ev.preventDefault(); show(n - 1); }
  });
  const peak = points.reduce((a, p) => (p.total > a.total ? p : a), points[0]);
  const keys = single ? [] : TYPE_ORDER.filter((k) => points.some((p) => p.parts[k]));
  const table = tableAlt("chart.table_caption", [t("chart.month"), t("chart.total"), ...(showUnread ? [t("chart.unread_col")] : []), ...keys.map((k) => code("type", k))],
    points.map((p) => [month(p.period), int(p.total), ...(showUnread ? [int(p.unread || 0)] : []), ...keys.map((k) => int(p.parts[k] || 0))]));
  return h("figure", { class: "chart" }, h("p", { class: "peak" }, t("chart.peak", { n: int(peak.total), month: month(peak.period) })), body, axis, readout, table);
}

/** A 100% bar and its legend. items: [{key, n}] ; total is the denominator. */
export function shareBar(items, total, { label }) {
  const svg = s("svg", { viewBox: "0 0 100 10", preserveAspectRatio: "none", role: "img", "aria-label": label, focusable: "false" });
  const hid = nextId("share");
  svg.append(s("defs", null, hatch(hid)));
  let x = 0;
  for (const it of items) {
    const w = total ? (it.n / total) * 100 : 0;
    if (w <= 0) continue;
    svg.append(s("rect", { class: it.key === "UNCLASSIFIED" ? "" : `f-${it.key}`, x, y: 0, width: w, height: 10, fill: it.key === "UNCLASSIFIED" ? `url(#${hid})` : undefined, stroke: "var(--surface)", "stroke-width": 2, "vector-effect": "non-scaling-stroke" }));
    x += w;
  }
  return h("div", { class: "share" }, svg);
}

export function legend(items, total) {
  return h("ul", { class: "legend" }, items.map((it) => h("li", null, swatch(it.key), h("span", null, code("type", it.key)), h("span", { class: "n" }, h("bdi", { dir: "ltr" }, `${int(it.n)} · ${pct(total ? (it.n / total) * 100 : 0)}`)))));
}

/** A tiny single-series column chart (small multiples). */
export function miniBars(points, valueOf, label) {
  const n = Math.max(points.length, 1), max = Math.max(1, ...points.map(valueOf));
  const svg = s("svg", { class: "mini", viewBox: `0 0 ${n * 10} 100`, preserveAspectRatio: "none", role: "img", "aria-label": label, focusable: "false" });
  points.forEach((p, i) => { const hgt = (valueOf(p) / max) * 100; if (hgt > 0) svg.append(s("rect", { class: "f-single", x: i * 10 + 1, y: 100 - hgt, width: 8, height: hgt })); });
  return h("div", { class: "chart-body" }, svg);
}

export const summary = (parts) => clean(parts.filter(Boolean).join(". "), 300);
