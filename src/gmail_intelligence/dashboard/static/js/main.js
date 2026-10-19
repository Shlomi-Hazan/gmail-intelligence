// Application shell: preferences (language, appearance), navigation, header status and the hash router. Nothing here stores or shows an account identifier.
import { h, clear } from "./util.js";
import { icon } from "./icons.js";
import { load as loadCatalog, t, tn, lang } from "./i18n.js";
import { takeTokenFromUrl, hasToken, get } from "./api.js";
import { SCREENS } from "./views.js";
import { ageText } from "./components.js";

const root = document.documentElement;
const store = {
  get(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } },
  set(key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* preferences just will not persist */ } },
};
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const themeColor = document.querySelector('meta[name="theme-color"]');

function applyTheme(choice) {
  root.setAttribute("data-theme", choice);
  const isDark = choice === "dark" || (choice === "system" && dark.matches);
  if (themeColor) themeColor.setAttribute("content", isDark ? "#0D1015" : "#F5F6F8");
}
dark.addEventListener("change", () => applyTheme(root.getAttribute("data-theme")));

async function applyLang(code) {
  await loadCatalog(code);
  root.lang = code;
  root.dir = code === "he" ? "rtl" : "ltr";
}

let current = null;
const nav = h("nav", { class: "nav", "aria-label": "" });
const title = h("h1", { id: "view-title", tabindex: "-1" });
const chipSlot = h("span", { id: "fresh-chip" });
const main = h("main", { id: "main", tabindex: "-1" });
const settings = h("details", { class: "menu" });

function radios(name, legendKey, options, value, onChange) {
  return h("fieldset", null, h("legend", null, t(legendKey)), h("div", { class: "seg", role: "radiogroup" }, options.map(([v, label]) =>
    h("label", null, h("input", { type: "radio", name, value: v, checked: v === value, onchange: () => onChange(v) }), h("span", null, label)))));
}

function buildSettings() {
  const panelEl = h("div", { class: "menu-panel" },
    radios("lang", "set.language", [["en", "English"], ["he", "עברית"]], lang(), async (v) => { store.set("gi.lang", v); await applyLang(v); build(); settings.open = true; settings.querySelector("input:checked")?.focus(); }),
    radios("theme", "set.appearance", [["system", t("set.system")], ["light", t("set.light")], ["dark", t("set.dark")]], root.getAttribute("data-theme"), (v) => { store.set("gi.theme", v); applyTheme(v); }));
  const wasOpen = settings.open;
  settings.replaceChildren(h("summary", { "aria-label": t("set.title") }, icon("settings")), panelEl);
  settings.open = wasOpen;
}

function shortLabel(id) { const key = `nav.${id}.short`; const text = t(key); return text === key ? t(`nav.${id}`) : text; }

function buildNav() {
  nav.setAttribute("aria-label", t("nav.label"));
  nav.replaceChildren(h("div", { class: "brand" }, h("strong", null, "Gmail Intelligence"), h("span", null, icon("lock"), t("brand.local"))),
    h("ul", null, SCREENS.map((s) => h("li", null, h("a", { href: `#/${s.id}`, "data-screen": s.id }, icon(s.icon), h("span", null, shortLabel(s.id)))))));
}

async function refreshChip() {
  chipSlot.replaceChildren();
  if (!hasToken()) return;
  try {
    const env = await get("freshness");
    const f = env.data;
    const kind = f.state === "empty" || f.issues.includes("PARTIAL") ? "warn" : f.issues.includes("STALE") || f.issues.includes("CLASSIFICATION_STALE") ? "warn" : "ok";
    chipSlot.replaceChildren(h("span", { class: `chip ${kind}` }, icon(kind === "ok" ? "ok" : "warn"), f.state === "empty" ? t("fresh.chip.empty") : `${t(`fresh.chip.${f.state}`)} · ${ageText(env)}`));
  } catch (e) { /* the screens report their own errors */ }
}

function gate() {
  main.replaceChildren(h("div", { class: "gate" }, icon("lock"), h("h2", null, t("gate.title")), h("p", { class: "muted" }, t("gate.body")), h("p", null, h("code", null, "gmail-intelligence dashboard serve"))));
  title.textContent = t("gate.title");
}

function route() {
  const id = (/^#\/(\w+)/.exec(window.location.hash) || [])[1];
  const screen = SCREENS.find((s) => s.id === id) || SCREENS[0];
  nav.querySelectorAll("a").forEach((a) => (a.dataset.screen === screen.id ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  title.textContent = t(`nav.${screen.id}`);
  document.title = `${t(`nav.${screen.id}`)} · Gmail Intelligence`;
  if (!hasToken()) return gate();
  clear(main).append(screen.render());
  refreshChip();
  if (current !== null && current !== screen.id) title.focus({ preventScroll: true });
  current = screen.id;
  window.scrollTo(0, 0);
}

function build() {
  buildNav(); buildSettings();
  const skip = document.body.querySelector(".skip");
  skip.textContent = t("skip");
  skip.onclick = (ev) => { ev.preventDefault(); main.focus(); };
  route();
}

async function start() {
  takeTokenFromUrl();
  const saved = store.get("gi.lang");
  await applyLang(saved === "he" || saved === "en" ? saved : root.lang);
  applyTheme(root.getAttribute("data-theme") || "system");
  document.body.querySelector("#shell").replaceWith(h("div", { class: "app" }, nav, h("div", { class: "stage" }, h("header", { class: "bar" }, title, chipSlot, settings), main)));
  build();
  window.addEventListener("hashchange", route);
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && settings.open) { settings.open = false; settings.querySelector("summary").focus(); } });
  document.addEventListener("click", (ev) => { if (settings.open && !settings.contains(ev.target)) settings.open = false; });
}
start();
export { tn };
