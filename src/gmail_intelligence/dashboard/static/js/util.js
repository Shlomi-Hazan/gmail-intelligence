// DOM helpers. Nothing here ever parses markup: text always goes through createTextNode / textContent, so mailbox-derived strings cannot become HTML or script.
const SVG_NS = "http://www.w3.org/2000/svg";
const UNSAFE = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]", "g");
export function clean(value, limit = 120) {
  const text = String(value ?? "").replace(UNSAFE, " ").replace(/ +/g, " ").trim();
  return text.length > limit ? text.slice(0, limit - 1) + "…" : text;
}

function apply(el, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (key === "class") el.setAttribute("class", value);
    else if (key === "vars") for (const [name, v] of Object.entries(value)) el.style.setProperty(name, String(v));
    else el.setAttribute(key, value === true ? "" : String(value));
  }
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function h(tag, attrs, ...children) { const el = document.createElement(tag); apply(el, attrs); return append(el, children); }
export function s(tag, attrs, ...children) { const el = document.createElementNS(SVG_NS, tag); apply(el, attrs); return append(el, children); }

/** Mailbox-derived text: isolated for bidirectional text, cleaned of control and bidi-override characters, never interpreted. */
export function untrusted(value, limit = 120) { return h("bdi", { dir: "auto" }, clean(value, limit)); }

export function sum(list, pick = (x) => x) { return list.reduce((a, x) => a + pick(x), 0); }
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
