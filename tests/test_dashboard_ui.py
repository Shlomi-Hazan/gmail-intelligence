"""M6C: the dashboard front end (issue #19), checked statically and with the real server. Synthetic data only; no Gmail, no external network.

What these tests prove: translations are complete in both languages (including the server's code vocabularies and plural forms), mailbox-derived text can only be rendered as text, no
external asset or inline code exists (so the strict CSP works), colours meet WCAG AA in both themes, CSS is direction-agnostic and motion-safe, and the shell sets language, direction
and theme before the first paint. The browser checks (screenshots, keyboard, RTL, responsive) are recorded in docs/DASHBOARD.md.
"""
import ast
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
STATIC = ROOT / "src" / "gmail_intelligence" / "dashboard" / "static"

from gmail_intelligence import analytics, classify, cleanup_audit, cleanup_candidates as cc, dashboard_server as ds, index as idx, label_hygiene  # noqa: E402


def read(rel):
    return (STATIC / rel).read_text(encoding="utf-8")


def js_files():
    return sorted((STATIC / "js").rglob("*.js"))


def catalogs():
    return json.loads(read("i18n/en.json")), json.loads(read("i18n/he.json"))


class CatalogTests(unittest.TestCase):
    def test_both_languages_have_exactly_the_same_keys_and_no_empty_text(self):
        en, he = catalogs()
        self.assertEqual(sorted(set(en) ^ set(he)), [])
        for lang, cat in (("en", en), ("he", he)):
            for key, text in cat.items():
                self.assertTrue(isinstance(text, str) and text.strip(), f"{lang}:{key}")

    def test_placeholders_match_between_languages(self):
        en, he = catalogs()
        for key in en:
            a, b = sorted(re.findall(r"\{(\w+)\}", en[key])), sorted(re.findall(r"\{(\w+)\}", he[key]))
            if key.endswith((".one", ".two")):
                self.assertTrue(set(b) <= set(a), key)  # Hebrew spells out "one" and "two" ("הודעה אחת"), so the count placeholder may be absent
            else:
                self.assertEqual(a, b, key)

    def test_plural_families_are_complete(self):
        en, he = catalogs()
        for cat, needed in ((en, {"other"}), (he, {"other"})):
            families = {}
            for key in cat:
                base, dot, rule = key.rpartition(".")
                if dot and rule in ("one", "two", "many", "other"):
                    families.setdefault(base, set()).add(rule)
            for base, rules in families.items():
                self.assertTrue(needed <= rules, base)
        he_bases = {k.rpartition(".")[0] for k in he if k.rpartition(".")[2] in ("one", "two", "many")}
        for base in he_bases:  # Hebrew distinguishes one, two and many; a family that starts must not be half-finished
            if (base + ".one") in he and (base + ".other") in he and base in ("ov.lede", "ch.events", "ch.applied"):
                self.assertTrue({base + ".two", base + ".many"} <= set(he), base)
        for base in ("ov.lede", "chart.messages", "chart.unread", "fresh.stale", "fresh.ago", "tr.subs.domains", "ch.events", "ch.applied"):
            self.assertIn(base + ".one", he)
            self.assertIn(base + ".other", he)

    def test_every_key_used_by_the_scripts_exists(self):
        en, _ = catalogs()
        used = set()
        for f in js_files():
            src = f.read_text(encoding="utf-8")
            used |= set(re.findall(r"\bt\(\"([\w.]+)\"", src))
            used |= set(re.findall(r"(?:title|desc): \"([\w.]+)\"", src))
            used |= set(re.findall(r"(?:segmented|radios)\(\"[\w-]+\", \"([\w.]+)\"", src))
            used |= {k for pair in re.findall(r"empty\(\"([\w.]+)\", \"([\w.]+)\"", src) for k in pair}
            used |= set(re.findall(r"tableAlt\(\"([\w.]+)\"", src))
            used |= {k + ".other" for k in re.findall(r"\btn\(\"([\w.]+)\"", src)}
            used |= set(re.findall(r"\[\"((?:dt\.[lp]\d))\"", src)) | {k for lst in re.findall(r"\[((?:\"dt\.[lp]\d\",? ?)+)\]", src) for k in re.findall(r"dt\.[lp]\d", lst)}
        used -= {"key", "key.other"}  # the documentation comment in i18n.js
        self.assertEqual(sorted(k for k in used if k not in en), [])
        self.assertGreater(len(used), 120)

    def test_the_server_vocabularies_are_all_translated(self):
        en, he = catalogs()
        schema = idx.SCHEMA + idx.SCHEMA_V2 + idx.SCHEMA_V3 + idx.SCHEMA_V4 + idx.SCHEMA_V5 + idx.SCHEMA_V6
        states = lambda table: set(re.findall(r"'([A-Z_]+)'", re.search(r"CREATE TABLE " + table + r" \(.*?state[^\n]*?IN \(([^)]*)\)", schema, re.S).group(1)))  # noqa: E731
        reasons = set(re.findall(r'add\("([A-Z_]+)"', (ROOT / "src/gmail_intelligence/cleanup_candidates.py").read_text())) | set(cc.HARD_LABELS) | {"MIXED_THREAD", "INDEX_PARTIAL", "USER_PROTECTED"}
        explain = set()
        for node in ast.walk(ast.parse((ROOT / "src/gmail_intelligence/analytics.py").read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "_envelope" and len(node.args) == 4 and isinstance(node.args[3], ast.List):
                explain |= {e.value for e in node.args[3].elts if isinstance(e, ast.Constant)}
        want = {"type": set(classify.TYPES) | {analytics.UNCLASSIFIED}, "confidence": set(classify.CONFIDENCE), "basis": {"OBSERVED", "INFERRED"},
                "health": {"OK", "EMPTY", "PARTIAL", "STALE", "CLASSIFICATION_STALE", "UNCLASSIFIED"}, "state": {"complete", "partial", "empty"},
                "plan": states("cleanup_plan") | states("label_plan"), "exec": states("cleanup_execution"), "item": states("cleanup_exec_item"), "event": set(cleanup_audit.EVENTS),
                "hyg": set(label_hygiene.CODE_ORDER), "outcome": {cc.ELIGIBLE, cc.REVIEW, cc.EXCLUDED}, "reason": reasons, "explain": explain | {"BASIS_OBSERVED", "BASIS_INFERRED", "BASIS_MIXED"}}
        for prefix, values in want.items():
            self.assertTrue(values, prefix)
            for v in values:
                self.assertIn(f"{prefix}.{v}", en, f"{prefix}.{v}")
                self.assertIn(f"{prefix}.{v}", he, f"{prefix}.{v}")

    def test_hebrew_text_is_hebrew_where_it_should_be(self):
        _, he = catalogs()
        for key, text in he.items():
            if key.startswith(("nav.", "kpi.", "set.", "ov.", "tr.", "sn.", "cl.", "ch.", "og.", "dt.")) and not key.endswith((".short",)):
                self.assertTrue(re.search(r"[\u0590-\u05ff]", text), key)


class SecurityTests(unittest.TestCase):
    def test_no_script_can_turn_text_into_markup_or_code(self):
        banned = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "srcdoc", "javascript:", "setTimeout(\"", "setInterval(\"", "createContextualFragment", "DOMParser", ".insertAdjacent"]
        for f in js_files():
            src = f.read_text(encoding="utf-8")
            for word in banned:
                self.assertNotIn(word, src, f"{f.name}: {word}")
            self.assertIsNone(re.search(r"setAttribute\(\s*[\"']on", src), f.name)
            self.assertIsNone(re.search(r"setAttribute\(\s*[\"']style", src), f.name)
            self.assertIsNone(re.search(r"\.(href|src|action)\s*=", src), f.name)

    def test_the_html_helper_only_creates_text_nodes(self):
        util = read("js/util.js")
        self.assertIn("createTextNode", util)
        self.assertIn("textContent", read("js/main.js") + util + read("js/views.js") + read("js/components.js"))
        self.assertIn('h("bdi"', util)

    def test_mailbox_text_goes_through_untrusted_isolation(self):
        views = read("js/views.js")
        for needle in ("untrusted(i.display)", "untrusted(d.domain)", "untrusted(n)", "untrusted(l)"):
            self.assertIn(needle, views)

    def test_no_external_resources_anywhere(self):
        for f in sorted(STATIC.rglob("*")):
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8")
            for url in re.findall(r"https?://[^\s\"'`)<>]+", text):
                self.assertEqual(url, "http://www.w3.org/2000/svg", f"{f.name}: {url}")
            self.assertNotIn("@import", text, f.name)
            self.assertNotIn("@font-face", text, f.name)
            self.assertIsNone(re.search(r"url\(\s*[\"']?(?!#|data:)", text), f.name)
            self.assertIsNone(re.search(r"\b(import|fetch)\s*\(\s*[\"']https?:", text), f.name)

    def test_the_page_has_no_inline_code_or_styles(self):
        html = read("index.html")
        for tag in re.findall(r"<script\b[^>]*>", html):
            self.assertIn("src=", tag)
        self.assertEqual([c for c in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S) if c.strip()], [])
        self.assertNotIn("<style", html)
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))
        self.assertIn('<meta name="referrer" content="no-referrer">', html)
        self.assertIn('rel="icon" href="data:,"', html)

    def test_network_calls_are_confined_to_the_two_same_origin_loaders(self):
        callers = {f.name for f in js_files() if re.search(r"\bfetch\(", f.read_text(encoding="utf-8"))}
        self.assertEqual(callers, {"api.js", "i18n.js"})
        for f in js_files():
            src = f.read_text(encoding="utf-8")
            for word in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "navigator.serviceWorker", "importScripts"):
                self.assertNotIn(word, src, f"{f.name}: {word}")
        api = read("js/api.js")
        self.assertIn("/api/v1/", api)
        self.assertIn('credentials: "omit"', api)
        self.assertIn('referrerPolicy: "no-referrer"', api)
        self.assertIn("Authorization", api)
        self.assertIn("/i18n/", read("js/i18n.js"))

    def test_the_token_is_never_stored(self):
        for f in js_files():
            src = f.read_text(encoding="utf-8")
            if f.name != "main.js" and f.name != "boot.js":
                self.assertNotIn("localStorage", src, f.name)
            for word in ("sessionStorage", "document.cookie", "indexedDB", "caches."):
                self.assertNotIn(word, src, f"{f.name}: {word}")
        api = read("js/api.js")
        self.assertIn("history.replaceState", api)
        self.assertIsNone(re.search(r"(localStorage|console\.).*token", api, re.I))
        keys = set(re.findall(r"store\.set\(\"([\w.]+)\"", read("js/main.js"))) | set(re.findall(r"read\(\"([\w.]+)\"", read("js/boot.js")))
        self.assertEqual(keys, {"gi.lang", "gi.theme"})  # the only things ever persisted: language and appearance
        code_only = "\n".join(line.split("//")[0] for line in (read("js/main.js") + read("js/boot.js")).splitlines())
        self.assertNotIn("account", code_only.lower())

    def test_the_token_pattern_matches_what_the_server_issues(self):
        import secrets
        pattern = re.search(r"\[A-Za-z0-9_-\]\{(\d+),(\d+)\}", read("js/api.js"))
        self.assertTrue(pattern)
        token = secrets.token_urlsafe(32)
        self.assertTrue(int(pattern.group(1)) <= len(token) <= int(pattern.group(2)))

    def test_every_static_file_is_served_and_every_reference_resolves(self):
        served = ds.load_static()
        for path in ("/index.html", "/css/app.css", "/js/boot.js", "/js/main.js", "/i18n/en.json", "/i18n/he.json"):
            self.assertIn(path, served)
        html = read("index.html")
        for ref in re.findall(r"(?:src|href)=\"(/[^\"]+)\"", html):
            self.assertIn(ref, served, ref)
        for f in js_files():
            for imp in re.findall(r"from \"(\./[\w./-]+)\"", f.read_text(encoding="utf-8")):
                self.assertTrue((f.parent / imp).is_file(), f"{f.name}: {imp}")
        self.assertEqual({p for p in served if p.endswith(".js")}, {"/js/" + f.name for f in js_files()})


def hex_of(css, selector):
    body = re.search(re.escape(selector) + r"\s*\{(.*?)\n?\}", css, re.S).group(1)
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})", body))


def luminance(h):
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class DesignTests(unittest.TestCase):
    css = read("css/app.css")

    def themes(self):
        light = hex_of(self.css, ":root")
        dark = hex_of(self.css, ':root[data-theme="dark"]')
        system = hex_of(self.css, ':root[data-theme="system"]')
        return {"light": light, "dark": dark, "system-dark": system}

    def test_the_system_dark_theme_is_identical_to_the_manual_dark_theme(self):
        themes = self.themes()
        self.assertEqual(themes["dark"], themes["system-dark"])
        self.assertIn("@media (prefers-color-scheme: dark)", self.css)

    def test_the_suggested_brand_tokens_are_kept(self):
        t = self.themes()
        for key, value in (("bg", "#F5F6F8"), ("surface", "#FFFFFF"), ("ink", "#14181F"), ("ink-2", "#5A6472"), ("accent", "#1F63E0")):
            self.assertEqual(t["light"][key].upper(), value, key)
        for key, value in (("bg", "#0D1015"), ("surface", "#151A21"), ("raised", "#1C222B"), ("ink", "#E6E9EE"), ("accent", "#6E9BFF")):
            self.assertEqual(t["dark"][key].upper(), value, key)

    def test_text_contrast_meets_wcag_aa_in_both_themes(self):
        text_pairs = [("ink", "bg"), ("ink", "surface"), ("ink", "raised"), ("ink", "sunken"), ("ink-2", "bg"), ("ink-2", "surface"), ("ink-2", "raised"), ("ink-2", "sunken"), ("accent", "surface"),
                      ("accent", "bg"), ("on-accent", "accent"), ("accent", "accent-soft"), ("accent", "sunken"), ("ok", "ok-soft"), ("warn", "warn-soft"), ("err", "err-soft"), ("ink", "ok-soft"),
                      ("ink", "warn-soft"), ("ink", "err-soft"), ("ok", "surface"), ("warn", "surface"), ("err", "surface")]
        for name, tokens in self.themes().items():
            for fg, bg in text_pairs:
                self.assertGreaterEqual(ratio(tokens[fg], tokens[bg]), 4.5, f"{name}: {fg} on {bg}")

    def test_chart_colours_are_distinguishable_from_their_surface(self):
        for name, tokens in self.themes().items():
            colours = {k: v for k, v in tokens.items() if k.startswith("c-")}
            self.assertEqual(len(colours), 10)
            for key, value in colours.items():
                self.assertGreaterEqual(ratio(value, tokens["surface"]), 3.0, f"{name}: {key}")
            self.assertEqual(len({v for k, v in colours.items() if k not in ("c-UNKNOWN", "c-UNCLASSIFIED")}), 8)  # eight distinct hues; direct labels and tables carry the meaning too

    def test_css_is_direction_agnostic(self):
        physical = re.compile(r"(margin|padding|border)-(left|right)\b|\b(left|right)\s*:|text-align\s*:\s*(left|right)|float\s*:|translateX\(-")
        for n, line in enumerate(self.css.splitlines(), 1):
            if physical.search(line):
                self.assertIn(".axis", line, f"physical property outside the LTR time axis (line {n}): {line.strip()}")
        self.assertIn("margin-inline", self.css)
        self.assertIn("inset-inline-start", self.css)
        self.assertIn("text-align: start", self.css)

    def test_motion_is_short_composited_and_optional(self):
        self.assertNotRegex(self.css, r"transition\s*:\s*all")
        self.assertRegex(self.css, r"--t-fast:\s*120ms")
        self.assertRegex(self.css, r"--t:\s*180ms")
        for ms in re.findall(r"(\d+)ms", self.css):
            self.assertLessEqual(int(ms), 200)
        self.assertIn("prefers-reduced-motion: reduce", self.css)
        self.assertIsNone(re.search(r"transition[^;]*\b(width|height|margin|padding|top|left|right|bottom)\b", self.css))
        self.assertIsNone(re.search(r"@keyframes[^{]*\{[^}]*\b(width|height|margin|top|left)\b", self.css))

    def test_touch_targets_and_safe_areas(self):
        self.assertRegex(self.css, r"@media \(pointer: coarse\)[^}]*min-block-size: 44px")
        self.assertIn("env(safe-area-inset-bottom)", self.css)
        self.assertIn("viewport-fit=cover", read("index.html"))
        self.assertIn("100dvh", self.css)
        self.assertIn("@media (hover: hover) and (pointer: fine)", self.css)
        for block in re.findall(r":hover[^{]*\{", self.css):
            pass
        outside = re.sub(r"@media \(hover: hover\) and \(pointer: fine\) \{.*?\n\}", "", self.css, flags=re.S)
        self.assertNotIn(":hover", outside)  # no hover-only affordance leaks onto touch devices

    def test_focus_is_visible_and_no_remote_fonts(self):
        self.assertIn(":focus-visible", self.css)
        for m in re.finditer(r"([^{}]*)\{[^{}]*outline\s*:\s*(none|0)\b", self.css):
            self.assertEqual(m.group(1).strip(), "main", "outline may only be removed from the programmatically focused <main>")
        self.assertIn("-apple-system", self.css)
        self.assertNotIn("@font-face", self.css)

    def test_one_stylesheet_serves_both_themes_without_inline_overrides(self):
        self.assertIn('[data-theme="dark"]', self.css)
        self.assertIn("forced-colors: active", self.css)
        radii = set(re.findall(r"--r-[\w-]+:\s*(\d+)px", self.css))
        self.assertGreaterEqual(len(radii), 3)  # graded corner radii, not one value for everything

    def test_the_shell_prepares_language_direction_and_theme_before_paint(self):
        boot = read("js/boot.js")
        for needle in ("root.lang", "root.dir", 'setAttribute("data-theme"', 'gi.lang', 'gi.theme', "he"):
            self.assertIn(needle, boot)
        html = read("index.html")
        self.assertLess(html.index("/js/boot.js"), html.index('type="module"'))
        self.assertNotRegex(html, r"boot\.js\"\s+(defer|async|type)")
        main = read("js/main.js")
        for needle in ("matchMedia(\"(prefers-color-scheme: dark)\")", "theme-color", "hashchange", "aria-current", "Escape"):
            self.assertIn(needle, main)

    def test_semantic_structure(self):
        main, views = read("js/main.js"), read("js/views.js") + read("js/components.js") + read("js/charts.js")
        for needle in ('h("nav"', 'h("main"', 'h("header"', 'h("h1"', 'h("h2"', "aria-label", "aria-live", "radiogroup", "role", "tabindex"):
            self.assertIn(needle, main + views)
        self.assertIn('class="skip"', read("index.html"))
        self.assertIn("View as table".split()[0], json.loads(read("i18n/en.json"))["chart.table"])  # every chart has a table alternative
        self.assertGreaterEqual(views.count("tableAlt("), 4)

    def test_no_write_actions_exist_in_the_interface(self):
        for f in js_files():
            src = f.read_text(encoding="utf-8")
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertNotIn(f"\"{method}\"", src, f.name)
            self.assertNotIn("<form", src)
            self.assertNotIn('"submit"', src)
        self.assertNotIn("<form", read("index.html"))
        self.assertIn('method: "GET"', read("js/api.js"))
        en, _ = catalogs()
        for key, text in en.items():
            self.assertNotRegex(text, r"(?i)\b(approve now|execute|confirm and|delete|create a label now)\b", key) if not key.startswith(("event.", "reason.", "hyg.", "item.", "exec.", "plan.", "ch.", "og.", "cl.", "explain.", "dt.", "set.")) else None


@unittest.skipUnless(shutil.which("node"), "node is not installed; the JavaScript unit checks are skipped")
class NodeBehaviourTests(unittest.TestCase):
    """Runs the real i18n and util modules under Node with a stub fetch that reads the catalogs from disk (no network)."""

    def run_node(self, body):
        script = f"""
import fs from "node:fs";
globalThis.fetch = async (url) => {{ const p = {json.dumps(str(STATIC))} + url.replace(/\\?.*$/, ""); return {{ ok: fs.existsSync(p), json: async () => JSON.parse(fs.readFileSync(p, "utf8")) }}; }};
const i18n = await import({json.dumps((STATIC / "js" / "i18n.js").as_uri())});
const util = await import({json.dumps((STATIC / "js" / "util.js").as_uri())});
{body}
"""
        out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_hebrew_plural_forms(self):
        r = self.run_node('await i18n.load("he"); console.log(JSON.stringify([1,2,3,11,0].map((n) => i18n.tn("chart.messages", n))));')
        self.assertEqual(r, ["הודעה אחת", "2 הודעות", "3 הודעות", "11 הודעות", "0 הודעות"])
        r = self.run_node('await i18n.load("he"); console.log(JSON.stringify([1,2,5].map((n) => i18n.tn("ov.lede", n, {from: "a", to: "b", classified: "9%"}))));')
        self.assertIn("הודעה אחת", r[0])
        self.assertIn("שתי הודעות", r[1])
        self.assertIn("5 הודעות", r[2])

    def test_english_plurals_and_fallbacks(self):
        r = self.run_node('await i18n.load("en"); console.log(JSON.stringify([i18n.tn("chart.messages", 1), i18n.tn("chart.messages", 1234), i18n.t("no.such.key"), i18n.code("type", "NOPE"), i18n.code("type", "NEWSLETTER")]));')
        self.assertEqual(r, ["1 message", "1,234 messages", "no.such.key", "NOPE", "Newsletters"])

    def test_numbers_and_dates_use_latin_digits_in_both_languages(self):
        for lang in ("en", "he"):
            r = self.run_node(f'await i18n.load("{lang}"); console.log(JSON.stringify([i18n.int(1234567), i18n.pct(33.3), i18n.day("2026-03-05"), i18n.month("2026-03"), i18n.bytes(42000000)]));')
            for text in r:
                self.assertFalse(re.search(r"[\u0660-\u0669\u06f0-\u06f9]", text), text)
            self.assertIn("1,234,567", r[0])
            self.assertIn("2026", r[2])
            self.assertIn("42", r[4])

    def test_clean_removes_control_and_bidi_characters(self):
        text = "a\u202eb\u2066c\u200fd\x07e\n  f" + "x" * 200
        r = self.run_node(f'console.log(JSON.stringify([util.clean({json.dumps(text)}), util.clean({json.dumps(text)}).length, util.clean(null), util.clean("  ")]));')
        self.assertEqual(r[0][:12], "a b c d e fx")
        self.assertEqual(r[1], 120)
        self.assertEqual(r[2:], ["", ""])
        for ch in ("\u202e", "\u2066", "\u200f", "\x07", "\n"):
            self.assertNotIn(ch, r[0])

    def test_every_javascript_file_parses_as_a_module(self):
        for f in js_files():
            if f.name == "boot.js":
                continue
            out = subprocess.run(["node", "--input-type=module", "--check"], input=f.read_text(encoding="utf-8"), capture_output=True, text=True, timeout=30)
            self.assertEqual(out.returncode, 0, f"{f.name}: {out.stderr}")
        out = subprocess.run(["node", "--check", str(STATIC / "js" / "boot.js")], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
