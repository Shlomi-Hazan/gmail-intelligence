/* Runs before first paint (classic script): applies the saved language, direction and theme so the page never flashes the wrong ones. No network, no storage of anything sensitive. */
(function () {
  var root = document.documentElement;
  function read(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } }
  var lang = read("gi.lang");
  if (lang !== "en" && lang !== "he") { lang = String(navigator.language || "en").toLowerCase().indexOf("he") === 0 ? "he" : "en"; }
  var theme = read("gi.theme");
  if (theme !== "light" && theme !== "dark" && theme !== "system") { theme = "system"; }
  root.lang = lang;
  root.dir = lang === "he" ? "rtl" : "ltr";
  root.setAttribute("data-theme", theme);
})();
