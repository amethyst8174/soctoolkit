/* Per-utility light / dark theme for the SOC Toolkit.
 * In-memory only: no cookies, no localStorage, nothing stored — a reload returns to the
 * default (dark), which keeps the toolkit's "nothing is stored" guarantee intact.
 * Applying a theme sets data-theme on THIS document's root, so when a utility runs inside
 * the SOC Toolkit shell it themes only that utility's frame, never the shell or other tools.
 * window.SOCTheme lets the shell proxy the toggle for the framed tool.
 */
(function () {
  "use strict";
  var current = "dark";

  function apply(t) {
    current = (t === "light") ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", current);
    var pressed = current === "light";
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(pressed));
      b.setAttribute("aria-label", pressed ? "Switch to dark theme" : "Switch to light theme");
    });
  }
  function toggle() { apply(current === "light" ? "dark" : "light"); return current; }

  window.SOCTheme = { get: function () { return current; }, set: apply, toggle: toggle };

  function wire() {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", function () { toggle(); });
    });
    apply(current);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();
})();
