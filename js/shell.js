// SOC Toolkit shell: home page, utilities panel and the frame each tool opens in.
// Privacy rules for this file: no browser storage, cookies or network calls. The address
// only carries the tool name (#ioc, #header-lens, ...), never any analyst data.
(function () {
  "use strict";

  var TOOLS = window.SOC_TOOLS || [];
  var SITE = "https://amethyst8174.github.io/soctoolkit/";
  var $ = function (id) { return document.getElementById(id); };
  var body = document.body, side = $("side"), tog = $("tog"), hint = $("hint");
  var home = $("home"), toolview = $("toolview"), frames = $("frames");
  var phone = window.matchMedia("(max-width: 760px)");
  var frameFor = {}, hintShown = false, hintTimer = null;

  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k];
      if (v === null || v === undefined) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "color") el.style.setProperty("--c", v);
      else el.setAttribute(k, v);
    }
    (kids || []).forEach(function (c) { if (c) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return el;
  }

  // Brand links from config; hide any left empty.
  var cfg = window.HL_CONFIG || {};
  document.querySelectorAll("[data-link]").forEach(function (a) {
    var url = cfg[a.getAttribute("data-link")];
    if (url && /^https:\/\//.test(url)) a.href = url;
    else if (a.closest(".links")) a.classList.add("hidden");
    else { a.removeAttribute("href"); a.removeAttribute("target"); }
  });
  document.querySelectorAll(".yr").forEach(function (y) { y.textContent = String(new Date().getFullYear()); });

  // Left panel and home cards, both built from js/tools.js.
  var nav = $("nav"), cards = $("cards");
  TOOLS.forEach(function (t) {
    nav.appendChild(h("a", { href: "#" + t.id, "data-id": t.id, title: t.name }, [
      h("img", { src: t.icon, alt: "", width: "36", height: "36" }),
      h("span", { class: "nl" }, [h("strong", { text: t.name }), h("small", { text: t.tag })])
    ]));
    cards.appendChild(h("article", { class: "ucard", color: t.color }, [
      h("img", { src: t.icon, alt: "", width: "72", height: "72" }),
      h("h3", null, [h("a", { class: "nm", href: "#" + t.id, text: t.name })]),
      h("p", { text: t.desc }),
      h("a", { class: "go", href: "#" + t.id, "aria-label": "Open " + t.name }, ["Open " + t.name + " ", h("span", { "aria-hidden": "true", text: "→" })])
    ]));
  });
  nav.appendChild(h("div", { class: "soon", title: "More utilities are on the way" }, [
    h("span", { class: "ic", "aria-hidden": "true", text: "+" }),
    h("span", { class: "nl" }, [h("strong", { text: "More coming soon" }), h("small", { text: "New tools land here" })])
  ]));

  // Share buttons follow the open tool.
  function setShare(tool) {
    var url = SITE + (tool ? "#" + tool.id : ""), u = encodeURIComponent(url);
    var text = encodeURIComponent(tool ? tool.share : "SOC Toolkit: free, private SOC utilities that run entirely in your browser");
    var links = [
      ["share-li", "https://www.linkedin.com/sharing/share-offsite/?url=" + u, "Share on LinkedIn", "in"],
      ["share-x", "https://x.com/intent/post?url=" + u + "&text=" + text, "Share on X (Twitter)", "X"],
      ["share-fb", "https://www.facebook.com/sharer/sharer.php?u=" + u, "Share on Facebook", "f"]
    ];
    document.querySelectorAll("[data-share]").forEach(function (n) {
      n.querySelectorAll(".share-btn").forEach(function (b) { b.remove(); });
      links.forEach(function (l) {
        n.appendChild(h("a", { class: "share-btn " + l[0], href: l[1], target: "_blank", rel: "noopener noreferrer", title: l[2], "aria-label": l[2] }, [h("span", { "aria-hidden": "true", text: l[3] })]));
      });
    });
  }

  // Panel open/closed.
  function setOpen(open) {
    body.classList.toggle("collapsed", !open);
    document.querySelectorAll("[aria-controls=side]").forEach(function (b) { b.setAttribute("aria-expanded", String(open)); });
    if (open) hideHint();
  }
  function isOpen() { return !body.classList.contains("collapsed"); }
  tog.addEventListener("click", function () { setOpen(!isOpen()); });
  document.querySelectorAll("[data-toggle]").forEach(function (b) { b.addEventListener("click", function () { setOpen(!isOpen()); }); });
  $("scrim").addEventListener("click", function () { setOpen(false); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && phone.matches && isOpen()) setOpen(false); });

  function showHint() {
    if (hintShown || phone.matches) return;
    hintShown = true;
    hint.classList.add("show");
    hintTimer = setTimeout(hideHint, 4500);
  }
  function hideHint() { clearTimeout(hintTimer); hint.classList.remove("show"); }

  // Per-tool light/dark: the toolbar toggle proxies to the active tool's own theme logic
  // (window.SOCTheme inside the frame), so it changes only that tool's frame — never the
  // shell, another tool, or the external Header-Lens site.
  var toolTheme = $("tool-theme");
  function themeableTool(tool) { return tool && !/^\.\.\//.test(tool.url) && !/header-lens/.test(tool.url); }
  function paintToggle(btn, state) {
    btn.setAttribute("data-theme-state", state);
    btn.setAttribute("aria-pressed", String(state === "dark"));
    btn.setAttribute("aria-label", state === "light" ? "Switch tool to dark theme" : "Switch tool to light theme");
    var lab = btn.querySelector(".tt-label"); if (lab) lab.textContent = state === "light" ? "Light" : "Dark";
  }
  function syncThemeToggle() {
    if (!toolTheme) return;
    var id = location.hash.slice(1), tool = null;
    TOOLS.forEach(function (t) { if (t.id === id) tool = t; });
    if (!themeableTool(tool)) { toolTheme.hidden = true; return; }
    toolTheme.hidden = false;
    var f = frameFor[id], th = "light";
    try { if (f && f.contentWindow && f.contentWindow.SOCTheme) th = f.contentWindow.SOCTheme.get(); } catch (e) { th = "light"; }
    paintToggle(toolTheme, th);
  }
  if (toolTheme) toolTheme.addEventListener("click", function () {
    var id = location.hash.slice(1), f = frameFor[id];
    try { if (f && f.contentWindow && f.contentWindow.SOCTheme) f.contentWindow.SOCTheme.toggle(); } catch (e) { }
    syncThemeToggle();
  });

  // Clicking a utility link that is already open does not fire hashchange; re-open it fresh.
  document.addEventListener("click", function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href^="#"]') : null;
    if (!a) return;
    var id = a.getAttribute("href").slice(1);
    if (id && location.hash === "#" + id && TOOLS.some(function (t) { return t.id === id; })) route();
  });

  // Routing: #<tool id> opens that tool, anything else shows the home page.
  function route() {
    var id = location.hash.slice(1), tool = null;
    TOOLS.forEach(function (t) { if (t.id === id) tool = t; });
    nav.querySelectorAll("a[data-id]").forEach(function (a) {
      var on = !!tool && a.getAttribute("data-id") === tool.id;
      a.classList.toggle("on", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    setShare(tool);
    if (!tool) {
      body.classList.add("is-home");
      toolview.classList.add("hidden"); home.classList.remove("hidden");
      if (toolTheme) toolTheme.hidden = true;
      document.title = "SOC Toolkit · Cyber Insight Signals";
      setOpen(!phone.matches);
      $("main").scrollTo(0, 0);
      return;
    }
    body.classList.remove("is-home");
    home.classList.add("hidden"); toolview.classList.remove("hidden");
    $("crumb-img").src = tool.icon;
    $("crumb-name").textContent = tool.name;
    document.title = tool.name + " · SOC Toolkit";
    // Open the tool fresh every time, so each visit starts at the input page with no old
    // results. Nothing is saved: the previous frame is discarded and a new one loaded.
    if (frameFor[tool.id]) { frameFor[tool.id].remove(); }
    frameFor[tool.id] = h("iframe", { class: "frame", src: tool.url, title: tool.name });
    frames.appendChild(frameFor[tool.id]);
    frameFor[tool.id].addEventListener("load", syncThemeToggle);
    for (var k in frameFor) frameFor[k].classList.toggle("hidden", k !== tool.id);
    setOpen(false);
    showHint();
    syncThemeToggle();
  }
  window.addEventListener("hashchange", route);
  route();
})();
