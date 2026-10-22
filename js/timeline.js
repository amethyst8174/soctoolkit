// Timeline Merger page controller for the SOC Toolkit.
// Stages log sources, calls the LOGNORM engine to normalize and merge them, then renders a
// time-sorted timeline with an events-over-time histogram, interactive filtering (time window,
// event type, keyword), grouping / pivoting, and local CSV / JSON export.
//
// Privacy rules for this file: no browser storage, cookies or network calls, and no dynamic
// markup injection. The DOM and the chart are built with createElement / createElementNS /
// textContent only; styling lives in css/style.css and SVG presentation attributes (no inline
// style attributes, no library, no eval). Exports are in-memory Blobs saved to the device.
(function () {
  "use strict";

  var L = window.LOGNORM;
  var $ = function (id) { return document.getElementById(id); };
  var SVGNS = "http://www.w3.org/2000/svg";
  var sources = [];      // [{ name, text }]
  var pasteCount = 0;

  // Results state: one parsed dataset, one filter/group object, three renderings of it.
  var VIEW = null;       // { res, disp }
  var F = null;          // filter+group state

  // ---- DOM helpers (text nodes only, no markup injection) -----------------
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    applyAttrs(el, attrs);
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) {
      if (c != null) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }
  function s(tag, attrs, kids) { // SVG element
    var el = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) { if (attrs.hasOwnProperty(k) && attrs[k] != null) el.setAttribute(k, attrs[k]); }
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) { if (c != null) el.appendChild(c); });
    return el;
  }
  function applyAttrs(el, attrs) {
    if (!attrs) return;
    for (var k in attrs) {
      if (!attrs.hasOwnProperty(k)) continue;
      var v = attrs[k]; if (v == null) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "color") el.style.setProperty("--c", v);     // CSSOM: allowed under style-src 'self'
      else if (k === "on") for (var ev in attrs[k]) el.addEventListener(ev, attrs[k][ev]);
      else el.setAttribute(k, v);
    }
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---- timezone options ---------------------------------------------------
  var TZ = [
    ["Browser local", "local"], ["UTC", 0],
    ["UTC+14:00", 840], ["UTC+13:00", 780], ["UTC+12:00", 720], ["UTC+11:00", 660],
    ["UTC+10:00", 600], ["UTC+09:30", 570], ["UTC+09:00", 540], ["UTC+08:00", 480],
    ["UTC+07:00", 420], ["UTC+06:30", 390], ["UTC+06:00", 360], ["UTC+05:45", 345],
    ["UTC+05:30", 330], ["UTC+05:00", 300], ["UTC+04:30", 270], ["UTC+04:00", 240],
    ["UTC+03:30", 210], ["UTC+03:00", 180], ["UTC+02:00", 120], ["UTC+01:00", 60],
    ["UTC-01:00", -60], ["UTC-02:00", -120], ["UTC-03:00", -180], ["UTC-03:30", -210],
    ["UTC-04:00", -240], ["UTC-05:00", -300], ["UTC-06:00", -360], ["UTC-07:00", -420],
    ["UTC-08:00", -480], ["UTC-09:00", -540], ["UTC-10:00", -600], ["UTC-11:00", -660],
    ["UTC-12:00", -720]
  ];
  function fillTz(sel, def) { TZ.forEach(function (o) { sel.appendChild(h("option", { value: String(o[1]), text: o[0] })); }); sel.value = String(def); }
  function tzValue(sel) { var v = sel.value; return v === "local" ? "local" : parseInt(v, 10); }

  // ---- time formatting ----------------------------------------------------
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function offLabel(min) { if (!min) return "UTC"; var g = min < 0 ? "-" : "+", a = Math.abs(min); return "UTC" + g + pad(Math.floor(a / 60)) + ":" + pad(a % 60); }
  function parts(epoch, disp) {
    var d;
    if (disp === "local") { d = new Date(epoch); return { Y: d.getFullYear(), Mo: d.getMonth() + 1, D: d.getDate(), h: d.getHours(), mi: d.getMinutes(), se: d.getSeconds() }; }
    d = new Date(epoch + disp * 60000); return { Y: d.getUTCFullYear(), Mo: d.getUTCMonth() + 1, D: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), se: d.getUTCSeconds() };
  }
  function fmtTime(epoch, disp) { var p = parts(epoch, disp); return p.Y + "-" + pad(p.Mo) + "-" + pad(p.D) + " " + pad(p.h) + ":" + pad(p.mi) + ":" + pad(p.se); }
  function fmtShort(epoch, disp) { var p = parts(epoch, disp); return pad(p.Mo) + "-" + pad(p.D) + " " + pad(p.h) + ":" + pad(p.mi); }
  function toInputVal(epoch, disp) { var p = parts(epoch, disp); return p.Y + "-" + pad(p.Mo) + "-" + pad(p.D) + "T" + pad(p.h) + ":" + pad(p.mi); }
  function fromInputVal(str, disp) {
    var m = String(str).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/); if (!m) return null;
    if (disp === "local") return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]).getTime();
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) - disp * 60000;
  }
  function dispLabel(disp) { return disp === "local" ? offLabel(-new Date().getTimezoneOffset()) + " (local)" : offLabel(disp); }

  // ---- severity -----------------------------------------------------------
  var SEV = { high: ["p-threat", "High"], med: ["p-warn", "Med"], low: ["p-geo", "Low"], info: ["p-unknown", "Info"] };
  var SEV_ORDER = ["high", "med", "low", "info", "none"]; // histogram stack, bottom to top

  // ---- field-alias resolver (for grouping, pivoting and export) -----------
  function isIp(v) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(v); }
  function fget(fields, keys) {
    if (!fields) return "";
    var low = {}; for (var k in fields) if (fields.hasOwnProperty(k)) low[k.toLowerCase()] = fields[k];
    for (var i = 0; i < keys.length; i++) { var v = low[keys[i]]; if (v != null && String(v) !== "") return String(v); }
    return "";
  }
  function alias(e, which) {
    var f = e.fields;
    if (which === "user") return fget(f, ["suser", "usrname", "user", "username", "account", "uid", "duser"]);
    if (which === "process") return e.app || fget(f, ["proc", "process", "sproc", "image", "exe"]);
    if (which === "srcip") { var v = fget(f, ["src", "src_ip", "source_ip", "sourceip", "srcip"]); if (!v) { var sh = fget(f, ["shost"]); if (isIp(sh)) v = sh; } return v; }
    if (which === "dstip") { var d = fget(f, ["dst", "dst_ip", "dest_ip", "destinationip", "dstip", "daddr"]); if (!d) { var dh = fget(f, ["dhost"]); if (isIp(dh)) d = dh; } return d; }
    return "";
  }
  var GROUP_LABEL = { none: "", severity: "Severity", format: "Format", source: "Source", host: "Host", process: "Process", user: "User", srcip: "Source IP", dstip: "Dest IP" };
  function groupKeyOf(e, by) {
    switch (by) {
      case "severity": return SEV[e.sev] ? SEV[e.sev][1] : "None";
      case "format": return e.format;
      case "source": return e.source;
      case "host": return e.host || "(unset)";
      case "process": return alias(e, "process") || "(unset)";
      case "user": return alias(e, "user") || "(unset)";
      case "srcip": return alias(e, "srcip") || "(unset)";
      case "dstip": return alias(e, "dstip") || "(unset)";
      default: return "";
    }
  }

  // ---- keyword matcher (supports field:value pivots) ----------------------
  var KW = {
    message: function (e) { return e.message; }, msg: function (e) { return e.message; },
    host: function (e) { return e.host; }, source: function (e) { return e.source; },
    severity: function (e) { return SEV[e.sev] ? SEV[e.sev][1] : ""; }, sev: function (e) { return SEV[e.sev] ? SEV[e.sev][1] : ""; },
    format: function (e) { return e.format; },
    user: function (e) { return alias(e, "user"); }, process: function (e) { return alias(e, "process"); }, app: function (e) { return alias(e, "process"); },
    src: function (e) { return alias(e, "srcip"); }, srcip: function (e) { return alias(e, "srcip"); },
    dst: function (e) { return alias(e, "dstip"); }, dstip: function (e) { return alias(e, "dstip"); }
  };
  function kwMatch(e, kw) {
    kw = kw.trim(); if (!kw) return true;
    var ci = kw.indexOf(":");
    if (ci > 0) {
      var field = kw.slice(0, ci).toLowerCase(), val = kw.slice(ci + 1).toLowerCase();
      if (/^\S+$/.test(field) && val !== "") {
        var getter = KW[field], hay = getter ? String(getter(e) || "") : fget(e.fields, [field]);
        if (getter || hay) return hay.toLowerCase().indexOf(val) >= 0;
      }
    }
    var all = (e.message + " " + e.host + " " + e.app + " " + e.source + " " + JSON.stringify(e.fields || {})).toLowerCase();
    return all.indexOf(kw.toLowerCase()) >= 0;
  }

  // ---- filter predicates --------------------------------------------------
  function passType(e) {
    if (e.sev !== "" && !F.sev[e.sev]) return false;
    if (!F.fmt[e.format]) return false;
    if (F.kw && !kwMatch(e, F.kw)) return false;
    return true;
  }
  function passTime(e) {
    if (F.from != null && e.epoch != null && e.epoch < F.from) return false;
    if (F.to != null && e.epoch != null && e.epoch > F.to) return false;
    return true;
  }

  // ---- sources / staging (input view) -------------------------------------
  function renderChips() {
    var box = $("src-chips"); clear(box);
    if (!sources.length) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    box.appendChild(h("span", { class: "src-l", text: sources.length + (sources.length === 1 ? " source" : " sources") + " staged:" }));
    sources.forEach(function (src, i) {
      var lines = src.text.split(/\r\n|\r|\n/).filter(function (x) { return x.trim(); }).length;
      box.appendChild(h("span", { class: "src-chip" }, [
        h("strong", { text: src.name }), h("span", { class: "src-n", text: lines + (lines === 1 ? " line" : " lines") }),
        h("button", { class: "src-x", type: "button", title: "Remove source", "aria-label": "Remove " + src.name, text: "×", on: { click: function () { sources.splice(i, 1); renderChips(); updateStatus(); } } })
      ]));
    });
  }
  function addSource(name, text) { if (!text || !text.trim()) return false; sources.push({ name: name, text: text }); renderChips(); return true; }
  function updateStatus(msg, cls) {
    var st = $("input-status"); st.className = "status" + (cls ? " " + cls : "");
    if (msg) { st.textContent = msg; return; }
    var staged = sources.length, pasted = $("text-input").value.trim() ? 1 : 0;
    st.textContent = (!staged && !pasted) ? "Waiting for logs" : (staged + pasted) + " source" + (staged + pasted === 1 ? "" : "s") + " ready — Build timeline";
  }

  // ---- view switching -----------------------------------------------------
  function showRes() { $("view-input").classList.add("hidden"); var v = $("view-res"); v.classList.remove("hidden"); document.body.classList.add("is-res"); window.scrollTo(0, 0); v.focus(); }
  function showInput() { $("view-res").classList.add("hidden"); $("view-input").classList.remove("hidden"); document.body.classList.remove("is-res"); window.scrollTo(0, 0); }

  // ---- build --------------------------------------------------------------
  function build() {
    var list = sources.slice();
    var pasted = $("text-input").value;
    if (pasted.trim()) list.push({ name: "Pasted " + (++pasteCount), text: pasted });
    if (!list.length) { updateStatus("Add or paste at least one log source", "warn"); return; }
    var res = L.parseSources(list, { format: $("fmt-sel").value, assumeTz: tzValue($("assume-sel")) });
    VIEW = { res: res, disp: tzValue($("display-sel")) };
    F = { from: null, to: null, kw: "", groupBy: "none", collapsed: {}, sev: { high: true, med: true, low: true, info: true }, fmt: { syslog: true, cef: true, leef: true, json: true, raw: true } };
    renderApp();
    showRes();
  }

  // ---- static results scaffold (built once per build) ---------------------
  function tile(num, label, color) { return h("div", { class: "tile" }, [h("div", { class: "num", color: color, text: String(num) }), h("div", { class: "tl-tilelab", text: label })]); }
  function chip(label, on, cb) { return h("button", { class: "tl-chip" + (on ? " on" : ""), type: "button", "aria-pressed": String(on), text: label, on: { click: cb } }); }

  function renderApp() {
    var view = $("view-res"); clear(view);
    var st = VIEW.res.stats, span = st.span ? humanSpan(st.span.to - st.span.from) : "—";

    view.appendChild(h("div", { class: "res-bar" }, [
      h("div", {}, [h("h2", { class: "res-title", text: "Merged timeline" }), h("p", { class: "status", id: "tl-count" })]),
      h("div", { class: "tools" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Export CSV", on: { click: function () { download("timeline-" + stamp() + ".csv", toCsv(), "text/csv"); } } }),
        h("button", { class: "btn btn-ghost", type: "button", text: "Export JSON", on: { click: function () { download("timeline-" + stamp() + ".json", toJson(), "application/json"); } } }),
        h("button", { class: "btn btn-primary", type: "button", text: "New input", on: { click: showInput } })
      ])
    ]));
    view.appendChild(h("div", { class: "tiles" }, [
      tile(st.timed, "Events", "var(--t-attack)"), tile(st.sources, "Sources", "var(--violet)"),
      tile(span, "Time span", "var(--magenta)"), tile(st.untimed, "No timestamp", st.untimed ? "var(--warn)" : "var(--muted)")
    ]));

    // histogram region
    view.appendChild(h("div", { class: "tl-hist-head" }, [
      h("div", { class: "tl-hleg" }, [
        legDot("High", "high"), legDot("Med", "med"), legDot("Low", "low"), legDot("Info", "info")
      ]),
      h("span", { class: "tl-hint", id: "tl-hist-note" })
    ]));
    view.appendChild(h("div", { class: "tl-hist", id: "tl-hist" }));

    // filter bar
    var sevBox = h("div", { class: "tl-chips", id: "sev-chips" });
    ["high", "med", "low", "info"].forEach(function (k) {
      sevBox.appendChild(chip(SEV[k][1], F.sev[k], function (e) { F.sev[k] = !F.sev[k]; e.currentTarget.classList.toggle("on"); e.currentTarget.setAttribute("aria-pressed", String(F.sev[k])); applyView(); }));
    });
    var fmtBox = h("div", { class: "tl-chips", id: "fmt-chips" });
    ["syslog", "cef", "leef", "json", "raw"].forEach(function (k) {
      if (!(VIEW.res.stats.byFormat[k])) return;
      fmtBox.appendChild(chip(k, F.fmt[k], function (e) { F.fmt[k] = !F.fmt[k]; e.currentTarget.classList.toggle("on"); e.currentTarget.setAttribute("aria-pressed", String(F.fmt[k])); applyView(); }));
    });

    var groupSel = h("select", { class: "field", id: "group-sel", "aria-label": "Group events by" });
    [["none", "No grouping"], ["severity", "Severity"], ["format", "Format"], ["source", "Source"], ["host", "Host"], ["process", "Process"], ["user", "User"], ["srcip", "Source IP"], ["dstip", "Dest IP"]].forEach(function (o) { groupSel.appendChild(h("option", { value: o[0], text: o[1] })); });
    groupSel.addEventListener("change", function () { F.groupBy = groupSel.value; F.collapsed = {}; applyView(); });

    var kwIn = h("input", { class: "field", id: "kw-input", type: "text", spellcheck: "false", autocomplete: "off", placeholder: "keyword, or field:value (host:fw01, src:45.155.205.233)", "aria-label": "Keyword filter" });
    var kwTimer = null;
    kwIn.addEventListener("input", function () { clearTimeout(kwTimer); kwTimer = setTimeout(function () { F.kw = kwIn.value; applyView(); }, 180); });

    var fromIn = h("input", { class: "field tl-dt", id: "from-input", type: "datetime-local", "aria-label": "From time" });
    var toIn = h("input", { class: "field tl-dt", id: "to-input", type: "datetime-local", "aria-label": "To time" });
    fromIn.addEventListener("change", function () { F.from = fromIn.value ? fromInputVal(fromIn.value, VIEW.disp) : null; applyView(); });
    toIn.addEventListener("change", function () { F.to = toIn.value ? fromInputVal(toIn.value, VIEW.disp) : null; applyView(); });

    view.appendChild(h("div", { class: "tl-filters" }, [
      h("span", { class: "tl-fgroup" }, [h("label", { for: "group-sel", text: "Group by" }), groupSel]),
      h("span", { class: "tl-fgroup tl-fchips" }, [h("span", { class: "tl-flab", text: "Type" }), sevBox, fmtBox]),
      h("span", { class: "tl-fgroup tl-fkw" }, [kwIn]),
      h("span", { class: "tl-fgroup" }, [h("label", { for: "from-input", text: "From" }), fromIn, h("label", { for: "to-input", text: "To" }), toIn]),
      h("span", { class: "tl-fgroup" }, [
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Clear filters", on: { click: clearFilters } }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Collapse all", on: { click: function () { setCollapseAll(true); } } }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Expand all", on: { click: function () { setCollapseAll(false); } } })
      ])
    ]));

    view.appendChild(h("div", { class: "tl-body", id: "tl-body" }));
    applyView();
  }
  function legDot(label, sev) { return h("span", { class: "tl-leg" }, [h("span", { class: "tl-legdot tl-b-" + sev }), label]); }

  // ---- apply filters + re-render histogram, table, count ------------------
  function computeGroups() {
    // events passing type+keyword (for histogram), and the subset also passing time (for table)
    var histEvents = VIEW.res.events.filter(passType);
    var tableTimed = histEvents.filter(passTime);
    var untimed = VIEW.res.untimedEvents.filter(passType);
    return { hist: histEvents, table: tableTimed, untimed: untimed };
  }
  function applyView() {
    var g = computeGroups();
    drawHistogram(g.hist);
    drawTable(g.table, g.untimed);
    var shown = g.table.length + g.untimed.length, total = VIEW.res.stats.total;
    var win = (F.from != null || F.to != null) ? " · window " + (F.from != null ? fmtShort(F.from, VIEW.disp) : "…") + " → " + (F.to != null ? fmtShort(F.to, VIEW.disp) : "…") : "";
    $("tl-count").textContent = "showing " + shown + " of " + total + " events · times in " + dispLabel(VIEW.disp) + win;
  }
  function clearFilters() {
    F.from = F.to = null; F.kw = "";
    ["high", "med", "low", "info"].forEach(function (k) { F.sev[k] = true; });
    ["syslog", "cef", "leef", "json", "raw"].forEach(function (k) { F.fmt[k] = true; });
    var kw = $("kw-input"); if (kw) kw.value = ""; var fi = $("from-input"); if (fi) fi.value = ""; var ti = $("to-input"); if (ti) ti.value = "";
    document.querySelectorAll("#sev-chips .tl-chip, #fmt-chips .tl-chip").forEach(function (c) { c.classList.add("on"); c.setAttribute("aria-pressed", "true"); });
    applyView();
  }
  function setCollapseAll(v) {
    if (F.groupBy === "none") return;
    F.collapsAll = v;
    // mark every current group
    var keys = {}; computeGroups().table.forEach(function (e) { keys[groupKeyOf(e, F.groupBy)] = 1; });
    F.collapsed = {}; if (v) for (var k in keys) F.collapsed[k] = true;
    drawTable(computeGroups().table, computeGroups().untimed);
  }

  // ---- histogram (inline SVG) ---------------------------------------------
  var IVS = [60e3, 5 * 60e3, 15 * 60e3, 30 * 60e3, 60 * 60e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 24 * 3600e3, 7 * 24 * 3600e3];
  function ivLabel(iv) {
    var map = {}; map[60e3] = "1 min"; map[300e3] = "5 min"; map[900e3] = "15 min"; map[1800e3] = "30 min";
    map[3600e3] = "1 hour"; map[3 * 3600e3] = "3 hours"; map[6 * 3600e3] = "6 hours"; map[12 * 3600e3] = "12 hours";
    map[24 * 3600e3] = "1 day"; map[7 * 24 * 3600e3] = "1 week"; return map[iv] || (Math.round(iv / 60000) + " min");
  }
  var HG = null;
  function makeBuckets(events) {
    var min = Infinity, max = -Infinity;
    events.forEach(function (e) { if (e.epoch < min) min = e.epoch; if (e.epoch > max) max = e.epoch; });
    if (!isFinite(min)) return null;
    var span = Math.max(max - min, 1), iv = IVS[IVS.length - 1];
    for (var i = 0; i < IVS.length; i++) { if (span / IVS[i] <= 150) { iv = IVS[i]; break; } }
    var start = Math.floor(min / iv) * iv, n = Math.floor((max - start) / iv) + 1; if (n < 1) n = 1;
    var b = []; for (var j = 0; j < n; j++) b.push({ high: 0, med: 0, low: 0, info: 0, none: 0, total: 0 });
    events.forEach(function (e) { var idx = Math.floor((e.epoch - start) / iv); if (idx < 0) idx = 0; if (idx >= n) idx = n - 1; var sv = e.sev || "none"; b[idx][sv]++; b[idx].total++; });
    return { b: b, start: start, iv: iv, n: n, max: max };
  }
  function drawHistogram(events) {
    var host = $("tl-hist"); clear(host);
    var note = $("tl-hist-note");
    var bk = makeBuckets(events);
    if (!bk) { host.appendChild(h("p", { class: "tl-note", text: "No timestamped events match the current filters." })); if (note) note.textContent = ""; return; }
    HG = bk;
    if (note) note.textContent = "each bar = " + ivLabel(bk.iv) + " · " + events.length + " event" + (events.length === 1 ? "" : "s");

    var W = 1000, H = 150, padL = 12, padR = 12, top = 10, base = 118, labY = 136;
    var plotW = W - padL - padR, slot = plotW / bk.n, bw = Math.max(1, slot - (slot > 4 ? 1 : 0));
    var maxT = 1; bk.b.forEach(function (x) { if (x.total > maxT) maxT = x.total; });
    var scale = (base - top) / maxT;

    var svg = s("svg", { viewBox: "0 0 " + W + " " + H, class: "tl-hist-svg", preserveAspectRatio: "none", role: "img", "aria-label": "Events over time, " + ivLabel(bk.iv) + " buckets" });
    svg.appendChild(s("line", { x1: padL, y1: base, x2: W - padR, y2: base, class: "tl-axis" }));

    function xOf(ep) { var t = (ep - bk.start) / (bk.n * bk.iv); t = t < 0 ? 0 : t > 1 ? 1 : t; return padL + t * plotW; }
    function epOf(x) { var t = (x - padL) / plotW; t = t < 0 ? 0 : t > 1 ? 1 : t; return bk.start + t * (bk.n * bk.iv); }

    // selection shading (behind bars)
    if (F.from != null || F.to != null) {
      var x1 = xOf(F.from != null ? F.from : bk.start), x2 = xOf(F.to != null ? F.to : bk.max);
      svg.appendChild(s("rect", { x: Math.min(x1, x2), y: top, width: Math.max(1, Math.abs(x2 - x1)), height: base - top, class: "tl-brush" }));
    }

    bk.b.forEach(function (c, i) {
      if (!c.total) return;
      var x = padL + i * slot, y = base;
      SEV_ORDER.forEach(function (sv) { var v = c[sv]; if (!v) return; var hgt = v * scale; y -= hgt; svg.appendChild(s("rect", { x: x, y: y, width: bw, height: hgt, class: "tl-b-" + sv })); });
      var col = s("rect", { x: x, y: top, width: Math.max(bw, slot), height: base - top, class: "tl-hovercol" });
      col.appendChild(s("title", {}, [document.createTextNode(fmtTime(bk.start + i * bk.iv, VIEW.disp) + "  ·  " + c.total + " event" + (c.total === 1 ? "" : "s"))]));
      svg.appendChild(col);
    });

    // x labels
    for (var t = 0; t <= 5; t++) {
      var ep = bk.start + (t / 5) * bk.n * bk.iv, lx = padL + (t / 5) * plotW;
      var tx = s("text", { x: Math.min(Math.max(lx, padL + 2), W - padR - 2), y: labY, class: "tl-xlab", "text-anchor": t === 0 ? "start" : t === 5 ? "end" : "middle" });
      tx.appendChild(document.createTextNode(fmtShort(ep, VIEW.disp))); svg.appendChild(tx);
    }

    // brush interaction
    var brush = null, x0 = 0, dragging = false, moved = false;
    function vbX(ev) { var r = svg.getBoundingClientRect(); return (ev.clientX - r.left) / r.width * W; }
    svg.addEventListener("pointerdown", function (ev) { dragging = true; moved = false; x0 = vbX(ev); try { svg.setPointerCapture(ev.pointerId); } catch (e) {} if (brush) { brush.remove(); brush = null; } });
    svg.addEventListener("pointermove", function (ev) {
      if (!dragging) return; var x = vbX(ev); if (Math.abs(x - x0) > 4) moved = true;
      if (!brush) { brush = s("rect", { y: top, height: base - top, class: "tl-brush tl-brush-live" }); svg.appendChild(brush); }
      brush.setAttribute("x", Math.min(x0, x)); brush.setAttribute("width", Math.abs(x - x0));
    });
    svg.addEventListener("pointerup", function (ev) {
      if (!dragging) return; dragging = false; var x = vbX(ev);
      if (moved) { F.from = Math.round(epOf(Math.min(x0, x))); F.to = Math.round(epOf(Math.max(x0, x))); }
      else { var idx = Math.floor((epOf(x) - bk.start) / bk.iv); if (idx >= 0 && idx < bk.n) { F.from = bk.start + idx * bk.iv; F.to = bk.start + (idx + 1) * bk.iv - 1; } else { F.from = F.to = null; } }
      syncTimeInputs(); applyView();
    });
    host.appendChild(svg);
  }
  function syncTimeInputs() { var fi = $("from-input"), ti = $("to-input"); if (fi) fi.value = F.from != null ? toInputVal(F.from, VIEW.disp) : ""; if (ti) ti.value = F.to != null ? toInputVal(F.to, VIEW.disp) : ""; }

  // ---- table / groups -----------------------------------------------------
  var CAP = 2000, GROUP_CAP = 500;
  function drawTable(timed, untimed) {
    var host = $("tl-body"); clear(host);
    if (F.groupBy === "none") {
      var w = h("div", { class: "tl-wrap" }, [tableHead()]);
      timed.slice(0, CAP).forEach(function (e) { w.appendChild(rowEl(e)); });
      host.appendChild(w);
      if (timed.length > CAP) host.appendChild(h("p", { class: "tl-note", text: "Showing the first " + CAP + " of " + timed.length + " events. Export to get them all." }));
    } else {
      var groups = {}, order = [];
      timed.forEach(function (e) { var k = groupKeyOf(e, F.groupBy); if (!groups[k]) { groups[k] = []; order.push(k); } groups[k].push(e); });
      order.sort(function (a, b) { return groups[b].length - groups[a].length || (a < b ? -1 : 1); });
      host.appendChild(h("p", { class: "tl-note", text: order.length + " " + (GROUP_LABEL[F.groupBy] || "group") + " value" + (order.length === 1 ? "" : "s") + " · click a group to pivot to it" }));
      order.forEach(function (k) {
        var rows = groups[k], open = !F.collapsed[k];
        var body = h("div", { class: "tl-wrap" + (open ? "" : " hidden") }, [tableHead()]);
        rows.slice(0, GROUP_CAP).forEach(function (e) { body.appendChild(rowEl(e)); });
        if (rows.length > GROUP_CAP) body.appendChild(h("p", { class: "tl-note", text: "first " + GROUP_CAP + " of " + rows.length }));
        var head = h("div", { class: "tl-ghead" + (open ? " open" : "") }, [
          h("span", { class: "tl-gcar", text: open ? "▾" : "▸" }),
          h("span", { class: "tl-gkey", text: k }),
          h("span", { class: "tl-gcount", text: rows.length + " event" + (rows.length === 1 ? "" : "s") }),
          h("button", { class: "btn btn-ghost btn-sm tl-pivot", type: "button", text: "Pivot →", title: "Filter to " + k, on: { click: function (e) { e.stopPropagation(); pivotTo(F.groupBy, k); } } })
        ]);
        head.addEventListener("click", function () { F.collapsed[k] = open; drawTable(computeGroups().table, computeGroups().untimed); });
        host.appendChild(h("div", { class: "tl-group" }, [head, body]));
      });
    }
    if (untimed.length) {
      host.appendChild(h("h3", { class: "tl-sub", text: "Without a timestamp (" + untimed.length + ")" }));
      var uw = h("div", { class: "tl-wrap" }, [tableHead()]);
      untimed.slice(0, 200).forEach(function (e) { uw.appendChild(rowEl(e, true)); });
      host.appendChild(uw);
    }
  }
  function tableHead() {
    return h("div", { class: "tl-head" }, [
      h("span", { text: "Time (" + dispLabel(VIEW.disp) + ")" }), h("span", { text: "Source" }), h("span", { text: "Host" }), h("span", { text: "Sev" }), h("span", { text: "Message" })
    ]);
  }
  var PIVOT_FIELD = { severity: "sev", format: "format", source: "source", host: "host", process: "process", user: "user", srcip: "src", dstip: "dst" };
  function pivotTo(by, value) {
    var f = PIVOT_FIELD[by]; if (!f || value === "(unset)") return;
    var kw = $("kw-input"); F.kw = f + ":" + value; if (kw) kw.value = F.kw;
    applyView();
  }
  function rowEl(e, untimed) {
    var t = untimed ? "—" : fmtTime(e.epoch, VIEW.disp), sev = SEV[e.sev];
    var fieldKeys = []; for (var k in e.fields) if (e.fields.hasOwnProperty(k)) fieldKeys.push(k);
    var hasDetail = fieldKeys.length || e.raw;
    var row = h("div", { class: "tl-row" + (hasDetail ? " tl-has" : "") });
    row.appendChild(h("span", { class: "tl-time mono", text: t }));
    row.appendChild(h("span", { class: "tl-src", title: e.source, text: e.source }));
    row.appendChild(h("span", { class: "tl-host", text: e.host || "—" }));
    row.appendChild(sev ? h("span", { class: "pill " + sev[0], text: sev[1] }) : h("span", { class: "tl-sev-none", text: "—" }));
    row.appendChild(h("span", { class: "tl-msg" }, [h("span", { class: "tl-fmtbadge tl-fmt-" + e.format, text: e.format }), h("span", { class: "tl-msgtext", text: e.message })]));
    if (!hasDetail) return h("div", { class: "tl-rowwrap" }, [row]);
    var detail = h("div", { class: "tl-detail hidden" });
    if (e.app) detail.appendChild(kv("app", e.app));
    if (e.sevText) detail.appendChild(kv("severity", e.sevText));
    fieldKeys.forEach(function (fk) { var val = e.fields[fk]; detail.appendChild(kv(fk, typeof val === "object" ? JSON.stringify(val) : String(val))); });
    detail.appendChild(h("div", { class: "tl-raw" }, [h("span", { class: "tl-kvk", text: "raw" }), h("code", { text: e.raw })]));
    row.addEventListener("click", function () { detail.classList.toggle("hidden"); row.classList.toggle("tl-open"); });
    return h("div", { class: "tl-rowwrap" }, [row, detail]);
  }
  function kv(k, v) { return h("div", { class: "tl-kv" }, [h("span", { class: "tl-kvk", text: k }), h("span", { class: "tl-kvv", text: v })]); }

  function humanSpan(ms) {
    if (ms <= 0) return "0s"; var se = Math.round(ms / 1000);
    var d = Math.floor(se / 86400); se -= d * 86400; var hh = Math.floor(se / 3600); se -= hh * 3600; var mm = Math.floor(se / 60); se -= mm * 60;
    if (d) return d + "d " + hh + "h"; if (hh) return hh + "h " + mm + "m"; if (mm) return mm + "m " + se + "s"; return se + "s";
  }

  // ---- export (reflects current filters) ----------------------------------
  function csvCell(v) { v = String(v == null ? "" : v); return /^[=+\-@\t\r]/.test(v) ? "\"'" + v.replace(/"/g, "\"\"") + "\"" : "\"" + v.replace(/"/g, "\"\"") + "\""; }
  function exportRows() { var g = computeGroups(); return g.table.concat(g.untimed); }
  function toCsv() {
    var rows = [["order", "time", "epoch_utc_ms", "source", "format", "host", "app", "severity", "severity_raw", "user", "src_ip", "dst_ip", "message", "fields"]];
    exportRows().forEach(function (e, i) {
      rows.push([e.order || (i + 1), e.epoch == null ? "" : fmtTime(e.epoch, VIEW.disp), e.epoch == null ? "" : e.epoch, e.source, e.format, e.host, e.app,
        SEV[e.sev] ? SEV[e.sev][1] : "", e.sevText, alias(e, "user"), alias(e, "srcip"), alias(e, "dstip"), e.message, JSON.stringify(e.fields || {})]);
    });
    return rows.map(function (r) { return r.map(csvCell).join(","); }).join("\r\n");
  }
  function toJson() {
    function out(e) {
      return { time: e.epoch == null ? null : fmtTime(e.epoch, VIEW.disp), epoch_utc_ms: e.epoch, source: e.source, format: e.format, host: e.host, app: e.app,
        severity: SEV[e.sev] ? SEV[e.sev][1] : "", severity_raw: e.sevText, user: alias(e, "user"), src_ip: alias(e, "srcip"), dst_ip: alias(e, "dstip"), message: e.message, fields: e.fields };
    }
    var g = computeGroups();
    return JSON.stringify({ generator: "SOC Toolkit Timeline Merger " + VIEW.res.version, timezone: dispLabel(VIEW.disp), filters: { from: F.from, to: F.to, keyword: F.kw, severity: F.sev, format: F.fmt, groupBy: F.groupBy }, shown: g.table.length + g.untimed.length, total: VIEW.res.stats.total, events: g.table.map(out), untimed: g.untimed.map(out) }, null, 2);
  }
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" }), url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function stamp() { return new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-"); }

  // ---- files --------------------------------------------------------------
  function readFiles(files) { Array.prototype.forEach.call(files, function (f) { var r = new FileReader(); r.onload = function () { if (addSource(f.name, String(r.result))) updateStatus(); }; r.readAsText(f); }); }

  // ---- sample -------------------------------------------------------------
  var SAMPLE = [
    { name: "perimeter-fw.log", text:
"<34>Oct 22 09:14:58 fw01 kernel: DROP IN=eth0 SRC=185.220.101.45 DST=10.20.30.41 PROTO=TCP DPT=8080\n" +
"<38>Oct 22 09:15:44 fw01 sshd[2213]: Failed password for root from 45.155.205.233 port 51022 ssh2\n" +
"<30>Oct 22 09:17:02 fw01 named[811]: query from 10.20.30.41 for api-telemetry.xyz" },
    { name: "edr-alerts.cef", text:
"<13>Oct 22 09:15:20 edr-mgr CEF:0|Acme|EDR|2.1|100|Suspicious Script Execution|7|rt=1761124520000 shost=FIN-WS-022 suser=jdoe act=blocked src=10.20.30.41 msg=powershell -enc downloaded a DLL\n" +
"<13>Oct 22 09:16:05 edr-mgr CEF:0|Acme|EDR|2.1|140|Malware Quarantined|9|shost=FIN-WS-022 suser=jdoe fname=qbot.dll act=quarantine msg=QakBot loader removed" },
    { name: "auth-service.ndjson", text:
'{"@timestamp":"2026-10-22T09:15:01.120Z","level":"warning","host":"app-auth-7","service":"auth","message":"MFA challenge failed","user":"jdoe","src_ip":"45.155.205.233"}\n' +
'{"@timestamp":"2026-10-22T09:16:40.900Z","level":"error","host":"app-auth-7","service":"auth","message":"account locked after repeated failures","user":"jdoe","src_ip":"45.155.205.233"}' }
  ];
  function loadSample() { sources = SAMPLE.map(function (x) { return { name: x.name, text: x.text }; }); $("text-input").value = ""; $("assume-sel").value = "0"; $("display-sel").value = "0"; renderChips(); build(); }

  // ---- wiring -------------------------------------------------------------
  function init() {
    if (!L) return;
    fillTz($("assume-sel"), 0); fillTz($("display-sel"), 0);
    if ($("year")) $("year").textContent = String(new Date().getFullYear());
    $("file-input").addEventListener("change", function (e) { readFiles(e.target.files); e.target.value = ""; });
    $("add-btn").addEventListener("click", function () { var ta = $("text-input"); if (addSource("Pasted " + (++pasteCount), ta.value)) { ta.value = ""; updateStatus(); ta.focus(); } else updateStatus("Nothing to add — paste some log lines first", "warn"); });
    $("sample-btn").addEventListener("click", loadSample);
    $("clear-btn").addEventListener("click", function () { sources = []; pasteCount = 0; $("text-input").value = ""; renderChips(); updateStatus(); $("text-input").focus(); });
    $("analyze-btn").addEventListener("click", build);
    $("text-input").addEventListener("input", function () { updateStatus(); });
    var dz = $("drop-zone");
    ["dragenter", "dragover"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("dragging"); }); });
    ["dragleave", "drop"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("dragging"); }); });
    dz.addEventListener("drop", function (e) { if (e.dataTransfer && e.dataTransfer.files.length) readFiles(e.dataTransfer.files); });
    updateStatus();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
