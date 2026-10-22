// Timeline Merger page controller for the SOC Toolkit.
// Stages log sources, calls the LOGNORM engine to normalize and merge them, renders one
// sorted timeline, and exports it locally.
//
// Privacy rules for this file: no browser storage, cookies or network calls, and no dynamic
// markup injection. The DOM is built with createElement / textContent only, so log content can
// never be interpreted as markup. Exports are produced as in-memory Blobs and saved to the device.
(function () {
  "use strict";

  var L = window.LOGNORM;
  var $ = function (id) { return document.getElementById(id); };
  var sources = [];      // [{ name, text }]
  var pasteCount = 0;
  var lastResult = null; // for export
  var lastDisplay = 0;

  // ---- DOM helper (text nodes only, no markup injection) -----------------
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (!attrs.hasOwnProperty(k)) continue;
      var v = attrs[k];
      if (v == null) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "color") el.style.setProperty("--c", v);
      else if (k === "on") for (var ev in attrs[k]) el.addEventListener(ev, attrs[k][ev]);
      else el.setAttribute(k, v);
    }
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) {
      if (c != null) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---- timezone options ---------------------------------------------------
  // value "local" = the viewer's browser timezone; otherwise minutes east of UTC.
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
  function fillTz(sel, def) {
    TZ.forEach(function (o) {
      sel.appendChild(h("option", { value: String(o[1]), text: o[0] }));
    });
    sel.value = String(def);
  }
  function tzValue(sel) { var v = sel.value; return v === "local" ? "local" : parseInt(v, 10); }

  // ---- time formatting ----------------------------------------------------
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function offLabel(min) {
    if (!min) return "UTC";
    var s = min < 0 ? "-" : "+", a = Math.abs(min);
    return "UTC" + s + pad(Math.floor(a / 60)) + ":" + pad(a % 60);
  }
  function fmtTime(epoch, disp) {
    var d, label;
    if (disp === "local") {
      d = new Date(epoch);
      return {
        text: d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
          pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()),
        label: offLabel(-d.getTimezoneOffset())
      };
    }
    d = new Date(epoch + disp * 60000);
    return {
      text: d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " +
        pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()),
      label: offLabel(disp)
    };
  }
  function dispLabel(disp) { return disp === "local" ? offLabel(-new Date().getTimezoneOffset()) + " (local)" : offLabel(disp); }

  // ---- severity -----------------------------------------------------------
  var SEV = { high: ["p-threat", "High"], med: ["p-warn", "Med"], low: ["p-geo", "Low"], info: ["p-unknown", "Info"] };

  // ---- sources ------------------------------------------------------------
  function renderChips() {
    var box = $("src-chips");
    clear(box);
    if (!sources.length) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    box.appendChild(h("span", { class: "src-l", text: sources.length + (sources.length === 1 ? " source" : " sources") + " staged:" }));
    sources.forEach(function (s, i) {
      var lines = s.text.split(/\r\n|\r|\n/).filter(function (x) { return x.trim(); }).length;
      box.appendChild(h("span", { class: "src-chip" }, [
        h("strong", { text: s.name }),
        h("span", { class: "src-n", text: lines + (lines === 1 ? " line" : " lines") }),
        h("button", { class: "src-x", type: "button", title: "Remove source", "aria-label": "Remove " + s.name, text: "×",
          on: { click: function () { sources.splice(i, 1); renderChips(); updateStatus(); } } })
      ]));
    });
  }
  function addSource(name, text) {
    if (!text || !text.trim()) return false;
    sources.push({ name: name, text: text });
    renderChips();
    return true;
  }
  function updateStatus(msg, cls) {
    var st = $("input-status");
    st.className = "status" + (cls ? " " + cls : "");
    if (msg) { st.textContent = msg; return; }
    var staged = sources.length, pasted = $("text-input").value.trim() ? 1 : 0;
    if (!staged && !pasted) st.textContent = "Waiting for logs";
    else st.textContent = (staged + pasted) + " source" + (staged + pasted === 1 ? "" : "s") + " ready — Build timeline";
  }

  // ---- view switching -----------------------------------------------------
  function showRes() {
    $("view-input").classList.add("hidden");
    var v = $("view-res"); v.classList.remove("hidden");
    document.body.classList.add("is-res");
    window.scrollTo(0, 0); v.focus();
  }
  function showInput() {
    $("view-res").classList.add("hidden");
    $("view-input").classList.remove("hidden");
    document.body.classList.remove("is-res");
    window.scrollTo(0, 0);
  }

  // ---- build + render -----------------------------------------------------
  function build() {
    var list = sources.slice();
    var pasted = $("text-input").value;
    if (pasted.trim()) list.push({ name: "Pasted " + (++pasteCount), text: pasted });
    if (!list.length) { updateStatus("Add or paste at least one log source", "warn"); return; }

    var disp = tzValue($("display-sel"));
    var res = L.parseSources(list, { format: $("fmt-sel").value, assumeTz: tzValue($("assume-sel")) });
    lastResult = res; lastDisplay = disp;
    render(res, disp);
    showRes();
  }

  function tile(num, label, color) {
    return h("div", { class: "tile" }, [
      h("div", { class: "num", color: color, text: String(num) }),
      h("div", { class: "tl-tilelab", text: label })
    ]);
  }

  function render(res, disp) {
    var view = $("view-res");
    clear(view);
    var st = res.stats;

    // header bar
    view.appendChild(h("div", { class: "res-bar" }, [
      h("div", {}, [
        h("h2", { class: "res-title", text: "Merged timeline" }),
        h("p", { class: "status", text:
          st.timed + " event" + (st.timed === 1 ? "" : "s") + " from " + st.sources + " source" + (st.sources === 1 ? "" : "s") +
          " · times in " + dispLabel(disp) + (st.untimed ? " · " + st.untimed + " without a timestamp" : "") })
      ]),
      h("div", { class: "tools" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Export CSV", on: { click: function () { download("timeline-" + stamp() + ".csv", toCsv(res, disp), "text/csv"); } } }),
        h("button", { class: "btn btn-ghost", type: "button", text: "Export JSON", on: { click: function () { download("timeline-" + stamp() + ".json", toJson(res, disp), "application/json"); } } }),
        h("button", { class: "btn btn-primary", type: "button", text: "New input", on: { click: showInput } })
      ])
    ]));

    // tiles
    var span = st.span ? humanSpan(st.span.to - st.span.from) : "—";
    view.appendChild(h("div", { class: "tiles" }, [
      tile(st.timed, "Events", "var(--t-attack)"),
      tile(st.sources, "Sources", "var(--violet)"),
      tile(span, "Time span", "var(--magenta)"),
      tile(st.untimed, "No timestamp", st.untimed ? "var(--warn)" : "var(--muted)")
    ]));

    // format legend
    var fmtRow = h("div", { class: "tl-legend" });
    ["syslog", "cef", "leef", "json", "raw"].forEach(function (f) {
      var n = st.byFormat[f] || 0; if (!n) return;
      fmtRow.appendChild(h("span", { class: "tl-fmt tl-fmt-" + f }, [h("span", { class: "tl-dot" }), f + " " + n]));
    });
    view.appendChild(fmtRow);

    // timeline
    var CAP = 2000;
    var rows = res.events;
    var head = h("div", { class: "tl-head" }, [
      h("span", { text: "Time (" + dispLabel(disp) + ")" }), h("span", { text: "Source" }),
      h("span", { text: "Host" }), h("span", { text: "Sev" }), h("span", { text: "Message" })
    ]);
    var wrap = h("div", { class: "tl-wrap" }, [head]);
    rows.slice(0, CAP).forEach(function (e) { wrap.appendChild(rowEl(e, disp)); });
    view.appendChild(wrap);
    if (rows.length > CAP) view.appendChild(h("p", { class: "tl-note", text: "Showing the first " + CAP + " of " + rows.length + " events. Export to get them all." }));

    // untimed / unparsed
    if (res.untimedEvents.length) {
      view.appendChild(h("h3", { class: "tl-sub", text: "Without a timestamp (" + res.untimedEvents.length + ")" }));
      view.appendChild(h("p", { class: "tl-note", text: "These lines could not be placed on the timeline because no timestamp was found. They are included in exports." }));
      var uw = h("div", { class: "tl-wrap" });
      res.untimedEvents.slice(0, 200).forEach(function (e) { uw.appendChild(rowEl(e, disp, true)); });
      view.appendChild(uw);
    }
  }

  function rowEl(e, disp, untimed) {
    var t = untimed ? { text: "—", label: "" } : fmtTime(e.epoch, disp);
    var sev = SEV[e.sev];
    var fieldKeys = [];
    for (var k in e.fields) if (e.fields.hasOwnProperty(k)) fieldKeys.push(k);
    var hasDetail = fieldKeys.length || e.raw;

    var row = h("div", { class: "tl-row" + (hasDetail ? " tl-has" : "") });
    row.appendChild(h("span", { class: "tl-time mono" }, [h("span", { text: t.text })]));
    row.appendChild(h("span", { class: "tl-src", title: e.source, text: e.source }));
    row.appendChild(h("span", { class: "tl-host", text: e.host || "—" }));
    row.appendChild(sev ? h("span", { class: "pill " + sev[0], text: sev[1] }) : h("span", { class: "tl-sev-none", text: "—" }));
    var msg = h("span", { class: "tl-msg" }, [
      h("span", { class: "tl-fmtbadge tl-fmt-" + e.format, text: e.format }),
      h("span", { class: "tl-msgtext", text: e.message })
    ]);
    row.appendChild(msg);

    if (hasDetail) {
      var detail = h("div", { class: "tl-detail hidden" });
      if (e.app) detail.appendChild(kv("app", e.app));
      if (e.sevText) detail.appendChild(kv("severity", e.sevText));
      fieldKeys.forEach(function (k) {
        var val = e.fields[k];
        detail.appendChild(kv(k, typeof val === "object" ? JSON.stringify(val) : String(val)));
      });
      detail.appendChild(h("div", { class: "tl-raw" }, [h("span", { class: "tl-kvk", text: "raw" }), h("code", { text: e.raw })]));
      row.addEventListener("click", function () { detail.classList.toggle("hidden"); row.classList.toggle("tl-open"); });
      var wrapRow = h("div", { class: "tl-rowwrap" }, [row, detail]);
      return wrapRow;
    }
    return h("div", { class: "tl-rowwrap" }, [row]);
  }
  function kv(k, v) { return h("div", { class: "tl-kv" }, [h("span", { class: "tl-kvk", text: k }), h("span", { class: "tl-kvv", text: v })]); }

  function humanSpan(ms) {
    if (ms <= 0) return "0s";
    var s = Math.round(ms / 1000);
    var d = Math.floor(s / 86400); s -= d * 86400;
    var hh = Math.floor(s / 3600); s -= hh * 3600;
    var mm = Math.floor(s / 60); s -= mm * 60;
    if (d) return d + "d " + hh + "h";
    if (hh) return hh + "h " + mm + "m";
    if (mm) return mm + "m " + s + "s";
    return s + "s";
  }

  // ---- export (formula-injection-safe CSV, same rule as the IOC extractor) ----
  function csvCell(v) {
    v = String(v == null ? "" : v);
    return /^[=+\-@\t\r]/.test(v) ? "\"'" + v.replace(/"/g, "\"\"") + "\"" : "\"" + v.replace(/"/g, "\"\"") + "\"";
  }
  function toCsv(res, disp) {
    var all = res.events.concat(res.untimedEvents);
    var rows = [["order", "time", "epoch_utc_ms", "source", "format", "host", "app", "severity", "severity_raw", "message", "fields"]];
    all.forEach(function (e, i) {
      var t = e.epoch == null ? "" : fmtTime(e.epoch, disp).text;
      rows.push([e.order || (i + 1), t, e.epoch == null ? "" : e.epoch, e.source, e.format, e.host, e.app,
        SEV[e.sev] ? SEV[e.sev][1] : "", e.sevText, e.message, JSON.stringify(e.fields || {})]);
    });
    return rows.map(function (r) { return r.map(csvCell).join(","); }).join("\r\n");
  }
  function toJson(res, disp) {
    function out(e) {
      return {
        time: e.epoch == null ? null : fmtTime(e.epoch, disp).text, epoch_utc_ms: e.epoch,
        source: e.source, format: e.format, host: e.host, app: e.app,
        severity: SEV[e.sev] ? SEV[e.sev][1] : "", severity_raw: e.sevText,
        message: e.message, fields: e.fields
      };
    }
    return JSON.stringify({
      generator: "SOC Toolkit Timeline Merger " + res.version,
      timezone: dispLabel(disp),
      stats: res.stats,
      events: res.events.map(out),
      untimed: res.untimedEvents.map(out)
    }, null, 2);
  }
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function stamp() { var d = new Date(); return d.toISOString().slice(0, 19).replace(/[:T]/g, "-"); }

  // ---- files --------------------------------------------------------------
  function readFiles(files) {
    Array.prototype.forEach.call(files, function (f) {
      var r = new FileReader();
      r.onload = function () { if (addSource(f.name, String(r.result))) updateStatus(); };
      r.readAsText(f);
    });
  }

  // ---- sample -------------------------------------------------------------
  var SAMPLE = [
    { name: "perimeter-fw.log", text:
"<34>Oct 22 09:14:58 fw01 kernel: DROP IN=eth0 SRC=185.220.101.45 DST=10.20.30.41 PROTO=TCP DPT=8080\n" +
"<38>Oct 22 09:15:44 fw01 sshd[2213]: Failed password for root from 45.155.205.233 port 51022 ssh2\n" +
"<30>Oct 22 09:17:02 fw01 named[811]: query from 10.20.30.41 for api-telemetry.xyz" },
    { name: "edr-alerts.cef", text:
"<13>Oct 22 09:15:20 edr-mgr CEF:0|Acme|EDR|2.1|100|Suspicious Script Execution|7|rt=1761124520000 shost=FIN-WS-022 suser=jdoe act=blocked msg=powershell -enc downloaded a DLL\n" +
"<13>Oct 22 09:16:05 edr-mgr CEF:0|Acme|EDR|2.1|140|Malware Quarantined|9|shost=FIN-WS-022 fname=qbot.dll act=quarantine msg=QakBot loader removed" },
    { name: "auth-service.ndjson", text:
'{"@timestamp":"2026-10-22T09:15:01.120Z","level":"warning","host":"app-auth-7","service":"auth","message":"MFA challenge failed","user":"jdoe","src_ip":"45.155.205.233"}\n' +
'{"@timestamp":"2026-10-22T09:16:40.900Z","level":"error","host":"app-auth-7","service":"auth","message":"account locked after repeated failures","user":"jdoe"}' }
  ];
  function loadSample() {
    sources = SAMPLE.map(function (s) { return { name: s.name, text: s.text }; });
    $("text-input").value = "";
    $("assume-sel").value = "0";   // the sample's naive syslog times are UTC
    $("display-sel").value = "0";
    renderChips(); build();
  }

  // ---- wiring -------------------------------------------------------------
  function init() {
    if (!L) return;
    fillTz($("assume-sel"), 0);
    fillTz($("display-sel"), 0);
    $("year") && ($("year").textContent = String(new Date().getFullYear()));

    $("file-input").addEventListener("change", function (e) { readFiles(e.target.files); e.target.value = ""; });
    $("add-btn").addEventListener("click", function () {
      var ta = $("text-input");
      if (addSource("Pasted " + (++pasteCount), ta.value)) { ta.value = ""; updateStatus(); ta.focus(); }
      else updateStatus("Nothing to add — paste some log lines first", "warn");
    });
    $("sample-btn").addEventListener("click", loadSample);
    $("clear-btn").addEventListener("click", function () {
      sources = []; pasteCount = 0; $("text-input").value = ""; renderChips(); updateStatus(); $("text-input").focus();
    });
    $("analyze-btn").addEventListener("click", build);
    $("text-input").addEventListener("input", function () { updateStatus(); });

    // drag & drop
    var dz = $("drop-zone");
    ["dragenter", "dragover"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("dragging"); }); });
    ["dragleave", "drop"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("dragging"); }); });
    dz.addEventListener("drop", function (e) { if (e.dataTransfer && e.dataTransfer.files.length) readFiles(e.dataTransfer.files); });

    updateStatus();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
