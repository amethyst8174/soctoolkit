// soc-toolkit IOC extractor page.
// Privacy rules for this file: no browser storage, cookies, network calls or URL
// parameters. Everything lives in memory and is wiped on page exit.
// The Privacy check workflow enforces this on every push.
(function () {
  "use strict";

  var X = window.SOCExtract, Q = window.SOCQueries, G = window.SOCGeo;
  var $ = function (id) { return document.getElementById(id); };
  var input = $("text-input"), exclInput = $("exclude-input"), statusEl = $("input-status");
  var fileInput = $("file-input"), drop = $("drop-zone"), analyzeBtn = $("analyze-btn");
  var viewInput = $("view-input"), viewRes = $("view-res");
  var MAX_BYTES = 5 * 1024 * 1024, MAX_ROWS = 1500;

  // Brand links from config; hide any left empty.
  var cfg = window.HL_CONFIG || {};
  document.querySelectorAll("[data-link]").forEach(function (a) {
    var url = cfg[a.getAttribute("data-link")];
    if (url && /^https:\/\//.test(url)) a.href = url;
    else if (a.closest(".links")) a.classList.add("hidden");
    else { a.removeAttribute("href"); a.removeAttribute("target"); }
  });
  $("year").textContent = String(new Date().getFullYear());

  // ---------- Small DOM helper: builds elements with DOM methods only ----------
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "on") for (var ev in v) el.addEventListener(ev, v[ev]);
      else if (k === "color") el.style.setProperty("--c", v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    (kids || []).forEach(function (c) { if (c !== null && c !== undefined && c !== false) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return el;
  }
  function setStatus(msg, kind) { statusEl.textContent = msg; statusEl.className = "status" + (kind ? " " + kind : ""); }

  // ---------- Type catalogue ----------
  var TYPES = {
    ipv4: ["IPv4", "ip"], ipv6: ["IPv6", "ip"], cidr: ["CIDR", "range"], domain: ["Domain", "domain"], url: ["URL", "url"], email: ["Email", "email"],
    md5: ["MD5", "hash"], sha1: ["SHA1", "hash"], sha256: ["SHA256", "hash"], sha512: ["SHA512", "hash"],
    filename: ["File", "file"], filepath: ["Path", "path"], registry: ["Registry", "registry"], cve: ["CVE", "cve"], attack: ["ATT&CK", "attack"]
  };
  var GROUPS = [
    ["ip", "IP addresses", "var(--t-ip)"], ["range", "IP ranges", "var(--t-ip)"], ["domain", "Domains", "var(--t-domain)"], ["url", "URLs", "var(--t-url)"],
    ["email", "Emails", "var(--t-email)"], ["hash", "Hashes", "var(--t-hash)"], ["file", "File names", "var(--t-file)"], ["path", "File paths", "var(--t-path)"],
    ["registry", "Registry keys", "var(--t-path)"], ["cve", "CVEs", "var(--t-cve)"], ["attack", "ATT&CK", "var(--t-attack)"]
  ];
  var GCOLOR = {}; GROUPS.forEach(function (g) { GCOLOR[g[0]] = g[2]; });
  var groupOf = function (t) { return TYPES[t] ? TYPES[t][1] : "file"; };

  // ---------- Local data (loaded from this site only, never from a third party) ----------
  var dataPromise = null;
  function addScript(src) {
    return new Promise(function (resolve) {
      var s = document.createElement("script");
      s.src = src; s.async = false;
      s.onload = function () { resolve(true); }; s.onerror = function () { resolve(false); };
      document.body.appendChild(s);
    });
  }
  function loadData() {
    if (!dataPromise) dataPromise = Promise.all(["data/world.js", "data/threat.js", "data/geo.js"].map(function (s) { return addScript(s + "?v=20261016c"); }))
      .then(function () { return G.load(); }).catch(function () { return null; });
    return dataPromise;
  }
  if ("requestIdleCallback" in window) window.requestIdleCallback(function () { loadData(); }, { timeout: 2500 });
  else setTimeout(loadData, 800);

  function sha256Hex(text) {
    if (!window.crypto || !crypto.subtle) return Promise.resolve("");
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(function (b) {
      return Array.prototype.map.call(new Uint8Array(b), function (x) { return ("0" + x.toString(16)).slice(-2); }).join("");
    }).catch(function () { return ""; });
  }

  // ---------- Input ----------
  function readFile(f) {
    if (!f) return;
    if (f.size > MAX_BYTES) { setStatus("That file is larger than 5 MB. Paste the relevant part instead.", "err"); return; }
    var r = new FileReader();
    r.onload = function () { input.value = String(r.result || ""); setStatus("Loaded " + f.name + " (" + Math.round(f.size / 1024) + " KB). Nothing was uploaded.", "ok"); };
    r.onerror = function () { setStatus("Could not read that file.", "err"); };
    r.readAsText(f);
  }
  fileInput.addEventListener("change", function () { readFile(fileInput.files[0]); fileInput.value = ""; });
  ["dragenter", "dragover"].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add("dragging"); }); });
  ["dragleave", "drop"].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove("dragging"); }); });
  drop.addEventListener("drop", function (ev) { var f = ev.dataTransfer && ev.dataTransfer.files[0]; if (f) readFile(f); });
  $("sample-btn").addEventListener("click", function () { input.value = window.SOC_SAMPLE || ""; exclInput.value = "yourco.com"; setStatus("Sample threat advisory loaded. Press Extract IOCs.", "ok"); input.focus(); });
  $("clear-btn").addEventListener("click", function () { input.value = ""; setStatus("Waiting for text"); input.focus(); });
  input.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
  analyzeBtn.addEventListener("click", run);

  function excludeList() {
    return exclInput.value.toLowerCase().split(/[\s,;]+/).map(function (d) { return d.replace(/^\*?\.|^@/, "").replace(/\.$/, ""); }).filter(function (d) { return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d); });
  }

  // ---------- State ----------
  var S = null;
  function run() {
    var text = input.value;
    if (!text.trim()) { setStatus("Paste some text or open a file first.", "warn"); input.focus(); return; }
    analyzeBtn.disabled = true;
    setStatus("Loading local IP data…");
    loadData().then(function (db) {
      setStatus("Extracting…");
      var res = X.extract(text, { exclude: excludeList(), lookup: db ? G.lookup : null });
      return sha256Hex(text).then(function (hash) {
        var info = G.info && G.info();
        S = { res: res, items: res.items, hash: hash, geo: info, created: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
          group: "all", q: "", tab: "hunt", plat: "kql", days: 30 };
        analyzeBtn.disabled = false;
        if (!res.items.length) { setStatus("No indicators found in that text.", "warn"); return; }
        setStatus("Found " + res.items.length + " indicators.", "ok");
        renderResults();
      });
    }).catch(function (e) { analyzeBtn.disabled = false; setStatus("Something went wrong: " + (e && e.message || e), "err"); });
  }

  // ---------- Results view ----------
  var els = {};
  function selected() { return S.items.filter(function (i) { return i.include; }); }

  function renderResults() {
    viewRes.textContent = "";
    document.body.classList.add("is-res");
    viewInput.classList.add("hidden");
    viewRes.classList.remove("hidden");

    var bar = h("div", { class: "res-bar" }, [
      h("div", null, [h("p", { class: "eyebrow", text: "IOC extractor" }), h("h2", { id: "res-title" })]),
      h("div", { class: "actions" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Edit text", on: { click: backToInput } }),
        h("button", { class: "btn btn-primary btn-new", type: "button", text: "New extraction", on: { click: newExtraction } })
      ])
    ]);
    els.title = bar.querySelector("#res-title");

    els.tiles = h("div", { class: "tiles", role: "group", "aria-label": "Filter by type" });
    var fp = h("p", { class: "fp" }, [
      "Input SHA-256 ", h("span", { class: "mono", text: S.hash ? S.hash.slice(0, 16) + "…" : "n/a", title: S.hash || "" }),
      " · engine " + S.res.version + " · " + S.res.lines + " lines · IP data " + (S.geo ? S.geo.built : "unavailable") + (S.geo && S.geo.threatBuilt ? " · threat lists " + S.geo.threatBuilt : "") + ". The same text and settings always give the same result."
    ]);

    // Left: indicator list
    var search = h("input", { class: "field search", type: "search", placeholder: "Filter indicators", "aria-label": "Filter indicators", spellcheck: "false" });
    search.addEventListener("input", function () { S.q = search.value.trim().toLowerCase(); renderRows(); });
    els.selInfo = h("span", { class: "sel-info", "aria-live": "polite" });
    els.rows = h("div", { class: "rows" });
    var list = h("section", { class: "card", "aria-labelledby": "list-title" }, [
      h("div", { class: "card-head" }, [h("h2", { id: "list-title", text: "Indicators" }), els.selInfo]),
      h("div", { class: "filters" }, [
        search,
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Suggested", title: "Select the indicators worth hunting (default)", on: { click: function () { bulk("suggested"); } } }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "All", on: { click: function () { bulk(true); } } }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "None", on: { click: function () { bulk(false); } } })
      ]),
      els.rows,
      h("p", { class: "note", text: "Internal IPs, your domains, reserved or well-known domains, empty-file hashes, CVEs and ATT&CK IDs start unticked. Tick them to include them in queries and exports." })
    ]);

    // Right: output
    els.out = h("div");
    var tabs = h("div", { class: "otabs", role: "tablist", "aria-label": "Output" }, [["hunt", "Hunt queries"], ["export", "Export"]].map(function (t) {
      return h("button", { class: "otab", role: "tab", type: "button", "data-tab": t[0], "aria-selected": String(S.tab === t[0]), text: t[1], on: { click: function () {
        S.tab = t[0]; tabs.querySelectorAll(".otab").forEach(function (b) { b.setAttribute("aria-selected", String(b.getAttribute("data-tab") === S.tab)); }); renderOut();
      } } });
    }));
    var out = h("section", { class: "card out-card", "aria-label": "Hunt queries and exports" }, [tabs, els.out]);

    viewRes.appendChild(bar);
    viewRes.appendChild(els.tiles);
    viewRes.appendChild(fp);
    viewRes.appendChild(h("div", { class: "res-grid" }, [list, out]));
    S.saved = S.items.map(function (i) { return i.include; });
    renderTiles(); renderRows(); renderOut(); updateCounts();
    window.scrollTo(0, 0);
    viewRes.focus({ preventScroll: true });
  }

  function renderTiles() {
    els.tiles.textContent = "";
    var counts = {}; S.items.forEach(function (i) { var g = groupOf(i.type); counts[g] = (counts[g] || 0) + 1; });
    var mk = function (key, label, color, n) {
      return h("button", { class: "tile", type: "button", color: color, "aria-pressed": String(S.group === key), on: { click: function () { S.group = key; renderTiles(); renderRows(); } } },
        [h("strong", { text: String(n) }), h("span", { text: label })]);
    };
    els.tiles.appendChild(mk("all", "All indicators", "var(--magenta)", S.items.length));
    GROUPS.forEach(function (g) { if (counts[g[0]]) els.tiles.appendChild(mk(g[0], g[1], g[2], counts[g[0]])); });
  }

  function visible() {
    return S.items.filter(function (i) {
      if (S.group !== "all" && groupOf(i.type) !== S.group) return false;
      if (S.q && i.value.toLowerCase().indexOf(S.q) < 0 && !i.tags.some(function (t) { return t.label.toLowerCase().indexOf(S.q) > -1; })) return false;
      return true;
    });
  }

  function pillsFor(i) {
    var out = i.tags.map(function (t) { return h("span", { class: "pill p-" + t.k, text: t.k === "threat" ? "Threat list: " + t.label : t.label }); });
    var g = i.meta && i.meta.geo;
    if (g && (g.country || g.asn)) out.push(h("span", { class: "pill p-geo", text: [g.country, g.asn ? "AS" + g.asn + (g.asnLabel ? " " + g.asnLabel : "") : ""].filter(Boolean).join(" · ") }));
    if (i.meta && i.meta.from) out.push(h("span", { class: "pill p-geo", text: "Host of " + (i.meta.from === "email" ? "an email" : "a URL") }));
    return out;
  }

  function renderRows() {
    els.rows.textContent = "";
    var v = visible();
    if (!v.length) { els.rows.appendChild(h("p", { class: "empty", text: "No indicators match this filter." })); return; }
    v.slice(0, MAX_ROWS).forEach(function (i) {
      var cb = h("input", { type: "checkbox", "aria-label": "Include " + i.value });
      cb.checked = !!i.include;
      var row = h("div", { class: "row" + (i.include ? "" : " off") }, [
        cb,
        h("span", { class: "tbadge", color: GCOLOR[groupOf(i.type)], text: TYPES[i.type] ? TYPES[i.type][0] : i.type }),
        h("div", { class: "rmain" }, [
          h("span", { class: "rval", text: i.value }),
          (function () { var p = pillsFor(i); return p.length ? h("div", { class: "rtags" }, p) : null; })(),
          i.context ? h("details", { class: "rctx" }, [h("summary", { text: "Context, line " + i.line }), h("p", { text: i.context })]) : null
        ]),
        h("span", { class: "rmeta", text: (i.count > 1 ? "×" + i.count + " · " : "") + "line " + i.line })
      ]);
      cb.addEventListener("change", function () { i.include = cb.checked; row.classList.toggle("off", !cb.checked); updateCounts(); renderOut(); });
      els.rows.appendChild(row);
    });
    if (v.length > MAX_ROWS) els.rows.appendChild(h("p", { class: "empty", text: "Showing the first " + MAX_ROWS + " of " + v.length + ". Use the filter to narrow down; queries and exports still include every ticked indicator." }));
  }

  function bulk(mode) {
    var v = visible();
    v.forEach(function (i) { i.include = mode === "suggested" ? S.saved[S.items.indexOf(i)] : mode; });
    renderRows(); updateCounts(); renderOut();
  }

  function updateCounts() {
    var n = selected().length;
    els.selInfo.textContent = n + " of " + S.items.length + " selected";
    els.title.textContent = S.items.length + " indicators found";
  }

  // ---------- Output ----------
  var PLATS = [["kql", "Sentinel / Defender", "KQL"], ["spl", "Splunk", "SPL"], ["elastic", "Elastic", "KQL"], ["cql", "CrowdStrike / LogScale", "CQL"]];
  var EXT = { kql: "kql", spl: "spl", elastic: "txt", cql: "cql" };

  function copyText(text, btn) {
    var done = function (ok) { var o = btn.textContent; btn.textContent = ok ? "Copied" : "Copy failed"; setTimeout(function () { btn.textContent = o; }, 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
    else done(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    var t = h("textarea", { "aria-hidden": "true", readonly: true }); t.value = text;
    t.style.position = "fixed"; t.style.top = "0"; t.style.left = "0"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    var ok = false; try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    t.remove(); return ok;
  }
  function download(name, text, mime) {
    var url = URL.createObjectURL(new Blob([text], { type: mime || "text/plain" }));
    var a = h("a", { href: url, download: name }); document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  var stamp = function () { return S.created.slice(0, 10); };

  function renderOut() {
    els.out.textContent = "";
    var sel = selected();
    if (!sel.length) { els.out.appendChild(h("p", { class: "empty", text: "Tick at least one indicator to build queries and exports." })); return; }
    if (S.tab === "hunt") return renderHunt(sel);
    renderExport(sel);
  }

  function renderHunt(sel) {
    var plats = h("div", { class: "plats", role: "group", "aria-label": "SIEM platform" }, PLATS.map(function (p) {
      return h("button", { class: "plat", type: "button", "aria-pressed": String(S.plat === p[0]), title: p[2], text: p[1], on: { click: function () { S.plat = p[0]; renderOut(); } } });
    }));
    var days = h("select", { class: "field", "aria-label": "Time range" }, [1, 7, 30, 90].map(function (d) {
      var o = h("option", { value: String(d), text: "Last " + d + (d === 1 ? " day" : " days") }); if (S.days === d) o.selected = true; return o;
    }));
    days.addEventListener("change", function () { S.days = +days.value; renderOut(); });
    var q = Q.build(sel, S.days)[S.plat] || "";
    var hasQ = q.trim().length > 0;
    var copyBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy" });
    copyBtn.addEventListener("click", function () { copyText(q, copyBtn); });
    var dlBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Download", on: { click: function () { download("hunt-" + S.plat + "-" + stamp() + "." + EXT[S.plat], q); } } });
    els.out.appendChild(plats);
    els.out.appendChild(h("div", { class: "qopts" }, [
      S.plat === "elastic" || S.plat === "cql" ? h("span", { class: "sel-info", text: "Set the time range in " + (S.plat === "cql" ? "the Falcon / LogScale" : "Kibana's") + " time picker" }) : days,
      hasQ ? h("div", { class: "actions" }, [copyBtn, dlBtn]) : null
    ]));
    els.out.appendChild(hasQ ? h("pre", { class: "code", tabindex: "0" }, [h("code", { text: q })]) : h("p", { class: "empty", text: "The ticked indicators are CVEs or ATT&CK IDs only, which have no log fields to hunt on. Tick IPs, domains, URLs, emails, hashes, files or registry keys." }));
    els.out.appendChild(h("p", { class: "note", text: "Field and table names follow each platform's defaults (Defender XDR and Sentinel tables, Splunk CIM, Elastic ECS, CrowdStrike Falcon telemetry and Next-Gen SIEM ECS fields). Adjust them to match your data sources before running." }));
  }

  function renderExport(sel) {
    var meta = { version: S.res.version, fingerprint: S.hash };
    var rows = [
      ["CSV", "Spreadsheet with type, value, defanged value, country, ASN, tags and context.", "iocs-" + stamp() + ".csv", "text/csv", function () { return Q.csv(sel); }],
      ["JSON", "Structured list with tags, geolocation and the input fingerprint.", "iocs-" + stamp() + ".json", "application/json", function () { return Q.json(sel, meta); }],
      ["STIX 2.1 bundle", "Indicator objects with deterministic IDs for a TIP or MISP import.", "iocs-" + stamp() + ".stix.json", "application/json", function () { return Q.stix(sel, S.created); }],
      ["Defanged list", "One per line, safe to paste into tickets, chat and email.", "iocs-defanged-" + stamp() + ".txt", "text/plain", function () { return Q.plain(sel, true); }],
      ["Plain list", "One per line, refanged, for blocklists and tools.", "iocs-" + stamp() + ".txt", "text/plain", function () { return Q.plain(sel, false); }]
    ];
    els.out.appendChild(h("div", { class: "exports" }, rows.map(function (r) {
      var copyBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy" });
      copyBtn.addEventListener("click", function () { copyText(r[4](), copyBtn); });
      return h("div", { class: "exp" }, [
        h("div", null, [h("strong", { text: r[0] }), h("span", { text: r[1] })]),
        h("div", { class: "actions" }, [copyBtn, h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Download", on: { click: function () { download(r[2], r[4](), r[3]); } } })])
      ]);
    })));
    els.out.appendChild(h("p", { class: "note", text: sel.length + " ticked indicators are exported. Downloads are created in your browser; nothing is uploaded." }));
    var preview = h("pre", { class: "code", tabindex: "0" }, [h("code", { text: Q.plain(sel, true) })]);
    els.out.appendChild(h("h3", { class: "note", text: "Defanged preview" }));
    els.out.appendChild(preview);
  }

  // ---------- Navigation and cleanup ----------
  function showInput() {
    viewRes.classList.add("hidden"); viewRes.textContent = "";
    viewInput.classList.remove("hidden"); document.body.classList.remove("is-res");
    window.scrollTo(0, 0);
  }
  function backToInput() { S = null; showInput(); setStatus("Edit the text and extract again."); input.focus(); }
  function newExtraction() { S = null; input.value = ""; showInput(); setStatus("Waiting for text"); input.focus(); }
  function clearAll() { S = null; input.value = ""; exclInput.value = ""; viewRes.textContent = ""; }
  window.addEventListener("pagehide", clearAll);
})();
