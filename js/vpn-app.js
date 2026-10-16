// VPN IP checker page.
// Privacy rules for this file: no browser storage, cookies, network calls or URL
// parameters. Everything lives in memory and is wiped on page exit.
(function () {
  "use strict";

  var V = window.SOCVpn, G = window.SOCGeo, X = window.SOCExtract;
  var $ = function (id) { return document.getElementById(id); };
  var input = $("text-input"), statusEl = $("input-status"), fileInput = $("file-input"), drop = $("drop-zone"), btn = $("analyze-btn");
  var viewInput = $("view-input"), viewRes = $("view-res");
  var MAX_BYTES = 5 * 1024 * 1024, MAX_IPS = 10000, MAX_ROWS = 2000;
  var SAMPLE = "Sign-in alerts, last 24 hours\n" +
    "185.220.101[.]45  Tor\n172.225.184.197  user: m.lee (iPhone)\n2.26.157.10  user: j.doe\n45.14.71.6  user: s.patel\n5.231.192.20  user: a.khan\n49.36.12.7  user: r.iyer\n" +
    "10.20.30.41  VPN gateway (internal)\n2a0d:5600:24:a1::7\n2001:550:1d05::10\n";

  // Brand links from config; hide any left empty.
  var cfg = window.HL_CONFIG || {};
  document.querySelectorAll("[data-link]").forEach(function (a) {
    var url = cfg[a.getAttribute("data-link")];
    if (url && /^https:\/\//.test(url)) a.href = url;
    else if (a.closest(".links")) a.classList.add("hidden");
    else { a.removeAttribute("href"); a.removeAttribute("target"); }
  });
  $("year").textContent = String(new Date().getFullYear());

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

  // ---------- Local data, loaded from this site only ----------
  var dataPromise = null;
  function addScript(src) {
    return new Promise(function (resolve) {
      var s = document.createElement("script"); s.src = src; s.async = false;
      s.onload = function () { resolve(true); }; s.onerror = function () { resolve(false); };
      document.body.appendChild(s);
    });
  }
  function loadData() {
    if (!dataPromise) dataPromise = Promise.all(["data/vpn.js", "data/world.js", "data/geo.js"].map(function (s) { return addScript(s + "?v=20261016g"); }))
      .then(function () { return Promise.all([V.load(), G.load()]); })
      .catch(function () { return [null, null]; });
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
    r.onload = function () { input.value = String(r.result || ""); setStatus("Loaded " + f.name + ". Nothing was uploaded.", "ok"); };
    r.onerror = function () { setStatus("Could not read that file.", "err"); };
    r.readAsText(f);
  }
  fileInput.addEventListener("change", function () { readFile(fileInput.files[0]); fileInput.value = ""; });
  ["dragenter", "dragover"].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add("dragging"); }); });
  ["dragleave", "drop"].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove("dragging"); }); });
  drop.addEventListener("drop", function (ev) { var f = ev.dataTransfer && ev.dataTransfer.files[0]; if (f) readFile(f); });
  $("sample-btn").addEventListener("click", function () { input.value = SAMPLE; setStatus("Sample loaded. Press Check IPs.", "ok"); input.focus(); });
  $("clear-btn").addEventListener("click", function () { input.value = ""; setStatus("Waiting for IP addresses"); input.focus(); });
  input.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
  btn.addEventListener("click", run);

  // ---------- Run ----------
  var S = null;
  function run() {
    var text = input.value;
    if (!text.trim()) { setStatus("Paste some IP addresses first.", "warn"); input.focus(); return; }
    var ips = V.addresses(text);
    if (!ips.length) { setStatus("No IPv4 or IPv6 addresses found in that text.", "warn"); return; }
    var truncated = ips.length > MAX_IPS;
    if (truncated) ips = ips.slice(0, MAX_IPS);
    btn.disabled = true;
    setStatus("Loading offline lists…");
    loadData().then(function (r) {
      var lists = r && r[0];
      if (!lists) { btn.disabled = false; setStatus("The offline lists could not be loaded in this browser, so no check was made.", "err"); return; }
      var geoOk = !!(r && r[1]);
      var rows = ips.map(function (ip) {
        var res = V.classify(ip, lists, X.ipKind);
        if (geoOk && res.valid && res.kind && res.kind.public) {
          var g = G.lookup(res.ip, res.kind);
          if (g && (g.cc || g.asn)) res.geo = { country: g.country || "", asn: g.asn || 0, owner: g.asnName || "" };
        }
        return res;
      });
      return sha256Hex(text).then(function (hash) {
        btn.disabled = false;
        S = { rows: rows, hash: hash, truncated: truncated, sources: V.sources(), geoInfo: geoOk && G.info ? G.info() : null, filter: "all", q: "" };
        setStatus("Checked " + rows.length + " addresses.", "ok");
        render();
      });
    }).catch(function (e) { btn.disabled = false; setStatus("Something went wrong: " + (e && e.message || e), "err"); });
  }

  // ---------- Results ----------
  var STATUS = {
    "Tor exit node": { k: "tor", c: "var(--bad)" },
    "iCloud Private Relay": { k: "relay", c: "var(--info)" },
    "Proton VPN server": { k: "vpn", c: "var(--magenta)" },
    "NordVPN server": { k: "vpn", c: "var(--magenta)" },
    "Proton VPN network": { k: "vpn", c: "var(--violet)" },
    "VPN network": { k: "vpn", c: "var(--violet)" },
    "Hosting network": { k: "hosting", c: "var(--amber)" },
    "Unknown": { k: "unknown", c: "var(--neutral)" },
    "Not a public IP": { k: "internal", c: "var(--t-path)" }
  };
  var ORDER = ["Tor exit node", "iCloud Private Relay", "Proton VPN server", "NordVPN server", "Proton VPN network", "VPN network", "Hosting network", "Unknown", "Not a public IP"];
  var els = {};

  function render() {
    viewRes.textContent = "";
    document.body.classList.add("is-res");
    viewInput.classList.add("hidden"); viewRes.classList.remove("hidden");

    var counts = {}; S.rows.forEach(function (r) { counts[r.status] = (counts[r.status] || 0) + 1; });
    var listed = S.rows.filter(function (r) { var k = (STATUS[r.status] || {}).k; return k === "tor" || k === "relay" || k === "vpn"; }).length;

    viewRes.appendChild(h("div", { class: "res-bar" }, [
      h("div", null, [h("p", { class: "eyebrow", text: "VPN IP checker" }), h("h2", { text: listed + " of " + S.rows.length + " addresses are on a VPN, Tor or Private Relay list" })]),
      h("div", { class: "actions" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Edit list", on: { click: back } }),
        h("button", { class: "btn btn-primary", type: "button", text: "New check", on: { click: fresh } })
      ])
    ]));

    els.tiles = h("div", { class: "tiles", role: "group", "aria-label": "Filter by status" });
    viewRes.appendChild(els.tiles);
    renderTiles(counts);

    var srcText = S.sources.map(function (s) { return s.available ? s.name + " " + s.updated : s.name + " not available"; }).join(" · ");
    viewRes.appendChild(h("p", { class: "fp" }, [
      "Input SHA-256 ", h("span", { class: "mono", text: S.hash ? S.hash.slice(0, 16) + "…" : "n/a", title: S.hash || "" }),
      " · engine " + V.VERSION + " · lists: " + srcText + (S.geoInfo ? " · IP registry data " + S.geoInfo.built : "") + ". The same input and lists always give the same result."
    ]));
    if (S.truncated) viewRes.appendChild(h("p", { class: "empty", text: "Only the first " + MAX_IPS + " addresses were checked. Split larger lists into several checks." }));

    var search = h("input", { class: "field search", type: "search", placeholder: "Filter addresses", "aria-label": "Filter addresses", spellcheck: "false" });
    search.addEventListener("input", function () { S.q = search.value.trim().toLowerCase(); renderRows(); });
    els.rows = h("div", { class: "rows" });
    var copyBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy listed IPs" });
    copyBtn.addEventListener("click", function () {
      copyText(S.rows.filter(function (r) { return ["tor", "relay", "vpn"].indexOf((STATUS[r.status] || {}).k) > -1; }).map(function (r) { return r.ip; }).join("\n"), copyBtn);
    });

    var list = h("section", { class: "card", "aria-labelledby": "res-title" }, [
      h("div", { class: "card-head" }, [h("h2", { id: "res-title", text: "Results" }),
        h("div", { class: "actions" }, [copyBtn, h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Download CSV", on: { click: function () { download("vpn-check-" + new Date().toISOString().slice(0, 10) + ".csv", csv(), "text/csv"); } } })])]),
      h("div", { class: "filters" }, [search]),
      els.rows
    ]);

    var legend = h("section", { class: "card out-card", "aria-label": "Sources and confidence" }, [
      h("h2", { text: "What the confidence means" }),
      h("ul", { class: "vlegend" }, [
        h("li", null, [h("span", { class: "pill p-conf-high", text: "High" }), " The operator publishes this address itself: Tor Project, Apple, or the VPN provider's own server list (Proton, NordVPN)."]),
        h("li", null, [h("span", { class: "pill p-conf-medium", text: "Medium" }), " Next to a listed VPN server (same /24 block) or in a curated list of VPN networks built mainly from network ownership, so the exact address could be another service."]),
        h("li", null, [h("span", { class: "pill p-conf-low", text: "Low" }), " Hosting or datacenter network that no VPN list names. A VPN is possible but not confirmed."]),
        h("li", null, [h("span", { class: "pill p-unknown", text: "Unknown" }), " No list checked says this is a VPN, Tor or Private Relay. That is not proof it isn't one."])
      ]),
      h("h3", { class: "vh3", text: "Lists checked" }),
      h("ul", { class: "vsources" }, S.sources.map(function (s) {
        return h("li", null, s.available
          ? [h("strong", { text: s.name }), h("span", { text: s.source + " · updated " + s.updated + " · " + s.ranges.toLocaleString("en-US") + " ranges" })]
          : [h("strong", { text: s.name }), h("span", { class: "vmissing", text: "Not available yet, so this check was not made." })]);
      })),
      h("p", { class: "note", text: "Country and network owner come from offline IP registry data (IPtoASN and ip-location-db). They describe who holds the address block, not who is using the address." }),
      h("p", { class: "note", text: "Not detectable offline: residential proxies, and new, small or self-hosted VPNs. Company VPNs and secure web gateways can appear as VPN or hosting networks." })
    ]);

    viewRes.appendChild(h("div", { class: "res-grid" }, [list, legend]));
    renderRows();
    window.scrollTo(0, 0);
    viewRes.focus({ preventScroll: true });
  }

  function renderTiles(counts) {
    els.tiles.textContent = "";
    var mk = function (key, label, color, n) {
      return h("button", { class: "tile", type: "button", color: color, "aria-pressed": String(S.filter === key), on: { click: function () { S.filter = key; renderTiles(counts); renderRows(); } } },
        [h("strong", { text: String(n) }), h("span", { text: label })]);
    };
    els.tiles.appendChild(mk("all", "All addresses", "var(--violet)", S.rows.length));
    ORDER.forEach(function (st) { if (counts[st]) els.tiles.appendChild(mk(st, st, STATUS[st].c, counts[st])); });
    if (counts["Not an IP address"]) els.tiles.appendChild(mk("Not an IP address", "Not an IP address", "var(--t-path)", counts["Not an IP address"]));
  }

  var LIST_NAMES = { tor: "Tor exit list", icloud: "iCloud Private Relay", proton: "Proton server list", nord: "NordVPN server list", proton24: "Proton /24 blocks", vpn: "X4B VPN list", dc: "Datacenter list" };
  function renderRows() {
    els.rows.textContent = "";
    var v = S.rows.filter(function (r) {
      if (S.filter !== "all" && r.status !== S.filter) return false;
      if (S.q && (r.ip || r.input).toLowerCase().indexOf(S.q) < 0 && (!r.geo || (r.geo.owner + " " + r.geo.country).toLowerCase().indexOf(S.q) < 0)) return false;
      return true;
    });
    if (!v.length) { els.rows.appendChild(h("p", { class: "empty", text: "No addresses match this filter." })); return; }
    v.slice(0, MAX_ROWS).forEach(function (r) {
      var st = STATUS[r.status] || { k: "unknown", c: "var(--neutral)" };
      var pills = [];
      if (r.confidence) pills.push(h("span", { class: "pill p-conf-" + r.confidence.toLowerCase(), text: "Confidence: " + r.confidence }));
      else if (r.status === "Unknown") pills.push(h("span", { class: "pill p-unknown", text: "Confidence: unknown" }));
      if (r.network && r.status !== "Hosting network") pills.push(h("span", { class: "pill p-geo", text: r.network }));
      if (r.geo) pills.push(h("span", { class: "pill p-geo", text: [r.geo.country, r.geo.asn ? "AS" + r.geo.asn + (r.geo.owner ? " " + r.geo.owner : "") : ""].filter(Boolean).join(" · ") }));
      (r.matches || []).forEach(function (m) { if (m !== "dc") pills.push(h("span", { class: "pill p-defanged", text: "Listed: " + (LIST_NAMES[m] || m) })); });
      if (r.mappedFrom) pills.push(h("span", { class: "pill p-geo", text: "Checked as IPv4 from " + r.mappedFrom }));
      els.rows.appendChild(h("div", { class: "row vrow" }, [
        h("span", { class: "tbadge", color: st.c, text: r.status }),
        h("div", { class: "rmain" }, [
          h("span", { class: "rval", text: r.ip || r.input }),
          pills.length ? h("div", { class: "rtags" }, pills) : null,
          h("p", { class: "rnote", text: r.note })
        ])
      ]));
    });
    if (v.length > MAX_ROWS) els.rows.appendChild(h("p", { class: "empty", text: "Showing the first " + MAX_ROWS + " of " + v.length + ". The CSV includes every address." }));
  }

  // ---------- Export ----------
  function cell(v) { v = String(v === null || v === undefined ? "" : v); return /^[=+\-@\t\r]/.test(v) ? "\"'" + v.replace(/"/g, "\"\"") + "\"" : "\"" + v.replace(/"/g, "\"\"") + "\""; }
  function csv() {
    var dates = S.sources.map(function (s) { return s.name + ": " + (s.available ? s.updated : "not available"); }).join("; ");
    var out = [["ip", "status", "confidence", "lists_matched", "network_type", "country", "asn", "network_owner", "note", "list_dates"]];
    S.rows.forEach(function (r) {
      out.push([r.ip || r.input, r.status, r.confidence || (r.status === "Unknown" ? "unknown" : ""), (r.matches || []).map(function (m) { return LIST_NAMES[m] || m; }).join("; "),
        r.network || "", r.geo ? r.geo.country : "", r.geo && r.geo.asn ? "AS" + r.geo.asn : "", r.geo ? r.geo.owner : "", r.note, dates]);
    });
    return out.map(function (row) { return row.map(cell).join(","); }).join("\r\n");
  }
  function copyText(text, b) {
    var done = function (ok) { var o = b.textContent; b.textContent = ok ? "Copied" : "Copy failed"; setTimeout(function () { b.textContent = o; }, 1400); };
    if (!text) { done(false); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    else done(false);
  }
  function download(name, text, mime) {
    var url = URL.createObjectURL(new Blob([text], { type: mime }));
    var a = h("a", { href: url, download: name }); document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ---------- Navigation and cleanup ----------
  function show() { viewRes.classList.add("hidden"); viewRes.textContent = ""; viewInput.classList.remove("hidden"); document.body.classList.remove("is-res"); window.scrollTo(0, 0); }
  function back() { S = null; show(); setStatus("Edit the list and check again."); input.focus(); }
  function fresh() { S = null; input.value = ""; show(); setStatus("Waiting for IP addresses"); input.focus(); }
  window.addEventListener("pagehide", function () { S = null; input.value = ""; viewRes.textContent = ""; });
})();
