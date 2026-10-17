/* Tracer-Lens - SOC Toolkit
 * Graphical PCAP/PCAPNG analyzer. Reads a capture locally, parses it in chunks (bounded
 * memory, cancellable), enriches external IPs with the toolkit's offline geo / ASN / threat /
 * VPN data, flags anomalies and builds hunt queries. No network, no storage.
 */
(function () {
  "use strict";

  var Q = typeof window !== "undefined" ? window.SOCQueries : null;
  var Geo = typeof window !== "undefined" ? window.SOCGeo : null;
  var Vpn = typeof window !== "undefined" ? window.SOCVpn : null;
  var X = typeof window !== "undefined" ? window.SOCExtract : null;

  var S = { running: false, cancel: false, analysis: null, enrich: {} };

  /* ---------- formatting ---------- */
  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 100 ? Math.round(n) : n.toFixed(1)) + " " + u[i];
  }
  function fmtNum(n) { return n.toLocaleString(); }
  function fmtDur(s) {
    if (!s || s < 0) return "0s";
    if (s < 60) return (s < 10 ? s.toFixed(1) : Math.round(s)) + "s";
    var m = Math.floor(s / 60), sec = Math.round(s % 60);
    if (m < 60) return m + "m " + sec + "s";
    var h = Math.floor(m / 60); m = m % 60; return h + "h " + m + "m";
  }
  function entropy(str) {
    if (!str) return 0;
    var f = {}, i; for (i = 0; i < str.length; i++) f[str[i]] = (f[str[i]] || 0) + 1;
    var e = 0; for (var k in f) { var p = f[k] / str.length; e -= p * Math.log2(p); }
    return e;
  }

  /* ---------- DOM helper ---------- */
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") el.className = attrs[k];
      else if (k === "text") el.textContent = attrs[k];
      else if (k === "html") el.innerHTML = attrs[k];
      else if (k === "color") el.style.setProperty("--c", attrs[k]);
      else if (k === "style") el.style.cssText = attrs[k]; // CSSOM: allowed under style-src 'self'
      else if (k === "on") for (var ev in attrs[k]) el.addEventListener(ev, attrs[k][ev]);
      else if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    }
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) { if (c != null) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return el;
  }
  function svgEl(tag, attrs) {
    var el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var k in attrs) if (attrs[k] != null) { if (k === "style") el.style.cssText = attrs[k]; else el.setAttribute(k, attrs[k]); }
    return el;
  }
  function css(v) { return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }

  function copyText(text, btn) {
    var done = function (ok) { var o = btn.textContent; btn.textContent = ok ? "Copied" : "Copy failed"; setTimeout(function () { btn.textContent = o; }, 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
    else done(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); var ok = false; try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta); return ok;
  }
  function download(name, text) {
    var blob = new Blob([text], { type: "text/plain" }); var url = URL.createObjectURL(blob);
    var a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  /* ---------- enrichment (offline) ---------- */
  var enrichReady = false;
  function loadEnrich() {
    var jobs = [];
    if (Geo && Geo.load) jobs.push(Geo.load().catch(function () { return null; }));
    if (Vpn && Vpn.load) jobs.push(Vpn.load().then(function (l) { S.vpnLists = l; }).catch(function () { return null; }));
    return Promise.all(jobs).then(function () { enrichReady = true; });
  }
  function enrichIp(ip) {
    if (S.enrich[ip]) return S.enrich[ip];
    var out = { ip: ip, internal: false, cc: "", country: "", asn: 0, asnName: "", asnLabel: "", threats: [], vpn: "" };
    try {
      var kind = X ? X.ipKind(ip) : null;
      out.internal = kind ? !kind.public : false;
      if (kind && kind.public) {
        if (Geo && Geo.lookup) { var g = Geo.lookup(ip, kind); if (g) { out.cc = g.cc; out.country = g.country; out.asn = g.asn; out.asnName = g.asnName; out.asnLabel = g.asnLabel; out.threats = g.threats || []; } }
        if (Vpn && Vpn.classify && S.vpnLists) { var v = Vpn.classify(ip, S.vpnLists, X.ipKind); if (v && v.status && v.status !== "Unknown" && v.status !== "Not a public IP") out.vpn = v.status; }
      }
    } catch (e) { /* leave defaults */ }
    S.enrich[ip] = out; return out;
  }
  function isTor(e) { return e.threats.some(function (t) { return /tor/i.test(t); }); }
  function isThreat(e) { return e.threats.length > 0; }

  /* ---------- chunked analysis ---------- */
  function analyzeFile(file, onProgress) {
    var parser = new window.PCAP.Parser({ onProgress: null });
    var CHUNK = 4 * 1024 * 1024, off = 0, size = file.size;
    function step() {
      if (S.cancel) return Promise.resolve({ cancelled: true });
      if (off >= size || parser.err) { parser.end(); return Promise.resolve(parser.result()); }
      var slice = file.slice(off, off + CHUNK);
      return slice.arrayBuffer().then(function (ab) {
        parser.push(new Uint8Array(ab));
        off += CHUNK;
        if (onProgress) onProgress(Math.min(1, off / size), parser.S.packets);
        return new Promise(function (r) { setTimeout(r, 0); }).then(step);
      });
    }
    return step();
  }

  /* ---------- findings ---------- */
  function buildFindings(a) {
    var out = [];
    // enrich the hosts/flows we will reason about
    var ipset = {};
    a.hosts.slice(0, 80).forEach(function (hst) { ipset[hst.ip] = 1; });
    a.flows.slice(0, 120).forEach(function (f) { ipset[f.src] = 1; ipset[f.dst] = 1; });
    Object.keys(ipset).forEach(enrichIp);

    // threat / tor / vpn hits
    var tor = [], threat = [], vpn = [];
    a.hosts.forEach(function (hst) {
      var e = S.enrich[hst.ip]; if (!e || e.internal) return;
      if (isTor(e)) tor.push(hst.ip);
      else if (isThreat(e)) threat.push(hst.ip);
      if (e.vpn) vpn.push(hst.ip + " (" + e.vpn + ")");
    });
    if (tor.length) out.push({ sev: "bad", title: "Tor exit traffic", why: "Communication with Tor exit node(s): " + tor.slice(0, 4).join(", ") + (tor.length > 4 ? " +" + (tor.length - 4) : "") });
    if (threat.length) out.push({ sev: "bad", title: "Threat-listed IP", why: "Traffic to address(es) on a bundled threat list: " + threat.slice(0, 4).join(", ") + (threat.length > 4 ? " +" + (threat.length - 4) : "") });

    // beaconing
    a.flows.forEach(function (f) {
      var e = S.enrich[f.dst] || enrichIp(f.dst);
      if (e.internal) return;
      if (f.gN >= 6 && f.gapMean >= 1 && f.gapMean <= 3600 && f.gapCv < 0.3 && f.pkts >= 6) {
        var sev = (isThreat(e) || isTor(e)) ? "bad" : "warn";
        out.push({ sev: sev, title: "Beaconing", why: f.src + " → " + f.dst + ":" + f.dport + " every ~" + fmtDur(f.gapMean) + " (" + f.pkts + " events, jitter " + Math.round(f.gapCv * 100) + "%)" });
      }
    });

    // plaintext credentials
    if (a.ftpCreds && a.ftpCreds.length) {
      var who = a.ftpCreds[0];
      out.push({ sev: "bad", title: "Plaintext credentials", why: "FTP " + a.ftpCreds.map(function (c) { return c.cmd; }).filter(function (v, i, s) { return s.indexOf(v) === i; }).join("/") + " sent in cleartext to " + who.dst });
    }

    // port scan
    (a.scans || []).forEach(function (sc) {
      var sev = sc.ndst >= 50 || sc.nport >= 500 ? "warn" : "warn";
      out.push({ sev: sev, title: "Possible scan", why: sc.src + " contacted " + sc.ndst + " host" + (sc.ndst === 1 ? "" : "s") + " across " + sc.nport + " port" + (sc.nport === 1 ? "" : "s") + (sc.window ? " in " + fmtDur(sc.window) : "") });
    });

    // DNS tunneling / DGA
    var dga = a.dns.filter(function (d) {
      var label = d.name.split(".")[0] || "";
      return label.length >= 30 || (label.length >= 12 && entropy(label) > 3.6);
    });
    if (dga.length) out.push({ sev: "warn", title: "Suspicious DNS", why: dga.length + " high-entropy / long-label name(s), e.g. " + dga[0].name.slice(0, 40) + " — possible DGA or tunneling" });
    var txt = a.dnsTypes && a.dnsTypes.TXT ? a.dnsTypes.TXT : 0;
    if (txt > 50) out.push({ sev: "warn", title: "DNS TXT volume", why: txt + " TXT queries — can indicate DNS tunneling" });
    if (a.nx > 100) out.push({ sev: "info", title: "High NXDOMAIN", why: a.nx + " NXDOMAIN responses — can indicate DGA" });

    // SMBv1
    if (a.smbv1) out.push({ sev: "warn", title: "Legacy SMBv1", why: "SMBv1 negotiated — deprecated and exploitable (e.g. EternalBlue)" });

    // cleartext HTTP
    if (a.cleartextHttpBytes > 0) out.push({ sev: "info", title: "Cleartext HTTP", why: fmtBytes(a.cleartextHttpBytes) + " of unencrypted HTTP to external hosts" });

    // VPN
    if (vpn.length) out.push({ sev: "info", title: "VPN / proxy network", why: "Peers on VPN or proxy networks: " + vpn.slice(0, 3).join(", ") });

    // large outbound transfer
    var bigOut = a.hosts.filter(function (hst) { var e = S.enrich[hst.ip]; return e && !e.internal && hst.in > 20 * 1024 * 1024; })
      .sort(function (x, y) { return y.in - x.in; });
    if (bigOut.length) out.push({ sev: "info", title: "Large outbound transfer", why: fmtBytes(bigOut[0].in) + " sent to external host " + bigOut[0].ip });

    var order = { bad: 0, warn: 1, info: 2 };
    out.sort(function (x, y) { return order[x.sev] - order[y.sev]; });
    return out;
  }

  /* ---------- IOCs ---------- */
  function buildIocs(a) {
    var items = [], seen = {};
    function add(type, v) { var key = type + "|" + String(v).toLowerCase(); if (!seen[key]) { seen[key] = 1; items.push({ type: type, value: v }); } }
    a.hosts.forEach(function (hst) { var e = S.enrich[hst.ip] || enrichIp(hst.ip); if (!e.internal && hst.ip.indexOf(":") === -1) add("ipv4", hst.ip); });
    var tlds = (typeof window !== "undefined" && window.SOC_TLDS) ? window.SOC_TLDS : "";
    var tldset = {}; if (tlds) tlds.split(" ").forEach(function (t) { if (t) tldset[t] = 1; });
    function okDom(d) { var last = d.split(".").pop().toLowerCase(); return tldset[last] === 1 || /^xn--/.test(last); }
    a.dns.concat(a.sni, a.httpHosts).forEach(function (d) { var n = d.name; if (/^[a-z0-9.\-]+$/i.test(n) && n.indexOf(".") > -1 && okDom(n)) add("domain", n); });
    a.httpUrls.forEach(function (u) { add("url", u.name); });
    return items.slice(0, 400);
  }

  /* ---------- charts ---------- */
  var PROTO_ORDER = [["tls", "--violet"], ["tcp", "--info"], ["udp", "--amber"], ["dns", "--magenta"], ["http", "--warn"], ["icmp", "--neutral"], ["other", "--line-strong"]];

  function drawTimeline(a) {
    var W = 720, H = 190, pad = 6;
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, width: "100%", preserveAspectRatio: "none", style: "display:block" });
    var T = a.timeline;
    if (!T || !T.buckets.length) { svg.appendChild(svgEl("text", { x: 10, y: 20, fill: css("--muted"), "font-size": 11, "font-family": "monospace" })).textContent = "no time data"; return svg; }
    var n = T.buckets.length;
    var totals = T.buckets.map(function (b) { b = b || {}; var t = 0; PROTO_ORDER.forEach(function (p) { t += b[p[0]] || 0; }); return t; });
    var max = Math.max.apply(null, totals) || 1;
    var x = function (i) { return pad + (n === 1 ? (W - 2 * pad) / 2 : i * (W - 2 * pad) / (n - 1)); };
    var y = function (v) { return H - pad - v / max * (H - 2 * pad); };
    var cum = new Array(n).fill(0);
    PROTO_ORDER.forEach(function (p) {
      var col = css(p[1]); var top = [], bot = [];
      for (var i = 0; i < n; i++) { var bk = T.buckets[i] || {}, b = cum[i], t = b + (bk[p[0]] || 0); bot.push([x(i), y(b)]); top.push([x(i), y(t)]); cum[i] = t; }
      var pts = top.concat(bot.reverse()).map(function (q) { return q[0].toFixed(1) + "," + q[1].toFixed(1); }).join(" ");
      svg.appendChild(svgEl("polygon", { points: pts, fill: col, "fill-opacity": "0.5", stroke: col, "stroke-opacity": "0.9", "stroke-width": "1" }));
    });
    return svg;
  }

  // Force-directed host graph: repulsion between nodes, springs along edges, gravity to centre.
  // Deterministic (seeded) and bounds-clamped, so each render settles the same way with no library.
  function drawGraph(a) {
    var W = 720, H = 320;
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, width: "100%", style: "display:block" });
    var top = a.hosts.slice(0, 24);
    if (!top.length) return svg;
    var maxB = Math.max.apply(null, top.map(function (hst) { return hst.bytes; })) || 1;
    var idx = {}, nodes = top.map(function (hst, i) {
      var e = S.enrich[hst.ip] || enrichIp(hst.ip); idx[hst.ip] = i;
      return { ip: hst.ip, bytes: hst.bytes, e: e, r: 7 + Math.sqrt(hst.bytes / maxB) * 18, m: 1 + Math.sqrt(hst.bytes / maxB) * 4 };
    });
    nodes.forEach(function (n, i) { var ang = i * 2.399963, rad = 44 + ((i * 97) % 120); n.x = W / 2 + Math.cos(ang) * rad; n.y = H / 2 + Math.sin(ang) * rad; n.vx = 0; n.vy = 0; });
    // aggregate edges among included nodes
    var emap = {};
    a.flows.slice(0, 250).forEach(function (f) {
      if (idx[f.src] == null || idx[f.dst] == null || idx[f.src] === idx[f.dst]) return;
      var lo = Math.min(idx[f.src], idx[f.dst]), hi = Math.max(idx[f.src], idx[f.dst]), k = lo + "-" + hi;
      if (!emap[k]) emap[k] = { a: lo, b: hi, w: 0, dst: f.dst }; emap[k].w += f.bytes;
    });
    var edges = Object.keys(emap).map(function (k) { return emap[k]; });
    var maxE = Math.max.apply(null, [1].concat(edges.map(function (e) { return e.w; })));
    var REP = 2600, SPR = 0.02, GRAV = 0.016, DAMP = 0.85, ITER = 320;
    for (var t = 0; t < ITER; t++) {
      for (var i = 0; i < nodes.length; i++) {
        var ni = nodes[i];
        for (var j = i + 1; j < nodes.length; j++) {
          var nj = nodes[j], dx = ni.x - nj.x, dy = ni.y - nj.y, d2 = dx * dx + dy * dy + 0.01, d = Math.sqrt(d2), f = REP / d2;
          var fx = dx / d * f, fy = dy / d * f; ni.vx += fx / ni.m; ni.vy += fy / ni.m; nj.vx -= fx / nj.m; nj.vy -= fy / nj.m;
        }
        ni.vx += (W / 2 - ni.x) * GRAV; ni.vy += (H / 2 - ni.y) * GRAV;
      }
      edges.forEach(function (e) {
        var A = nodes[e.a], B = nodes[e.b], dx = B.x - A.x, dy = B.y - A.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
        var ideal = 64 + 120 * (1 - e.w / maxE), f = (d - ideal) * SPR, fx = dx / d * f, fy = dy / d * f;
        A.vx += fx / A.m; A.vy += fy / A.m; B.vx -= fx / B.m; B.vy -= fy / B.m;
      });
      nodes.forEach(function (n) { n.vx *= DAMP; n.vy *= DAMP; n.x += n.vx; n.y += n.vy; n.x = Math.max(n.r + 6, Math.min(W - n.r - 6, n.x)); n.y = Math.max(n.r + 14, Math.min(H - n.r - 18, n.y)); });
    }
    edges.forEach(function (e) {
      var A = nodes[e.a], B = nodes[e.b], de = S.enrich[e.dst] || {};
      var col = (isThreat(de) || isTor(de)) ? css("--bad") : css("--line-strong"), w = 0.5 + Math.min(4, e.w / maxE * 4);
      svg.appendChild(svgEl("line", { x1: A.x.toFixed(1), y1: A.y.toFixed(1), x2: B.x.toFixed(1), y2: B.y.toFixed(1), stroke: col, "stroke-opacity": "0.33", "stroke-width": w.toFixed(1) }));
    });
    nodes.forEach(function (n) {
      var e = n.e, col = (isThreat(e) || isTor(e)) ? css("--bad") : e.internal ? css("--violet") : e.vpn ? css("--info") : css("--magenta");
      var c = svgEl("circle", { cx: n.x.toFixed(1), cy: n.y.toFixed(1), r: n.r.toFixed(1), fill: col, "fill-opacity": "0.2", stroke: col, "stroke-width": "2" });
      var ttl = svgEl("title"); ttl.textContent = n.ip + (e.internal ? " (internal)" : " " + (e.country || e.cc || "") + (e.asnLabel ? " · " + e.asnLabel : "") + (isTor(e) ? " · Tor" : isThreat(e) ? " · threat" : e.vpn ? " · " + e.vpn : "")) + " · " + fmtBytes(n.bytes); c.appendChild(ttl);
      svg.appendChild(c);
      if (n.r > 10.5) { var lbl = svgEl("text", { x: n.x.toFixed(1), y: (n.y + n.r + 11).toFixed(1), "text-anchor": "middle", fill: css("--text"), "font-size": "9.5", "font-family": "monospace" }); lbl.textContent = n.ip; svg.appendChild(lbl); }
    });
    return svg;
  }

  /* ---------- queries panel ---------- */
  var PLATS = [["kql", "Sentinel / Defender"], ["spl", "Splunk"], ["elastic", "Elastic"], ["cql", "CrowdStrike / LogScale"]];
  var QEXT = { kql: "kql", spl: "spl", elastic: "txt", cql: "cql" };
  function renderQueries(items) {
    if (!Q || !items.length) return card("Hunting queries", h("p", { class: "empty", text: "No external indicators to hunt on." }));
    var st = { plat: "kql", days: 30 }, body = h("div", {});
    var sec = h("section", { class: "card" }, [h("div", { class: "card-head" }, [h("h2", { text: "Hunting queries" }), h("span", { class: "sel-info", text: items.length + " indicators" })]), body]);
    function draw() {
      body.innerHTML = "";
      var plats = h("div", { class: "plats", role: "group" }, PLATS.map(function (p) {
        return h("button", { class: "plat", type: "button", "aria-pressed": String(st.plat === p[0]), text: p[1], on: { click: function () { st.plat = p[0]; draw(); } } });
      }));
      var q = ""; try { q = Q.build(items, st.days)[st.plat] || ""; } catch (e) { q = ""; }
      var copyBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy" }); copyBtn.addEventListener("click", function () { copyText(q, copyBtn); });
      var dlBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Download", on: { click: function () { download("tracerlens-hunt-" + st.plat + "." + QEXT[st.plat], q); } } });
      var days = h("select", { class: "field", "aria-label": "Time range" }, [1, 7, 30, 90].map(function (d) { var o = h("option", { value: String(d), text: "Last " + d + (d === 1 ? " day" : " days") }); if (st.days === d) o.selected = true; return o; }));
      days.addEventListener("change", function () { st.days = +days.value; draw(); });
      body.appendChild(plats);
      body.appendChild(h("div", { class: "qopts" }, [(st.plat === "elastic" || st.plat === "cql") ? h("span", { class: "sel-info", text: "Set the range in the platform's time picker" }) : days, q.trim() ? h("div", { class: "actions" }, [copyBtn, dlBtn]) : null]));
      body.appendChild(q.trim() ? h("pre", { class: "code" }, [h("code", { text: q })]) : h("p", { class: "empty", text: "No queryable indicators." }));
    }
    draw(); return sec;
  }

  /* ---------- small render helpers ---------- */
  function tile(num, label, color) { return h("div", { class: "tile tile-static", color: color }, [h("strong", { text: String(num) }), h("span", { text: label })]); }
  function card(title, body, sub) { return h("section", { class: "card" }, [title ? h("div", { class: "panel-head" }, [h("h2", { text: title }), sub ? h("span", { class: "panel-sub", text: sub }) : null]) : null, body]); }
  function sevPill(sev) { return { bad: "p-threat", warn: "p-warn", info: "p-geo" }[sev] || "p-geo"; }
  function sevWord(sev) { return { bad: "High", warn: "Suspicious", info: "Note" }[sev] || "Note"; }

  /* ---------- main render ---------- */
  function render(a) {
    var view = document.getElementById("view-res"); view.innerHTML = "";
    var findings = buildFindings(a);
    var iocs = buildIocs(a);
    var topSev = findings.length ? findings[0].sev : null;

    view.appendChild(h("div", { class: "res-bar" }, [
      h("div", {}, [
        h("h2", { class: "res-title", text: "Capture analysis" }),
        h("p", { class: "status" + (topSev === "bad" ? " err" : topSev === "warn" ? " warn" : ""), text:
          (S.fileName || "capture") + " · " + a.meta.format + " · " + fmtNum(a.meta.packets) + " packets · " + fmtDur(a.meta.duration) + (a.meta.truncated ? " · truncated at cap" : "") })
      ]),
      h("div", { class: "tools", style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Export report", on: { click: function () { download("tracerlens-report.txt", report(a, findings, iocs)); } } }),
        h("button", { class: "btn btn-ghost", type: "button", text: "Copy IOCs", on: { click: function (e) { copyText(iocs.map(function (i) { return i.value; }).join("\n"), e.currentTarget); } } }),
        h("button", { class: "btn btn-primary", type: "button", text: "New capture", on: { click: showInput } })
      ])
    ]));

    view.appendChild(h("div", { class: "tiles" }, [
      tile(fmtNum(a.meta.packets), "Packets", "var(--violet)"),
      tile(fmtNum(a.flowCount), "Flows", "var(--info)"),
      tile(fmtNum(a.hosts.length), "Hosts", "var(--magenta)"),
      tile(fmtDur(a.meta.duration), "Duration", "var(--amber)"),
      tile(fmtBytes(a.meta.bytes), "Volume", "var(--ok)"),
      tile(findings.length, "Findings", topSev === "bad" ? "var(--bad)" : topSev === "warn" ? "var(--warn)" : "var(--neutral)")
    ]));

    var grid = h("div", { class: "res-grid" });
    var left = h("div", { class: "col" });

    // timeline
    var tl = card("Traffic over time", drawTimeline(a), "stacked by protocol");
    tl.appendChild(h("div", { class: "legend" }, PROTO_ORDER.slice(0, 5).map(function (p) { return h("span", {}, [h("i", { class: "dot", color: "var(" + p[1] + ")", style: "background:var(" + p[1] + ")" }), p[0].toUpperCase()]); })));
    left.appendChild(tl);

    // protocols + services
    var protoTotal = 0; PROTO_ORDER.forEach(function (p) { protoTotal += a.proto[p[0]] || 0; }); protoTotal = protoTotal || 1;
    var protoBody = h("div", { class: "bars2" }, PROTO_ORDER.filter(function (p) { return a.proto[p[0]]; }).map(function (p) {
      var pct = Math.round((a.proto[p[0]] || 0) / protoTotal * 100);
      return h("div", { class: "bar2" }, [h("span", { class: "lbl", text: p[0].toUpperCase() }), h("span", { class: "track" }, [h("span", { class: "fill", style: "width:" + pct + "%;background:var(" + p[1] + ")" })]), h("span", { class: "val", text: pct + "%" })]);
    }));
    var svcBody = h("div", { class: "bars2" }, a.services.slice(0, 6).map(function (s) {
      var maxS = a.services[0] ? a.services[0].bytes : 1;
      return h("div", { class: "bar2" }, [h("span", { class: "lbl", text: s.port + " " + s.proto }), h("span", { class: "track" }, [h("span", { class: "fill", style: "width:" + Math.round(s.bytes / maxS * 100) + "%;background:var(--violet)" })]), h("span", { class: "val", text: fmtBytes(s.bytes) })]);
    }));
    left.appendChild(h("div", { class: "two" }, [card("Protocols", protoBody), card("Top services", svcBody)]));

    // top talkers
    var talkBody = h("div", { style: "display:grid;gap:7px" });
    talkBody.appendChild(h("div", { class: "rowhead talk", style: "display:grid;gap:10px;margin-bottom:2px" }, [h("span", { text: "Host" }), h("span", { text: "Geo" }), h("span", { text: "ASN / owner" }), h("span", { text: "Pkts" }), h("span", { text: "Bytes" })]));
    a.hosts.slice(0, 8).forEach(function (hst) {
      var e = S.enrich[hst.ip] || enrichIp(hst.ip);
      var geo = e.internal ? h("span", { class: "cc", style: "background:rgba(163,151,189,.12);color:var(--neutral)", text: "LAN" }) : h("span", { class: "cc", text: e.cc || "?" });
      var owner = e.internal ? h("span", { class: "dim", text: "Internal host" }) : h("span", { class: "dim" }, [document.createTextNode((e.asn ? "AS" + e.asn + " " : "") + (e.asnLabel || e.asnName || "")), isTor(e) ? h("span", { class: "tag t-tor", text: " Tor" }) : isThreat(e) ? h("span", { class: "tag t-threat", text: " threat" }) : e.vpn ? h("span", { class: "tag t-vpn", text: " " + e.vpn.split(" ")[0] }) : null]);
      talkBody.appendChild(h("div", { class: "trow talk" }, [h("span", { class: "mono2", text: hst.ip }), geo, owner, h("span", { class: "num", text: fmtNum(hst.pkts) }), h("span", { class: "num", text: fmtBytes(hst.bytes) })]));
    });
    left.appendChild(card("Top talkers", talkBody, a.hosts.length + " hosts · enriched offline"));

    // conversations
    var flowBody = h("div", { style: "display:grid;gap:7px" });
    flowBody.appendChild(h("div", { class: "rowhead flow", style: "display:grid;gap:10px;margin-bottom:2px" }, [h("span", { text: "Source → Destination" }), h("span", { text: "Service" }), h("span", { text: "Bytes" }), h("span", { text: "Duration" })]));
    a.flows.slice(0, 8).forEach(function (f) {
      var e = S.enrich[f.dst] || enrichIp(f.dst);
      var tag = isTor(e) ? h("span", { class: "tag t-tor", text: "Tor" }) : isThreat(e) ? h("span", { class: "tag t-threat", text: "bad" }) : null;
      flowBody.appendChild(h("div", { class: "trow flow" }, [h("span", { class: "mono2" }, [document.createTextNode(f.src + " → " + f.dst + " "), tag]), h("span", { class: "dim", text: f.dport + " / " + f.proto }), h("span", { class: "num", text: fmtBytes(f.bytes) }), h("span", { class: "num", text: fmtDur(f.dur) })]));
    });
    left.appendChild(card("Conversations", flowBody, fmtNum(a.flowCount) + " flows · top by bytes"));

    // host graph
    left.appendChild(card("Host communication graph", drawGraph(a), "node size = volume · red = flagged"));

    // DNS & SNI
    var names = a.dns.map(function (d) { return { name: d.name, count: d.count, kind: "dns" }; }).concat(a.sni.map(function (d) { return { name: d.name, count: d.count, kind: "sni" }; }));
    names.sort(function (x, y) { return y.count - x.count; });
    if (names.length) {
      var dnsBody = h("div", { style: "display:grid;gap:7px" });
      names.slice(0, 10).forEach(function (d) {
        var label = d.name.split(".")[0] || "";
        var flag = (label.length >= 30 || (label.length >= 12 && entropy(label) > 3.6)) ? h("span", { class: "tag t-threat", text: "high-entropy" }) : null;
        dnsBody.appendChild(h("div", { class: "trow dns" }, [h("span", { class: "mono2" }, [document.createTextNode(d.name + " "), flag]), h("span", { class: "num", text: fmtNum(d.count) })]));
      });
      left.appendChild(card("DNS & TLS SNI", dnsBody, "requested names"));
    }

    // TLS fingerprints (JA3 / JA3S)
    if ((a.ja3 && a.ja3.length) || (a.ja3s && a.ja3s.length)) {
      var fpBody = h("div", { style: "display:grid;gap:7px" });
      (a.ja3 || []).slice(0, 8).forEach(function (d) {
        var e = S.enrich[d.dst] || enrichIp(d.dst) || {};
        var tag = isTor(e) ? h("span", { class: "tag t-tor", text: "Tor" }) : isThreat(e) ? h("span", { class: "tag t-threat", text: "threat" }) : null;
        fpBody.appendChild(h("div", { class: "trow fp" }, [
          h("span", { class: "tbadge", color: "var(--info)", text: "JA3" }),
          h("div", { class: "fpmid" }, [h("span", { class: "mono2", text: d.hash }), h("span", { class: "dim" }, [document.createTextNode((d.sni || d.dst || "") + " "), tag])]),
          h("span", { class: "num", text: fmtNum(d.count) })
        ]));
      });
      (a.ja3s || []).slice(0, 4).forEach(function (d) {
        fpBody.appendChild(h("div", { class: "trow fp" }, [
          h("span", { class: "tbadge", color: "var(--magenta)", text: "JA3S" }),
          h("div", { class: "fpmid" }, [h("span", { class: "mono2", text: d.hash }), h("span", { class: "dim", text: d.dst || "" })]),
          h("span", { class: "num", text: fmtNum(d.count) })
        ]));
      });
      left.appendChild(card("TLS fingerprints", fpBody, (a.ja3Total || 0) + " JA3 · " + (a.ja3sTotal || 0) + " JA3S"));
    }

    grid.appendChild(left);

    // RIGHT (sticky)
    var right = h("div", { class: "col out-card" });
    var fBody = h("div", {});
    if (findings.length) findings.forEach(function (f) { fBody.appendChild(h("div", { class: "flagline" }, [h("span", { class: "pill " + sevPill(f.sev), text: sevWord(f.sev) }), h("span", { class: "flagwhy" }, [h("b", { text: f.title + " — " }), document.createTextNode(f.why)])])); });
    else fBody.appendChild(h("p", { class: "empty", text: "No anomalies flagged in this capture." }));
    right.appendChild(card("Findings", fBody, String(findings.length)));

    // geo by country
    var byCc = {}; a.hosts.forEach(function (hst) { var e = S.enrich[hst.ip] || enrichIp(hst.ip); if (e.internal || !e.cc) return; byCc[e.cc] = (byCc[e.cc] || 0) + hst.bytes; });
    var ccs = Object.keys(byCc).map(function (k) { return { cc: k, bytes: byCc[k] }; }).sort(function (x, y) { return y.bytes - x.bytes; }).slice(0, 8);
    if (ccs.length) {
      var geoBody = h("div", {});
      var maxCc = ccs[0].bytes || 1;
      ccs.forEach(function (c) { geoBody.appendChild(h("div", { class: "maprow" }, [h("span", { class: "cc", text: c.cc }), h("span", { class: "track", style: "height:9px;border-radius:6px;background:rgba(255,255,255,0.05);overflow:hidden" }, [h("span", { style: "display:block;height:100%;width:" + Math.round(c.bytes / maxCc * 100) + "%;background:var(--violet);border-radius:6px" })]), h("span", { class: "num", text: fmtBytes(c.bytes) })])); });
      right.appendChild(card("Destinations by country", geoBody, "offline geo"));
    }

    // queries
    right.appendChild(renderQueries(iocs));

    grid.appendChild(right);
    view.appendChild(grid);

    view.appendChild(h("p", { class: "note", style: "text-align:center;margin-top:20px", text: "Parsed locally in your browser" + (a.meta.malformed ? " · " + a.meta.malformed + " unparsed packets" : "") + (a.flowOverflow ? " · " + fmtNum(a.flowOverflow) + " flows beyond display cap" : "") + ". Nothing was uploaded." }));

    document.getElementById("view-input").classList.add("hidden");
    view.classList.remove("hidden");
    document.body.classList.add("is-res");
    window.scrollTo(0, 0); view.focus();
  }

  function report(a, findings, iocs) {
    var L = [];
    L.push("SOC Toolkit - Tracer-Lens report");
    L.push("Parsed locally in the browser. Nothing was uploaded.");
    L.push("");
    L.push("== CAPTURE =="); L.push("file: " + (S.fileName || "")); L.push("format: " + a.meta.format + "  packets: " + a.meta.packets + "  bytes: " + a.meta.bytes + "  duration: " + fmtDur(a.meta.duration) + (a.meta.truncated ? "  (truncated at cap)" : "")); L.push("");
    L.push("== FINDINGS (" + findings.length + ") =="); if (!findings.length) L.push("(none)"); findings.forEach(function (f) { L.push("[" + sevWord(f.sev) + "] " + f.title + " - " + f.why); }); L.push("");
    L.push("== TOP TALKERS =="); a.hosts.slice(0, 15).forEach(function (hst) { var e = S.enrich[hst.ip] || {}; L.push("  " + hst.ip + "  " + (e.internal ? "internal" : (e.cc || "") + " " + (e.asnLabel || "")) + "  " + fmtBytes(hst.bytes)); }); L.push("");
    L.push("== INDICATORS =="); iocs.forEach(function (i) { L.push("  [" + i.type + "] " + i.value); }); L.push("");
    if ((a.ja3 && a.ja3.length) || (a.ja3s && a.ja3s.length)) {
      L.push("== TLS FINGERPRINTS ==");
      (a.ja3 || []).forEach(function (d) { L.push("  JA3  " + d.hash + "  " + (d.sni || d.dst || "") + "  x" + d.count); });
      (a.ja3s || []).forEach(function (d) { L.push("  JA3S " + d.hash + "  " + (d.dst || "") + "  x" + d.count); });
      L.push("");
    }
    if (Q && iocs.length) { var b = {}; try { b = Q.build(iocs, 30); } catch (e) { } L.push("== HUNT QUERIES =="); PLATS.forEach(function (p) { var q = (b[p[0]] || "").trim(); if (q) { L.push(""); L.push("--- " + p[1] + " ---"); L.push(q); } }); }
    return L.join("\n");
  }

  /* ---------- views / wiring ---------- */
  function showInput() {
    document.getElementById("view-res").classList.add("hidden");
    document.getElementById("view-input").classList.remove("hidden");
    document.body.classList.remove("is-res");
    setProgress(false); S.cancel = false; S.enrich = {};
    window.scrollTo(0, 0);
  }
  function setStatus(msg, cls) { var s = document.getElementById("input-status"); if (s) { s.textContent = msg; s.className = "status" + (cls ? " " + cls : ""); } }
  function setProgress(on, frac, label) {
    var w = document.getElementById("progress-wrap"); if (!w) return;
    w.hidden = !on;
    if (on) { document.getElementById("progress-bar").style.width = Math.round((frac || 0) * 100) + "%"; document.getElementById("progress-label").textContent = label || ""; }
  }

  function b64ToBytes(b64) { var bin = atob(b64), out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
  var SAMPLE_B64 = "1MOyoQIABAAAAAAAAAAAAAAABAABAAAA6AMAAAAAAACXAAAAlwAAAKq7zN3uAaq7zN3uAggARQAAiQAAQABABgAACgoEEWgVBbLDUQG7AAAAAQAAAABQGP//AAAAABYDAQBcAQAAWAMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQTARMCAQAAKwAAABcAFQAAEmNkbi5jbG91ZGZsYXJlLm5ldAAKAAYABAAdABcACwACAQDoAwAAoIYBAG0AAABtAAAAqrvM3e4BqrvM3e4CCABFAABfAABAAEAGAABoFQWyCgoEEQG7w1EAAAABAAAAAFAY//8AAAAAFgMDADICAAAuAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATAQAABgArAAIDBOgDAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw1oBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQEAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw1sBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw1wBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJwEAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw10BuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANgEAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw14BuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQFAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw18BuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAFAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2ABuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIwFAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2EBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMgFAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2IBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQGAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2MBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAGAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2QBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwGAAAAAAAAAQEAAAEBAACqu8zd7gGqu8zd7gIIAEUAAPMAAEAAQAYAAAoKBBG53GUtw2UBuwAAAAEAAAAAUBj//wAAAAAXAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOkDAAAAAAAA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";

  function runAnalysis(file) {
    if (S.running) return;
    S.running = true; S.cancel = false; S.enrich = {}; S.fileName = file.name;
    setStatus("");
    setProgress(true, 0, "Reading…");
    var big = file.size > 150 * 1024 * 1024;
    if (big) setProgress(true, 0, "Large capture (" + fmtBytes(file.size) + ") — parsing may take a while…");
    Promise.resolve().then(function () { return enrichReady ? null : loadEnrich(); })
      .then(function () {
        return analyzeFile(file, function (frac, pkts) { setProgress(true, frac, fmtNum(pkts) + " packets · " + Math.round(frac * 100) + "%"); });
      })
      .then(function (res) {
        S.running = false; setProgress(false);
        if (!res || res.cancelled) { setStatus("Cancelled."); return; }
        if (!res.ok) { setStatus(res.error || "Could not parse this file.", "err"); return; }
        if (res.meta.packets === 0) { setStatus("No packets found. Is this an Ethernet capture?", "warn"); return; }
        S.analysis = res; render(res);
      })
      .catch(function (err) { S.running = false; setProgress(false); setStatus("Error: " + (err && err.message ? err.message : "unexpected"), "err"); });
  }

  function bind() {
    var fileInput = document.getElementById("file-input");
    var drop = document.getElementById("drop-zone");
    if (!drop) return;
    function handle(file) { if (file) runAnalysis(file); }
    if (fileInput) fileInput.addEventListener("change", function () { handle(fileInput.files[0]); fileInput.value = ""; });
    drop.addEventListener("dragover", function (e) { e.preventDefault(); drop.classList.add("dragging"); });
    drop.addEventListener("dragleave", function () { drop.classList.remove("dragging"); });
    drop.addEventListener("drop", function (e) { e.preventDefault(); drop.classList.remove("dragging"); var f = e.dataTransfer && e.dataTransfer.files[0]; if (f) handle(f); });

    var sample = document.getElementById("sample-btn");
    if (sample) sample.addEventListener("click", function () {
      try { var bytes = b64ToBytes(SAMPLE_B64); var f = new File([bytes], "sample-capture.pcap", { type: "application/vnd.tcpdump.pcap" }); runAnalysis(f); }
      catch (e) { setStatus("Sample unavailable.", "err"); }
    });
    var cancelBtn = document.getElementById("cancel-btn");
    if (cancelBtn) cancelBtn.addEventListener("click", function () { S.cancel = true; });

    var yr = document.getElementById("year"); if (yr) yr.textContent = new Date().getFullYear();
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bind); else bind();
  }
})();
