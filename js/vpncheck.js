// VPN IP checker engine. Checks addresses against offline published lists in data/vpn.js.
// Pure lookups: no network, no storage. The same address and data always give the same answer.
// It never guesses: an address is only called VPN, Tor or Private Relay when a list says so,
// and everything else is reported as Unknown.
(function (root) {
  "use strict";

  var VERSION = "1.0.0";

  // ---------- Address normalisation ----------
  function v4hex(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    var out = "";
    for (var i = 1; i <= 4; i++) { var n = +m[i]; if (n > 255 || (m[i].length > 1 && m[i][0] === "0")) return null; out += ("0" + n.toString(16)).slice(-2); }
    return out;
  }
  function v6hex(s) {
    s = s.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
    var tail4 = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s), extra = [];
    if (tail4) {
      var h = v4hex(tail4[1]); if (!h) return null;
      extra = [h.slice(0, 4), h.slice(4)];
      s = s.slice(0, -tail4[1].length) + "0:0";
    }
    if (!/^[0-9a-f:]+$/.test(s)) return null;
    var parts = s.split("::");
    if (parts.length > 2) return null;
    var head = parts[0] ? parts[0].split(":") : [], tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
    var fill = 8 - head.length - tail.length;
    if (fill < 0 || (parts.length === 1 && fill !== 0)) return null;
    var zeros = [];
    if (parts.length === 2) for (var z = 0; z < fill; z++) zeros.push("0");
    var groups = head.concat(zeros, tail);
    if (groups.length !== 8) return null;
    if (extra.length) { groups[6] = extra[0]; groups[7] = extra[1]; }
    for (var i = 0; i < 8; i++) { if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null; groups[i] = ("000" + groups[i]).slice(-4); }
    return groups.join("");
  }
  // Returns { ip, v: 4|6, hex, mappedFrom } or null for text that is not an address.
  function parse(raw) {
    var s = String(raw || "").trim();
    var h4 = v4hex(s);
    if (h4) return { ip: s, v: 4, hex: h4 };
    var h6 = v6hex(s);
    if (!h6) return null;
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) is checked as the IPv4 address it carries.
    if (h6.slice(0, 24) === "00000000000000000000ffff") {
      var b = h6.slice(24), v4 = [0, 2, 4, 6].map(function (i) { return parseInt(b.slice(i, i + 2), 16); }).join(".");
      return { ip: v4, v: 4, hex: b, mappedFrom: s };
    }
    return { ip: s, v: 6, hex: h6 };
  }

  // ---------- Range lookup over packed "starthex endhex" records ----------
  function inPacked(packed, hex) {
    if (!packed) return false;
    var w = hex.length, rec = w * 2, n = packed.length / rec, lo = 0, hi = n - 1;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1, at = mid * rec;
      var start = packed.substr(at, w), end = packed.substr(at + w, w);
      if (hex < start) hi = mid - 1;
      else if (hex > end) lo = mid + 1;
      else return true;
    }
    return false;
  }

  // ---------- Classification ----------
  var RULES = [
    { id: "tor", status: "Tor exit node", confidence: "High",
      why: "Listed by the Tor Project as a Tor exit node as of the list date shown in "Lists checked"." },
    { id: "icloud", status: "iCloud Private Relay", confidence: "High",
      why: "Listed by Apple as an iCloud Private Relay egress range as of the list date shown in "Lists checked"." },
    { id: "vpn", status: "VPN network", confidence: "Medium",
      why: "In X4B's curated list of known VPN networks. The list is built mainly from network ownership, so this exact address could be another service on the same network." }
  ];

  // lists: { id: { v4: packedString, v6: packedString } }, loaded: ids that are available.
  function classify(input, lists, kindOf) {
    var p = parse(input);
    if (!p) return { input: String(input), valid: false, status: "Not an IP address", confidence: "", note: "This is not a valid IPv4 or IPv6 address." };
    var res = { input: String(input), ip: p.ip, v: p.v, valid: true, mappedFrom: p.mappedFrom || "", matches: [], network: "", status: "", confidence: "", note: "" };
    var kind = kindOf ? kindOf(p.ip) : null;
    if (kind && !kind.public) {
      res.status = "Not a public IP"; res.confidence = "";
      res.note = (kind.label || "Private or reserved") + " address. Public VPN and proxy lists do not apply.";
      res.kind = kind;
      return res;
    }
    res.kind = kind;
    for (var id in lists) if (inPacked(p.v === 4 ? lists[id].v4 : lists[id].v6, p.hex)) res.matches.push(id);
    var dc = res.matches.indexOf("dc") > -1;
    res.network = dc ? "Hosting or datacenter" : "";
    for (var i = 0; i < RULES.length; i++) {
      if (res.matches.indexOf(RULES[i].id) > -1) {
        res.status = RULES[i].status; res.confidence = RULES[i].confidence; res.note = RULES[i].why;
        return res;
      }
    }
    res.status = "Unknown";
    res.confidence = "";
    res.note = dc
      ? "Hosting or datacenter network. VPNs, proxies and ordinary servers all run on networks like this, and this address is not in any VPN list."
      : "Not in any list checked. This does not prove it is not a VPN: small, new or self-hosted VPNs and residential proxies are not listed.";
    return res;
  }

  // ---------- Browser data loading ----------
  var cache = null;
  function b64bytes(s) { var bin = atob(s), out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
  function gunzipText(b64) {
    if (!b64) return Promise.resolve("");
    var stream = new Blob([b64bytes(b64)]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(stream).text();
  }
  function load() {
    if (cache) return Promise.resolve(cache);
    var D = root.SOC_VPN;
    if (!D || typeof DecompressionStream === "undefined") return Promise.resolve(null);
    var ids = Object.keys(D.lists), jobs = [];
    var lists = {};
    ids.forEach(function (id) {
      lists[id] = {};
      jobs.push(gunzipText(D.lists[id].v4).then(function (t) { lists[id].v4 = t; }));
      jobs.push(gunzipText(D.lists[id].v6).then(function (t) { lists[id].v6 = t; }));
    });
    return Promise.all(jobs).then(function () { cache = lists; return lists; }).catch(function () { return null; });
  }
  function sources() {
    var D = root.SOC_VPN, all = ["tor", "icloud", "vpn", "dc"], names = { tor: "Tor exit node", icloud: "iCloud Private Relay", vpn: "Known VPN network", dc: "Hosting or datacenter network" };
    return all.map(function (id) {
      var l = D && D.lists[id];
      return l ? { id: id, name: l.name, source: l.source, url: l.url, updated: l.updated, ranges: l.n4 + l.n6, available: true }
        : { id: id, name: names[id], available: false };
    });
  }

  // Pulls IPv4/IPv6 addresses out of any text (defanged forms included), in first-seen order.
  function addresses(text) {
    var seen = {}, out = [], X = root.SOCExtract;
    if (X) {
      X.extract(text, {}).items.forEach(function (i) {
        if ((i.type === "ipv4" || i.type === "ipv6") && !seen[i.value]) { seen[i.value] = 1; out.push(i.value); }
      });
    }
    return out;
  }

  var api = { VERSION: VERSION, parse: parse, classify: classify, inPacked: inPacked, load: load, sources: sources, addresses: addresses };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SOCVpn = api;
})(typeof window !== "undefined" ? window : globalThis);
