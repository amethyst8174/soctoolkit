// Offline IP lookups: country, ASN and threat-list membership (adapted from header-lens).
// Data comes from /data/*.js on this site; nothing is sent anywhere.
(function (root) {
  "use strict";

  var db = null;
  var MAIL_ASN = { 8075: "Microsoft", 15169: "Google", 36647: "Yahoo", 26211: "Proofpoint", 22843: "Proofpoint", 30031: "Mimecast", 11377: "SendGrid", 54994: "Mailgun", 14618: "Amazon", 16509: "Amazon", 13335: "Cloudflare" };
  var HOSTING_ASN = { 14061: "DigitalOcean", 16276: "OVH", 24940: "Hetzner", 63949: "Akamai Linode", 20473: "Vultr", 51167: "Contabo", 45102: "Alibaba Cloud", 132203: "Tencent Cloud", 31898: "Oracle Cloud", 60781: "LeaseWeb", 16265: "LeaseWeb", 9009: "M247", 36352: "ColoCrossing", 53667: "FranTech", 212238: "Datacamp", 49505: "Selectel", 202425: "IP Volume", 44477: "Stark Industries", 8100: "QuadraNet", 197540: "netcup", 12876: "Scaleway", 136907: "Huawei Cloud", 22612: "Namecheap", 47583: "Hostinger", 204915: "Hostinger", 399629: "BL Networks", 210644: "Aeza", 216246: "Aeza", 215540: "Global Connectivity Solutions", 211252: "Delis", 62904: "Eonix", 40021: "Contabo US", 46664: "VolumeDrive" };

  function b64bytes(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function gunzip(bytes) {
    var ds = new DecompressionStream("gzip");
    var stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Response(stream).arrayBuffer().then(function (b) { return new Uint8Array(b); });
  }

  function decode(buf) {
    var pos = 0;
    function vi() { // unsigned LEB128, values up to 2^53
      var result = 0, mul = 1, b;
      do { b = buf[pos++]; result += (b & 0x7f) * mul; mul *= 128; } while (b & 0x80);
      return result;
    }
    function section(v6) {
      var n = vi(), starts = v6 ? new Float64Array(n) : new Uint32Array(n), vals = new Uint32Array(n), acc = 0, i;
      for (i = 0; i < n; i++) { acc += vi(); starts[i] = acc; }
      for (i = 0; i < n; i++) vals[i] = vi();
      return { starts: starts, vals: vals };
    }
    var c4 = section(false), c6 = section(true), a4 = section(false), a6 = section(true);
    var m = vi(), asns = new Uint32Array(m);
    for (var i = 0; i < m; i++) asns[i] = vi();
    return { c4: c4, c6: c6, a4: a4, a6: a6, asns: asns };
  }

  function find(t, key) {
    var lo = 0, hi = t.starts.length - 1;
    while (lo < hi) { var mid = (lo + hi + 1) >> 1; if (t.starts[mid] <= key) lo = mid; else hi = mid - 1; }
    return t.vals[lo];
  }

  function load() {
    if (db) return Promise.resolve(db);
    var G = root.HL_GEO;
    if (!G || typeof DecompressionStream === "undefined") return Promise.resolve(null);
    return gunzip(b64bytes(G.bin)).then(function (buf) {
      db = decode(buf);
      db.cc = G.cc; db.names = G.names.split("\n"); db.built = G.built;
      var T = root.HL_THREAT; db.threat = T ? T.lists : {}; db.threatBuilt = T ? T.built : "";
      return db;
    }).catch(function () { return null; });
  }

  function inRanges(ranges, n) {
    var lo = 0, hi = ranges.length - 1;
    while (lo <= hi) { var mid = (lo + hi) >> 1, r = ranges[mid]; if (n < r[0]) hi = mid - 1; else if (n > r[1]) lo = mid + 1; else return true; }
    return false;
  }

  // kind = HL.ipKind(ip): { v: 4|6, n: number, public: bool }
  function lookup(ip, kind) {
    if (!db || !kind || !kind.public) return null;
    var v6 = kind.v === 6;
    var ci = find(v6 ? db.c6 : db.c4, kind.n), ai = find(v6 ? db.a6 : db.a4, kind.n);
    var cc = db.cc[ci] || "", asn = ai ? db.asns[ai] : 0, name = ai ? db.names[ai] : "";
    var W = root.HL_WORLD;
    var type = asn && MAIL_ASN[asn] ? "mail" : asn && HOSTING_ASN[asn] ? "hosting" : "";
    var threats = [];
    if (!v6) for (var k in db.threat) if (inRanges(db.threat[k].ranges, kind.n)) threats.push(db.threat[k].name);
    return {
      cc: cc, country: cc && W && W.names[cc] ? W.names[cc] : cc, asn: asn, asnName: name,
      asnType: type, asnLabel: type === "mail" ? MAIL_ASN[asn] : type === "hosting" ? HOSTING_ASN[asn] : name.split(" ")[0], threats: threats
    };
  }

  root.SOCGeo = { load: load, lookup: lookup, info: function () { return db ? { built: db.built, threatBuilt: db.threatBuilt, lists: Object.keys(db.threat).map(function (k) { return db.threat[k].name; }) } : null; } };
})(typeof globalThis !== "undefined" ? globalThis : this);
