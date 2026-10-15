// IOC extraction engine. Pure functions: no DOM, no network, no storage, no AI.
// The same input always gives the same output (ordered by first appearance).
(function (root) {
  "use strict";

  var VERSION = "1.0.0";

  // ---------- Refanging ----------
  // Undo common defanging so defanged reports are read correctly. Returns the refanged line.
  function refang(s) {
    return s
      .replace(/\bh(?:xx|\*\*|XX|xX|Xx)p(s?)(\[?:\]?|:)\/\//g, "http$1://")
      .replace(/\bhxxp(s?)\b/gi, "http$1")
      .replace(/\bfxp:\/\//gi, "ftp://")
      .replace(/\[:\/\/\]|\[:\]\/\//g, "://")
      .replace(/\s?(\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\[DOT\]|\(DOT\))\s?/g, ".")
      .replace(/\\\./g, ".")
      .replace(/\s?(\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}|\[AT\]|\(AT\))\s?/g, "@")
      .replace(/\[\/\]/g, "/");
  }

  // ---------- Reference lists ----------
  var TLD = null;
  function tldSet() {
    if (TLD) return TLD;
    TLD = {};
    (root.SOC_TLDS || "").split(" ").forEach(function (t) { if (t) TLD[t] = 1; });
    return TLD;
  }
  // File extensions that look like domain endings in prose (".zip", ".sh", ".py" are real TLDs too).
  var FILE_EXT = /^(exe|dll|scr|pif|bat|cmd|ps1|psm1|psd1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|msix|lnk|iso|img|vhd|vhdx|cab|jar|war|apk|ipa|dmg|pkg|deb|rpm|zip|rar|7z|gz|tgz|tar|bz2|xz|doc|docx|docm|dot|dotm|xls|xlsx|xlsm|xlsb|xla|xlam|ppt|pptx|pptm|ppam|pdf|rtf|txt|log|csv|tsv|json|xml|yml|yaml|html|htm|mht|php|asp|aspx|jsp|cgi|pl|py|rb|sh|ps|c|cpp|h|cs|go|rs|java|class|png|jpg|jpeg|gif|bmp|svg|ico|webp|tif|tiff|mp3|mp4|mov|avi|wav|mkv|sys|drv|ocx|cpl|dat|tmp|bin|ini|cfg|conf|config|bak|old|db|sqlite|one|onepkg|eml|msg|pst|ost|evtx|etl|pcap|pcapng|reg|inf|chm|url|library-ms|md|lock|so|dylib|elf|ko|dll_|xll|wll|gadget|application|appx|appxbundle|torrent|crx|xpi|vsix|nupkg|whl|egg|py_|lua|kts|kt|scpt|app|command|desktop|service|timer|plist)$/i;
  var RISKY_FILE = /\.(exe|dll|scr|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|msix|lnk|iso|img|vhd|vhdx|cab|jar|docm|dotm|xlsm|xlam|pptm|ppam|one|xll|chm|reg|cpl|sys|dmg|pkg|apk|sh|py|elf|so|dylib|zip|rar|7z|tgz|gz)$/i;
  // Well-known services that appear in reports as references, not as attacker infrastructure.
  var BENIGN = /^(microsoft\.com|windows\.com|windowsupdate\.com|office\.com|office365\.com|microsoftonline\.com|live\.com|outlook\.com|bing\.com|msn\.com|azure\.com|google\.com|googleapis\.com|gstatic\.com|youtube\.com|gmail\.com|apple\.com|icloud\.com|amazon\.com|cloudflare\.com|github\.com|gitlab\.com|twitter\.com|x\.com|linkedin\.com|facebook\.com|instagram\.com|wikipedia\.org|mitre\.org|nist\.gov|cisa\.gov|us-cert\.gov|ncsc\.gov\.uk|virustotal\.com|abuse\.ch|shodan\.io|w3\.org|mozilla\.org|adobe\.com|oracle\.com|ietf\.org|iana\.org|first\.org|owasp\.org|sans\.org|python\.org|npmjs\.com|docker\.com|ubuntu\.com|debian\.org|redhat\.com|apache\.org|cve\.org|attack\.mitre\.org|schemas\.microsoft\.com|schemas\.openxmlformats\.org|purl\.org|xmlsoap\.org|digicert\.com|letsencrypt\.org|verisign\.com|godaddy\.com|zoom\.us|slack\.com|dropbox\.com|box\.com|akamai\.net|akamaihd\.net|cloudfront\.net)$/;
  var RESERVED_DOMAIN = /(^|\.)(example\.(com|net|org)|example|test|invalid|localhost|local|internal|lan|home\.arpa|corp)$/;
  var SL = /\.(co|com|net|org|gov|ac|edu|ltd|plc|nic|res|or|ne|go|gob|mil|nhs|police|sch)\.[a-z]{2}$/;
  function orgDomain(d) { var p = d.split("."); if (p.length <= 2) return d; return SL.test(d) ? p.slice(-3).join(".") : p.slice(-2).join("."); }

  var EMPTY_HASH = { "d41d8cd98f00b204e9800998ecf8427f": 1, "da39a3ee5e6b4b0d3255bfef95601890afd80709": 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": 1, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": 1 };

  // ---------- IP helpers ----------
  function v4num(ip) { var p = ip.split("."); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3]; }
  var V4R = [["0.0.0.0", 8, "This network"], ["10.0.0.0", 8, "Private"], ["100.64.0.0", 10, "Carrier NAT"], ["127.0.0.0", 8, "Loopback"], ["169.254.0.0", 16, "Link-local"], ["172.16.0.0", 12, "Private"], ["192.0.0.0", 24, "Reserved"], ["192.0.2.0", 24, "Documentation"], ["192.168.0.0", 16, "Private"], ["198.18.0.0", 15, "Benchmarking"], ["198.51.100.0", 24, "Documentation"], ["203.0.113.0", 24, "Documentation"], ["224.0.0.0", 4, "Multicast"], ["240.0.0.0", 4, "Reserved"], ["255.255.255.255", 32, "Broadcast"]];
  function v6groups(ip) {
    if (ip.indexOf(".") > -1) return null;
    var parts = ip.split("::"); if (parts.length > 2) return null;
    var head = parts[0] ? parts[0].split(":") : [], tail = parts.length > 1 && parts[1] ? parts[1].split(":") : [];
    var fill = 8 - head.length - tail.length;
    if (fill < 0 || (parts.length === 1 && fill !== 0)) return null;
    var g = head.concat(new Array(parts.length > 1 ? fill : 0).fill("0"), tail);
    if (g.some(function (x) { return !/^[0-9a-f]{1,4}$/i.test(x); })) return null;
    return g.map(function (x) { return parseInt(x, 16); });
  }
  function ipKind(ip) {
    var bare = ip.split("/")[0];
    if (bare.indexOf(":") === -1) {
      var n = v4num(bare);
      for (var i = 0; i < V4R.length; i++) { var r = V4R[i], mask = r[1] === 0 ? 0 : (~0 << (32 - r[1])) >>> 0; if (((n & mask) >>> 0) === v4num(r[0])) return { v: 4, n: n, public: false, label: r[2] }; }
      return { v: 4, n: n, public: true };
    }
    var g = v6groups(bare); if (!g) return { v: 6, public: false, label: "Unparsed" };
    if (g.every(function (x) { return x === 0; })) return { v: 6, public: false, label: "Unspecified" };
    if (g.slice(0, 7).every(function (x) { return x === 0; })) return { v: 6, public: false, label: "Loopback" };
    if ((g[0] & 0xfe00) === 0xfc00) return { v: 6, public: false, label: "Private (ULA)" };
    if ((g[0] & 0xffc0) === 0xfe80) return { v: 6, public: false, label: "Link-local" };
    if (g[0] === 0x2001 && g[1] === 0x0db8) return { v: 6, public: false, label: "Documentation" };
    if ((g[0] & 0xff00) === 0xff00) return { v: 6, public: false, label: "Multicast" };
    return { v: 6, n: g[0] * 4294967296 + g[1] * 65536 + g[2], public: true };
  }

  // ---------- Patterns ----------
  var RE = {
    url: /\b(?:https?|ftp|sftp|ws|wss):\/\/[^\s<>"'`{}|\\^\]\[]+/gi,
    email: /\b[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b/gi,
    ipv4: /(?:^|[^\w.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/(?:3[0-2]|[12]?\d))?)(?![\w.]?\d)/g,
    ipv6: /(?:^|[^\w:.])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/\d{1,3})?)(?![\w:])/gi,
    domain: /(?:^|[^\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63}))(?![\w-]|\.[a-z0-9])/gi,
    sha512: /\b[a-f0-9]{128}\b/gi, sha256: /\b[a-f0-9]{64}\b/gi, sha1: /\b[a-f0-9]{40}\b/gi, md5: /\b[a-f0-9]{32}\b/gi,
    cve: /\bCVE-(?:19|20)\d{2}-\d{4,7}\b/gi,
    attack: /\b(?:T[0-9]{4}(?:\.[0-9]{3})?|TA00[0-9]{2})\b/g,
    registry: /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s"'<>|]+/g,
    winpath: /(?:\b[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\[A-Za-z0-9._-]+\\)(?:[^\\\s"'<>|:*?]+\\)*[^\\\s"'<>|:*?]*/g,
    filename: /(?:^|[^\w\\/.@-])([\w$][\w$.-]{0,120}?\.(?:exe|dll|scr|pif|bat|cmd|ps1|psm1|vbs|vbe|jse|wsf|wsh|hta|msi|lnk|iso|img|vhdx?|cab|jar|docm|dotm|xlsm|xlam|pptm|one|xll|chm|cpl|sys|dmg|apk|elf|zip|rar|7z|dat|bin|js|sh|py))(?!\w|\.\w)/gi
  };

  function trimUrl(u) {
    u = u.replace(/[.,;:!?'"»”’]+$/, "");
    // drop an unbalanced trailing ")"
    while (/\)$/.test(u) && (u.split("(").length - 1) < (u.split(")").length - 1)) u = u.slice(0, -1);
    return u.replace(/[.,;:!?]+$/, "");
  }
  function hostOfUrl(u) { var m = u.match(/^[a-z]+:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^/:?#]+)/i); return m ? m[1].replace(/^\[|\]$/g, "").toLowerCase() : ""; }
  function isAllSame(h) { return /^(.)\1+$/.test(h) || /^0+$/.test(h); }

  // ---------- Main ----------
  // opts: { exclude: ["yourco.com", ...], lookup: fn(ip, kind) -> {country, asn, asnName, threats[]} }
  function extract(text, opts) {
    opts = opts || {};
    var tlds = tldSet();
    var exclude = (opts.exclude || []).map(function (d) { return d.trim().toLowerCase().replace(/^\*\./, ""); }).filter(Boolean);
    var items = {}, order = 0;
    var lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
    function add(type, value, key, lineNo, col, line, defanged, extra) {
      var k = type + "|" + key;
      var it = items[k];
      if (!it) {
        it = items[k] = { type: type, value: value, key: key, count: 0, line: lineNo + 1, pos: order++, context: line.trim().slice(0, 400), defanged: false, tags: [], meta: {} };
        if (extra) for (var e in extra) it.meta[e] = extra[e];
      }
      it.count++;
      if (defanged) it.defanged = true;
      return it;
    }
    lines.forEach(function (orig, ln) {
      var line = refang(orig);
      var changed = line !== orig;
      var covered = []; // spans already claimed (URLs, emails) so their parts aren't double-typed as file names
      function claimed(a, b) { return covered.some(function (c) { return a < c[1] && b > c[0]; }); }
      function wasDefanged(v) { return changed && orig.indexOf(v) === -1; }
      var m;
      RE.url.lastIndex = 0;
      while ((m = RE.url.exec(line))) {
        var u = trimUrl(m[0]);
        if (u.length < 10) continue;
        covered.push([m.index, m.index + u.length]);
        add("url", u, u, ln, m.index, orig, wasDefanged(u), { host: hostOfUrl(u) });
      }
      RE.email.lastIndex = 0;
      while ((m = RE.email.exec(line))) {
        var em = m[0].toLowerCase(), dom = em.split("@")[1], tld = dom.split(".").pop();
        if (!tlds[tld]) continue;
        covered.push([m.index, m.index + m[0].length]);
        add("email", em, em, ln, m.index, orig, wasDefanged(m[0]));
      }
      RE.ipv4.lastIndex = 0;
      while ((m = RE.ipv4.exec(line))) {
        var ip = m[1], at = m.index + m[0].indexOf(ip);
        var before = line.slice(Math.max(0, at - 14), at);
        if (/\b(v|ver|version|build|release|rev|firmware|update|kb)\s*:?\s*$/i.test(before)) continue; // version numbers
        if (/^0\./.test(ip) && ip.indexOf("/") === -1) continue;
        add(ip.indexOf("/") > -1 ? "cidr" : "ipv4", ip, ip, ln, at, orig, wasDefanged(ip));
      }
      RE.ipv6.lastIndex = 0;
      while ((m = RE.ipv6.exec(line))) {
        var c6 = m[1].replace(/:+$/, function (x) { return x.length > 1 ? "::" : ""; });
        var bare = c6.split("/")[0];
        if (bare.split(":").length < 3) continue;
        if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(bare)) continue; // clock times
        var g = v6groups(bare);
        if (!g) continue;
        if (!/[a-f]/i.test(bare) && bare.indexOf("::") === -1 && bare.split(":").length < 6) continue;
        add("ipv6", c6.toLowerCase(), c6.toLowerCase(), ln, m.index, orig, wasDefanged(c6));
      }
      ["sha512", "sha256", "sha1", "md5"].forEach(function (t) {
        RE[t].lastIndex = 0;
        while ((m = RE[t].exec(line))) {
          var hsh = m[0].toLowerCase();
          if (isAllSame(hsh) || /^[0-9]+$/.test(hsh)) continue;
          // skip hashes that are part of a longer hex run already matched as a bigger hash
          if (claimed(m.index, m.index + m[0].length)) continue;
          covered.push([m.index, m.index + m[0].length]);
          add(t, hsh, hsh, ln, m.index, orig, false);
        }
      });
      RE.cve.lastIndex = 0;
      while ((m = RE.cve.exec(line))) if (!claimed(m.index, m.index + m[0].length)) add("cve", m[0].toUpperCase(), m[0].toUpperCase(), ln, m.index, orig, false);
      RE.attack.lastIndex = 0;
      while ((m = RE.attack.exec(line))) if (!claimed(m.index, m.index + m[0].length)) add("attack", m[0], m[0], ln, m.index, orig, false);
      RE.registry.lastIndex = 0;
      while ((m = RE.registry.exec(line))) { var rk = m[0].replace(/[.,;:)]+$/, ""); covered.push([m.index, m.index + m[0].length]); add("registry", rk, rk.toLowerCase(), ln, m.index, orig, false); }
      RE.winpath.lastIndex = 0;
      while ((m = RE.winpath.exec(line))) {
        var wp = m[0].replace(/[.,;:)]+$/, "");
        if (wp.length < 6 || claimed(m.index, m.index + 1)) continue;
        covered.push([m.index, m.index + m[0].length]);
        add("filepath", wp, wp.toLowerCase(), ln, m.index, orig, false);
      }
      RE.domain.lastIndex = 0;
      while ((m = RE.domain.exec(line))) {
        var d = m[1].toLowerCase(), dat = m.index + m[0].indexOf(m[1]);
        var last = d.split(".").pop();
        if (!tlds[last] && !/^xn--/.test(last)) continue;
        var inUrlOrEmail = claimed(dat, dat + d.length);
        var defangedHere = wasDefanged(m[1]);
        // "invoice.zip" in prose is a file, not a domain, unless it was defanged or is inside a URL.
        if (FILE_EXT.test(last) && !defangedHere && !inUrlOrEmail && d.split(".").length === 2) {
          if (RISKY_FILE.test(d)) add("filename", m[1], d, ln, dat, orig, false);
          continue;
        }
        if (d.split(".").length === 2 && d.length <= 5 && !defangedHere) continue; // "e.g", "i.e", "a.m"
        covered.push([dat, dat + d.length]);
        add("domain", d, d, ln, dat, orig, defangedHere);
      }
      RE.filename.lastIndex = 0;
      while ((m = RE.filename.exec(line))) {
        var fn = m[1].trim(), fat = m.index + m[0].indexOf(m[1]);
        if (claimed(fat, fat + fn.length)) continue;
        if (fn.length < 3) continue;
        add("filename", fn, fn.toLowerCase(), ln, fat, orig, false);
      }
    });

    // Domains seen only as URL hosts or email domains are listed too, so domain hunts cover them.
    Object.keys(items).forEach(function (k) {
      var it = items[k];
      var host = it.type === "url" ? it.meta.host : it.type === "email" ? it.value.split("@")[1] : "";
      if (!host) return;
      var isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.indexOf(":") > -1;
      var dk = (isIp ? (host.indexOf(":") > -1 ? "ipv6|" : "ipv4|") : "domain|") + host;
      if (!items[dk]) items[dk] = { type: isIp ? (host.indexOf(":") > -1 ? "ipv6" : "ipv4") : "domain", value: host, key: host, count: 1, line: it.line, pos: it.pos + 0.5, context: it.context, defanged: it.defanged, tags: [], meta: { from: it.type } };
    });

    // Tags and enrichment
    var list = Object.keys(items).map(function (k) { return items[k]; });
    list.forEach(function (it) {
      var t = it.type;
      if (t === "ipv4" || t === "ipv6" || t === "cidr") {
        var kind = ipKind(it.value);
        it.meta.kind = kind;
        if (!kind.public) it.tags.push({ k: "internal", label: kind.label });
        else if (opts.lookup && t !== "cidr") {
          var g = opts.lookup(it.value, kind);
          if (g) {
            it.meta.geo = g;
            if (g.threats && g.threats.length) it.tags.push({ k: "threat", label: g.threats.join(", ") });
          }
        }
      }
      if (t === "domain" || t === "url" || t === "email") {
        var host = t === "domain" ? it.value : t === "url" ? it.meta.host : it.value.split("@")[1];
        var org = orgDomain(host || "");
        if (host && RESERVED_DOMAIN.test(host)) it.tags.push({ k: "reserved", label: "Reserved or test domain" });
        else if (host && exclude.some(function (x) { return host === x || host.slice(-(x.length + 1)) === "." + x || org === x; })) it.tags.push({ k: "excluded", label: "Your domain" });
        else if (host && BENIGN.test(org) || BENIGN.test(host || "")) it.tags.push({ k: "benign", label: "Well-known service" });
        if (host && /(^|\.)xn--/.test(host)) it.tags.push({ k: "warn", label: "Punycode" });
      }
      if (/^(md5|sha1|sha256|sha512)$/.test(t) && EMPTY_HASH[it.value]) it.tags.push({ k: "benign", label: "Hash of an empty file" });
      if (t === "filename" && RISKY_FILE.test(it.value)) it.tags.push({ k: "warn", label: "Risky file type" });
      if (it.defanged) it.tags.push({ k: "defanged", label: "Defanged in source" });
      it.include = !it.tags.some(function (x) { return x.k === "internal" || x.k === "reserved" || x.k === "benign" || x.k === "excluded"; }) && t !== "attack" && t !== "cve";
    });
    list.sort(function (a, b) { return a.pos - b.pos; });
    return { version: VERSION, items: list, lines: lines.length, chars: String(text || "").length };
  }

  function defang(type, v) {
    if (/^(md5|sha1|sha256|sha512|cve|attack|registry|filepath|filename)$/.test(type)) return v;
    return v.replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp").replace(/\./g, "[.]").replace(/@/g, "[@]").replace(/:\/\//, "[://]");
  }

  var api = { VERSION: VERSION, extract: extract, refang: refang, defang: defang, ipKind: ipKind, orgDomain: orgDomain };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SOCExtract = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
