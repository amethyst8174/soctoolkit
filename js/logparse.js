// Log Normalizer engine for the SOC Toolkit's Timeline Merger.
// Parses syslog (RFC 3164 / RFC 5424), CEF, LEEF and JSON / JSON-lines into one normalized
// event shape, converts every timestamp to epoch-ms UTC, and merges several sources into a
// single time-sorted timeline.
//
// Privacy: this file is pure logic. It has no DOM, no browser storage, no cookies and makes no
// network calls. It only transforms strings the caller already holds in memory.
(function () {
  "use strict";
  var VERSION = "1.0.0";

  var root = typeof window !== "undefined" ? window : globalThis;

  var MONTHS = { Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6, Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12 };

  // ---- severity -----------------------------------------------------------
  // Normalized levels: "high" | "med" | "low" | "info" | "".
  var SYSLOG_SEV = ["high", "high", "high", "high", "med", "low", "info", "info"]; // emerg..debug
  var SYSLOG_SEV_WORD = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"];

  function levelFromWord(w) {
    if (!w) return "";
    var s = String(w).toLowerCase();
    if (/\b(emerg|alert|crit|fatal|error|err|severe)\b/.test(s)) return "high";
    if (/\b(warn|warning)\b/.test(s)) return "med";
    if (/\b(notice|info|information|informational)\b/.test(s)) return "low";
    if (/\b(debug|trace|verbose)\b/.test(s)) return "info";
    return "";
  }
  function levelFromNum(n, scale) {
    // scale "cef" = 0..10, scale "num" = generic numeric
    n = Number(n);
    if (isNaN(n)) return "";
    if (scale === "cef") return n >= 7 ? "high" : n >= 4 ? "med" : n >= 1 ? "low" : "info";
    return "";
  }

  // ---- timestamps ---------------------------------------------------------
  // assume: minutes east of UTC for naive timestamps, or the string "local".

  function fromNaive(Y, Mo, D, h, mi, s, ms, assume) {
    if (assume === "local") return new Date(Y, Mo - 1, D, h, mi, s, ms || 0).getTime();
    return Date.UTC(Y, Mo - 1, D, h, mi, s, ms || 0) - (Number(assume) || 0) * 60000;
  }

  function inferYear(Mo, D, h, mi, s, assume) {
    var now = new Date();
    var y = now.getUTCFullYear();
    var guess = fromNaive(y, Mo, D, h, mi, s, 0, assume);
    // A log line can't be more than ~a day in the future; if it is, it belongs to last year.
    if (guess - now.getTime() > 86400000) y -= 1;
    return y;
  }

  // Parse a timestamp out of the START of a string. Returns { epoch, text, len } or null.
  function parseTsHead(str, assume) {
    var m;

    // RFC 5424 / ISO 8601: 2026-10-22T19:16:03(.sss)?(Z|+hh:mm)
    m = str.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?/);
    if (m) {
      var ms = m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0;
      var epoch;
      if (m[8]) {
        var iso = m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] +
          (m[7] ? "." + m[7] : "") + (m[8] === "Z" ? "Z" : m[8].replace(/(\d{2})(\d{2})$/, "$1:$2"));
        epoch = Date.parse(iso);
      } else {
        epoch = fromNaive(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], ms, assume);
      }
      if (!isNaN(epoch)) return { epoch: epoch, text: m[0], len: m[0].length };
    }

    // RFC 3164 (BSD): "Oct 22 19:16:03" (no year, no tz).
    m = str.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (m && MONTHS[m[1]]) {
      var Mo = MONTHS[m[1]], D = +m[2], h = +m[3], mi = +m[4], s = +m[5];
      var Y = inferYear(Mo, D, h, mi, s, assume);
      return { epoch: fromNaive(Y, Mo, D, h, mi, s, 0, assume), text: m[0], len: m[0].length };
    }

    return null;
  }

  // Parse a standalone timestamp value (whole string), including epoch numbers. Returns epoch or NaN.
  function parseTsValue(v, assume) {
    if (v == null) return NaN;
    if (typeof v === "number") return v < 1e12 ? v * 1000 : v; // seconds vs ms
    var s = String(v).trim();
    if (/^\d{10}$/.test(s)) return +s * 1000;
    if (/^\d{13}$/.test(s)) return +s;
    if (/^\d+(\.\d+)?$/.test(s)) { var n = parseFloat(s); return n < 1e12 ? n * 1000 : n; }
    var head = parseTsHead(s, assume);
    if (head) return head.epoch;
    var p = Date.parse(s);
    return isNaN(p) ? NaN : p;
  }

  // ---- field helpers ------------------------------------------------------
  function firstKey(obj, keys) {
    for (var i = 0; i < keys.length; i++) {
      for (var k in obj) {
        if (obj.hasOwnProperty(k) && k.toLowerCase() === keys[i]) return obj[k];
      }
    }
    return undefined;
  }

  // CEF / LEEF extension: key=value pairs. CEF escapes with backslash; LEEF uses a delimiter char.
  function parseKv(str, delim) {
    var out = {};
    if (delim === "\t" || delim === "|" || (delim && delim !== " ")) {
      // Fixed single-char delimiter (LEEF): split, then key=value each.
      str.split(delim).forEach(function (pair) {
        var eq = pair.indexOf("=");
        if (eq > 0) out[pair.slice(0, eq).trim()] = pair.slice(eq + 1);
      });
      return out;
    }
    // Space-delimited with escaped characters (CEF). Values may contain spaces; a new key is
    // "word=" preceded by whitespace. Walk the string and split on " key=" boundaries.
    var re = /([^\s=\\]+)=((?:\\.|[^\\])*?)(?=\s+[^\s=\\]+=|$)/g, m;
    while ((m = re.exec(str))) {
      out[m[1]] = m[2].replace(/\\([=|\\n r])/g, function (_, c) { return c === "n" ? "\n" : c === "r" ? "\r" : c; });
    }
    return out;
  }

  // ---- per-format parsers -------------------------------------------------
  // Each returns a normalized event object (without source/line/raw, added by the caller).

  function parseSyslog(line, assume) {
    var rest = line, sev = "", sevText = "", host = "", app = "";
    var pri = rest.match(/^<(\d{1,3})>/);
    if (pri) {
      var p = +pri[1];
      sev = SYSLOG_SEV[p % 8]; sevText = SYSLOG_SEV_WORD[p % 8];
      rest = rest.slice(pri[0].length);
    }
    // RFC 5424 has a version digit right after PRI: "<13>1 2026-..."
    var ver = rest.match(/^(\d{1,2})\s+/);
    var is5424 = pri && ver && /^\d{4}-\d{2}-\d{2}/.test(rest.slice(ver[0].length));
    if (is5424) rest = rest.slice(ver[0].length);

    var ts = parseTsHead(rest, assume);
    var epoch = null, tsText = "";
    if (ts) { epoch = ts.epoch; tsText = ts.text; rest = rest.slice(ts.len).replace(/^\s+/, ""); }

    var msg = rest;
    if (is5424) {
      // HOSTNAME APP-NAME PROCID MSGID [SD] MSG
      var parts = rest.split(/\s+/);
      host = nd(parts[0]); app = nd(parts[1]);
      var procid = nd(parts[2]);
      // skip MSGID and structured data to reach MSG
      var after = rest.replace(/^\S+\s+\S+\s+\S+\s+\S+\s+/, "");
      after = after.replace(/^(\[(?:[^\]\\]|\\.)*\]\s*)+/, ""); // drop [SD ...]
      msg = after || rest;
      if (procid) app = app + (app ? "[" + procid + "]" : procid);
    } else {
      // BSD: HOST TAG[pid]: message
      var bm = rest.match(/^(\S+)\s+([^\s:\[]+)(\[\d+\])?:\s?(.*)$/);
      if (bm) { host = bm[1]; app = bm[2] + (bm[3] || ""); msg = bm[4]; }
    }
    return { epoch: epoch, tsText: tsText, format: "syslog", host: host, app: app, sev: sev, sevText: sevText, message: msg, fields: {} };
  }

  function parseCef(line, assume) {
    // Optional syslog-ish prefix before CEF: "<pri>Mmm dd hh:mm:ss host CEF:..."
    var pre = {}, epoch = null, tsText = "", host = "";
    var idx = line.indexOf("CEF:");
    if (idx > 0) {
      var prefix = line.slice(0, idx).replace(/^<\d{1,3}>/, "").trim();
      var ts = parseTsHead(prefix, assume);
      if (ts) { epoch = ts.epoch; tsText = ts.text; prefix = prefix.slice(ts.len).trim(); }
      if (prefix) host = prefix.split(/\s+/)[0];
    }
    var body = line.slice(idx);
    // CEF:Ver|Vendor|Product|Version|SigID|Name|Severity|Extension   (pipes escaped as \|)
    var head = splitEscaped(body.replace(/^CEF:/, ""), "|", 7);
    var name = head[5] || "", sevRaw = head[6] || "", ext = head[7] || "";
    var fields = parseKv(ext, " ");
    if (epoch == null) {
      var rt = fields.rt || fields.start || fields.end;
      if (rt != null) { var e = parseTsValue(rt, assume); if (!isNaN(e)) epoch = e; }
    }
    if (!host) host = fields.dvchost || fields.dhost || fields.shost || "";
    var app = (head[1] ? head[1] + " " : "") + (head[2] || "");
    var sev = levelFromNum(sevRaw, "cef"); if (!sev) sev = levelFromWord(sevRaw);
    var msg = fields.msg ? name + " — " + fields.msg : name;
    return { epoch: epoch, tsText: tsText, format: "cef", host: host, app: app.trim(), sev: sev, sevText: String(sevRaw), message: msg, fields: fields };
  }

  function parseLeef(line, assume) {
    var epoch = null, tsText = "", host = "";
    var idx = line.indexOf("LEEF:");
    if (idx > 0) {
      var prefix = line.slice(0, idx).replace(/^<\d{1,3}>/, "").trim();
      var ts = parseTsHead(prefix, assume);
      if (ts) { epoch = ts.epoch; tsText = ts.text; prefix = prefix.slice(ts.len).trim(); }
      if (prefix) host = prefix.split(/\s+/)[0];
    }
    var body = line.slice(idx).replace(/^LEEF:/, "");
    // LEEF:1.0|Vendor|Product|Version|EventID|attrs
    // LEEF:2.0|Vendor|Product|Version|EventID|<delim>|attrs   (delim e.g. x09 or a literal char)
    var ver = body.slice(0, 3);
    var parts = splitEscaped(body, "|", ver === "2.0" ? 6 : 5);
    var delim = "\t", attrs;
    if (ver === "2.0") {
      var d = parts[5] || "";
      if (/^x[0-9a-fA-F]{2}$/.test(d)) delim = String.fromCharCode(parseInt(d.slice(1), 16));
      else if (d) delim = d;
      attrs = parts[6] || "";
    } else {
      attrs = parts[5] || "";
    }
    var fields = parseKv(attrs, delim);
    if (epoch == null && fields.devTime != null) { var e = parseTsValue(fields.devTime, assume); if (!isNaN(e)) epoch = e; }
    if (!host) host = fields.devname || fields.identHostName || fields.src || "";
    var app = ((parts[1] || "") + " " + (parts[2] || "")).trim();
    var sev = levelFromWord(fields.sev); if (!sev && fields.sev != null && /^\d+$/.test(fields.sev)) sev = levelFromNum(Math.round(+fields.sev / 1), "cef");
    var evId = parts[4] || "";
    var msg = fields.msg || fields.cat || evId || "";
    return { epoch: epoch, tsText: tsText, format: "leef", host: host, app: app, sev: sev, sevText: String(fields.sev || ""), message: String(msg), fields: fields };
  }

  function parseJsonObj(obj, assume) {
    var tsRaw = firstKey(obj, ["@timestamp", "timestamp", "time", "ts", "_time", "eventtime", "date", "datetime"]);
    var epoch = tsRaw != null ? parseTsValue(tsRaw, assume) : NaN;
    var host = firstKey(obj, ["host", "hostname", "computer", "computername", "source_host", "beat.hostname"]);
    var app = firstKey(obj, ["app", "application", "program", "process", "processname", "logsource", "service", "source"]);
    var sevRaw = firstKey(obj, ["severity", "level", "loglevel", "syslog_severity", "priority", "sev"]);
    var msg = firstKey(obj, ["message", "msg", "event", "text", "raw", "log", "description"]);
    var used = {};
    ["@timestamp", "timestamp", "time", "ts", "_time", "eventtime", "date", "datetime", "host", "hostname", "computer",
     "computername", "source_host", "app", "application", "program", "process", "processname", "logsource", "service",
     "source", "severity", "level", "loglevel", "syslog_severity", "priority", "sev", "message", "msg", "event", "text",
     "raw", "log", "description"].forEach(function (k) { used[k] = 1; });
    var fields = {};
    for (var k in obj) if (obj.hasOwnProperty(k) && !used[k.toLowerCase()]) fields[k] = obj[k];
    var sev = levelFromWord(sevRaw); if (!sev && sevRaw != null && /^\d+$/.test(String(sevRaw))) sev = SYSLOG_SEV[(+sevRaw) % 8] || "";
    if (msg == null) msg = JSON.stringify(obj);
    return {
      epoch: isNaN(epoch) ? null : epoch, tsText: tsRaw != null ? String(tsRaw) : "", format: "json",
      host: host != null ? String(host) : "", app: app != null ? String(app) : "",
      sev: sev, sevText: sevRaw != null ? String(sevRaw) : "", message: typeof msg === "string" ? msg : JSON.stringify(msg), fields: fields
    };
  }

  // ---- small utilities ----------------------------------------------------
  function nd(v) { return v === "-" || v == null ? "" : v; }

  // Split on a delimiter that may be backslash-escaped, into at most `limit`+1 parts (last keeps rest).
  function splitEscaped(str, delim, limit) {
    var out = [], cur = "", i = 0;
    while (i < str.length) {
      var c = str[i];
      if (c === "\\" && i + 1 < str.length) { cur += c + str[i + 1]; i += 2; continue; }
      if (c === delim && out.length < limit) { out.push(cur); cur = ""; i++; continue; }
      cur += c; i++;
    }
    out.push(cur);
    return out.map(function (s) { return s.replace(/\\(.)/g, "$1"); });
  }

  function detect(line) {
    if (/\bCEF:\d/.test(line)) return "cef";
    if (/\bLEEF:\d/.test(line)) return "leef";
    var t = line.replace(/^\uFEFF/, "").trimStart ? line.trimStart() : line.replace(/^\s+/, "");
    if (t.charAt(0) === "{") return "json";
    if (/^<\d{1,3}>/.test(line) || /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(line) || /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(line)) return "syslog";
    return "raw";
  }

  function parseLine(line, fmt, assume) {
    var f = fmt === "auto" ? detect(line) : fmt;
    try {
      if (f === "cef") return parseCef(line, assume);
      if (f === "leef") return parseLeef(line, assume);
      if (f === "json") return parseJsonObj(JSON.parse(line), assume);
      if (f === "syslog") return parseSyslog(line, assume);
    } catch (e) { /* fall through to raw */ }
    // raw / unparsed: still try to lift a leading timestamp so it can be placed on the timeline.
    var ts = parseTsHead(line.replace(/^<\d{1,3}>/, ""), assume);
    return { epoch: ts ? ts.epoch : null, tsText: ts ? ts.text : "", format: "raw", host: "", app: "", sev: "", sevText: "", message: line, fields: {} };
  }

  // ---- public API ---------------------------------------------------------
  // sources: [{ name, text }]
  // opts: { format: "auto"|"syslog"|"cef"|"leef"|"json", assumeTz: <minutes east of UTC> | "local" }
  function parseSources(sources, opts) {
    opts = opts || {};
    var fmt = opts.format || "auto";
    var assume = opts.assumeTz == null ? 0 : opts.assumeTz;
    var events = [], counts = { syslog: 0, cef: 0, leef: 0, json: 0, raw: 0 }, untimed = 0;

    (sources || []).forEach(function (src) {
      var name = src.name || "source";
      var text = String(src.text || "");
      var objs = null;
      // Whole-text JSON array support (one source that is a JSON array of events).
      if (fmt === "json" || fmt === "auto") {
        var trimmed = text.replace(/^\uFEFF/, "").trim();
        if (trimmed.charAt(0) === "[") {
          try { var arr = JSON.parse(trimmed); if (Array.isArray(arr)) objs = arr; } catch (e) { objs = null; }
        }
      }
      if (objs) {
        objs.forEach(function (o, i) {
          var ev = (o && typeof o === "object") ? parseJsonObj(o, assume) : parseLine(String(o), "auto", assume);
          finalize(ev, name, i + 1, typeof o === "string" ? o : JSON.stringify(o));
        });
      } else {
        var lines = text.split(/\r\n|\r|\n/);
        lines.forEach(function (ln, i) {
          if (!ln.trim()) return;
          var ev = parseLine(ln, fmt, assume);
          finalize(ev, name, i + 1, ln);
        });
      }
    });

    function finalize(ev, name, lineNo, raw) {
      ev.source = name; ev.line = lineNo; ev.raw = raw;
      if (!ev.message) ev.message = raw;
      counts[ev.format] = (counts[ev.format] || 0) + 1;
      if (ev.epoch == null || isNaN(ev.epoch)) { ev.epoch = null; untimed++; }
      events.push(ev);
    }

    var timed = events.filter(function (e) { return e.epoch != null; });
    var noTime = events.filter(function (e) { return e.epoch == null; });
    // Stable sort by time, then source, then original line, so equal timestamps stay deterministic.
    timed.sort(function (a, b) {
      return a.epoch - b.epoch || cmp(a.source, b.source) || (a.line - b.line);
    });
    timed.forEach(function (e, i) { e.order = i + 1; });

    var span = timed.length ? { from: timed[0].epoch, to: timed[timed.length - 1].epoch } : null;
    return {
      version: VERSION,
      events: timed,
      untimedEvents: noTime,
      stats: {
        total: events.length, timed: timed.length, untimed: untimed,
        sources: (sources || []).length, byFormat: counts, span: span
      }
    };
  }

  function cmp(a, b) { a = a || ""; b = b || ""; return a < b ? -1 : a > b ? 1 : 0; }

  root.LOGNORM = {
    VERSION: VERSION,
    parseSources: parseSources,
    parseLine: parseLine,
    parseTsValue: parseTsValue,
    detect: detect
  };
})();
