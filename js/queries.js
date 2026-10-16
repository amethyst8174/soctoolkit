// Hunt query templates and exports. Pure functions: the same IOCs always give the same text.
(function (root) {
  "use strict";

  function group(items) {
    var g = { ips: [], cidrs: [], domains: [], urls: [], emails: [], md5: [], sha1: [], sha256: [], sha512: [], files: [], paths: [], registry: [] };
    items.forEach(function (i) {
      var t = i.type, v = i.value;
      if (t === "ipv4" || t === "ipv6") g.ips.push(v);
      else if (t === "cidr") g.cidrs.push(v);
      else if (t === "domain") g.domains.push(v);
      else if (t === "url") g.urls.push(v);
      else if (t === "email") g.emails.push(v);
      else if (t === "md5" || t === "sha1" || t === "sha256" || t === "sha512") g[t].push(v);
      else if (t === "filename") g.files.push(v);
      else if (t === "filepath") g.paths.push(v);
      else if (t === "registry") g.registry.push(v);
    });
    return g;
  }
  var esc = function (v) { return String(v).replace(/\\/g, "\\\\").replace(/"/g, "\\\""); };
  var dq = function (a) { return a.map(function (v) { return "\"" + esc(v) + "\""; }).join(", "); };
  var sq = function (a) { return a.map(function (v) { return "'" + String(v).replace(/'/g, "''") + "'"; }).join(", "); };
  var base = function (p) { return p.split("\\").pop(); };

  // ---------- Microsoft Sentinel / Defender XDR (KQL) ----------
  function kql(g, days) {
    var out = [], t = "ago(" + days + "d)";
    if (g.ips.length) out.push("// IP addresses: endpoint connections, sign-ins and firewall logs\nlet iocIPs = dynamic([" + dq(g.ips) + "]);\nunion isfuzzy=true\n  (DeviceNetworkEvents | where Timestamp > " + t + " | where RemoteIP in (iocIPs) | project Timestamp, Source=\"DeviceNetworkEvents\", DeviceName, Account=InitiatingProcessAccountName, IOC=RemoteIP, Detail=RemoteUrl),\n  (SigninLogs | where TimeGenerated > " + t + " | where IPAddress in (iocIPs) | project Timestamp=TimeGenerated, Source=\"SigninLogs\", DeviceName=\"\", Account=UserPrincipalName, IOC=IPAddress, Detail=AppDisplayName),\n  (CommonSecurityLog | where TimeGenerated > " + t + " | where DestinationIP in (iocIPs) or SourceIP in (iocIPs) | project Timestamp=TimeGenerated, Source=\"CommonSecurityLog\", DeviceName=DeviceName, Account=SourceUserName, IOC=iff(DestinationIP in (iocIPs), DestinationIP, SourceIP), Detail=Activity)\n| sort by Timestamp desc");
    if (g.cidrs.length) out.push("// IP ranges\nlet iocRanges = dynamic([" + dq(g.cidrs) + "]);\nDeviceNetworkEvents\n| where Timestamp > " + t + "\n| where ipv4_is_in_any_range(RemoteIP, iocRanges)\n| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, InitiatingProcessFileName");
    var doms = g.domains.slice();
    if (doms.length || g.urls.length) out.push("// Domains and URLs: DNS, web traffic, email links and clicks\nlet iocDomains = dynamic([" + dq(doms) + "]);\nlet iocUrls = dynamic([" + dq(g.urls) + "]);\nunion isfuzzy=true\n  (DeviceNetworkEvents | where Timestamp > " + t + " | where RemoteUrl has_any (iocDomains) or RemoteUrl in (iocUrls) | project Timestamp, Source=\"DeviceNetworkEvents\", DeviceName, IOC=RemoteUrl),\n  (DeviceEvents | where Timestamp > " + t + " | where ActionType == \"DnsQueryResponse\" | extend Q=tostring(parse_json(AdditionalFields).DnsQueryString) | where Q has_any (iocDomains) | project Timestamp, Source=\"DNS\", DeviceName, IOC=Q),\n  (EmailUrlInfo | where Timestamp > " + t + " | where UrlDomain in~ (iocDomains) or Url in (iocUrls) | project Timestamp, Source=\"EmailUrlInfo\", DeviceName=\"\", IOC=Url),\n  (UrlClickEvents | where Timestamp > " + t + " | where Url has_any (iocDomains) or Url in (iocUrls) | project Timestamp, Source=\"UrlClickEvents\", DeviceName=AccountUpn, IOC=Url)\n| sort by Timestamp desc");
    if (g.emails.length) out.push("// Sender addresses\nlet iocSenders = dynamic([" + dq(g.emails) + "]);\nEmailEvents\n| where Timestamp > " + t + "\n| where SenderFromAddress in~ (iocSenders) or SenderMailFromAddress in~ (iocSenders)\n| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, NetworkMessageId");
    var anyHash = g.md5.length || g.sha1.length || g.sha256.length;
    if (anyHash) out.push("// File hashes: files, processes and email attachments\nlet iocSHA256 = dynamic([" + dq(g.sha256) + "]);\nlet iocSHA1 = dynamic([" + dq(g.sha1) + "]);\nlet iocMD5 = dynamic([" + dq(g.md5) + "]);\nunion isfuzzy=true DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents, EmailAttachmentInfo\n| where Timestamp > " + t + "\n| where SHA256 in (iocSHA256) or SHA1 in (iocSHA1) or MD5 in (iocMD5)\n| project Timestamp, Type, DeviceName, FileName, FolderPath, SHA256, RecipientEmailAddress");
    if (g.files.length || g.paths.length) out.push("// File names and paths\nlet iocFiles = dynamic([" + dq(uniq(g.files.concat(g.paths.map(base)))) + "]);\nunion isfuzzy=true DeviceFileEvents, DeviceProcessEvents\n| where Timestamp > " + t + "\n| where FileName in~ (iocFiles)\n| project Timestamp, Type, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256");
    if (g.registry.length) out.push("// Registry keys\nlet iocKeys = dynamic([" + dq(g.registry.map(regFull)) + "]);\nDeviceRegistryEvents\n| where Timestamp > " + t + "\n| where RegistryKey has_any (iocKeys)\n| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName");
    return out.join("\n\n");
  }
  function regFull(k) { return k.replace(/^HKLM\\/i, "HKEY_LOCAL_MACHINE\\").replace(/^HKCU\\/i, "HKEY_CURRENT_USER\\").replace(/^HKCR\\/i, "HKEY_CLASSES_ROOT\\").replace(/^HKU\\/i, "HKEY_USERS\\"); }
  function uniq(a) { var s = {}; return a.filter(function (x) { var k = x.toLowerCase(); if (s[k]) return false; s[k] = 1; return true; }); }

  // ---------- Splunk (SPL, CIM field names) ----------
  function spl(g, days) {
    var out = [], e = "earliest=-" + days + "d";
    if (g.ips.length) out.push("`comment(\"IP addresses\")`\nindex=* " + e + " (src_ip IN (" + dq(g.ips) + ") OR dest_ip IN (" + dq(g.ips) + ") OR src IN (" + dq(g.ips) + ") OR dest IN (" + dq(g.ips) + "))\n| stats count min(_time) as first_seen max(_time) as last_seen values(sourcetype) as sourcetypes by src, dest, user\n| convert ctime(first_seen) ctime(last_seen)");
    if (g.cidrs.length) out.push("`comment(\"IP ranges\")`\nindex=* " + e + "\n| where " + g.cidrs.map(function (c) { return "cidrmatch(\"" + c + "\", dest_ip) OR cidrmatch(\"" + c + "\", src_ip)"; }).join(" OR ") + "\n| stats count by src_ip, dest_ip, sourcetype");
    if (g.domains.length || g.urls.length) out.push("`comment(\"Domains and URLs: proxy, DNS and email\")`\nindex=* " + e + " (" + g.domains.map(function (d) { return "query=\"*" + esc(d) + "\" OR url=\"*" + esc(d) + "*\" OR dest=\"" + esc(d) + "\""; }).concat(g.urls.map(function (u) { return "url=\"" + esc(u) + "\""; })).join("\n  OR ") + ")\n| stats count min(_time) as first_seen max(_time) as last_seen by src, user, url, query, sourcetype\n| convert ctime(first_seen) ctime(last_seen)");
    if (g.emails.length) out.push("`comment(\"Sender addresses\")`\nindex=* " + e + " (src_user IN (" + dq(g.emails) + ") OR sender IN (" + dq(g.emails) + ") OR from IN (" + dq(g.emails) + "))\n| stats count by src_user, recipient, subject, action");
    var hs = g.md5.concat(g.sha1, g.sha256, g.sha512);
    if (hs.length) out.push("`comment(\"File hashes\")`\nindex=* " + e + " (file_hash IN (" + dq(hs) + ") OR hash IN (" + dq(hs) + ") OR sha256 IN (" + dq(g.sha256) + ") OR md5 IN (" + dq(g.md5) + "))\n| stats count by dest, user, file_name, file_path, file_hash, sourcetype");
    if (g.files.length || g.paths.length) out.push("`comment(\"File names and paths\")`\nindex=* " + e + " (file_name IN (" + dq(uniq(g.files.concat(g.paths.map(base)))) + ") OR process_name IN (" + dq(uniq(g.files.concat(g.paths.map(base)))) + "))\n| stats count by dest, user, file_name, file_path, process");
    if (g.registry.length) out.push("`comment(\"Registry keys\")`\nindex=* " + e + " (" + g.registry.map(function (k) { return "registry_path=\"*" + esc(k.replace(/^[^\\]+\\/, "")) + "*\""; }).join(" OR ") + ")\n| stats count by dest, registry_path, registry_value_name, registry_value_data, process");
    return out.join("\n\n").replace(/`comment\("([^"]+)"\)`\n/g, "``` $1 ```\n");
  }

  // ---------- Elastic (Kibana KQL, ECS field names) ----------
  function elastic(g) {
    var out = [];
    var or = function (a) { return "(" + a.map(function (v) { return "\"" + esc(v) + "\""; }).join(" or ") + ")"; };
    if (g.ips.length) out.push("// IP addresses\nsource.ip : " + or(g.ips) + " or destination.ip : " + or(g.ips));
    if (g.cidrs.length) out.push("// IP ranges\ndestination.ip : " + or(g.cidrs) + " or source.ip : " + or(g.cidrs));
    if (g.domains.length || g.urls.length) out.push("// Domains and URLs\n" + [g.domains.length ? "dns.question.name : " + or(g.domains) + " or url.domain : " + or(g.domains) + " or destination.domain : " + or(g.domains) : "", g.urls.length ? "url.full : " + or(g.urls) : ""].filter(Boolean).join(" or "));
    if (g.emails.length) out.push("// Sender addresses\nemail.from.address : " + or(g.emails) + " or email.sender.address : " + or(g.emails));
    var parts = [];
    if (g.sha256.length) parts.push("file.hash.sha256 : " + or(g.sha256) + " or process.hash.sha256 : " + or(g.sha256));
    if (g.sha1.length) parts.push("file.hash.sha1 : " + or(g.sha1) + " or process.hash.sha1 : " + or(g.sha1));
    if (g.md5.length) parts.push("file.hash.md5 : " + or(g.md5) + " or process.hash.md5 : " + or(g.md5));
    if (parts.length) out.push("// File hashes\n" + parts.join(" or "));
    if (g.files.length || g.paths.length) out.push("// File names\nfile.name : " + or(uniq(g.files.concat(g.paths.map(base)))) + " or process.name : " + or(uniq(g.files.concat(g.paths.map(base)))));
    if (g.registry.length) out.push("// Registry keys\n" + g.registry.map(function (k) { return "registry.path : *" + k.replace(/^[^\\]+\\/, "").replace(/\\/g, "\\\\").replace(/ /g, "\\ ") + "*"; }).join(" or "));
    return out.join("\n\n");
  }

  // ---------- CrowdStrike Falcon / LogScale (CQL) ----------
  // Endpoint blocks use Falcon telemetry fields; "third-party" blocks use the ECS-style
  // fields Next-Gen SIEM parsers produce for firewall, proxy and email logs.
  function cql(g) {
    var out = [];
    var rxEsc = function (v) { return String(v).replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); };
    var rx = function (a, flags) { return "/^(" + a.map(rxEsc).join("|") + ")$/" + (flags || ""); };
    var vals = function (a) { return "[" + dq(a) + "]"; };
    var v4 = g.ips.filter(function (v) { return v.indexOf(":") < 0; }), v6 = g.ips.filter(function (v) { return v.indexOf(":") > -1; });
    if (v4.length) out.push("// IPv4 addresses: Falcon endpoint network connections\n#event_simpleName=NetworkConnectIP4\n| in(field=RemoteAddressIP4, values=" + vals(v4) + ")\n| table([@timestamp, ComputerName, aid, RemoteAddressIP4, RemotePort, ContextBaseFileName], limit=1000)");
    if (v6.length) out.push("// IPv6 addresses: Falcon endpoint network connections\n#event_simpleName=NetworkConnectIP6\n| in(field=RemoteAddressIP6, values=" + vals(v6) + ")\n| table([@timestamp, ComputerName, aid, RemoteAddressIP6, RemotePort, ContextBaseFileName], limit=1000)");
    if (g.ips.length) out.push("// IP addresses: third-party firewall, proxy and sign-in logs\nsource.ip=" + rx(g.ips, "i") + " or destination.ip=" + rx(g.ips, "i") + "\n| table([@timestamp, #Vendor, source.ip, destination.ip, user.name, event.action], limit=1000)");
    if (g.cidrs.length) out.push("// IP ranges: Falcon endpoint network connections\n#event_simpleName=NetworkConnectIP4\n| cidr(RemoteAddressIP4, subnet=" + vals(g.cidrs) + ")\n| table([@timestamp, ComputerName, aid, RemoteAddressIP4, RemotePort, ContextBaseFileName], limit=1000)");
    if (g.domains.length) {
      var drx = "/(^|\\.)(" + g.domains.map(rxEsc).join("|") + ")$/i";
      out.push("// Domains: Falcon endpoint DNS requests (includes subdomains)\n#event_simpleName=DnsRequest\n| DomainName=" + drx + "\n| table([@timestamp, ComputerName, aid, DomainName, ContextBaseFileName], limit=1000)");
      out.push("// Domains: third-party proxy and DNS logs\nurl.domain=" + drx + " or dns.question.name=" + drx + " or destination.domain=" + drx + "\n| table([@timestamp, #Vendor, source.ip, user.name, url.domain, dns.question.name, url.original], limit=1000)");
    }
    if (g.urls.length) out.push("// URLs: third-party proxy and email logs\nurl.original=" + rx(g.urls, "i") + "\n| table([@timestamp, #Vendor, source.ip, user.name, url.original, event.action], limit=1000)");
    if (g.emails.length) out.push("// Sender addresses: third-party email logs\nemail.from.address=" + rx(g.emails, "i") + " or email.sender.address=" + rx(g.emails, "i") + "\n| table([@timestamp, #Vendor, email.from.address, email.to.address, email.subject, event.action], limit=1000)");
    var hp = [];
    if (g.sha256.length) hp.push("SHA256HashData=" + rx(g.sha256, "i"));
    if (g.sha1.length) hp.push("SHA1HashData=" + rx(g.sha1, "i"));
    if (g.md5.length) hp.push("MD5HashData=" + rx(g.md5, "i"));
    if (hp.length) out.push("// File hashes: Falcon process and file events\n" + hp.join(" or ") + "\n| table([@timestamp, ComputerName, aid, #event_simpleName, FileName, FilePath, SHA256HashData, CommandLine], limit=1000)");
    if (g.files.length || g.paths.length) out.push("// File names: Falcon process and file-write events\n#event_simpleName=/ProcessRollup2|FileWritten/\n| FileName=" + rx(uniq(g.files.concat(g.paths.map(base))), "i") + "\n| table([@timestamp, ComputerName, aid, #event_simpleName, FileName, FilePath, CommandLine], limit=1000)");
    if (g.registry.length) out.push("// Registry keys: Falcon registry and autostart events (the last segment may be a value name)\n#event_simpleName=/^(AsepValueUpdate|RegGenericValueUpdate|RegSystemConfigValueUpdate|RegKeyCreate)$/\n| RegObjectName=/(" + g.registry.map(function (k) {
      var parts = k.replace(/^[^\\]+\\/, "").split("\\"), last = parts.pop();
      return parts.map(rxEsc).join("\\\\") + "(\\\\" + rxEsc(last) + ")?";
    }).join("|") + ")$/i\n| table([@timestamp, ComputerName, aid, RegObjectName, RegValueName, RegStringValue], limit=1000)");
    return out.join("\n\n");
  }

  function build(items, days) {
    var g = group(items);
    days = days || 30;
    return { kql: kql(g, days), spl: spl(g, days), elastic: elastic(g), cql: cql(g), groups: g };
  }

  // ---------- Exports ----------
  function csvCell(v) { v = String(v === null || v === undefined ? "" : v); return /^[=+\-@\t\r]/.test(v) ? "\"'" + v.replace(/"/g, "\"\"") + "\"" : "\"" + v.replace(/"/g, "\"\"") + "\""; }
  function csv(items) {
    var rows = [["type", "value", "defanged", "count", "first_line", "country", "asn", "tags", "context"]];
    items.forEach(function (i) {
      var geo = i.meta && i.meta.geo;
      rows.push([i.type, i.value, root.SOCExtract.defang(i.type, i.value), i.count, i.line, geo ? geo.country : "", geo && geo.asn ? "AS" + geo.asn + " " + geo.asnName : "", i.tags.map(function (t) { return t.label; }).join("; "), i.context]);
    });
    return rows.map(function (r) { return r.map(csvCell).join(","); }).join("\r\n");
  }
  function json(items, meta) {
    return JSON.stringify({ generator: "SOC Toolkit IOC extractor " + meta.version, fingerprint: meta.fingerprint, indicators: items.map(function (i) { return { type: i.type, value: i.value, count: i.count, line: i.line, tags: i.tags.map(function (t) { return t.label; }), geo: i.meta && i.meta.geo ? { country: i.meta.geo.country, asn: i.meta.geo.asn, asn_name: i.meta.geo.asnName } : undefined, context: i.context }; }) }, null, 2);
  }

  // Deterministic UUIDv5 (SHA-1) so the same IOC always gets the same STIX id.
  function sha1(msg) {
    var b = Array.prototype.slice.call(new TextEncoder().encode(msg)), l = b.length * 8;
    b.push(0x80); while (b.length % 64 !== 56) b.push(0);
    for (var i = 7; i >= 0; i--) b.push(i > 3 ? 0 : (l >>> (i * 8)) & 255);
    var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], w = new Array(80);
    for (var o = 0; o < b.length; o += 64) {
      for (i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24) | (b[o + 4 * i + 1] << 16) | (b[o + 4 * i + 2] << 8) | b[o + 4 * i + 3];
      for (i = 16; i < 80; i++) { var x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = (x << 1) | (x >>> 31); }
      var a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
      for (i = 0; i < 80; i++) {
        var f = i < 20 ? (bb & c) | (~bb & d) : i < 40 ? bb ^ c ^ d : i < 60 ? (bb & c) | (bb & d) | (c & d) : bb ^ c ^ d;
        var k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6;
        var t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0; e = d; d = c; c = (bb << 30) | (bb >>> 2); bb = a; a = t;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + bb) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0;
    }
    return h.map(function (v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }).join("");
  }
  function uuid5(name) {
    var ns = "a1e3f2c4b5d6478998a7b6c5d4e3f2a1"; // fixed namespace for this tool
    var hx = sha1(ns + name);
    return hx.slice(0, 8) + "-" + hx.slice(8, 12) + "-5" + hx.slice(13, 16) + "-" + ((parseInt(hx.slice(16, 18), 16) & 0x3f) | 0x80).toString(16) + hx.slice(18, 20) + "-" + hx.slice(20, 32);
  }
  function stixPattern(i) {
    var v = String(i.value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    switch (i.type) {
      case "ipv4": case "cidr": return "[ipv4-addr:value = '" + v + "']";
      case "ipv6": return "[ipv6-addr:value = '" + v + "']";
      case "domain": return "[domain-name:value = '" + v + "']";
      case "url": return "[url:value = '" + v + "']";
      case "email": return "[email-addr:value = '" + v + "']";
      case "md5": return "[file:hashes.'MD5' = '" + v + "']";
      case "sha1": return "[file:hashes.'SHA-1' = '" + v + "']";
      case "sha256": return "[file:hashes.'SHA-256' = '" + v + "']";
      case "sha512": return "[file:hashes.'SHA-512' = '" + v + "']";
      case "filename": return "[file:name = '" + v + "']";
      case "registry": return "[windows-registry-key:key = '" + regFull(i.value).replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "']";
      default: return null;
    }
  }
  function stix(items, createdIso) {
    var objs = items.map(function (i) {
      var p = stixPattern(i); if (!p) return null;
      return { type: "indicator", spec_version: "2.1", id: "indicator--" + uuid5(p), created: createdIso, modified: createdIso, valid_from: createdIso, name: i.type + ": " + i.value, pattern: p, pattern_type: "stix", indicator_types: ["malicious-activity"], labels: i.tags.map(function (t) { return t.label; }) };
    }).filter(Boolean);
    return JSON.stringify({ type: "bundle", id: "bundle--" + uuid5(objs.map(function (o) { return o.id; }).join(",")), objects: objs }, null, 2);
  }
  function plain(items, defanged) { return items.map(function (i) { return defanged ? root.SOCExtract.defang(i.type, i.value) : i.value; }).join("\n"); }

  var api = { build: build, csv: csv, json: json, stix: stix, plain: plain, uuid5: uuid5, sha1: sha1 };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SOCQueries = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
