// Builds data/vpn.js, the offline lists the VPN IP checker uses in the browser.
// Nothing here runs in the browser and no analyst data is involved: it only turns published
// lists into compact sorted ranges.
//
// Usage: node tools/build-vpn.mjs <source-dir>
// <source-dir> may contain (each optional; a missing file keeps that list's previous data and date):
//   tor-exits.txt            Tor Project bulk exit list (check.torproject.org)
//   icloud-egress.csv        Apple iCloud Private Relay egress ranges (mask-api.icloud.com, RFC 8805 CSV)
//   x4b-vpn-ipv4.txt         X4BNet/lists_vpn output/vpn/ipv4.txt (MIT)
//   x4b-vpn-ipv6.txt         X4BNet/lists_vpn output/vpn/ipv6.txt (MIT)
//   x4b-dc-ipv4.txt          X4BNet/lists_vpn output/datacenter/ipv4.txt (MIT)
//   x4b-dc-ipv6.txt          X4BNet/lists_vpn output/datacenter/ipv6.txt (MIT)
//   proton-ips.txt           tn3w/ProtonVPN-IPs protonvpn_ips.txt (Apache-2.0), Proton's advertised server IPs
//   proton-entry-ips.txt     tn3w/ProtonVPN-IPs protonvpn_entry_ips.txt (Apache-2.0)
//   proton-ranges.txt        tn3w/ProtonVPN-IPs protonvpn_ip_ranges.txt, the /24 of each advertised IPv4
//   nord-servers.txt         NordVPN public server list (api.nordvpn.com/v1/servers), station IPv4/IPv6, one per line

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const src = process.argv[2];
if (!src) { console.error("usage: node tools/build-vpn.mjs <source-dir>"); process.exit(1); }
const outFile = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "data", "vpn.js");
const has = (f) => fs.existsSync(path.join(src, f)) && fs.statSync(path.join(src, f)).size > 0;
const read = (f) => fs.readFileSync(path.join(src, f), "utf8");
const today = new Date().toISOString().slice(0, 10);

// Previous data, so a source that fails to download keeps its last good copy and date.
let prev = { lists: {} };
if (fs.existsSync(outFile)) {
  const w = {};
  new Function("window", fs.readFileSync(outFile, "utf8"))(w);
  if (w.SOC_VPN) prev = w.SOC_VPN;
}

// ---------- Parsing: every range becomes [startHex, endHex] at fixed width ----------
function v4num(s) {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m || m.slice(1).some((x) => +x > 255)) return null;
  return (BigInt(m[1]) << 24n) + (BigInt(m[2]) << 16n) + (BigInt(m[3]) << 8n) + BigInt(m[4]);
}
function v6num(s) {
  if (!/^[0-9a-f:]+$/i.test(s) || s.indexOf(":") < 0) return null;
  const parts = s.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [], tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (parts.length === 1 && fill !== 0)) return null;
  const groups = head.concat(Array(parts.length === 2 ? fill : 0).fill("0"), tail);
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n);
}
function parseRange(token) {
  const [addr, bitsStr] = token.trim().split("/");
  const v6 = addr.indexOf(":") > -1;
  const n = v6 ? v6num(addr) : v4num(addr);
  if (n === null) return null;
  const width = v6 ? 128 : 32;
  const bits = bitsStr === undefined ? width : +bitsStr;
  if (!Number.isInteger(bits) || bits < 0 || bits > width) return null;
  const size = 1n << BigInt(width - bits);
  const start = (n / size) * size;
  return { v6, start, end: start + size - 1n };
}
function collect(lines) {
  const v4 = [], v6 = [];
  for (const line of lines) {
    const r = parseRange(line);
    if (r) (r.v6 ? v6 : v4).push([r.start, r.end]);
  }
  return { v4: merge(v4), v6: merge(v6) };
}
// Sort and merge overlapping or touching ranges.
function merge(rs) {
  rs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1n) { if (r[1] > last[1]) last[1] = r[1]; }
    else out.push([r[0], r[1]]);
  }
  return out;
}
const hex = (n, w) => n.toString(16).padStart(w, "0");
function pack(ranges, w) {
  const text = ranges.map((r) => hex(r[0], w) + hex(r[1], w)).join("");
  return zlib.gzipSync(Buffer.from(text), { level: 9 }).toString("base64");
}
const lineList = (text) => text.split(/\r?\n/).map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);

// ---------- Lists ----------
const DEFS = [
  { id: "tor", name: "Tor exit node", source: "Tor Project bulk exit list", url: "https://check.torproject.org/torbulkexitlist",
    files: ["tor-exits.txt"], lines: (t) => lineList(t) },
  { id: "icloud", name: "iCloud Private Relay", source: "Apple iCloud Private Relay egress ranges", url: "https://mask-api.icloud.com/egress-ip-ranges.csv",
    files: ["icloud-egress.csv"], lines: (t) => t.split(/\r?\n/).map((l) => l.split(",")[0].trim()).filter(Boolean) },
  { id: "proton", name: "Proton VPN servers", source: "Proton VPN server list via tn3w/ProtonVPN-IPs (Apache-2.0)", url: "https://github.com/tn3w/ProtonVPN-IPs",
    files: ["proton-ips.txt", "proton-entry-ips.txt"], lines: (t) => lineList(t) },
  { id: "nord", name: "NordVPN servers", source: "NordVPN public server list (api.nordvpn.com)", url: "https://api.nordvpn.com/v1/servers",
    files: ["nord-servers.txt"], lines: (t) => lineList(t) },
  { id: "proton24", name: "Proton VPN /24 blocks", source: "tn3w/ProtonVPN-IPs, /24 around each Proton server (Apache-2.0)", url: "https://github.com/tn3w/ProtonVPN-IPs",
    files: ["proton-ranges.txt"], lines: (t) => lineList(t) },
  { id: "vpn", name: "Known VPN network", source: "X4BNet lists_vpn, VPN list (MIT)", url: "https://github.com/X4BNet/lists_vpn",
    files: ["x4b-vpn-ipv4.txt", "x4b-vpn-ipv6.txt"], lines: (t) => lineList(t) },
  { id: "dc", name: "Hosting or datacenter network", source: "X4BNet lists_vpn, datacenter list (MIT)", url: "https://github.com/X4BNet/lists_vpn",
    files: ["x4b-dc-ipv4.txt", "x4b-dc-ipv6.txt"], lines: (t) => lineList(t) }
];

const lists = {};
for (const d of DEFS) {
  const present = d.files.filter(has);
  if (present.length !== d.files.length) {
    if (prev.lists[d.id]) { lists[d.id] = prev.lists[d.id]; console.log(d.id, "source missing, kept previous data from", prev.lists[d.id].updated); }
    else console.log(d.id, "source missing and no previous data: list not included");
    continue;
  }
  const r = collect(present.flatMap((f) => d.lines(read(f))));
  if (!r.v4.length && !r.v6.length) {
    if (prev.lists[d.id]) { lists[d.id] = prev.lists[d.id]; console.log(d.id, "source empty, kept previous data"); }
    continue;
  }
  lists[d.id] = { name: d.name, source: d.source, url: d.url, updated: today, n4: r.v4.length, n6: r.v6.length, v4: pack(r.v4, 8), v6: pack(r.v6, 32) };
  console.log(d.id, "ranges v4", r.v4.length, "v6", r.v6.length);
}

fs.writeFileSync(outFile,
  "// Generated by tools/build-vpn.mjs. Tor Project exit list, Apple iCloud Private Relay egress ranges,\n" +
  "// and X4BNet lists_vpn (MIT). Each list carries the date it was last refreshed.\n" +
  "window.SOC_VPN=" + JSON.stringify({ built: today, lists }) + ";\n");
console.log("vpn.js", (fs.statSync(outFile).size / 1024).toFixed(0) + " KB");
