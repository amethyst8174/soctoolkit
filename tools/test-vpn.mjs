// VPN IP checker logic test with fixed fixture lists (not the live data), so it checks the
// rules themselves: only listed addresses get a VPN/Tor/Relay status, everything else is Unknown.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
globalThis.window = globalThis;
const X = require("../js/extract.js"); globalThis.SOCExtract = X;
const V = require("../js/vpncheck.js");

const h4 = (ip) => ip.split(".").map((n) => (+n).toString(16).padStart(2, "0")).join("");
const r4 = (a, b) => h4(a) + h4(b);
const lists = {
  tor: { v4: r4("185.220.101.45", "185.220.101.45"), v6: "" },
  icloud: { v4: r4("172.224.224.0", "172.224.224.31"), v6: "26001234000000000000000000000000" + "260012340000ffffffffffffffffffff" },
  proton: { v4: r4("37.19.199.10", "37.19.199.10"), v6: "" },
  nord: { v4: r4("89.35.28.131", "89.35.28.131"), v6: "" },
  proton24: { v4: r4("37.19.199.0", "37.19.199.255"), v6: "" },
  vpn: { v4: r4("2.26.157.0", "2.26.157.255") + r4("185.220.101.0", "185.220.101.255"), v6: "" },
  dc: { v4: r4("2.26.0.0", "2.26.255.255") + r4("5.231.192.0", "5.231.192.255") + r4("37.19.0.0", "37.19.255.255") + r4("89.35.0.0", "89.35.255.255") + r4("185.220.0.0", "185.220.255.255"), v6: "" }
};
const cases = [
  ["185.220.101.45", "Tor exit node", "High", "tor,vpn,dc"],
  ["185.220.101.46", "VPN network", "Medium", "vpn,dc"],
  ["172.224.224.9", "iCloud Private Relay", "High", "icloud"],
  ["2600:1234::abcd", "iCloud Private Relay", "High", "icloud"],
  ["2.26.157.10", "VPN network", "Medium", "vpn,dc"],
  ["5.231.192.20", "Hosting network", "Low", "dc"],
  ["37.19.199.10", "Proton VPN server", "High", "proton,proton24,dc"],
  ["37.19.199.77", "Proton VPN network", "Medium", "proton24,dc"],
  ["89.35.28.131", "NordVPN server", "High", "nord,dc"],
  ["49.36.12.7", "Unknown", "", ""],
  ["10.20.30.41", "Not a public IP", "", ""],
  ["::ffff:185.220.101.45", "Tor exit node", "High", "tor,vpn,dc"],
  ["2001:db8::1", "Not a public IP", "", ""],
  ["300.1.1.1", "Not an IP address", "", ""]
];
let fail = 0;
for (const [ip, status, conf, matches] of cases) {
  const a = V.classify(ip, lists, X.ipKind), b = V.classify(ip, lists, X.ipKind);
  const got = [a.status, a.confidence, (a.matches || []).join(",")];
  const ok = got[0] === status && got[1] === conf && got[2] === matches && JSON.stringify(a) === JSON.stringify(b);
  if (!ok) { fail++; console.error("FAIL", ip, got, "expected", [status, conf, matches]); }
}
const found = V.addresses("from 185.220.101[.]45, hxxp://2.26.157[.]10/x and 2600:1234::abcd; dup 185.220.101.45");
if (found.join(" ") !== "185.220.101.45 2.26.157.10 2600:1234::abcd") { fail++; console.error("FAIL addresses", found); }
if (fail) process.exit(1);
console.log("PASS: " + cases.length + " VPN checker cases, deterministic, Unknown when unlisted");
