// Engine consistency test: extraction and query output for test/report.txt must match
// test/expected.json exactly, and two runs must give identical output.
// Usage: node tools/test-engine.mjs            (check)
//        node tools/test-engine.mjs --update   (rewrite expected.json after an intended change)
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
const require = createRequire(import.meta.url);
const root = new URL("..", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");

globalThis.window = globalThis;
new Function(read("data/tlds.js"))();
const X = require("../js/extract.js");
globalThis.SOCExtract = X;
const Q = require("../js/queries.js");

function snapshot() {
  const res = X.extract(read("test/report.txt"), { exclude: ["yourco.com"] });
  const sel = res.items.filter((i) => i.include);
  const q = Q.build(sel, 30);
  const sha = (s) => createHash("sha256").update(s).digest("hex");
  return {
    engine: res.version,
    items: res.items.map((i) => [i.type, i.value, i.count, i.line, i.include, i.tags.map((t) => t.k).join(",")]),
    queries: { kql: sha(q.kql), spl: sha(q.spl), elastic: sha(q.elastic), cql: sha(q.cql) },
    stix: sha(Q.stix(sel, "2026-01-01T00:00:00Z")),
    csv: sha(Q.csv(sel)),
    defanged: Q.plain(sel, true).split("\n"),
  };
}

const a = JSON.stringify(snapshot(), null, 1), b = JSON.stringify(snapshot(), null, 1);
if (a !== b) { console.error("FAIL: two runs over the same input gave different output"); process.exit(1); }
const expPath = new URL("test/expected.json", root);
if (process.argv.includes("--update")) { writeFileSync(expPath, a + "\n"); console.log("Updated test/expected.json"); process.exit(0); }
const exp = readFileSync(expPath, "utf8").trim();
if (exp !== a) {
  const E = JSON.parse(exp), A = JSON.parse(a);
  for (const k of Object.keys(A)) if (JSON.stringify(E[k]) !== JSON.stringify(A[k])) console.error("Differs: " + k);
  console.error("FAIL: output changed. If intended, run node tools/test-engine.mjs --update and bump the engine VERSION.");
  process.exit(1);
}
console.log("PASS: " + JSON.parse(a).items.length + " indicators, queries and exports match, deterministic across runs");
