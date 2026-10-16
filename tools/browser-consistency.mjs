// Runs the built-in sample through the page in each browser engine and checks they all
// produce the same indicators, selections, tags and hunt queries, with no errors and no
// requests leaving the site. Usage: node tools/browser-consistency.mjs chromium,firefox,webkit
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import * as pw from "playwright";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".woff2": "font/woff2" };
const server = http.createServer(async (req, res) => {
  let p = normalize(decodeURIComponent(req.url.split("?")[0])).replace(/^(\.\.[/\\])+/, "");
  if (p.endsWith("/")) p += "index.html";
  try { const body = await readFile(join(ROOT, p)); res.writeHead(200, { "content-type": TYPES[extname(p)] || "application/octet-stream" }); res.end(body); }
  catch { res.writeHead(404); res.end(); }
}).listen(0);
const base = `http://localhost:${server.address().port}/`;

const results = {};
let failed = false;
for (const name of (process.argv[2] || "chromium").split(",")) {
  const browser = await pw[name].launch();
  const page = await browser.newPage();
  const errors = [], external = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => { if (!r.url().startsWith(base)) external.push(r.url()); });
  await page.goto(base + "ioc.html");
  await page.click("#sample-btn");
  await page.click("#analyze-btn");
  await page.waitForSelector(".row", { timeout: 30000 });
  const rows = await page.$$eval(".row", (rs) => rs.map((r) => [r.querySelector(".tbadge").textContent, r.querySelector(".rval").textContent, r.querySelector("input").checked, [...r.querySelectorAll(".pill")].map((p) => p.textContent).join("|")].join(" ")));
  const queries = [];
  for (const plat of ["Sentinel", "Splunk", "Elastic", "CrowdStrike"]) { await page.click(`.plat:has-text("${plat}")`); queries.push(await page.textContent("pre.code")); }
  results[name] = JSON.stringify({ rows, queries });
  console.log(`${name}: ${rows.length} indicators, ${errors.length} errors, ${external.length} external requests`);
  if (errors.length || external.length) { failed = true; console.error(errors, external); }
  await browser.close();
}
server.close();
const outs = Object.values(results);
if (outs.some((o) => o !== outs[0])) { failed = true; console.error("FAIL: browsers disagree"); for (const k in results) console.error(k, results[k].slice(0, 400)); }
if (failed) process.exit(1);
console.log("PASS: identical output in " + Object.keys(results).join(", "));
