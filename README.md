# SOC Toolkit

Free, private utilities for SOC analysts and incident responders, by Cyber Insight Signals. Every tool runs entirely in your browser. There is no AI, no API and no server, and nothing is stored.

**Live:** https://amethyst8174.github.io/soctoolkit/

| Utility | Opens at | What it does |
|---|---|---|
| IOC Extractor | `#ioc` (`ioc.html`) | Extracts IOCs from text and builds hunt queries (this repository) |
| Header-Lens | `#header-lens` | Visual email header analysis ([header-lens](https://github.com/amethyst8174/header-lens)) |
| Email Triage | `#email-triage` | Full .eml / .msg phishing triage ([header-lens](https://github.com/amethyst8174/header-lens)) |

The home page (`index.html`) lists the utilities and has a collapsible utilities panel on the left. A tool opens inside the same page in a frame from this site, with the panel collapsed. Each tool still works on its own page too.

**Adding a tool:** add one entry to `js/tools.js` (name, short tag, description, icon, page address, accent colour). It then appears in the panel and as a card on the home page. To hide the tool's own top bar and footer inside the toolkit, load `js/embed.js` in its page and add the `.embedded` rules from `css/style.css`.

## IOC Extractor

- **Extracts 15 IOC types:** IPv4, IPv6, CIDR ranges, domains, URLs, email addresses, MD5/SHA1/SHA256/SHA512 hashes, file names, Windows paths, registry keys, CVE IDs and MITRE ATT&CK IDs.
- **Refangs automatically:** `hxxps://`, `[.]`, `(dot)`, `[@]`, `(at)`, `[://]` and similar.
- **Cuts false positives:** checks domains against the IANA TLD list, and skips version numbers, clock times and placeholder hashes. Internal IPs, reserved domains, well-known services, empty-file hashes and your own domains start unticked.
- **Enriches offline:** adds country and ASN for public IPs, and flags Tor exit nodes and FireHOL level 1 matches, all from data files shipped with the page.
- **Writes hunt queries** for Microsoft Sentinel / Defender XDR (KQL), Splunk (SPL, CIM fields), Elastic (KQL, ECS fields) and CrowdStrike Falcon / LogScale (CQL, Falcon telemetry and Next-Gen SIEM fields), with a selectable time range for KQL and SPL.
- **Exports** CSV (formula-injection safe), JSON, a STIX 2.1 bundle with deterministic IDs, and defanged or plain lists.
- **Gives deterministic results:** the same text always gives the same indicators, queries and exports. The page shows the input's SHA-256, the engine version and the data dates.

## Privacy

- A Content Security Policy (`connect-src 'none'`, `form-action 'none'`) stops the page from sending data anywhere.
- Fonts, scripts, images and data are served from this repository. There are no CDNs, analytics or trackers.
- No cookies or browser storage are used. Leaving or reloading the page wipes everything.
- The **Privacy check** workflow fails any push that adds storage APIs, network calls, third-party resources or HTML injection.

## Development

```
npm ci --prefix tools
node tools/test-engine.mjs                         # engine consistency test
node tools/browser-consistency.mjs chromium        # same output in the browser
node tools/build-sample.mjs                        # regenerate js/sample.js from test/report.txt
```

The **Refresh offline data** workflow rebuilds `data/` on a schedule: threat lists and TLDs weekly, IP country/ASN data monthly.

To show the YouTube and blog links, set them in `js/config.js`.

## Data sources and licenses

- IP to country and ASN: [sapics/ip-location-db](https://github.com/sapics/ip-location-db) (server-country and iptoasn), PDDL / public domain
- [FireHOL level 1](https://github.com/firehol/blocklist-ipsets) blocklist
- [Tor Project](https://check.torproject.org/torbulkexitlist) exit node list
- Country names: [world-atlas](https://github.com/topojson/world-atlas) (Natural Earth, public domain) and i18n-iso-countries (MIT)
- TLD list: [tlds](https://github.com/stephenmathieson/node-tlds) (MIT), from the IANA root zone

© 2026 @CyberInsightSignal. All rights reserved.
