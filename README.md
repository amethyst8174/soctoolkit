# soc-toolkit · IOC extractor

Paste a threat report, alert, ticket or log and get every indicator of compromise pulled out, refanged, checked and turned into hunt queries. It runs entirely in your browser. There is no AI, no API and no server, and nothing is stored.

**Live:** https://amethyst8174.github.io/soctoolkit/

Companion tools: [header-lens](https://amethyst8174.github.io/header-lens/) (email header analysis) and [Email triage](https://amethyst8174.github.io/header-lens/triage.html).

## What it does

- **Extracts 15 IOC types:** IPv4, IPv6, CIDR ranges, domains, URLs, email addresses, MD5/SHA1/SHA256/SHA512 hashes, file names, Windows paths, registry keys, CVE IDs and MITRE ATT&CK IDs.
- **Refangs automatically:** `hxxps://`, `[.]`, `(dot)`, `[@]`, `(at)`, `[://]` and similar.
- **Cuts false positives:** checks domains against the IANA TLD list, and skips version numbers, clock times and placeholder hashes. Internal IPs, reserved domains, well-known services, empty-file hashes and your own domains start unticked.
- **Enriches offline:** adds country and ASN for public IPs, and flags Tor exit nodes and FireHOL level 1 matches, all from data files shipped with the page.
- **Writes hunt queries** for Microsoft Sentinel / Defender XDR (KQL), Splunk (SPL, CIM fields), Elastic (KQL, ECS fields) and IBM QRadar (AQL), with a selectable time range.
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
