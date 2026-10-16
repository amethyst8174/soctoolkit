# SOC Toolkit

Free, private utilities for SOC analysts and incident responders, by Cyber Insight Signals. Every tool runs entirely in your browser. There is no AI, no API and no server, and nothing is stored.

**Live:** https://amethyst8174.github.io/soctoolkit/

| Utility | Opens at | What it does |
|---|---|---|
| IOC Extractor | `#ioc` (`ioc.html`) | Extracts IOCs from text and builds hunt queries (this repository) |
| Header-Lens | `#header-lens` | Visual email header analysis ([header-lens](https://github.com/amethyst8174/header-lens)) |
| Email Triage | `#email-triage` | Full .eml / .msg phishing triage ([header-lens](https://github.com/amethyst8174/header-lens)) |
| VPN IP Checker | `#vpn-check` (`vpn.html`) | Checks IPs against published VPN, Tor and iCloud Private Relay lists (this repository) |

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

## VPN IP Checker

- **Checks** IPv4 and IPv6 addresses (pasted, or pulled out of any text, defanged forms included) against offline lists refreshed twice a week:
  - Tor Project bulk exit list: **Tor exit node**, confidence High
  - Apple iCloud Private Relay egress ranges: **iCloud Private Relay**, confidence High
  - Proton VPN server IPs via [tn3w/ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) (Apache-2.0): **Proton VPN server**, confidence High
  - NordVPN's public server list (api.nordvpn.com): **NordVPN server**, confidence High
  - The /24 block around each Proton server: **Proton VPN network**, confidence Medium
  - [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) VPN list (MIT): **VPN network**, confidence Medium (built mainly from network ownership)
  - X4BNet datacenter list: **Hosting network**, confidence Low (VPN possible, not confirmed)
- **Never guesses:** anything not on a list is **Unknown**, with the reason. Each list shows its source and last refresh date, and a list that failed to refresh keeps its previous data and date.
- Adds country and network owner (ASN) from the same offline registry data as the IOC Extractor.
- Exports CSV (formula-injection safe) with the status, confidence, matched lists and list dates.

## Privacy

- A Content Security Policy (`connect-src 'none'`, `form-action 'none'`) stops the page from sending data anywhere.
- Fonts, scripts, images and data are served from this repository. There are no CDNs, analytics or trackers.
- No cookies or browser storage are used. Leaving or reloading the page wipes everything.
- The **Privacy check** workflow fails any push that adds storage APIs, network calls, third-party resources or HTML injection.

## Development

```
npm ci --prefix tools
node tools/test-engine.mjs                         # engine consistency test
node tools/test-vpn.mjs                            # VPN checker rules test
node tools/browser-consistency.mjs chromium        # same output in the browser
node tools/build-sample.mjs                        # regenerate js/sample.js from test/report.txt
```

The **Refresh offline data** workflow rebuilds `data/` on a schedule: threat, Tor, VPN and Private Relay lists and TLDs twice a week (Monday and Thursday), IP country/ASN data monthly.

To show the YouTube and blog links, set them in `js/config.js`.

## Data sources and licenses

- IP to country and ASN: [sapics/ip-location-db](https://github.com/sapics/ip-location-db) (server-country and iptoasn), PDDL / public domain
- [FireHOL level 1](https://github.com/firehol/blocklist-ipsets) blocklist
- [Tor Project](https://check.torproject.org/torbulkexitlist) exit node list
- VPN lists: [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) (MIT), [tn3w/ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) (Apache-2.0), NordVPN public server list, [Apple iCloud Private Relay egress ranges](https://mask-api.icloud.com/egress-ip-ranges.csv)
- Country names: [world-atlas](https://github.com/topojson/world-atlas) (Natural Earth, public domain) and i18n-iso-countries (MIT)
- TLD list: [tlds](https://github.com/stephenmathieson/node-tlds) (MIT), from the IANA root zone

© 2026 @CyberInsightSignal. All rights reserved.
