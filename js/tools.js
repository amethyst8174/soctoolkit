// The SOC Toolkit's list of utilities. To add a tool, add one entry here: it then appears
// in the left panel and as a card on the home page, and opens at index.html#<id>.
//   id    short name used in the address (index.html#id)
//   name  display name
//   tag   a few words shown under the name in the left panel
//   desc  one or two sentences for the home page card
//   icon  image in assets/img (square, transparent background)
//   url   page to open inside the toolkit (same site)
//   color accent colour for the card
//   share text used when sharing this tool
window.SOC_TOOLS = [
  {
    id: "ioc", name: "IOC Extractor", tag: "IOCs to hunt queries",
    desc: "Pull every IP, domain, URL, hash, file and registry key out of a threat report, alert or log, and get hunt queries for Sentinel, Splunk, Elastic and CrowdStrike.",
    icon: "assets/img/avatar.png", url: "ioc.html", color: "var(--magenta)",
    share: "IOC extractor with ready-made hunt queries, running entirely in your browser"
  },
  {
    id: "header-lens", name: "Header-Lens", tag: "Email header analysis",
    desc: "Paste raw email headers and get a visual phishing verdict: routing map, SPF, DKIM and DMARC, spam scores and sender mismatches.",
    icon: "assets/img/header-lens.png", url: "../header-lens/", color: "var(--violet)",
    share: "Header-Lens: visual email header analysis that runs entirely in your browser"
  },
  {
    id: "email-triage", name: "Email Triage", tag: "Full .eml / .msg triage",
    desc: "Drop in an .eml or .msg file to check its headers, links, QR codes and attachments together, with one verdict and IOCs ready to hunt.",
    icon: "assets/img/triage.png", url: "../header-lens/triage.html", color: "var(--amber)",
    share: "Phishing email triage that runs entirely in your browser"
  },
  {
    id: "decoder", name: "DecodeSphere", tag: "PowerShell & cmd deobfuscation",
    desc: "Paste an obfuscated PowerShell or Windows command line and peel it layer by layer: Base64 -EncodedCommand, gzip, hex, char codes and caret tricks, with behaviour flags and hunt queries for Sentinel, Splunk, Elastic and CrowdStrike.",
    icon: "assets/img/decoder.png", url: "decoder.html", color: "var(--info)",
    share: "DecodeSphere: PowerShell and command-line decoder that runs entirely in your browser"
  },
  {
    id: "tracer-lens", name: "Tracer-Lens", tag: "PCAP / PCAPNG analyzer",
    desc: "Open a packet capture and read it as a dashboard: flows, top talkers, protocol and timeline charts, a host graph, offline IP geo / ASN / threat / VPN enrichment, anomaly findings and hunt queries.",
    icon: "assets/img/tracerlens.png", url: "tracerlens.html", color: "var(--warn)",
    share: "Tracer-Lens: a graphical PCAP analyzer that runs entirely in your browser"
  },
  {
    id: "vpn-check", name: "VPN IP Checker", tag: "VPN, Tor and Private Relay",
    desc: "Check whether IP addresses belong to a VPN, Tor or iCloud Private Relay using published lists, with a source and confidence level for every answer.",
    icon: "assets/img/vpn.png", url: "vpn.html", color: "var(--ok)",
    share: "VPN IP checker that runs entirely in your browser"
  },
  {
    id: "timeline", name: "Timeline Merger", tag: "Normalize & merge logs",
    desc: "Parse syslog, CEF, LEEF and JSON logs, normalize timezones and merge several sources into one sorted timeline you can read across tools in order.",
    icon: "assets/img/timeline.png", url: "timeline.html", color: "var(--t-attack)",
    share: "Normalize and merge syslog, CEF, LEEF and JSON logs into one sorted timeline, entirely in your browser"
  }
];
