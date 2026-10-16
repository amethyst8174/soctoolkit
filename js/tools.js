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
  }
];
