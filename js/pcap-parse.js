/* Tracer-Lens PCAP/PCAPNG parser + aggregator - SOC Toolkit
 * Streaming, bounded-memory, dependency-free. Runs in the browser and in Node (tests).
 * Reads classic libpcap (both byte orders, microsecond and nanosecond) and pcapng
 * (SHB/IDB/EPB/SPB), decodes Ethernet/RAW/NULL/SLL -> IPv4/IPv6 -> TCP/UDP/ICMP and a
 * little app-layer (DNS, TLS SNI, HTTP host/URI, FTP creds, SMB version), and keeps only
 * aggregates so memory stays flat regardless of file size. No network, no storage.
 *
 * Usage:
 *   var p = new PCAP.Parser({ maxPackets, maxFlows, maxHosts, maxNames });
 *   p.push(uint8arrayChunk);  // feed chunks in order
 *   p.end();
 *   var analysis = p.result();
 */
(function (root) {
  "use strict";

  var LINKTYPE = { NULL: 0, ETHERNET: 1, RAW: 101, RAW2: 12, LOOP: 108, SLL: 113, IPV4: 228, IPV6: 229, SLL2: 276 };

  // ---- small helpers ----
  function concat(a, b) {
    if (!a || !a.length) return b;
    if (!b || !b.length) return a;
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length); return out;
  }
  function ipv4str(dv, off) { return dv.getUint8(off) + "." + dv.getUint8(off + 1) + "." + dv.getUint8(off + 2) + "." + dv.getUint8(off + 3); }
  function u32(dv, off) { return dv.getUint32(off) >>> 0; } // big-endian (network order) for IP fields
  function ipv6str(dv, off) {
    var g = [];
    for (var i = 0; i < 8; i++) g.push(dv.getUint16(off + i * 2).toString(16));
    // compress longest zero run
    var best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (var j = 0; j < 8; j++) {
      if (g[j] === "0") { if (cur < 0) cur = j; curLen++; if (curLen > bestLen) { bestLen = curLen; best = cur; } }
      else { cur = -1; curLen = 0; }
    }
    if (bestLen > 1) { g.splice(best, bestLen, ""); if (best === 0) g.unshift(""); if (best + bestLen >= 8) g.push(""); }
    return g.join(":").replace(/:{3,}/, "::");
  }
  function isPrivate4(n) { // n = uint32
    var a = (n >>> 24) & 255;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && ((n >>> 16) & 255) >= 16 && ((n >>> 16) & 255) <= 31) return true;
    if (a === 192 && ((n >>> 16) & 255) === 168) return true;
    if (a === 169 && ((n >>> 16) & 255) === 254) return true;
    if (a === 100 && ((n >>> 16) & 255) >= 64 && ((n >>> 16) & 255) <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  function isPrivate6(s) {
    s = s.toLowerCase();
    return s === "::1" || s === "::" || s.indexOf("fe80") === 0 || s.indexOf("fc") === 0 || s.indexOf("fd") === 0 || s.indexOf("ff") === 0;
  }
  function ascii(bytes, off, len) {
    var s = "", end = Math.min(off + len, bytes.length);
    for (var i = off; i < end; i++) { var c = bytes[i]; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : "."; }
    return s;
  }
  // like ascii but preserves control bytes (CR/LF/TAB) so header line-breaks survive; stops at NUL
  function latin1(bytes, off, len) {
    var s = "", end = Math.min(off + len, bytes.length);
    for (var i = off; i < end; i++) { var c = bytes[i]; if (c === 0) break; s += String.fromCharCode(c); }
    return s;
  }

  // ---- DNS QNAME (first question) ----
  function dnsName(bytes, off, limit) {
    var name = "", jumps = 0, p = off, started = false, end = p;
    while (p < limit) {
      var len = bytes[p];
      if (len === 0) { if (!started) end = p + 1; else if (end <= off) end = p + 1; break; }
      if ((len & 0xc0) === 0xc0) { // pointer
        if (!started) { end = p + 2; started = true; }
        p = ((len & 0x3f) << 8) | bytes[p + 1];
        if (++jumps > 12) break;
        continue;
      }
      p++;
      if (p + len > limit) break;
      if (name) name += ".";
      name += ascii(bytes, p, len);
      p += len;
      if (!started) end = p;
    }
    return { name: name, end: end };
  }

  // ---- TLS ClientHello SNI ----
  function tlsSni(b, off, len) {
    var e = off + len;
    if (off + 6 > e) return null;
    if (b[off] !== 0x16 || b[off + 1] !== 0x03) return null;       // handshake, TLS 1.x
    if (b[off + 5] !== 0x01) return null;                          // ClientHello
    var p = off + 5 + 4;                                           // skip record(5) + handshake type(1)+len(3)
    p += 2 + 32;                                                   // client version + random
    if (p >= e) return null;
    var sidLen = b[p]; p += 1 + sidLen;
    if (p + 2 > e) return null;
    var csLen = (b[p] << 8) | b[p + 1]; p += 2 + csLen;
    if (p >= e) return null;
    var compLen = b[p]; p += 1 + compLen;
    if (p + 2 > e) return null;
    var extTotal = (b[p] << 8) | b[p + 1]; p += 2;
    var extEnd = Math.min(e, p + extTotal);
    while (p + 4 <= extEnd) {
      var type = (b[p] << 8) | b[p + 1], l = (b[p + 2] << 8) | b[p + 3]; p += 4;
      if (type === 0x0000) { // server_name
        if (p + 5 > extEnd) return null;
        var nameLen = (b[p + 3] << 8) | b[p + 4];
        var s = ascii(b, p + 5, nameLen);
        return /^[A-Za-z0-9.\-_]+$/.test(s) ? s : null;
      }
      p += l;
    }
    return null;
  }

  var HTTP_METHODS = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "];
  function httpReq(b, off, len) {
    var head = latin1(b, off, Math.min(len, 800));
    var isReq = false; for (var i = 0; i < HTTP_METHODS.length; i++) if (head.indexOf(HTTP_METHODS[i]) === 0) { isReq = true; break; }
    if (!isReq) return null;
    var firstLine = (head.split("\r\n")[0] || head.split("\n")[0] || "");
    var parts = firstLine.split(" ");
    var method = parts[0], path = parts[1] || "/";
    var hm = /\r?\nhost:\s*([^\r\n]+)/i.exec(head);
    var host = hm ? hm[1].trim() : "";
    return { method: method, path: path, host: host };
  }

  // ---- streaming aggregator ----
  function Parser(opts) {
    opts = opts || {};
    this.caps = {
      maxPackets: opts.maxPackets || 3000000,
      maxFlows: opts.maxFlows || 20000,
      maxHosts: opts.maxHosts || 20000,
      maxNames: opts.maxNames || 8000,
      maxBuckets: opts.maxBuckets || 480
    };
    this.leftover = null;
    this.headerDone = false;
    this.fmt = null;          // 'pcap' | 'pcapng'
    this.le = true;
    this.nano = false;
    this.linktype = 1;
    this.snaplen = 0;
    this.ifaces = [];         // pcapng: {linktype, tsresol}
    this.err = null;
    this.onProgress = opts.onProgress || null;

    var caps = this.caps;
    this.S = {
      packets: 0, bytes: 0, firstTs: null, lastTs: null, truncated: false, malformed: 0,
      l3: { ipv4: 0, ipv6: 0, arp: 0, other: 0 },
      proto: { tls: 0, tcp: 0, udp: 0, dns: 0, http: 0, icmp: 0, other: 0 },
      protoPkts: { tls: 0, tcp: 0, udp: 0, dns: 0, http: 0, icmp: 0, other: 0 },
      services: {},           // "port/proto" -> {bytes,pkts}
      hosts: {}, hostCount: 0, hostOverflow: 0,
      flows: {}, flowCount: 0, flowOverflow: 0,
      dns: {}, dnsCount: 0, nx: 0, dnsTypes: {},
      sni: {}, sniCount: 0,
      httpHosts: {}, httpUrls: {}, httpCount: 0,
      scan: {},               // srcip -> {dsts:{}, ndst, ports:{}, nport, first, last}
      ftpCreds: [], smbv1: false, smb2: false, cleartextHttpBytes: 0,
      caps: caps
    };
  }

  Parser.prototype._bucket = function (tsSec, proto, bytes) {
    var S = this.S;
    if (!S.timeline) S.timeline = { start: tsSec, bucketMs: 250, b: [] };
    var T = S.timeline;
    var idx = Math.floor((tsSec - T.start) * 1000 / T.bucketMs);
    if (idx < 0) { T.start = tsSec; idx = 0; }
    while (T.b.length > this.caps.maxBuckets) { // rebucket: double window, merge pairs
      var nb = [];
      for (var i = 0; i < T.b.length; i += 2) {
        var a = T.b[i], c = T.b[i + 1];
        if (c) for (var k in c) a[k] = (a[k] || 0) + c[k];
        nb.push(a);
      }
      T.b = nb; T.bucketMs *= 2;
      idx = Math.floor((tsSec - T.start) * 1000 / T.bucketMs);
    }
    if (idx > this.caps.maxBuckets * 4) { S.truncated = S.truncated; } // guard against absurd gaps
    var bk = T.b[idx]; if (!bk) bk = T.b[idx] = {};
    bk[proto] = (bk[proto] || 0) + bytes;
  };

  Parser.prototype._svc = function (port, proto, bytes) {
    var k = port + "/" + proto, S = this.S, s = S.services[k];
    if (!s) s = S.services[k] = { port: port, proto: proto, bytes: 0, pkts: 0 };
    s.bytes += bytes; s.pkts++;
  };

  Parser.prototype._host = function (ip, outBytes, inBytes) {
    var S = this.S, h = S.hosts[ip];
    if (!h) {
      if (S.hostCount >= this.caps.maxHosts) { S.hostOverflow++; return; }
      h = S.hosts[ip] = { ip: ip, pkts: 0, out: 0, in: 0, internal: null }; S.hostCount++;
    }
    h.pkts++; h.out += outBytes; h.in += inBytes;
  };

  Parser.prototype._flow = function (src, sport, dst, dport, proto, bytes, ts, isSyn) {
    var S = this.S;
    // A conversation groups both directions AND rotating client ephemeral ports: key by
    // {proto, unordered host pair, server port}. Server = the side with the lower port.
    var clientIp, clientPort, serverIp, serverPort;
    if (dport === 0 && sport === 0) { serverIp = dst; serverPort = 0; clientIp = src; clientPort = 0; }
    else if (dport <= sport) { serverIp = dst; serverPort = dport; clientIp = src; clientPort = sport; }
    else { serverIp = src; serverPort = sport; clientIp = dst; clientPort = dport; }
    var pair = clientIp < serverIp ? clientIp + "|" + serverIp : serverIp + "|" + clientIp;
    var key = proto + "|" + pair + "|" + serverPort;
    var f = S.flows[key];
    if (!f) {
      if (S.flowCount >= this.caps.maxFlows) { S.flowOverflow++; return; }
      f = S.flows[key] = { src: clientIp, sport: clientPort, dst: serverIp, dport: serverPort, proto: proto, bytes: 0, pkts: 0, first: ts, last: ts, gN: 0, gSum: 0, gSq: 0, syn: 0 };
      S.flowCount++;
    }
    f.bytes += bytes; f.pkts++;
    if (ts < f.first) f.first = ts;
    if (ts > f.last) { if (f.pkts > 1) { var gap = ts - f.last; if (gap > 0) { f.gN++; f.gSum += gap; f.gSq += gap * gap; } } f.last = ts; }
    if (isSyn) f.syn++;
  };

  Parser.prototype._scan = function (src, dst, dport, ts) {
    var S = this.S, s = S.scan[src];
    if (!s) s = S.scan[src] = { dsts: {}, ndst: 0, ports: {}, nport: 0, first: ts, last: ts };
    s.last = ts;
    if (!s.dsts[dst] && s.ndst < 5000) { s.dsts[dst] = 1; s.ndst++; }
    if (!s.ports[dport] && s.nport < 5000) { s.ports[dport] = 1; s.nport++; }
  };

  // process one packet's bytes (Uint8Array view starting at link layer), with timestamp
  Parser.prototype._packet = function (b, off, caplen, origlen, tsSec, linktype) {
    var S = this.S;
    S.packets++;
    S.bytes += origlen;
    if (S.firstTs === null || tsSec < S.firstTs) S.firstTs = tsSec;
    if (S.lastTs === null || tsSec > S.lastTs) S.lastTs = tsSec;

    var end = off + caplen;
    var etherType = null, l3off = off;

    // ---- link layer ----
    if (linktype === LINKTYPE.ETHERNET) {
      if (off + 14 > end) { S.malformed++; return; }
      etherType = (b[off + 12] << 8) | b[off + 13]; l3off = off + 14;
      while (etherType === 0x8100 || etherType === 0x88a8) { // VLAN tag(s)
        if (l3off + 4 > end) { S.malformed++; return; }
        etherType = (b[l3off + 2] << 8) | b[l3off + 3]; l3off += 4;
      }
    } else if (linktype === LINKTYPE.RAW || linktype === LINKTYPE.RAW2 || linktype === LINKTYPE.IPV4 || linktype === LINKTYPE.IPV6) {
      var v = b[off] >> 4; etherType = v === 6 ? 0x86dd : 0x0800; l3off = off;
    } else if (linktype === LINKTYPE.NULL || linktype === LINKTYPE.LOOP) {
      if (off + 4 > end) { S.malformed++; return; }
      var fam = this.le && linktype === LINKTYPE.NULL ? b[off] : b[off + 3];
      etherType = (fam === 24 || fam === 28 || fam === 30) ? 0x86dd : 0x0800; l3off = off + 4;
    } else if (linktype === LINKTYPE.SLL) {
      if (off + 16 > end) { S.malformed++; return; }
      etherType = (b[off + 14] << 8) | b[off + 15]; l3off = off + 16;
    } else if (linktype === LINKTYPE.SLL2) {
      if (off + 20 > end) { S.malformed++; return; }
      etherType = (b[off] << 8) | b[off + 1]; l3off = off + 20;
    } else {
      S.l3.other += origlen; S.proto.other += origlen; S.protoPkts.other++; return;
    }

    var dv = this._dv; // DataView over same buffer
    // ---- L3 ----
    var src, dst, l4proto, l4off, srcPriv, dstPriv;
    if (etherType === 0x0806) { S.l3.arp += origlen; S.proto.other += origlen; S.protoPkts.other++; this._bucket(tsSec, "other", origlen); return; }
    if (etherType === 0x0800) { // IPv4
      if (l3off + 20 > end) { S.malformed++; return; }
      var ihl = (b[l3off] & 0x0f) * 4; if (ihl < 20) { S.malformed++; return; }
      l4proto = b[l3off + 9];
      var sN = u32(dv, l3off + 12), dN = u32(dv, l3off + 16);
      src = ipv4str(dv, l3off + 12); dst = ipv4str(dv, l3off + 16);
      srcPriv = isPrivate4(sN); dstPriv = isPrivate4(dN);
      l4off = l3off + ihl; S.l3.ipv4 += origlen;
    } else if (etherType === 0x86dd) { // IPv6
      if (l3off + 40 > end) { S.malformed++; return; }
      l4proto = b[l3off + 6]; var hdr = l3off + 40, hops = 0;
      while ((l4proto === 0 || l4proto === 43 || l4proto === 60 || l4proto === 44) && hops < 8) {
        if (hdr + 2 > end) break;
        var nxt = b[hdr], extLen = l4proto === 44 ? 8 : (b[hdr + 1] + 1) * 8;
        l4proto = nxt; hdr += extLen; hops++;
      }
      src = ipv6str(dv, l3off + 8); dst = ipv6str(dv, l3off + 24);
      srcPriv = isPrivate6(src); dstPriv = isPrivate6(dst);
      l4off = hdr; S.l3.ipv6 += origlen;
    } else { S.l3.other += origlen; S.proto.other += origlen; S.protoPkts.other++; this._bucket(tsSec, "other", origlen); return; }

    this._host(src, origlen, 0); this._host(dst, 0, origlen);

    // ---- L4 ----
    var proto = "other", sport = 0, dport = 0, isSyn = false, payOff = l4off, payLen = 0;
    if (l4proto === 6) { // TCP
      if (l4off + 20 > end) { S.malformed++; proto = "tcp"; }
      else {
        sport = (b[l4off] << 8) | b[l4off + 1]; dport = (b[l4off + 2] << 8) | b[l4off + 3];
        var doff = (b[l4off + 12] >> 4) * 4; var flags = b[l4off + 13];
        isSyn = (flags & 0x12) === 0x02; // SYN set, ACK not
        payOff = l4off + doff; payLen = Math.max(0, end - payOff);
        proto = "tcp";
      }
    } else if (l4proto === 17) { // UDP
      if (l4off + 8 > end) { S.malformed++; proto = "udp"; }
      else { sport = (b[l4off] << 8) | b[l4off + 1]; dport = (b[l4off + 2] << 8) | b[l4off + 3]; payOff = l4off + 8; payLen = Math.max(0, end - payOff); proto = "udp"; }
    } else if (l4proto === 1 || l4proto === 58) { // ICMP / ICMPv6
      proto = "icmp";
    } else { proto = "other"; }

    // ---- app-layer classification + extraction ----
    var chart = proto;
    if (proto === "tcp") {
      if (dport === 443 || sport === 443 || dport === 8443 || sport === 8443) {
        chart = "tls";
        if (payLen > 6) { var sni = tlsSni(b, payOff, payLen); if (sni) this._name(S.sni, "sniCount", sni); }
      } else if (dport === 80 || sport === 80 || dport === 8080 || sport === 8080 || dport === 8000) {
        var hr = payLen > 8 ? httpReq(b, payOff, payLen) : null;
        if (hr) { chart = "http"; this._http(hr); if (!dstPriv) S.cleartextHttpBytes += origlen; }
        else chart = "http";
      } else if (dport === 53 || sport === 53) {
        chart = "dns";
        if (payLen > 2) { this._dns(b, payOff + 2, end); } // TCP DNS has 2-byte length prefix
      } else if (dport === 21 || sport === 21) {
        if (payLen > 5) this._ftp(b, payOff, payLen, src, dst);
      } else if (dport === 445 || sport === 445) {
        if (payLen > 8) this._smb(b, payOff, payLen);
      }
    } else if (proto === "udp") {
      if (dport === 53 || sport === 53) { chart = "dns"; if (payLen > 12) this._dns(b, payOff, end); }
    }

    S.proto[chart] += origlen; S.protoPkts[chart]++;
    this._bucket(tsSec, chart, origlen);
    if (dport) this._svc(dport, proto, origlen);
    this._flow(src, sport, dst, dport, proto, origlen, tsSec, isSyn);
    if (isSyn && dport) this._scan(src, dst, dport, tsSec);
  };

  Parser.prototype._name = function (map, counter, name) {
    var S = this.S;
    if (map[name] === undefined) { if (S[counter] >= this.caps.maxNames) return; S[counter]++; }
    map[name] = (map[name] || 0) + 1;
  };
  Parser.prototype._dns = function (b, h, end) {
    // h = start of the DNS header (id,flags,counts); question follows at h+12.
    var S = this.S;
    if (h + 12 > end) return;
    var flags = (b[h + 2] << 8) | b[h + 3], qd = (b[h + 4] << 8) | b[h + 5];
    if (((flags >> 15) & 1) === 1 && (flags & 0x0f) === 3) S.nx++; // NXDOMAIN response
    if (qd < 1) return;
    var r = dnsName(b, h + 12, end);
    if (r.name && r.name.length > 1 && /[a-z0-9]/i.test(r.name)) {
      this._name(S.dns, "dnsCount", r.name.toLowerCase());
      var tOff = r.end; if (tOff + 2 <= end) { var qtype = (b[tOff] << 8) | b[tOff + 1]; var tn = ({ 1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 12: "PTR", 6: "SOA", 33: "SRV", 65: "HTTPS" })[qtype] || ("T" + qtype); S.dnsTypes[tn] = (S.dnsTypes[tn] || 0) + 1; }
    }
  };
  Parser.prototype._http = function (hr) {
    var S = this.S;
    if (hr.host) this._name(S.httpHosts, "httpCount", hr.host.toLowerCase());
    if (hr.host && hr.path) { var u = "http://" + hr.host + hr.path; if (u.length < 200) this._name(S.httpUrls, "httpCount", u); }
  };
  Parser.prototype._ftp = function (b, off, len, src, dst) {
    var S = this.S; if (S.ftpCreds.length >= 20) return;
    var s = ascii(b, off, Math.min(len, 120));
    var m = /\b(USER|PASS)\s+(\S+)/i.exec(s);
    if (m) S.ftpCreds.push({ cmd: m[1].toUpperCase(), val: m[2].slice(0, 40), src: src, dst: dst });
  };
  Parser.prototype._smb = function (b, off, len) {
    var S = this.S;
    for (var i = off; i < off + Math.min(len, 64) - 4; i++) {
      if (b[i + 1] === 0x53 && b[i + 2] === 0x4d && b[i + 3] === 0x42) { // 'S''M''B'
        if (b[i] === 0xff) { S.smbv1 = true; return; }
        if (b[i] === 0xfe) { S.smb2 = true; return; }
      }
    }
  };

  // ---- feed chunks ----
  Parser.prototype.push = function (chunk) {
    if (this.err) return;
    var buf = concat(this.leftover, chunk); this.leftover = null;
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this._dv = dv; this._buf = buf;
    var pos = 0;

    if (!this.headerDone) {
      if (buf.length < 4) { this.leftover = buf; return; }
      var m0 = buf[0], m1 = buf[1], m2 = buf[2], m3 = buf[3];
      if (m0 === 0x0a && m1 === 0x0d && m2 === 0x0d && m3 === 0x0a) { this.fmt = "pcapng"; }
      else if ((m0 === 0xa1 && m1 === 0xb2 && m2 === 0xc3 && m3 === 0xd4)) { this.fmt = "pcap"; this.le = false; this.nano = false; }
      else if ((m0 === 0xd4 && m1 === 0xc3 && m2 === 0xb2 && m3 === 0xa1)) { this.fmt = "pcap"; this.le = true; this.nano = false; }
      else if ((m0 === 0xa1 && m1 === 0xb2 && m2 === 0x3c && m3 === 0x4d)) { this.fmt = "pcap"; this.le = false; this.nano = true; }
      else if ((m0 === 0x4d && m1 === 0x3c && m2 === 0xb2 && m3 === 0xa1)) { this.fmt = "pcap"; this.le = true; this.nano = true; }
      else { this.err = "Not a PCAP or PCAPNG file (bad magic)."; return; }

      if (this.fmt === "pcap") {
        if (buf.length < 24) { this.leftover = buf; return; }
        this.snaplen = this.le ? dv.getUint32(16, true) : dv.getUint32(16, false);
        this.linktype = (this.le ? dv.getUint32(20, true) : dv.getUint32(20, false)) & 0xffff;
        pos = 24; this.headerDone = true;
      } else { this.headerDone = true; pos = 0; } // pcapng: blocks parsed below, incl. SHB
    }

    if (this.fmt === "pcap") pos = this._pcap(buf, dv, pos);
    else pos = this._pcapng(buf, dv, pos);

    this.leftover = pos < buf.length ? buf.slice(pos) : null;
    if (this.onProgress) this.onProgress(this.S.packets, this.S.bytes);
  };

  Parser.prototype._pcap = function (buf, dv, pos) {
    var le = this.le, lt = this.linktype, cap = this.caps.maxPackets;
    while (pos + 16 <= buf.length) {
      if (this.S.packets >= cap) { this.S.truncated = true; return buf.length; }
      var tsSec = dv.getUint32(pos, le) >>> 0;
      var tsFrac = dv.getUint32(pos + 4, le) >>> 0;
      var inclLen = dv.getUint32(pos + 8, le) >>> 0;
      var origLen = dv.getUint32(pos + 12, le) >>> 0;
      if (inclLen > 262144 || origLen > 10 * 1024 * 1024) { this.err = "Corrupt record (length out of range)."; return buf.length; }
      if (pos + 16 + inclLen > buf.length) return pos; // need more data
      var ts = tsSec + (this.nano ? tsFrac / 1e9 : tsFrac / 1e6);
      try { this._packet(buf, pos + 16, inclLen, origLen, ts, lt); } catch (e) { this.S.malformed++; }
      pos += 16 + inclLen;
    }
    return pos;
  };

  Parser.prototype._pcapng = function (buf, dv, pos) {
    var cap = this.caps.maxPackets;
    while (pos + 12 <= buf.length) {
      if (this.S.packets >= cap) { this.S.truncated = true; return buf.length; }
      // need endianness: determined by SHB; default LE until SHB seen
      var le = this._ngle === undefined ? true : this._ngle;
      var btype = dv.getUint32(pos, le) >>> 0;
      var blen = dv.getUint32(pos + 4, le) >>> 0;
      if (btype === 0x0a0d0d0a) { // SHB - read BOM to set endianness
        var bomBE = dv.getUint32(pos + 8, false) >>> 0;
        this._ngle = (bomBE !== 0x1a2b3c4d); // if BE read != magic, it's LE
        le = this._ngle;
        blen = dv.getUint32(pos + 4, le) >>> 0;
      }
      if (blen < 12 || blen > 268435456) { this.err = "Corrupt pcapng block length."; return buf.length; }
      if (pos + blen > buf.length) return pos; // need more

      if (btype === 0x00000001) { // IDB
        var ltype = dv.getUint16(pos + 8, le);
        var iface = { linktype: ltype, tsresol: 6 };
        // parse options for if_tsresol (code 9)
        var op = pos + 16;
        while (op + 4 <= pos + blen - 4) {
          var code = dv.getUint16(op, le), olen = dv.getUint16(op + 2, le); op += 4;
          if (code === 0) break;
          if (code === 9 && olen >= 1) { var raw = buf[op]; iface.tsresol = (raw & 0x80) ? -(raw & 0x7f) : raw; }
          op += olen + ((4 - (olen % 4)) % 4);
        }
        this.ifaces.push(iface);
      } else if (btype === 0x00000006) { // EPB
        var ifid = dv.getUint32(pos + 8, le) >>> 0;
        var tsHigh = dv.getUint32(pos + 12, le) >>> 0, tsLow = dv.getUint32(pos + 16, le) >>> 0;
        var capLen = dv.getUint32(pos + 20, le) >>> 0, origLen = dv.getUint32(pos + 24, le) >>> 0;
        var ifc = this.ifaces[ifid] || this.ifaces[0] || { linktype: 1, tsresol: 6 };
        var unit = ifc.tsresol < 0 ? Math.pow(2, ifc.tsresol) : Math.pow(10, -ifc.tsresol);
        var tsVal = (tsHigh * 4294967296 + tsLow) * unit;
        if (pos + 28 + capLen <= pos + blen) { try { this._packet(buf, pos + 28, capLen, origLen, tsVal, ifc.linktype); } catch (e) { this.S.malformed++; } }
      } else if (btype === 0x00000003) { // SPB
        var oLen = dv.getUint32(pos + 8, le) >>> 0;
        var ifc0 = this.ifaces[0] || { linktype: 1 };
        var capL = Math.min(oLen, blen - 16);
        try { this._packet(buf, pos + 12, capL, oLen, this.S.lastTs || 0, ifc0.linktype); } catch (e) { this.S.malformed++; }
      }
      pos += blen;
    }
    return pos;
  };

  Parser.prototype.end = function () { /* leftover discarded */ };

  // ---- finalize into a plain analysis object (sorted/capped lists) ----
  Parser.prototype.result = function () {
    var S = this.S, caps = this.caps;
    if (this.err) return { ok: false, error: this.err };

    var dur = (S.firstTs !== null && S.lastTs !== null) ? Math.max(0, S.lastTs - S.firstTs) : 0;

    // top hosts
    var hosts = Object.keys(S.hosts).map(function (k) { var h = S.hosts[k]; return { ip: h.ip, pkts: h.pkts, bytes: h.out + h.in, out: h.out, in: h.in }; });
    hosts.sort(function (a, b) { return b.bytes - a.bytes; });

    // flows
    var flows = Object.keys(S.flows).map(function (k) {
      var f = S.flows[k]; var mean = f.gN ? f.gSum / f.gN : 0;
      var variance = f.gN ? Math.max(0, f.gSq / f.gN - mean * mean) : 0; var cv = mean > 0 ? Math.sqrt(variance) / mean : 0;
      return { src: f.src, sport: f.sport, dst: f.dst, dport: f.dport, proto: f.proto, bytes: f.bytes, pkts: f.pkts, dur: Math.max(0, f.last - f.first), first: f.first, last: f.last, gN: f.gN, gapMean: mean, gapCv: cv, syn: f.syn };
    });
    flows.sort(function (a, b) { return b.bytes - a.bytes; });

    // services
    var services = Object.keys(S.services).map(function (k) { return S.services[k]; });
    services.sort(function (a, b) { return b.bytes - a.bytes; });

    function topMap(m, n) { return Object.keys(m).map(function (k) { return { name: k, count: m[k] }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, n); }

    // scan summary
    var scans = Object.keys(S.scan).map(function (k) { var s = S.scan[k]; return { src: k, ndst: s.ndst, nport: s.nport, window: Math.max(0, s.last - s.first) }; })
      .filter(function (s) { return s.ndst >= 20 || s.nport >= 100; })
      .sort(function (a, b) { return (b.ndst + b.nport) - (a.ndst + a.nport); });

    // timeline to a DENSE array (the bucket array is sparse; .map would keep the holes)
    var timeline = null;
    if (S.timeline) {
      var raw = S.timeline.b, dense = [];
      for (var bi = 0; bi < raw.length; bi++) dense.push(raw[bi] || {});
      timeline = { bucketMs: S.timeline.bucketMs, start: S.timeline.start, buckets: dense };
    }

    return {
      ok: true,
      meta: {
        format: this.fmt, linktype: this.linktype || (this.ifaces[0] && this.ifaces[0].linktype) || 0,
        packets: S.packets, bytes: S.bytes, firstTs: S.firstTs, lastTs: S.lastTs, duration: dur,
        truncated: S.truncated, malformed: S.malformed, snaplen: this.snaplen,
        interfaces: this.ifaces.length
      },
      l3: S.l3, proto: S.proto, protoPkts: S.protoPkts,
      timeline: timeline,
      hosts: hosts, hostOverflow: S.hostOverflow,
      flows: flows, flowCount: S.flowCount, flowOverflow: S.flowOverflow,
      services: services,
      dns: topMap(S.dns, 200), dnsTotal: S.dnsCount, dnsTypes: S.dnsTypes, nx: S.nx,
      sni: topMap(S.sni, 200), sniTotal: S.sniCount,
      httpHosts: topMap(S.httpHosts, 100), httpUrls: topMap(S.httpUrls, 100),
      scans: scans,
      ftpCreds: S.ftpCreds, smbv1: S.smbv1, smb2: S.smb2, cleartextHttpBytes: S.cleartextHttpBytes
    };
  };

  // Convenience for tests / small files: parse an entire buffer at once.
  function parse(bytes, opts) { var p = new Parser(opts); p.push(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)); p.end(); return p.result(); }

  var api = { Parser: Parser, parse: parse, LINKTYPE: LINKTYPE };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PCAP = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
