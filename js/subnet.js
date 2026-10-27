/* ============================================================================
 *  subnet.js - IPv4 maths engine
 *  Pure logic with NO DOM access, so it can be unit-tested in Node or a console.
 *  All addresses are handled as unsigned 32-bit integers; `>>> 0` forces
 *  JavaScript's signed bitwise results back to unsigned.
 * ========================================================================== */
const Subnet = (() => {
  'use strict';

  /** "192.168.1.1" -> 3232235777 (null if invalid). */
  function ipToInt(ip) {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p) || +p > 255) return null;  // digits only, 0-255
      n = n * 256 + +p;                                   // shift one octet left
    }
    return n;
  }

  /** 3232235777 -> "192.168.1.1". */
  const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

  /** Prefix length -> mask integer (e.g. 24 -> 255.255.255.0). */
  const maskFromPrefix = (p) => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);

  /** Dotted mask -> prefix length; null if the mask is not contiguous ones. */
  function prefixFromMask(maskStr) {
    const m = ipToInt(maskStr);
    if (m === null) return null;
    const bin = m.toString(2).padStart(32, '0');
    if (!/^1*0*$/.test(bin)) return null;                 // e.g. 255.0.255.0 is invalid
    const ones = bin.indexOf('0');
    return ones === -1 ? 32 : ones;
  }

  /** Accepts "ip/24", "ip/255.255.255.0" or "ip 255.255.255.0". */
  function parse(raw) {
    const [ipStr, rest] = raw.trim().split(/[/\s]+/);
    const ip = ipToInt(ipStr || '');
    if (ip === null) return { error: 'Invalid IPv4 address.' };
    if (rest === undefined) return { error: 'Add a prefix, e.g. /24 or a mask.' };
    const prefix = /^\d+$/.test(rest) ? +rest : prefixFromMask(rest);
    if (prefix === null || prefix < 0 || prefix > 32) return { error: 'Invalid prefix or subnet mask.' };
    return { ip, prefix };
  }

  /** Core calculation: everything derived from an address + prefix. */
  function calc(ip, prefix) {
    const mask = maskFromPrefix(prefix);
    const wildcard = ~mask >>> 0;                         // inverted mask = host bits
    const network = (ip & mask) >>> 0;                    // AND keeps only network bits
    const broadcast = (network | wildcard) >>> 0;         // OR sets every host bit
    const total = 2 ** (32 - prefix);
    // RFC 3021: /31 is a point-to-point link (2 usable), /32 is a single host.
    const usable = prefix === 32 ? 1 : prefix === 31 ? 2 : total - 2;
    const first = prefix >= 31 ? network : network + 1;
    const last = prefix >= 31 ? broadcast : broadcast - 1;
    const o = ip >>> 24;
    const cls = o < 128 ? 'A' : o < 192 ? 'B' : o < 224 ? 'C' : o < 240 ? 'D (multicast)' : 'E (reserved)';
    return {
      ip, prefix, mask, network, broadcast, total, usable, cls,
      ipStr: intToIp(ip), maskStr: intToIp(mask), wildcardStr: intToIp(wildcard),
      networkStr: intToIp(network), broadcastStr: intToIp(broadcast),
      firstStr: intToIp(first), lastStr: intToIp(last),
    };
  }

  /** Address blocks with special meaning: [base, prefix, label, risk, note]. */
  const RANGES = [
    ['10.0.0.0', 8, 'Private (RFC 1918)', 'low', 'Internal only. Reaching it normally requires a foothold, VPN or pivot.'],
    ['172.16.0.0', 12, 'Private (RFC 1918)', 'low', 'Internal only. Common in cloud VPCs and container networks.'],
    ['192.168.0.0', 16, 'Private (RFC 1918)', 'low', 'Typical home/office LAN. Not routable on the internet.'],
    ['127.0.0.0', 8, 'Loopback', 'info', 'Traffic never leaves the host. Useful for local service testing.'],
    ['169.254.0.0', 16, 'Link-local (APIPA)', 'info', 'Self-assigned when DHCP fails. Often signals a network fault.'],
    ['100.64.0.0', 10, 'Carrier-grade NAT (RFC 6598)', 'info', 'ISP shared address space; not directly reachable from outside.'],
    ['192.0.2.0', 24, 'Documentation (TEST-NET-1)', 'info', 'Reserved for examples; safe to use in reports.'],
    ['198.51.100.0', 24, 'Documentation (TEST-NET-2)', 'info', 'Reserved for examples; safe to use in reports.'],
    ['203.0.113.0', 24, 'Documentation (TEST-NET-3)', 'info', 'Reserved for examples; safe to use in reports.'],
    ['224.0.0.0', 4, 'Multicast', 'info', 'One-to-many delivery; not a host address.'],
    ['240.0.0.0', 4, 'Reserved', 'info', 'Reserved for future use; should never appear on a network.'],
    ['0.0.0.0', 8, '"This" network', 'info', 'Source-only placeholder; not a valid destination.'],
  ];

  /** Classify an address against RANGES; anything left is public. */
  function classify(ip) {
    for (const [base, p, label, risk, note] of RANGES) {
      const m = maskFromPrefix(p);
      if (((ip & m) >>> 0) === ipToInt(base)) return { label, risk, note };
    }
    return { label: 'Public / Internet-routable', risk: 'high',
             note: 'Exposed address space. Only scan ranges you own or have written authorization to test.' };
  }

  /** Split a network into subnets of `newPrefix` (rows capped for the UI). */
  function split(info, newPrefix, limit = 256) {
    const size = 2 ** (32 - newPrefix);
    const count = 2 ** (newPrefix - info.prefix);
    const rows = [];
    for (let i = 0; i < Math.min(count, limit); i++) rows.push(calc(info.network + i * size, newPrefix));
    return { count, rows };
  }

  /** 32-bit int -> "11000000.10101000.00000001.00001010". */
  const toBinary = (n) => [24, 16, 8, 0].map((s) => ((n >>> s) & 255).toString(2).padStart(8, '0')).join('.');

  /** Rough sweep time for `hosts` probes at `pps` packets per second. */
  function scanTime(hosts, pps = 1000) {
    const s = hosts / pps;
    if (s < 1) return '< 1 second';
    if (s < 60) return `~${Math.round(s)} seconds`;
    if (s < 3600) return `~${(s / 60).toFixed(1)} minutes`;
    if (s < 86400) return `~${(s / 3600).toFixed(1)} hours`;
    return `~${(s / 86400).toFixed(1)} days`;
  }

  return { parse, calc, classify, split, toBinary, scanTime, intToIp };
})();

