/**
 * IP address normalization, validation, CIDR stripping, and RFC privacy classification.
 * Ensures host IPs like "10.33.24.244/32" display cleanly as "10.33.24.244"
 * and excludes private, loopback, link-local, multicast, and reserved ranges from geolocation.
 */

export function stripCidrSuffix(rawIp: string): string {
  const trimmed = rawIp.trim();
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx === -1) return trimmed;
  return trimmed.slice(0, slashIdx).trim();
}

export function isValidIpv4(ip: string): boolean {
  const clean = stripCidrSuffix(ip);
  const parts = clean.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

export function isValidIpv6(ip: string): boolean {
  const clean = stripCidrSuffix(ip);
  if (!clean.includes(':')) return false;
  // Reject obviously invalid characters or multiple ::
  if (!/^[0-9a-fA-F:]+$/.test(clean)) return false;
  const doubleColons = clean.split('::');
  if (doubleColons.length > 2) return false;
  const segments = clean.split(':').filter((s) => s.length > 0);
  if (doubleColons.length === 1 && segments.length !== 8) return false;
  if (doubleColons.length === 2 && segments.length > 7) return false;
  return segments.every((seg) => seg.length >= 1 && seg.length <= 4);
}

export function getIpVersion(ip: string): 4 | 6 | null {
  if (isValidIpv4(ip)) return 4;
  if (isValidIpv6(ip)) return 6;
  return null;
}

export function normalizeIp(rawIp: string): string | null {
  const stripped = stripCidrSuffix(rawIp);
  const version = getIpVersion(stripped);
  if (!version) return null;
  return version === 6 ? stripped.toLowerCase() : stripped;
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = normalizeIp(rawIp);
  if (!ip) return true;

  if (isValidIpv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    // 0.0.0.0/8 ("This network")
    if (a === 0) return true;
    // 10.0.0.0/8 (RFC 1918)
    if (a === 10) return true;
    // 100.64.0.0/10 (RFC 6598 CGNAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (Link-local)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (RFC 1918)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (a === 192 && b === 0 && c === 0) return true;
    // 192.0.2.0/24 (TEST-NET-1)
    if (a === 192 && b === 0 && c === 2) return true;
    // 192.168.0.0/16 (RFC 1918)
    if (a === 192 && b === 168) return true;
    // 198.18.0.0/15 (Benchmarking)
    if (a === 198 && (b === 18 || b === 19)) return true;
    // 198.51.100.0/24 (TEST-NET-2)
    if (a === 198 && b === 51 && c === 100) return true;
    // 203.0.113.0/24 (TEST-NET-3)
    if (a === 203 && b === 0 && c === 113) return true;
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
    if (a >= 224) return true;
    return false;
  }

  // IPv6 checks
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA fc00::/7
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true; // Link-local fe80::/10
  if (lower.startsWith('ff')) return true; // Multicast ff00::/8
  if (lower.startsWith('2001:db8:') || lower.startsWith('2001:0db8:')) return true; // Documentation
  return false;
}

export function inferTrafficDirection(srcIp: string, dstIp: string): 'outbound' | 'inbound' | 'internal' | 'unknown' {
  const srcNorm = normalizeIp(srcIp);
  const dstNorm = normalizeIp(dstIp);
  if (!srcNorm || !dstNorm) return 'unknown';

  const srcPriv = isPrivateOrReservedIp(srcNorm);
  const dstPriv = isPrivateOrReservedIp(dstNorm);

  if (srcPriv && dstPriv) return 'internal';
  if (srcPriv && !dstPriv) return 'outbound';
  if (!srcPriv && dstPriv) return 'inbound';
  return 'unknown';
}
