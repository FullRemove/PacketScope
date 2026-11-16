/**
 * Public IP Intelligence & Geolocation Caching Service.
 *
 * - Strips CIDR suffixes and rejects private, reserved, loopback, multicast, and invalid IPs.
 * - Caches results in the database `ip_intelligence` table (24-hour TTL) so per-packet geolocation never occurs.
 * - Enforces a token-bucket rate limiter (max 40 external lookups/minute) with 2.5s request timeout.
 * - Never fabricates coordinates or locations; if external providers are unreachable, returns unlocated status.
 */

import { getIpVersion, isPrivateOrReservedIp, normalizeIp } from './ipUtils.ts';

export interface IpIntelRecord {
  ip: string;
  ipVersion: number;
  isPublic: boolean;
  asn: string | null;
  isp: string | null;
  orgName: string | null;
  countryCode: string | null;
  countryName: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  providerSource: string;
  lastRefreshedAt: string;
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_LOOKUPS_PER_MINUTE = 40;

let lookupTimestamps: number[] = [];
const inFlightLookups = new Map<string, Promise<IpIntelRecord>>();

export function getGeoIpRateLimitStatus() {
  const now = Date.now();
  lookupTimestamps = lookupTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  return {
    usedInWindow: lookupTimestamps.length,
    limitPerMinute: MAX_LOOKUPS_PER_MINUTE,
    remaining: Math.max(0, MAX_LOOKUPS_PER_MINUTE - lookupTimestamps.length),
  };
}

function consumeRateToken(): boolean {
  const now = Date.now();
  lookupTimestamps = lookupTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (lookupTimestamps.length >= MAX_LOOKUPS_PER_MINUTE) return false;
  lookupTimestamps.push(now);
  return true;
}

async function fetchExternalGeoIp(ip: string): Promise<Partial<IpIntelRecord> & { providerSource: string }> {
  // Primary provider: ipwho.is (HTTPS, no API key required for low volume)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as any;
      if (data && data.success !== false && typeof data.latitude === 'number' && typeof data.longitude === 'number') {
        return {
          asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
          isp: data.connection?.isp || null,
          orgName: data.connection?.org || data.connection?.isp || null,
          countryCode: data.country_code || null,
          countryName: data.country || null,
          city: data.city || null,
          latitude: data.latitude,
          longitude: data.longitude,
          providerSource: 'ipwho.is',
        };
      }
    }
  } catch {
    // Fall through to secondary provider
  }

  // Secondary provider: ip-api.com (rate limit 45 req/min)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,city,lat,lon,isp,org,as`,
      { signal: controller.signal }
    );
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as any;
      if (data && data.status === 'success' && typeof data.lat === 'number' && typeof data.lon === 'number') {
        const asnMatch = typeof data.as === 'string' ? data.as.match(/^(AS\d+)/i) : null;
        return {
          asn: asnMatch ? asnMatch[1].toUpperCase() : data.as || null,
          isp: data.isp || null,
          orgName: data.org || data.isp || null,
          countryCode: data.countryCode || null,
          countryName: data.country || null,
          city: data.city || null,
          latitude: data.lat,
          longitude: data.lon,
          providerSource: 'ip-api.com',
        };
      }
    }
  } catch {
    // Fall through to tertiary provider
  }

  // Tertiary provider: ipapi.co (HTTPS fallback)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as any;
      if (data && !data.error && typeof data.latitude === 'number' && typeof data.longitude === 'number') {
        const rawAsn = typeof data.asn === 'string' ? data.asn.trim().toUpperCase() : null;
        return {
          asn: rawAsn ? (rawAsn.startsWith('AS') ? rawAsn : `AS${rawAsn}`) : null,
          isp: data.org || null,
          orgName: data.org || null,
          countryCode: data.country_code || null,
          countryName: data.country_name || null,
          city: data.city || null,
          latitude: data.latitude,
          longitude: data.longitude,
          providerSource: 'ipapi.co',
        };
      }
    }
  } catch {
    // External lookup unavailable
  }

  return {
    asn: null,
    isp: null,
    orgName: null,
    countryCode: null,
    countryName: null,
    city: null,
    latitude: null,
    longitude: null,
    providerSource: 'unavailable',
  };
}

export interface IpIntelStoreAdapter {
  getCachedIpIntel(ip: string): IpIntelRecord | null;
  upsertIpIntel(record: IpIntelRecord): void;
}

export async function resolvePublicIpIntelligence(
  rawIp: string,
  store: IpIntelStoreAdapter,
  options: { forceRefresh?: boolean; skipExternal?: boolean } = {}
): Promise<IpIntelRecord | null> {
  const ip = normalizeIp(rawIp);
  if (!ip) return null;

  const ipVersion = getIpVersion(ip);
  if (!ipVersion) return null;

  if (isPrivateOrReservedIp(ip)) {
    return {
      ip,
      ipVersion,
      isPublic: false,
      asn: null,
      isp: null,
      orgName: 'Private / Reserved Network',
      countryCode: null,
      countryName: null,
      city: null,
      latitude: null,
      longitude: null,
      providerSource: 'rfc_filter',
      lastRefreshedAt: new Date().toISOString(),
    };
  }

  const cached = store.getCachedIpIntel(ip);
  if (cached && !options.forceRefresh) {
    const ageMs = Date.now() - new Date(cached.lastRefreshedAt).getTime();
    if (ageMs < CACHE_TTL_MS && (cached.providerSource !== 'unavailable' || options.skipExternal)) {
      return cached;
    }
  }

  if (options.skipExternal) {
    return cached;
  }

  const existingPromise = inFlightLookups.get(ip);
  if (existingPromise) return existingPromise;

  const promise = (async () => {
    try {
      if (!consumeRateToken()) {
        return (
          cached ?? {
            ip,
            ipVersion,
            isPublic: true,
            asn: null,
            isp: null,
            orgName: null,
            countryCode: null,
            countryName: null,
            city: null,
            latitude: null,
            longitude: null,
            providerSource: 'rate_limited',
            lastRefreshedAt: new Date().toISOString(),
          }
        );
      }

      const geo = await fetchExternalGeoIp(ip);
      const record: IpIntelRecord = {
        ip,
        ipVersion,
        isPublic: true,
        asn: geo.asn ?? null,
        isp: geo.isp ?? null,
        orgName: geo.orgName ?? null,
        countryCode: geo.countryCode ?? null,
        countryName: geo.countryName ?? null,
        city: geo.city ?? null,
        latitude: geo.latitude ?? null,
        longitude: geo.longitude ?? null,
        providerSource: geo.providerSource,
        lastRefreshedAt: new Date().toISOString(),
      };
      store.upsertIpIntel(record);
      return record;
    } finally {
      inFlightLookups.delete(ip);
    }
  })();

  inFlightLookups.set(ip, promise);
  return promise;
}
