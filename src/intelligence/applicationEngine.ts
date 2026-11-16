/**
 * PacketScope Application Intelligence Engine.
 *
 * Best-effort application classification using multi-source evidence:
 * - DNS query domain
 * - TLS Server Name Indication (SNI)
 * - HTTP Host header
 * - Confirmed protocol / ASN / service signatures
 *
 * Confidence levels:
 * - HIGH: Multiple reliable matching indicators (e.g., matching DNS/TLS SNI + corroborating protocol/port/endpoint)
 * - MEDIUM: One reliable indicator (e.g., verified TLS SNI or DNS query domain)
 * - LOW: Weak or incomplete evidence (e.g., cloud ASN or generic endpoint hint only)
 * - UNCLASSIFIED: Encrypted or ambiguous traffic with no reliable application evidence
 *
 * Strictly enforces:
 * - Encrypted traffic without reliable SNI/DNS stays UNCLASSIFIED.
 * - Facebook/Meta IP ranges alone NEVER classify as Facebook Messenger.
 */

import type { ConfidenceLevel, ProtocolAnalysisResult, RawPacketMetadata } from './protocolEngine';

export interface AppClassificationResult {
  appName: string;
  evidenceSource: string;
  confidence: ConfidenceLevel;
  classificationMode: 'confirmed' | 'inferred';
  hostname: string | null;
}

interface AppSignatureRule {
  appName: string;
  domainSuffixes: string[];
  preferredProtocols: string[];
}

const APP_SIGNATURES: AppSignatureRule[] = [
  {
    appName: 'WhatsApp',
    domainSuffixes: ['whatsapp.net', 'whatsapp.com', 'wa.me', 'g.whatsapp.net', 'whatsapp.biz'],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Facebook Messenger',
    domainSuffixes: [
      'messenger.com',
      'm.me',
      'edge-chat.facebook.com',
      'mqtt-mini.facebook.com',
      'graph.facebook.com',
      'rupload.facebook.com',
      'msgr.facebook.com',
    ],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Instagram',
    domainSuffixes: ['instagram.com', 'cdninstagram.com', 'i.instagram.com', 'ig.me'],
    preferredProtocols: ['TLS', 'QUIC', 'DNS'],
  },
  {
    appName: 'Snapchat',
    domainSuffixes: ['snapchat.com', 'sc-cdn.net', 'snap-dev.net', 'feelinsonice.com'],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'DNS'],
  },
  {
    appName: 'Telegram',
    domainSuffixes: ['telegram.org', 't.me', 'telegram.me', 'tdesktop.com', 'web.telegram.org', 'cdn-telegram.org', 'telesco.pe'],
    preferredProtocols: ['TLS', 'MTPROTO', 'DNS'],
  },
  {
    appName: 'Viber',
    domainSuffixes: ['viber.com', 'viber.cdn', 'viber.me'],
    preferredProtocols: ['TLS', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Signal',
    domainSuffixes: ['signal.org', 'whispersystems.org'],
    preferredProtocols: ['TLS', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Apple Services / FaceTime',
    domainSuffixes: ['ess.apple.com', 'push.apple.com', 'icloud.com'],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Microsoft Teams',
    domainSuffixes: ['teams.microsoft.com', 'teams.live.com', 'lync.com', 'skype.com', 'trouter.teams.microsoft.com'],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Google Meet',
    domainSuffixes: ['meet.google.com', 'hangouts.google.com', 'stun.l.google.com', 'meetings.googleapis.com'],
    preferredProtocols: ['TLS', 'QUIC', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Zoom',
    domainSuffixes: ['zoom.us', 'zoomgov.com', 'zoom.com'],
    preferredProtocols: ['TLS', 'UDP', 'STUN', 'TURN', 'DNS'],
  },
  {
    appName: 'Discord',
    domainSuffixes: ['discord.com', 'discordapp.com', 'discord.gg', 'discord.media', 'discordapp.net'],
    preferredProtocols: ['TLS', 'QUIC', 'UDP', 'STUN', 'DNS'],
  },
  {
    appName: 'Microsoft 365',
    domainSuffixes: ['office.com', 'office365.com', 'microsoftonline.com', 'outlook.com', 'live.com'],
    preferredProtocols: ['TLS', 'HTTP', 'DNS'],
  },
  {
    appName: 'Google Services',
    domainSuffixes: ['google.com', 'googleapis.com', 'gstatic.com', '1e100.net', 'googlevideo.com'],
    preferredProtocols: ['TLS', 'QUIC', 'DNS'],
  },
  {
    appName: 'Cloudflare',
    domainSuffixes: ['cloudflare.com', 'cloudflare-dns.com', '1.1.1.1', 'workers.dev'],
    preferredProtocols: ['TLS', 'QUIC', 'DNS'],
  },
  {
    appName: 'Amazon AWS',
    domainSuffixes: ['amazonaws.com', 'aws.amazon.com', 'cloudfront.net'],
    preferredProtocols: ['TLS', 'QUIC', 'HTTP', 'DNS'],
  },
];

function matchDomain(hostname: string | null | undefined, suffixes: string[]): boolean {
  if (!hostname) return false;
  const lower = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!lower) return false;
  return suffixes.some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
}

export function classifyApplication(
  pkt: RawPacketMetadata,
  proto: ProtocolAnalysisResult,
  endpointOrgHint?: string | null
): AppClassificationResult {
  const dns = pkt.dnsQuery?.trim().toLowerCase() || null;
  const sni = pkt.tlsSni?.trim().toLowerCase() || null;
  const httpHost = pkt.httpHost?.trim().toLowerCase() || null;
  const primaryHostname = sni || dns || httpHost || null;

  for (const rule of APP_SIGNATURES) {
    const matchedSources: string[] = [];
    if (matchDomain(sni, rule.domainSuffixes)) matchedSources.push(`TLS SNI (${sni})`);
    if (matchDomain(dns, rule.domainSuffixes)) matchedSources.push(`DNS query (${dns})`);
    if (matchDomain(httpHost, rule.domainSuffixes)) matchedSources.push(`HTTP Host (${httpHost})`);

    if (matchedSources.length >= 2) {
      return {
        appName: rule.appName,
        evidenceSource: matchedSources.join(' + '),
        confidence: 'HIGH',
        classificationMode: 'confirmed',
        hostname: primaryHostname,
      };
    }

    if (matchedSources.length === 1) {
      const hasCorroboratingProto =
        proto.dissectorConfirmed && rule.preferredProtocols.includes(proto.protocol);
      // Multiple reliable indicators: e.g. verified TLS SNI + confirmed TLS/QUIC dissection on standard port
      const standardPortMatch =
        (pkt.dstPort === 443 || pkt.srcPort === 443 || pkt.dstPort === 3478 || pkt.dstPort === 8801) &&
        hasCorroboratingProto;

      if (sni && standardPortMatch) {
        return {
          appName: rule.appName,
          evidenceSource: `${matchedSources[0]} + confirmed ${proto.protocol} handshake`,
          confidence: 'HIGH',
          classificationMode: 'inferred',
          hostname: primaryHostname,
        };
      }

      return {
        appName: rule.appName,
        evidenceSource: matchedSources[0],
        confidence: 'MEDIUM',
        classificationMode: 'inferred',
        hostname: primaryHostname,
      };
    }
  }

  // If a valid hostname was observed via SNI/DNS/HTTP that isn't in known apps, label generically with domain
  if (primaryHostname) {
    const cleanDomain = primaryHostname.split('.').slice(-2).join('.');
    return {
      appName: `Web / Service (${cleanDomain})`,
      evidenceSource: sni ? `TLS SNI (${sni})` : dns ? `DNS query (${dns})` : `HTTP Host (${httpHost})`,
      confidence: 'MEDIUM',
      classificationMode: 'inferred',
      hostname: primaryHostname,
    };
  }

  // Notice: Endpoint org/ASN hint (even if Meta/Facebook) is NEVER treated as proof of Messenger!
  // Only return a LOW-confidence infrastructure hint if it's a clearly non-personal CDN/DNS endpoint,
  // otherwise keep encrypted or STUN-only traffic UNCLASSIFIED.
  if (endpointOrgHint && proto.protocol !== 'STUN' && proto.protocol !== 'TURN') {
    const lowerOrg = endpointOrgHint.toLowerCase();
    if (lowerOrg.includes('cloudflare') || lowerOrg.includes('akamai') || lowerOrg.includes('fastly')) {
      return {
        appName: 'CDN / Edge Infrastructure',
        evidenceSource: `Endpoint ASN/Org hint only (${endpointOrgHint})`,
        confidence: 'LOW',
        classificationMode: 'inferred',
        hostname: null,
      };
    }
  }

  return {
    appName: 'Unclassified',
    evidenceSource: proto.stunTurn
      ? `Protocol metadata only (${proto.protocol}; application unverified)`
      : 'Encrypted or insufficient metadata',
    confidence: 'UNCLASSIFIED',
    classificationMode: 'inferred',
    hostname: null,
  };
}
