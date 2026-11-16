/**
 * PacketScope Network Protocol & STUN/TURN Intelligence Engine.
 *
 * Strictly distinguishes:
 * 1. Confirmed protocol dissection (from TShark dissector fields / protocol headers)
 * 2. Suspected WebRTC-related flows (e.g., DTLS/SRTP/RTP media indicators)
 * 3. Unclassified UDP/TCP flows
 *
 * NEVER infers STUN solely from arbitrary UDP traffic or well-known port numbers alone.
 */

export type TransportProtocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNCLASSIFIED';

export type StunTurnCategory =
  | 'confirmed_stun'
  | 'confirmed_turn'
  | 'suspected_webrtc'
  | 'unclassified_udp';

export interface RawPacketMetadata {
  eventUid?: string;
  observedAt: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number | null;
  dstPort?: number | null;
  transport: string;
  dissectorProtocol?: string | null; // TShark _ws.col.Protocol
  packetLength: number;
  dnsQuery?: string | null;
  tlsSni?: string | null;
  httpHost?: string | null;
  stunType?: string | null;       // TShark stun.type (e.g. 0x0001, 0x0101, 0x0003)
  stunClass?: string | null;      // TShark stun.type.class or parsed
  stunMethod?: string | null;     // TShark stun.type.method or parsed
  stunAttributes?: string | null; // Comma-separated attribute type names ONLY (no payloads)
  dtlsHandshake?: boolean;
  rtpDetected?: boolean;
}

export interface ProtocolAnalysisResult {
  transport: TransportProtocol;
  protocol: string;
  dissectorConfirmed: boolean;
  evidence: string;
  stunTurn?: {
    category: StunTurnCategory;
    messageType: string;
    stunMethod: string | null;
    stunClass: string | null;
    attributesMeta: string | null;
    positivelyDecoded: boolean;
    confidence: ConfidenceLevel;
    evidence: string;
  };
}

const STUN_METHOD_MAP: Record<number, { name: string; isTurn: boolean }> = {
  0x001: { name: 'Binding', isTurn: false },
  0x002: { name: 'SharedSecret', isTurn: false },
  0x003: { name: 'Allocate', isTurn: true },
  0x004: { name: 'Refresh', isTurn: true },
  0x006: { name: 'Send', isTurn: true },
  0x007: { name: 'Data', isTurn: true },
  0x008: { name: 'CreatePermission', isTurn: true },
  0x009: { name: 'ChannelBind', isTurn: true },
  0x00a: { name: 'Connect', isTurn: true },
  0x00b: { name: 'ConnectionBind', isTurn: true },
  0x00c: { name: 'ConnectionAttempt', isTurn: true },
};

const STUN_CLASS_MAP: Record<number, string> = {
  0b00: 'Request',
  0b01: 'Indication',
  0b10: 'Success Response',
  0b11: 'Error Response',
};

/**
 * Decodes an RFC 5389 / RFC 5766 16-bit STUN/TURN message type (e.g. "0x0001", "0x0101", "0x0003").
 * Bits C1 (bit 8) and C0 (bit 4) encode class; remaining 12 bits encode method.
 */
export function decodeStunMessageType(rawType?: string | null): {
  method: string;
  msgClass: string;
  messageType: string;
  isTurn: boolean;
} | null {
  if (!rawType) return null;
  const trimmed = rawType.trim();
  let val: number;
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    val = parseInt(trimmed, 16);
  } else if (/^\d+$/.test(trimmed)) {
    val = parseInt(trimmed, 10);
  } else {
    return null;
  }

  if (Number.isNaN(val) || val < 0 || val > 0x3fff) return null;

  const c0 = (val >> 4) & 1;
  const c1 = (val >> 8) & 1;
  const classCode = (c1 << 1) | c0;

  const methodBits =
    (val & 0x000f) |
    ((val & 0x00e0) >> 1) |
    ((val & 0x3e00) >> 2);

  const methodInfo = STUN_METHOD_MAP[methodBits];
  if (!methodInfo) return null;

  const msgClass = STUN_CLASS_MAP[classCode] ?? 'Unknown';
  const label = `${methodInfo.isTurn ? 'TURN ' : 'STUN '}${methodInfo.name} ${msgClass}`;

  return {
    method: methodInfo.name,
    msgClass,
    messageType: label,
    isTurn: methodInfo.isTurn,
  };
}

function normalizeTransport(raw: string): TransportProtocol {
  const upper = (raw || '').trim().toUpperCase();
  if (upper === 'TCP' || upper.includes('TCP')) return 'TCP';
  if (upper === 'UDP' || upper.includes('UDP')) return 'UDP';
  if (upper === 'ICMP' || upper === 'ICMPV6' || upper.includes('ICMP')) return 'ICMP';
  return 'OTHER';
}

function sanitizeAttributeNames(rawAttrs?: string | null): string | null {
  if (!rawAttrs) return null;
  // Strip any values; retain attribute metadata names/codes only
  const cleaned = rawAttrs
    .split(',')
    .map((s) => s.trim().replace(/[^a-zA-Z0-9_\- ]/g, ''))
    .filter((s) => s.length > 0)
    .slice(0, 12);
  return cleaned.length > 0 ? cleaned.join(', ') : null;
}

export function analyzeProtocol(pkt: RawPacketMetadata): ProtocolAnalysisResult {
  const transport = normalizeTransport(pkt.transport);
  const dissector = (pkt.dissectorProtocol || '').trim().toUpperCase();
  const srcPort = pkt.srcPort ?? 0;
  const dstPort = pkt.dstPort ?? 0;

  // 1. Confirmed STUN / TURN dissection (TShark dissector confirmed or valid STUN message type)
  const decodedStun = decodeStunMessageType(pkt.stunType);
  const dissectorIsStunOrTurn =
    dissector === 'STUN' ||
    dissector === 'TURN' ||
    dissector === 'CLASSICSTUN' ||
    dissector.includes('STUN');

  if (decodedStun || dissectorIsStunOrTurn) {
    const isTurn =
      decodedStun?.isTurn ||
      dissector === 'TURN' ||
      (pkt.stunMethod ? ['allocate', 'refresh', 'createpermission', 'channelbind', 'send', 'data'].includes(pkt.stunMethod.toLowerCase()) : false);

    const stunMethod = decodedStun?.method || pkt.stunMethod || (isTurn ? 'Allocate' : 'Binding');
    const stunClass = decodedStun?.msgClass || pkt.stunClass || 'Message';
    const messageType =
      decodedStun?.messageType ||
      `${isTurn ? 'TURN' : 'STUN'} ${stunMethod} ${stunClass}`.trim();

    const category: StunTurnCategory = isTurn ? 'confirmed_turn' : 'confirmed_stun';
    const protocol = isTurn ? 'TURN' : 'STUN';
    const attrsMeta = sanitizeAttributeNames(pkt.stunAttributes);

    return {
      transport,
      protocol,
      dissectorConfirmed: true,
      evidence: decodedStun
        ? `TShark STUN/TURN dissector (${pkt.stunType} -> ${messageType})`
        : `TShark dissector confirmed ${protocol}`,
      stunTurn: {
        category,
        messageType,
        stunMethod,
        stunClass,
        attributesMeta: attrsMeta,
        positivelyDecoded: true,
        confidence: 'HIGH',
        evidence: decodedStun
          ? `Decoded RFC 5389/5766 message type ${pkt.stunType} (${messageType})`
          : `Confirmed by TShark ${dissector} dissector`,
      },
    };
  }

  // 2. Confirmed DNS
  if (dissector === 'DNS' || (pkt.dnsQuery && pkt.dnsQuery.trim().length > 0)) {
    return {
      transport,
      protocol: 'DNS',
      dissectorConfirmed: dissector === 'DNS' || Boolean(pkt.dnsQuery),
      evidence: pkt.dnsQuery
        ? `DNS dissector query (${pkt.dnsQuery.trim()})`
        : 'TShark DNS dissector',
    };
  }

  // 3. Confirmed mDNS
  if (dissector === 'MDNS' || (transport === 'UDP' && (srcPort === 5353 || dstPort === 5353))) {
    return {
      transport,
      protocol: 'mDNS',
      dissectorConfirmed: dissector === 'MDNS',
      evidence: dissector === 'MDNS' ? 'TShark mDNS dissector' : 'UDP port 5353 multicast DNS',
    };
  }

  // 4. Confirmed SSDP
  if (dissector === 'SSDP' || (transport === 'UDP' && (srcPort === 1900 || dstPort === 1900))) {
    return {
      transport,
      protocol: 'SSDP',
      dissectorConfirmed: dissector === 'SSDP',
      evidence: dissector === 'SSDP' ? 'TShark SSDP dissector' : 'UDP port 1900 SSDP discovery',
    };
  }

  // 5. Confirmed DHCP
  if (
    dissector === 'DHCP' ||
    dissector === 'BOOTP' ||
    (transport === 'UDP' && ((srcPort === 67 && dstPort === 68) || (srcPort === 68 && dstPort === 67)))
  ) {
    return {
      transport,
      protocol: 'DHCP',
      dissectorConfirmed: dissector === 'DHCP' || dissector === 'BOOTP',
      evidence: dissector === 'DHCP' || dissector === 'BOOTP' ? `TShark ${dissector} dissector` : 'UDP ports 67/68 DHCP',
    };
  }

  // 6. Confirmed QUIC
  if (dissector === 'QUIC' || dissector.includes('QUIC')) {
    return {
      transport: 'UDP',
      protocol: 'QUIC',
      dissectorConfirmed: true,
      evidence: pkt.tlsSni ? `TShark QUIC dissector (SNI: ${pkt.tlsSni})` : 'TShark QUIC dissector',
    };
  }

  // 7. DTLS / RTP / WebRTC media indicators (suspected WebRTC, NOT labeled confirmed STUN)
  if (
    dissector.startsWith('DTLS') ||
    dissector === 'RTP' ||
    dissector === 'SRTP' ||
    dissector === 'RTCP' ||
    dissector === 'WEBRTC' ||
    pkt.dtlsHandshake ||
    pkt.rtpDetected
  ) {
    const protoLabel = dissector || (pkt.rtpDetected ? 'RTP' : 'DTLS');
    return {
      transport,
      protocol: protoLabel,
      dissectorConfirmed: Boolean(dissector),
      evidence: `WebRTC-adjacent media/handshake indicator (${protoLabel})`,
      stunTurn: {
        category: 'suspected_webrtc',
        messageType: `Suspected WebRTC (${protoLabel})`,
        stunMethod: null,
        stunClass: null,
        attributesMeta: null,
        positivelyDecoded: false,
        confidence: 'MEDIUM',
        evidence: `Observed ${protoLabel} media/DTLS transport without confirmed STUN header`,
      },
    };
  }

  // 8. Confirmed TLS
  if (
    dissector.startsWith('TLS') ||
    dissector === 'SSL' ||
    (pkt.tlsSni && pkt.tlsSni.trim().length > 0)
  ) {
    return {
      transport,
      protocol: 'TLS',
      dissectorConfirmed: dissector.startsWith('TLS') || Boolean(pkt.tlsSni),
      evidence: pkt.tlsSni ? `TLS ClientHello SNI (${pkt.tlsSni.trim()})` : `TShark ${dissector || 'TLS'} dissector`,
    };
  }

  // 9. HTTP metadata when visible
  if (dissector === 'HTTP' || (pkt.httpHost && pkt.httpHost.trim().length > 0)) {
    return {
      transport,
      protocol: 'HTTP',
      dissectorConfirmed: dissector === 'HTTP' || Boolean(pkt.httpHost),
      evidence: pkt.httpHost ? `HTTP Host header (${pkt.httpHost.trim()})` : 'TShark HTTP dissector',
    };
  }

  // 10. ICMP
  if (transport === 'ICMP' || dissector === 'ICMP' || dissector === 'ICMPV6') {
    return {
      transport: 'ICMP',
      protocol: dissector === 'ICMPV6' ? 'ICMPv6' : 'ICMP',
      dissectorConfirmed: true,
      evidence: `TShark ${dissector || 'ICMP'} dissector`,
    };
  }

  // 11. Generic UDP — NEVER infer STUN solely from arbitrary UDP or port 3478!
  if (transport === 'UDP') {
    const highEphemeral = srcPort >= 1024 && dstPort >= 1024;
    return {
      transport: 'UDP',
      protocol: dissector && dissector !== 'UDP' ? dissector : 'UDP',
      dissectorConfirmed: dissector === 'UDP',
      evidence: dissector && dissector !== 'UDP' ? `TShark ${dissector} over UDP` : 'Generic UDP datagram (no STUN/TURN dissection)',
      stunTurn: highEphemeral && !pkt.dnsQuery && !pkt.tlsSni
        ? {
            category: 'unclassified_udp',
            messageType: 'Unclassified High-Port UDP',
            stunMethod: null,
            stunClass: null,
            attributesMeta: null,
            positivelyDecoded: false,
            confidence: 'UNCLASSIFIED',
            evidence: 'Unclassified bidirectional/ephemeral UDP flow; STUN not decoded',
          }
        : undefined,
    };
  }

  // 12. Generic TCP / Other
  return {
    transport,
    protocol: dissector || transport,
    dissectorConfirmed: Boolean(dissector),
    evidence: dissector ? `TShark ${dissector} over ${transport}` : `${transport} transport segment`,
  };
}
