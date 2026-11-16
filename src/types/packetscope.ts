export type NavSection =
  | 'overview'
  | 'live-traffic'
  | 'applications'
  | 'protocols'
  | 'stun-turn'
  | 'geography'
  | 'ip-intelligence'
  | 'sensors'
  | 'inventory'
  | 'alerts'
  | 'analytics'
  | 'reports'
  | 'settings'
  | 'administration';

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  role: 'owner' | 'admin' | 'analyst' | 'viewer';
}

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
}

export interface OverviewResponse {
  kpis: {
    packets24h: number;
    packetsPerSecond: number;
    activeSensors: number;
    registeredSensors: number;
    uniqueSrcIps: number;
    uniqueDstIps: number;
    detectedApplications: number;
    confirmedStunPackets: number;
    confirmedTurnPackets: number;
    suspectedWebrtcFlows: number;
    unclassifiedPackets: number;
    lastPacketAt: string | null;
  };
  protocolDistribution: Array<{ name: string; count: number; bytes: number }>;
  appDistribution: Array<{ name: string; count: number; highConfidence: number }>;
  volumeTimeline: Array<{ bucket: string; packets: number; bytes: number }>;
  topSrcIps: Array<{ ip: string; packets: number; bytes: number }>;
  topDstIps: Array<{ ip: string; packets: number; bytes: number }>;
  recentFeed: TrafficEventItem[];
  sensors: Array<{
    id: string;
    name: string;
    status: string;
    activeInterface: string | null;
    captureRunning: number;
    packetsObserved: number;
    lastHeartbeatAt: string | null;
    lastError: string | null;
  }>;
  openAlerts: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    status: string;
    triggeredAt: string;
  }>;
  updatedAt: string;
}

export interface TrafficEventItem {
  id: string;
  observedAt: string;
  sensorId: string;
  sensorName: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  transport: string;
  protocol: string;
  appLabel: string;
  hostname: string | null;
  packetLength: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNCLASSIFIED';
  detectionMethod?: string;
  classificationMode?: 'confirmed' | 'inferred';
  trafficDirection?: string;
}

export interface SensorRecord {
  id: string;
  organizationId: string;
  networkId: string | null;
  networkName: string | null;
  name: string;
  hostname: string | null;
  osVersion: string | null;
  agentVersion: string | null;
  tokenPrefix: string;
  status: 'online' | 'offline' | 'warning' | 'error' | 'paused';
  captureRunning: number;
  interfaceAvailable: number;
  activeInterface: string | null;
  packetsObserved: number;
  recordsParsed: number;
  recordsQueued: number;
  recordsSubmitted: number;
  recordsAccepted: number;
  recordsRejected: number;
  lastHeartbeatAt: string | null;
  lastPacketAt: string | null;
  lastError: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface StunTurnEventRecord {
  id: string;
  category: 'confirmed_stun' | 'confirmed_turn' | 'suspected_webrtc' | 'unclassified_udp';
  messageType: string;
  stunMethod: string | null;
  stunClass: string | null;
  attributesMeta: string | null;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  positivelyDecoded: number;
  confidence: string;
  evidence: string;
  observedAt: string;
  sensorId: string;
  sensorName: string;
}

export interface GeoMarkerItem {
  ip: string;
  activityCount: number;
  lastObservedAt: string;
  asn: string | null;
  isp: string | null;
  orgName: string | null;
  countryCode: string | null;
  countryName: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  providerSource: string;
}
