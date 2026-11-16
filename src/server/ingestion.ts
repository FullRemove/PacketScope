import { getDb, newId } from './db/sqlite.ts';
import { normalizeIp, inferTrafficDirection, isPrivateOrReservedIp } from '../intelligence/ipUtils.ts';
import { analyzeProtocol, type RawPacketMetadata } from '../intelligence/protocolEngine.ts';
import { classifyApplication } from '../intelligence/applicationEngine.ts';
import { resolvePublicIpIntelligence, type IpIntelStoreAdapter, type IpIntelRecord } from '../intelligence/ipIntel.ts';
import { broadcastToOrganization } from './ws.ts';

export const ipIntelDbAdapter: IpIntelStoreAdapter = {
  getCachedIpIntel(ip: string): IpIntelRecord | null {
    const db = getDb();
    const row = db.prepare(`SELECT * FROM ip_intelligence WHERE ip = ?`).get(ip) as any;
    if (!row) return null;
    return {
      ip: row.ip,
      ipVersion: row.ip_version,
      isPublic: Boolean(row.is_public),
      asn: row.asn,
      isp: row.isp,
      orgName: row.org_name,
      countryCode: row.country_code,
      countryName: row.country_name,
      city: row.city,
      latitude: row.latitude,
      longitude: row.longitude,
      providerSource: row.provider_source,
      lastRefreshedAt: row.last_refreshed_at,
    };
  },
  upsertIpIntel(record: IpIntelRecord): void {
    const db = getDb();
    db.prepare(
      `INSERT INTO ip_intelligence (ip, ip_version, is_public, asn, isp, org_name, country_code, country_name, city, latitude, longitude, provider_source, last_refreshed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(ip) DO UPDATE SET
         asn = excluded.asn,
         isp = excluded.isp,
         org_name = excluded.org_name,
         country_code = excluded.country_code,
         country_name = excluded.country_name,
         city = excluded.city,
         latitude = excluded.latitude,
         longitude = excluded.longitude,
         provider_source = excluded.provider_source,
         last_refreshed_at = excluded.last_refreshed_at`
    ).run(
      record.ip,
      record.ipVersion,
      record.isPublic ? 1 : 0,
      record.asn,
      record.isp,
      record.orgName,
      record.countryCode,
      record.countryName,
      record.city,
      record.latitude,
      record.longitude,
      record.providerSource,
      record.lastRefreshedAt
    );
  },
};

export interface IngestSummary {
  accepted: number;
  duplicates: number;
  rejected: number;
  alertsTriggered: number;
}

export async function processIngestBatch(
  sensor: { id: string; organizationId: string; name: string; status: string },
  events: RawPacketMetadata[]
): Promise<IngestSummary> {
  const db = getDb();
  const now = new Date().toISOString();

  let accepted = 0;
  let duplicates = 0;
  let rejected = 0;
  const recentFeedItems: any[] = [];
  const publicIpsToEnrich = new Set<string>();
  let dnsCountInBatch = 0;
  let lastObservedAt = now;

  const insertPacket = db.prepare(
    `INSERT INTO packet_events (
      id, organization_id, sensor_id, event_uid, observed_at, src_ip, dst_ip, src_port, dst_port,
      transport, protocol, packet_length, dns_query, tls_sni, http_host, app_label,
      detection_method, confidence, classification_mode, traffic_direction, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const upsertFlow = db.prepare(
    `INSERT INTO network_flows (
      id, organization_id, sensor_id, flow_key, src_ip, dst_ip, src_port, dst_port,
      transport, protocol, app_label, confidence, packet_count, byte_count, first_seen_at, last_seen_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    ON CONFLICT(organization_id, sensor_id, flow_key) DO UPDATE SET
      packet_count = network_flows.packet_count + 1,
      byte_count = network_flows.byte_count + excluded.byte_count,
      last_seen_at = MAX(network_flows.last_seen_at, excluded.last_seen_at),
      app_label = CASE WHEN excluded.confidence IN ('HIGH','MEDIUM') THEN excluded.app_label ELSE network_flows.app_label END,
      confidence = CASE WHEN excluded.confidence IN ('HIGH','MEDIUM') THEN excluded.confidence ELSE network_flows.confidence END`
  );

  const insertProtoDet = db.prepare(
    `INSERT INTO protocol_detections (id, organization_id, sensor_id, packet_event_id, protocol, dissector_confirmed, evidence, observed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const insertAppDet = db.prepare(
    `INSERT INTO application_detections (id, organization_id, sensor_id, packet_event_id, flow_id, app_name, evidence_source, confidence, classification_mode, observed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const insertStun = db.prepare(
    `INSERT INTO stun_turn_events (
      id, organization_id, sensor_id, packet_event_id, category, message_type, stun_method, stun_class,
      attributes_meta, src_ip, src_port, dst_ip, dst_port, positively_decoded, confidence, evidence, observed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const checkExistingUid = db.prepare(`SELECT 1 FROM packet_events WHERE sensor_id = ? AND event_uid = ?`);

  db.exec('BEGIN IMMEDIATE');
  try {
    for (const raw of events) {
      const srcIp = normalizeIp(raw.srcIp);
      const dstIp = normalizeIp(raw.dstIp);
      if (!srcIp || !dstIp) {
        rejected++;
        continue;
      }

      const eventUid = raw.eventUid && raw.eventUid.trim() ? raw.eventUid.trim() : newId('evt');
      if (checkExistingUid.get(sensor.id, eventUid)) {
        duplicates++;
        continue;
      }

      const observedAt = Number.isNaN(Date.parse(raw.observedAt)) ? now : new Date(raw.observedAt).toISOString();
      if (observedAt > lastObservedAt) lastObservedAt = observedAt;

      const protoResult = analyzeProtocol({ ...raw, srcIp, dstIp, observedAt });
      const cachedDstIntel = !isPrivateOrReservedIp(dstIp) ? ipIntelDbAdapter.getCachedIpIntel(dstIp) : null;
      const appResult = classifyApplication({ ...raw, srcIp, dstIp, observedAt }, protoResult, cachedDstIntel?.orgName);
      const direction = inferTrafficDirection(srcIp, dstIp);

      if (protoResult.protocol === 'DNS' || raw.dnsQuery) dnsCountInBatch++;
      if (!isPrivateOrReservedIp(srcIp)) publicIpsToEnrich.add(srcIp);
      if (!isPrivateOrReservedIp(dstIp)) publicIpsToEnrich.add(dstIp);

      const pktId = newId('pkt');
      const pktLen = Math.max(0, Math.min(65535, Math.round(raw.packetLength || 0)));

      insertPacket.run(
        pktId,
        sensor.organizationId,
        sensor.id,
        eventUid,
        observedAt,
        srcIp,
        dstIp,
        raw.srcPort ?? null,
        raw.dstPort ?? null,
        protoResult.transport,
        protoResult.protocol,
        pktLen,
        raw.dnsQuery?.trim() || null,
        raw.tlsSni?.trim() || null,
        raw.httpHost?.trim() || null,
        appResult.appName,
        appResult.evidenceSource,
        appResult.confidence,
        appResult.classificationMode,
        direction,
        now
      );

      const flowKey = `${srcIp}:${raw.srcPort ?? 0}->${dstIp}:${raw.dstPort ?? 0}:${protoResult.transport}`;
      const flowId = newId('flw');
      upsertFlow.run(
        flowId,
        sensor.organizationId,
        sensor.id,
        flowKey,
        srcIp,
        dstIp,
        raw.srcPort ?? null,
        raw.dstPort ?? null,
        protoResult.transport,
        protoResult.protocol,
        appResult.appName,
        appResult.confidence,
        pktLen,
        observedAt,
        observedAt
      );

      insertProtoDet.run(
        newId('pdet'),
        sensor.organizationId,
        sensor.id,
        pktId,
        protoResult.protocol,
        protoResult.dissectorConfirmed ? 1 : 0,
        protoResult.evidence,
        observedAt
      );

      if (appResult.appName !== 'Unclassified') {
        insertAppDet.run(
          newId('adet'),
          sensor.organizationId,
          sensor.id,
          pktId,
          null,
          appResult.appName,
          appResult.evidenceSource,
          appResult.confidence,
          appResult.classificationMode,
          observedAt
        );
      }

      if (protoResult.stunTurn) {
        insertStun.run(
          newId('stun'),
          sensor.organizationId,
          sensor.id,
          pktId,
          protoResult.stunTurn.category,
          protoResult.stunTurn.messageType,
          protoResult.stunTurn.stunMethod,
          protoResult.stunTurn.stunClass,
          protoResult.stunTurn.attributesMeta,
          srcIp,
          raw.srcPort ?? null,
          dstIp,
          raw.dstPort ?? null,
          protoResult.stunTurn.positivelyDecoded ? 1 : 0,
          protoResult.stunTurn.confidence,
          protoResult.stunTurn.evidence,
          observedAt
        );
      }

      accepted++;
      if (recentFeedItems.length < 25) {
        recentFeedItems.push({
          id: pktId,
          observedAt,
          sensorId: sensor.id,
          sensorName: sensor.name,
          srcIp,
          srcPort: raw.srcPort ?? null,
          dstIp,
          dstPort: raw.dstPort ?? null,
          transport: protoResult.transport,
          protocol: protoResult.protocol,
          appLabel: appResult.appName,
          hostname: appResult.hostname,
          packetLength: pktLen,
          confidence: appResult.confidence,
        });
      }
    }

    // Update sensor telemetry metrics
    db.prepare(
      `UPDATE sensors SET
        status = CASE WHEN status = 'paused' THEN 'paused' ELSE 'online' END,
        packets_observed = packets_observed + ?,
        records_accepted = records_accepted + ?,
        records_rejected = records_rejected + ?,
        last_packet_at = CASE WHEN ? > 0 THEN ? ELSE last_packet_at END,
        last_heartbeat_at = COALESCE(last_heartbeat_at, ?),
        updated_at = ?
       WHERE id = ?`
    ).run(events.length, accepted, rejected, accepted, lastObservedAt, now, now, sensor.id);

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  // Evaluate configurable alert rules for this organization
  const alertsTriggered = evaluateAlertRules(sensor, accepted, dnsCountInBatch, Array.from(publicIpsToEnrich));

  // Background public IP geolocation caching (strictly rate-limited, max 5 new IPs per batch)
  const settings = db
    .prepare(`SELECT geoip_enabled FROM organization_settings WHERE organization_id = ?`)
    .get(sensor.organizationId) as { geoip_enabled: number } | undefined;

  if (!settings || settings.geoip_enabled === 1) {
    const newIps = Array.from(publicIpsToEnrich)
      .filter((ip) => !ipIntelDbAdapter.getCachedIpIntel(ip))
      .slice(0, 5);
    for (const ip of newIps) {
      // Fire-and-forget rate-limited cache warm without delaying ingestion response
      void resolvePublicIpIntelligence(ip, ipIntelDbAdapter);
    }
  }

  if (accepted > 0) {
    broadcastToOrganization(sensor.organizationId, 'traffic:ingested', {
      sensorId: sensor.id,
      sensorName: sensor.name,
      accepted,
      recentPackets: recentFeedItems,
    });
  }

  return { accepted, duplicates, rejected, alertsTriggered };
}

function evaluateAlertRules(
  sensor: { id: string; organizationId: string; name: string },
  acceptedInBatch: number,
  dnsInBatch: number,
  publicIps: string[]
): number {
  const db = getDb();
  const now = new Date().toISOString();
  const rules = db
    .prepare(`SELECT * FROM alert_rules WHERE organization_id = ? AND enabled = 1`)
    .all(sensor.organizationId) as any[];

  let triggered = 0;
  const insertAlert = db.prepare(
    `INSERT INTO alerts (id, organization_id, rule_id, sensor_id, severity, title, description, status, triggered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)`
  );

  for (const rule of rules) {
    if (rule.rule_type === 'traffic_spike' && acceptedInBatch >= rule.threshold) {
      insertAlert.run(
        newId('alrt'),
        sensor.organizationId,
        rule.id,
        sensor.id,
        rule.severity,
        `Traffic volume threshold exceeded on ${sensor.name}`,
        `Observed ${acceptedInBatch} packet metadata events in a single batch (threshold: ${rule.threshold}).`,
        now
      );
      triggered++;
    } else if (rule.rule_type === 'dns_burst' && dnsInBatch >= rule.threshold) {
      insertAlert.run(
        newId('alrt'),
        sensor.organizationId,
        rule.id,
        sensor.id,
        rule.severity,
        `Excessive DNS activity on ${sensor.name}`,
        `Observed ${dnsInBatch} DNS queries in ingestion window (threshold: ${rule.threshold}).`,
        now
      );
      triggered++;
    } else if (rule.rule_type === 'new_public_endpoint' && publicIps.length > 0) {
      const uncached = publicIps.filter((ip) => !ipIntelDbAdapter.getCachedIpIntel(ip));
      if (uncached.length >= rule.threshold) {
        insertAlert.run(
          newId('alrt'),
          sensor.organizationId,
          rule.id,
          sensor.id,
          rule.severity,
          `Newly observed public endpoints on ${sensor.name}`,
          `Detected ${uncached.length} previously unseen public IP endpoint(s): ${uncached.slice(0, 3).join(', ')}.`,
          now
        );
        triggered++;
      }
    }
  }

  if (triggered > 0) {
    broadcastToOrganization(sensor.organizationId, 'alerts:updated', { triggered });
  }
  return triggered;
}
