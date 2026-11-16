import { Router } from 'express';
import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';
import rateLimit from 'express-rate-limit';
import { getDb, newId } from './db/sqlite.ts';
import {
  generateSensorToken,
  hashPassword,
  requireSensorAuth,
  requireTenantAccess,
  requireUserAuth,
  signSessionToken,
  verifyPassword,
  type AuthRequest,
} from './auth.ts';
import { ipIntelDbAdapter, processIngestBatch } from './ingestion.ts';
import { getGeoIpRateLimitStatus, resolvePublicIpIntelligence } from '../intelligence/ipIntel.ts';
import { isPrivateOrReservedIp, normalizeIp, stripCidrSuffix } from '../intelligence/ipUtils.ts';
import { broadcastToOrganization } from './ws.ts';
import { getOpenApiSpec } from './openapi.ts';

function writeAuditLog(
  orgId: string,
  actorUserId: string | null,
  actorEmail: string | null,
  action: string,
  resourceType: string,
  resourceId: string | null,
  details: Record<string, unknown> = {}
) {
  const db = getDb();
  db.prepare(
    `INSERT INTO audit_logs (id, organization_id, actor_user_id, actor_email, action, resource_type, resource_id, details_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('aud'), orgId, actorUserId, actorEmail, action, resourceType, resourceId, JSON.stringify(details), new Date().toISOString());
}

function createOrganizationWithDefaults(orgName: string, ownerUserId: string) {
  const db = getDb();
  const now = new Date().toISOString();
  const orgId = newId('org');
  const baseSlug = orgName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '') || 'workspace';
  const slug = `${baseSlug}-${orgId.slice(-6)}`;

  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare(`INSERT INTO organizations (id, name, slug, owner_user_id, created_at) VALUES (?, ?, ?, ?, ?)`).run(
      orgId,
      orgName,
      slug,
      ownerUserId,
      now
    );

    db.prepare(`INSERT INTO memberships (id, organization_id, user_id, role_id, created_at) VALUES (?, ?, ?, 'role_owner', ?)`).run(
      newId('mem'),
      orgId,
      ownerUserId,
      now
    );

    const netId = newId('net');
    db.prepare(
      `INSERT INTO networks (id, organization_id, name, cidr, deployment_mode, description, created_at)
       VALUES (?, ?, 'Primary Corporate Network', NULL, 'host-interface', 'Default authorized monitoring network', ?)`
    ).run(netId, orgId, now);

    db.prepare(`INSERT INTO organization_settings (organization_id, updated_at) VALUES (?, ?)`).run(orgId, now);
    db.prepare(`INSERT INTO retention_policies (organization_id, updated_at) VALUES (?, ?)`).run(orgId, now);

    // Default alert rules (disabled or sensible enterprise defaults)
    const defaultRules = [
      ['Traffic Spike Guard', 'traffic_spike', 450, 5, 'warning'],
      ['Excessive DNS Query Burst', 'dns_burst', 150, 5, 'warning'],
      ['New Public Endpoint Observed', 'new_public_endpoint', 20, 5, 'info'],
    ] as const;
    const insertRule = db.prepare(
      `INSERT INTO alert_rules (id, organization_id, name, rule_type, threshold, window_minutes, severity, enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
    );
    for (const [name, type, threshold, win, sev] of defaultRules) {
      insertRule.run(newId('rul'), orgId, name, type, threshold, win, sev, now);
    }

    db.exec('COMMIT');
    return { id: orgId, name: orgName, slug, defaultNetworkId: netId };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function createApiRouter() {
  const router = Router();

  const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts. Please retry shortly.' },
  });

  const ingestLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Ingestion rate limit exceeded. Agent should back off and buffer locally.' },
  });

  // ==========================================
  // HEALTH & OPENAPI DOCS
  // ==========================================
  router.get('/health', (_req, res) => {
    try {
      const db = getDb();
      const row = db.prepare(`SELECT COUNT(*) as orgCount FROM organizations`).get() as { orgCount: number };
      res.json({
        status: 'healthy',
        service: 'PacketScope API',
        version: '1.0.0',
        database: 'connected',
        organizations: row.orgCount,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      res.status(503).json({ status: 'degraded', error: err.message });
    }
  });

  router.get('/openapi.json', (req, res) => {
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host') || 'localhost:3000';
    res.json(getOpenApiSpec(`${proto}://${host}`));
  });

  // ==========================================
  // AUTHENTICATION & ORGANIZATIONS
  // ==========================================
  const registerSchema = z.object({
    email: z.string().email().max(254),
    password: z.string().min(8).max(128),
    displayName: z.string().min(2).max(120),
    organizationName: z.string().min(2).max(120).optional(),
  });

  router.post('/auth/register', authLimiter, (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid registration details', details: parsed.error.flatten() });
    }

    const db = getDb();
    const email = parsed.data.email.trim().toLowerCase();
    const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
    if (existing) {
      return res.status(409).json({ error: 'An operator account with this email already exists' });
    }

    const now = new Date().toISOString();
    const userId = newId('usr');
    const pwHash = hashPassword(parsed.data.password);

    db.prepare(
      `INSERT INTO users (id, uid, email, display_name, password_hash, email_verified, created_at, updated_at)
       VALUES (?, NULL, ?, ?, ?, 1, ?, ?)`
    ).run(userId, email, parsed.data.displayName.trim(), pwHash, now, now);

    const orgName = parsed.data.organizationName?.trim() || `${parsed.data.displayName.trim()} Operations`;
    const org = createOrganizationWithDefaults(orgName, userId);
    writeAuditLog(org.id, userId, email, 'organization.created', 'organization', org.id, { name: org.name });

    const token = signSessionToken({ userId, email, displayName: parsed.data.displayName.trim() });
    res.status(201).json({
      token,
      user: { id: userId, email, displayName: parsed.data.displayName.trim() },
      organizations: [{ id: org.id, name: org.name, slug: org.slug, role: 'owner' }],
    });
  });

  const loginSchema = z.object({
    email: z.string().email().max(254),
    password: z.string().min(1).max(128),
  });

  router.post('/auth/login', authLimiter, (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const db = getDb();
    const email = parsed.data.email.trim().toLowerCase();
    const user = db.prepare(`SELECT id, email, display_name, password_hash FROM users WHERE email = ?`).get(email) as any;

    if (!user || !user.password_hash || !verifyPassword(parsed.data.password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const orgs = db
      .prepare(
        `SELECT o.id, o.name, o.slug, r.name as role
         FROM memberships m
         JOIN organizations o ON m.organization_id = o.id
         JOIN roles r ON m.role_id = r.id
         WHERE m.user_id = ?
         ORDER BY o.created_at ASC`
      )
      .all(user.id);

    const token = signSessionToken({ userId: user.id, email: user.email, displayName: user.display_name });
    res.json({
      token,
      user: { id: user.id, email: user.email, displayName: user.display_name },
      organizations: orgs,
    });
  });

  router.post('/auth/firebase-sync', authLimiter, requireUserAuth, (req: AuthRequest, res) => {
    const user = req.authUser!;
    const db = getDb();
    let orgs = db
      .prepare(
        `SELECT o.id, o.name, o.slug, r.name as role
         FROM memberships m
         JOIN organizations o ON m.organization_id = o.id
         JOIN roles r ON m.role_id = r.id
         WHERE m.user_id = ?
         ORDER BY o.created_at ASC`
      )
      .all(user.id) as any[];

    if (orgs.length === 0) {
      const orgName = typeof req.body?.organizationName === 'string' && req.body.organizationName.trim().length >= 2
        ? req.body.organizationName.trim()
        : `${user.displayName} Network Ops`;
      const created = createOrganizationWithDefaults(orgName, user.id);
      orgs = [{ id: created.id, name: created.name, slug: created.slug, role: 'owner' }];
    }

    res.json({ user, organizations: orgs });
  });

  router.get('/auth/me', requireUserAuth, (req: AuthRequest, res) => {
    const user = req.authUser!;
    const db = getDb();
    const orgs = db
      .prepare(
        `SELECT o.id, o.name, o.slug, r.name as role
         FROM memberships m
         JOIN organizations o ON m.organization_id = o.id
         JOIN roles r ON m.role_id = r.id
         WHERE m.user_id = ?
         ORDER BY o.created_at ASC`
      )
      .all(user.id);
    res.json({ user, organizations: orgs });
  });

  router.post('/organizations', requireUserAuth, (req: AuthRequest, res) => {
    const schema = z.object({ name: z.string().min(2).max(120) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Valid organization name is required' });

    const org = createOrganizationWithDefaults(parsed.data.name.trim(), req.authUser!.id);
    writeAuditLog(org.id, req.authUser!.id, req.authUser!.email, 'organization.created', 'organization', org.id, {
      name: org.name,
    });
    res.status(201).json({ id: org.id, name: org.name, slug: org.slug, role: 'owner' });
  });

  // ==========================================
  // AGENT CHECK-IN & INGESTION (SENSOR AUTH)
  // ==========================================
  const checkInSchema = z.object({
    hostname: z.string().max(120).optional(),
    osVersion: z.string().max(120).optional(),
    agentVersion: z.string().max(40).optional(),
    activeInterface: z.string().max(240).optional(),
    captureRunning: z.boolean().optional(),
    interfaceAvailable: z.boolean().optional(),
    packetsObserved: z.number().int().min(0).optional(),
    recordsParsed: z.number().int().min(0).optional(),
    recordsQueued: z.number().int().min(0).optional(),
    recordsSubmitted: z.number().int().min(0).optional(),
    recordsAccepted: z.number().int().min(0).optional(),
    recordsRejected: z.number().int().min(0).optional(),
    lastError: z.string().max(500).nullable().optional(),
    interfaces: z
      .array(
        z.object({
          name: z.string().min(1).max(240),
          type: z.string().max(40).optional(),
          macAddress: z.string().max(40).optional(),
          ipAddress: z.string().max(64).optional(),
        })
      )
      .max(32)
      .optional(),
  });

  router.post('/agent/check-in', requireSensorAuth, (req: AuthRequest, res) => {
    const parsed = checkInSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid agent check-in payload', details: parsed.error.flatten() });
    }

    const sensor = req.sensor!;
    const data = parsed.data;
    const db = getDb();
    const now = new Date().toISOString();

    let nextStatus = sensor.status === 'paused' ? 'paused' : 'online';
    if (sensor.status !== 'paused' && data.lastError) {
      nextStatus = data.captureRunning === false ? 'error' : 'warning';
    } else if (sensor.status !== 'paused' && data.captureRunning === false) {
      nextStatus = 'warning';
    }

    db.prepare(
      `UPDATE sensors SET
        hostname = COALESCE(?, hostname),
        os_version = COALESCE(?, os_version),
        agent_version = COALESCE(?, agent_version),
        active_interface = COALESCE(?, active_interface),
        capture_running = COALESCE(?, capture_running),
        interface_available = COALESCE(?, interface_available),
        records_parsed = COALESCE(?, records_parsed),
        records_queued = COALESCE(?, records_queued),
        records_submitted = COALESCE(?, records_submitted),
        last_error = ?,
        status = ?,
        last_heartbeat_at = ?,
        updated_at = ?
       WHERE id = ?`
    ).run(
      data.hostname ?? null,
      data.osVersion ?? null,
      data.agentVersion ?? null,
      data.activeInterface ?? null,
      typeof data.captureRunning === 'boolean' ? (data.captureRunning ? 1 : 0) : null,
      typeof data.interfaceAvailable === 'boolean' ? (data.interfaceAvailable ? 1 : 0) : null,
      data.recordsParsed ?? null,
      data.recordsQueued ?? null,
      data.recordsSubmitted ?? null,
      data.lastError ?? null,
      nextStatus,
      now,
      now,
      sensor.id
    );

    if (data.interfaces && data.interfaces.length > 0) {
      const upsertIfc = db.prepare(
        `INSERT INTO network_interfaces (id, organization_id, sensor_id, interface_name, interface_type, mac_address, ip_address, is_active, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(sensor_id, interface_name) DO UPDATE SET
           interface_type = COALESCE(excluded.interface_type, network_interfaces.interface_type),
           mac_address = COALESCE(excluded.mac_address, network_interfaces.mac_address),
           ip_address = COALESCE(excluded.ip_address, network_interfaces.ip_address),
           is_active = excluded.is_active,
           last_seen_at = excluded.last_seen_at`
      );
      for (const ifc of data.interfaces) {
        const cleanIp = ifc.ipAddress ? stripCidrSuffix(ifc.ipAddress) : null;
        upsertIfc.run(
          newId('ifc'),
          sensor.organizationId,
          sensor.id,
          ifc.name,
          ifc.type ?? null,
          ifc.macAddress ?? null,
          cleanIp,
          data.activeInterface === ifc.name ? 1 : 0,
          now
        );
      }
    }

    if (data.lastError && data.captureRunning === false) {
      db.prepare(
        `INSERT INTO alerts (id, organization_id, rule_id, sensor_id, severity, title, description, status, triggered_at)
         VALUES (?, ?, NULL, ?, 'critical', ?, ?, 'open', ?)`
      ).run(
        newId('alrt'),
        sensor.organizationId,
        sensor.id,
        `Capture failure on ${sensor.name}`,
        data.lastError,
        now
      );
    }

    broadcastToOrganization(sensor.organizationId, 'sensor:heartbeat', {
      sensorId: sensor.id,
      status: nextStatus,
      lastHeartbeatAt: now,
    });

    res.json({
      ok: true,
      sensorId: sensor.id,
      status: nextStatus,
      serverTime: now,
      maxBatchSize: 500,
    });
  });

  const packetEventSchema = z.object({
    eventUid: z.string().max(128).optional(),
    observedAt: z.string().max(64),
    srcIp: z.string().min(3).max(64),
    dstIp: z.string().min(3).max(64),
    srcPort: z.number().int().min(0).max(65535).nullable().optional(),
    dstPort: z.number().int().min(0).max(65535).nullable().optional(),
    transport: z.string().min(1).max(20),
    dissectorProtocol: z.string().max(40).nullable().optional(),
    packetLength: z.number().int().min(0).max(65535),
    dnsQuery: z.string().max(255).nullable().optional(),
    tlsSni: z.string().max(255).nullable().optional(),
    httpHost: z.string().max(255).nullable().optional(),
    stunType: z.string().max(32).nullable().optional(),
    stunClass: z.string().max(40).nullable().optional(),
    stunMethod: z.string().max(40).nullable().optional(),
    stunAttributes: z.string().max(256).nullable().optional(),
    dtlsHandshake: z.boolean().optional(),
    rtpDetected: z.boolean().optional(),
  });

  const ingestSchema = z.object({
    agentVersion: z.string().max(40).optional(),
    events: z.array(packetEventSchema).min(1).max(500),
  });

  router.post('/agent/ingest', ingestLimiter, requireSensorAuth, async (req: AuthRequest, res) => {
    const sensor = req.sensor!;
    if (sensor.status === 'paused') {
      return res.status(409).json({ error: 'Sensor is currently paused by an administrator' });
    }

    const parsed = ingestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid ingestion batch payload', details: parsed.error.flatten() });
    }

    try {
      const result = await processIngestBatch(sensor, parsed.data.events);
      res.json({
        ok: true,
        sensorId: sensor.id,
        accepted: result.accepted,
        duplicates: result.duplicates,
        rejected: result.rejected,
        alertsTriggered: result.alertsTriggered,
      });
    } catch (err: any) {
      console.error('Ingestion failure:', err);
      res.status(500).json({ error: 'Internal ingestion failure' });
    }
  });

  // ==========================================
  // AGENT SCRIPT & INSTALLER DOWNLOADS
  // ==========================================
  router.get('/agent/download/script', (_req, res) => {
    const filePath = path.resolve(process.cwd(), 'agent', 'PacketScope-Agent.ps1');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent script not found' });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="PacketScope-Agent.ps1"');
    res.sendFile(filePath);
  });

  router.get('/agent/download/installer', (_req, res) => {
    const filePath = path.resolve(process.cwd(), 'agent', 'Install-PacketScopeAgent.ps1');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Installer script not found' });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="Install-PacketScopeAgent.ps1"');
    res.sendFile(filePath);
  });

  // ==========================================
  // OVERVIEW DASHBOARD (REAL DB AGGREGATIONS)
  // ==========================================
  router.get('/dashboard/overview', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const since60s = new Date(Date.now() - 60 * 1000).toISOString();

    const kpis = db
      .prepare(
        `SELECT
          COUNT(*) as packets24h,
          COUNT(DISTINCT src_ip) as uniqueSrcIps,
          COUNT(DISTINCT dst_ip) as uniqueDstIps,
          MAX(observed_at) as lastPacketAt,
          SUM(CASE WHEN app_label = 'Unclassified' THEN 1 ELSE 0 END) as unclassifiedCount
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?`
      )
      .get(orgId, since24h) as any;

    const ppsRow = db
      .prepare(`SELECT COUNT(*) as cnt FROM packet_events WHERE organization_id = ? AND observed_at >= ?`)
      .get(orgId, since60s) as { cnt: number };

    const sensorStats = db
      .prepare(
        `SELECT
          COUNT(*) as totalSensors,
          SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as activeSensors
         FROM sensors WHERE organization_id = ? AND revoked_at IS NULL`
      )
      .get(orgId) as any;

    const appCountRow = db
      .prepare(
        `SELECT COUNT(DISTINCT app_name) as detectedApps
         FROM application_detections
         WHERE organization_id = ? AND observed_at >= ?`
      )
      .get(orgId, since24h) as any;

    const stunStats = db
      .prepare(
        `SELECT
          SUM(CASE WHEN category = 'confirmed_stun' THEN 1 ELSE 0 END) as confirmedStun,
          SUM(CASE WHEN category = 'confirmed_turn' THEN 1 ELSE 0 END) as confirmedTurn,
          SUM(CASE WHEN category = 'suspected_webrtc' THEN 1 ELSE 0 END) as suspectedWebrtc
         FROM stun_turn_events
         WHERE organization_id = ? AND observed_at >= ?`
      )
      .get(orgId, since24h) as any;

    const protocolDistribution = db
      .prepare(
        `SELECT protocol as name, COUNT(*) as count, SUM(packet_length) as bytes
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?
         GROUP BY protocol
         ORDER BY count DESC
         LIMIT 10`
      )
      .all(orgId, since24h);

    const appDistribution = db
      .prepare(
        `SELECT app_label as name, COUNT(*) as count,
          SUM(CASE WHEN confidence = 'HIGH' THEN 1 ELSE 0 END) as highConfidence
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?
         GROUP BY app_label
         ORDER BY count DESC
         LIMIT 10`
      )
      .all(orgId, since24h);

    const volumeTimeline = db
      .prepare(
        `SELECT substr(observed_at, 1, 13) || ':00:00Z' as bucket, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?
         GROUP BY bucket
         ORDER BY bucket ASC`
      )
      .all(orgId, since24h);

    const topSrcIps = db
      .prepare(
        `SELECT src_ip as ip, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?
         GROUP BY src_ip
         ORDER BY packets DESC
         LIMIT 8`
      )
      .all(orgId, since24h);

    const topDstIps = db
      .prepare(
        `SELECT dst_ip as ip, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events
         WHERE organization_id = ? AND observed_at >= ?
         GROUP BY dst_ip
         ORDER BY packets DESC
         LIMIT 8`
      )
      .all(orgId, since24h);

    const recentFeed = db
      .prepare(
        `SELECT p.id, p.observed_at as observedAt, p.sensor_id as sensorId, s.name as sensorName,
          p.src_ip as srcIp, p.src_port as srcPort, p.dst_ip as dstIp, p.dst_port as dstPort,
          p.transport, p.protocol, p.app_label as appLabel,
          COALESCE(p.tls_sni, p.dns_query, p.http_host) as hostname,
          p.packet_length as packetLength, p.confidence
         FROM packet_events p
         JOIN sensors s ON p.sensor_id = s.id
         WHERE p.organization_id = ?
         ORDER BY p.observed_at DESC
         LIMIT 25`
      )
      .all(orgId);

    const sensors = db
      .prepare(
        `SELECT id, name, status, active_interface as activeInterface, capture_running as captureRunning,
          packets_observed as packetsObserved, last_heartbeat_at as lastHeartbeatAt, last_error as lastError
         FROM sensors
         WHERE organization_id = ? AND revoked_at IS NULL
         ORDER BY updated_at DESC`
      )
      .all(orgId);

    const openAlerts = db
      .prepare(
        `SELECT id, severity, title, description, status, triggered_at as triggeredAt
         FROM alerts
         WHERE organization_id = ? AND status != 'resolved'
         ORDER BY triggered_at DESC
         LIMIT 10`
      )
      .all(orgId);

    res.json({
      kpis: {
        packets24h: kpis?.packets24h ?? 0,
        packetsPerSecond: Number(((ppsRow?.cnt ?? 0) / 60).toFixed(2)),
        activeSensors: sensorStats?.activeSensors ?? 0,
        registeredSensors: sensorStats?.totalSensors ?? 0,
        uniqueSrcIps: kpis?.uniqueSrcIps ?? 0,
        uniqueDstIps: kpis?.uniqueDstIps ?? 0,
        detectedApplications: appCountRow?.detectedApps ?? 0,
        confirmedStunPackets: stunStats?.confirmedStun ?? 0,
        confirmedTurnPackets: stunStats?.confirmedTurn ?? 0,
        suspectedWebrtcFlows: stunStats?.suspectedWebrtc ?? 0,
        unclassifiedPackets: kpis?.unclassifiedCount ?? 0,
        lastPacketAt: kpis?.lastPacketAt ?? null,
      },
      protocolDistribution,
      appDistribution,
      volumeTimeline,
      topSrcIps,
      topDstIps,
      recentFeed,
      sensors,
      openAlerts,
      updatedAt: new Date().toISOString(),
    });
  });

  // ==========================================
  // LIVE TRAFFIC, FLOWS & CSV EXPORT
  // ==========================================
  router.get('/traffic', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const page = Math.max(1, Number(req.query.page || 1));
    const pageSize = Math.min(100, Math.max(10, Number(req.query.pageSize || 25)));
    const offset = (page - 1) * pageSize;

    const { clauses, params } = buildTrafficFilters(orgId, req.query);
    const whereSql = clauses.join(' AND ');

    const sortColumnMap: Record<string, string> = {
      observedAt: 'p.observed_at',
      protocol: 'p.protocol',
      appLabel: 'p.app_label',
      packetLength: 'p.packet_length',
      srcIp: 'p.src_ip',
      dstIp: 'p.dst_ip',
      confidence: 'p.confidence',
    };
    const sortBy = sortColumnMap[String(req.query.sortBy || 'observedAt')] || 'p.observed_at';
    const sortDir = String(req.query.sortDir || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    const countRow = db
      .prepare(`SELECT COUNT(*) as total FROM packet_events p WHERE ${whereSql}`)
      .get(...params) as { total: number };

    const rows = db
      .prepare(
        `SELECT p.id, p.observed_at as observedAt, p.sensor_id as sensorId, s.name as sensorName,
          p.src_ip as srcIp, p.src_port as srcPort, p.dst_ip as dstIp, p.dst_port as dstPort,
          p.transport, p.protocol, p.app_label as appLabel,
          COALESCE(p.tls_sni, p.dns_query, p.http_host) as hostname,
          p.packet_length as packetLength, p.confidence, p.detection_method as detectionMethod,
          p.classification_mode as classificationMode, p.traffic_direction as trafficDirection
         FROM packet_events p
         JOIN sensors s ON p.sensor_id = s.id
         WHERE ${whereSql}
         ORDER BY ${sortBy} ${sortDir}
         LIMIT ? OFFSET ?`
      )
      .all(...params, pageSize, offset);

    res.json({
      items: rows,
      total: countRow.total,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(countRow.total / pageSize)),
    });
  });

  router.get('/traffic/export.csv', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const { clauses, params } = buildTrafficFilters(orgId, req.query);
    const rows = db
      .prepare(
        `SELECT p.observed_at, s.name as sensor_name, p.src_ip, p.src_port, p.dst_ip, p.dst_port,
          p.transport, p.protocol, p.app_label, COALESCE(p.tls_sni, p.dns_query, p.http_host, '') as hostname,
          p.packet_length, p.confidence, p.detection_method
         FROM packet_events p
         JOIN sensors s ON p.sensor_id = s.id
         WHERE ${clauses.join(' AND ')}
         ORDER BY p.observed_at DESC
         LIMIT 5000`
      )
      .all(...params) as any[];

    const header = 'Timestamp,Sensor,Source IP,Source Port,Destination IP,Destination Port,Transport,Protocol,Application,Hostname,Packet Size,Confidence,Evidence';
    const csvLines = rows.map((r) =>
      [
        r.observed_at,
        r.sensor_name,
        stripCidrSuffix(r.src_ip),
        r.src_port ?? '',
        stripCidrSuffix(r.dst_ip),
        r.dst_port ?? '',
        r.transport,
        r.protocol,
        r.app_label,
        r.hostname,
        r.packet_length,
        r.confidence,
        r.detection_method,
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(',')
    );

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="packetscope-traffic.csv"');
    res.send([header, ...csvLines].join('\n'));
  });

  router.get('/traffic/flows', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const rows = db
      .prepare(
        `SELECT f.id, f.sensor_id as sensorId, s.name as sensorName, f.src_ip as srcIp, f.src_port as srcPort,
          f.dst_ip as dstIp, f.dst_port as dstPort, f.transport, f.protocol, f.app_label as appLabel,
          f.confidence, f.packet_count as packetCount, f.byte_count as byteCount,
          f.first_seen_at as firstSeenAt, f.last_seen_at as lastSeenAt
         FROM network_flows f
         JOIN sensors s ON f.sensor_id = s.id
         WHERE f.organization_id = ?
         ORDER BY f.last_seen_at DESC
         LIMIT 200`
      )
      .all(orgId);
    res.json({ items: rows });
  });

  // ==========================================
  // APPLICATIONS, PROTOCOLS & STUN/TURN
  // ==========================================
  router.get('/applications', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const summary = db
      .prepare(
        `SELECT app_label as appName, confidence, classification_mode as classificationMode,
          COUNT(*) as packetCount, SUM(packet_length) as byteCount, MAX(observed_at) as lastSeenAt
         FROM packet_events
         WHERE organization_id = ?
         GROUP BY app_label, confidence, classification_mode
         ORDER BY packetCount DESC`
      )
      .all(orgId);

    const detections = db
      .prepare(
        `SELECT a.id, a.app_name as appName, a.evidence_source as evidenceSource, a.confidence,
          a.classification_mode as classificationMode, a.observed_at as observedAt,
          s.name as sensorName, p.src_ip as srcIp, p.dst_ip as dstIp, p.dst_port as dstPort, p.protocol
         FROM application_detections a
         JOIN sensors s ON a.sensor_id = s.id
         LEFT JOIN packet_events p ON a.packet_event_id = p.id
         WHERE a.organization_id = ?
         ORDER BY a.observed_at DESC
         LIMIT 200`
      )
      .all(orgId);

    res.json({ summary, detections });
  });

  router.get('/protocols', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const summary = db
      .prepare(
        `SELECT pd.protocol,
          COUNT(*) as totalObservations,
          SUM(CASE WHEN pd.dissector_confirmed = 1 THEN 1 ELSE 0 END) as confirmedCount,
          SUM(CASE WHEN pd.dissector_confirmed = 0 THEN 1 ELSE 0 END) as heuristicCount,
          MAX(pd.observed_at) as lastSeenAt
         FROM protocol_detections pd
         WHERE pd.organization_id = ?
         GROUP BY pd.protocol
         ORDER BY totalObservations DESC`
      )
      .all(orgId);

    const recent = db
      .prepare(
        `SELECT pd.id, pd.protocol, pd.dissector_confirmed as dissectorConfirmed, pd.evidence, pd.observed_at as observedAt,
          s.name as sensorName, p.src_ip as srcIp, p.dst_ip as dstIp, p.src_port as srcPort, p.dst_port as dstPort, p.transport
         FROM protocol_detections pd
         JOIN sensors s ON pd.sensor_id = s.id
         LEFT JOIN packet_events p ON pd.packet_event_id = p.id
         WHERE pd.organization_id = ?
         ORDER BY pd.observed_at DESC
         LIMIT 150`
      )
      .all(orgId);

    res.json({ summary, recent });
  });

  router.get('/stun-turn', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const clauses: string[] = ['st.organization_id = ?'];
    const params: any[] = [orgId];

    if (req.query.sensorId) {
      clauses.push('st.sensor_id = ?');
      params.push(String(req.query.sensorId));
    }
    if (req.query.category) {
      clauses.push('st.category = ?');
      params.push(String(req.query.category));
    }
    if (req.query.confidence) {
      clauses.push('st.confidence = ?');
      params.push(String(req.query.confidence));
    }
    if (req.query.messageType) {
      clauses.push('st.message_type LIKE ?');
      params.push(`%${String(req.query.messageType)}%`);
    }
    if (req.query.srcIp) {
      clauses.push('st.src_ip LIKE ?');
      params.push(`%${stripCidrSuffix(String(req.query.srcIp))}%`);
    }
    if (req.query.dstIp) {
      clauses.push('st.dst_ip LIKE ?');
      params.push(`%${stripCidrSuffix(String(req.query.dstIp))}%`);
    }
    if (req.query.startDate) {
      clauses.push('st.observed_at >= ?');
      params.push(String(req.query.startDate));
    }
    if (req.query.endDate) {
      clauses.push('st.observed_at <= ?');
      params.push(String(req.query.endDate));
    }

    const counters = db
      .prepare(
        `SELECT
          SUM(CASE WHEN category = 'confirmed_stun' THEN 1 ELSE 0 END) as confirmedStunPackets,
          SUM(CASE WHEN category = 'confirmed_turn' THEN 1 ELSE 0 END) as confirmedTurnPackets,
          SUM(CASE WHEN category = 'suspected_webrtc' THEN 1 ELSE 0 END) as suspectedWebrtcFlows,
          SUM(CASE WHEN category = 'unclassified_udp' THEN 1 ELSE 0 END) as unclassifiedUdpFlows,
          SUM(CASE WHEN stun_method = 'Binding' AND stun_class = 'Request' THEN 1 ELSE 0 END) as bindingRequests,
          SUM(CASE WHEN stun_method = 'Binding' AND stun_class LIKE '%Response%' THEN 1 ELSE 0 END) as bindingResponses,
          SUM(CASE WHEN stun_method = 'Allocate' THEN 1 ELSE 0 END) as turnAllocations
         FROM stun_turn_events
         WHERE organization_id = ?`
      )
      .get(orgId) as any;

    const events = db
      .prepare(
        `SELECT st.id, st.category, st.message_type as messageType, st.stun_method as stunMethod,
          st.stun_class as stunClass, st.attributes_meta as attributesMeta,
          st.src_ip as srcIp, st.src_port as srcPort, st.dst_ip as dstIp, st.dst_port as dstPort,
          st.positively_decoded as positivelyDecoded, st.confidence, st.evidence,
          st.observed_at as observedAt, s.id as sensorId, s.name as sensorName
         FROM stun_turn_events st
         JOIN sensors s ON st.sensor_id = s.id
         WHERE ${clauses.join(' AND ')}
         ORDER BY st.observed_at DESC
         LIMIT 200`
      )
      .all(...params);

    const udpFlows = db
      .prepare(
        `SELECT f.src_ip as srcIp, f.src_port as srcPort, f.dst_ip as dstIp, f.dst_port as dstPort,
          f.protocol, f.packet_count as packetCount, f.byte_count as byteCount,
          f.first_seen_at as firstSeenAt, f.last_seen_at as lastSeenAt, s.name as sensorName
         FROM network_flows f
         JOIN sensors s ON f.sensor_id = s.id
         WHERE f.organization_id = ? AND f.transport = 'UDP'
         ORDER BY f.last_seen_at DESC
         LIMIT 100`
      )
      .all(orgId);

    res.json({
      counters: {
        confirmedStunPackets: counters?.confirmedStunPackets ?? 0,
        confirmedTurnPackets: counters?.confirmedTurnPackets ?? 0,
        suspectedWebrtcFlows: counters?.suspectedWebrtcFlows ?? 0,
        unclassifiedUdpFlows: counters?.unclassifiedUdpFlows ?? 0,
        bindingRequests: counters?.bindingRequests ?? 0,
        bindingResponses: counters?.bindingResponses ?? 0,
        turnAllocations: counters?.turnAllocations ?? 0,
      },
      events,
      udpFlows,
      privacyNotice:
        'STUN/TURN telemetry identifies protocol endpoints (relays, NAT gateways, VPNs, carrier/cloud infrastructure) and does not identify a specific person, call content, or physical location.',
    });
  });

  // ==========================================
  // NETWORK GEOGRAPHY & IP INTELLIGENCE
  // ==========================================
  router.get('/geography', requireUserAuth, requireTenantAccess('viewer'), async (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const refresh = req.query.refresh === '1';

    const clauses: string[] = ['organization_id = ?'];
    const params: any[] = [orgId];
    if (req.query.sensorId) {
      clauses.push('sensor_id = ?');
      params.push(String(req.query.sensorId));
    }
    if (req.query.startDate) {
      clauses.push('observed_at >= ?');
      params.push(String(req.query.startDate));
    }
    if (req.query.endDate) {
      clauses.push('observed_at <= ?');
      params.push(String(req.query.endDate));
    }

    const endpointRows = db
      .prepare(
        `SELECT ip, SUM(cnt) as activityCount, MAX(lastSeen) as lastObservedAt
         FROM (
           SELECT src_ip as ip, COUNT(*) as cnt, MAX(observed_at) as lastSeen FROM packet_events WHERE ${clauses.join(' AND ')} GROUP BY src_ip
           UNION ALL
           SELECT dst_ip as ip, COUNT(*) as cnt, MAX(observed_at) as lastSeen FROM packet_events WHERE ${clauses.join(' AND ')} GROUP BY dst_ip
         )
         GROUP BY ip
         ORDER BY activityCount DESC
         LIMIT 200`
      )
      .all(...params, ...params) as Array<{ ip: string; activityCount: number; lastObservedAt: string }>;

    const publicEndpoints = endpointRows
      .map((r) => ({ ...r, ip: stripCidrSuffix(r.ip) }))
      .filter((r) => !isPrivateOrReservedIp(r.ip));

    const markers: any[] = [];
    let externalLookups = 0;

    for (const ep of publicEndpoints) {
      const cached = ipIntelDbAdapter.getCachedIpIntel(ep.ip);
      const needsExternal = !cached || cached.providerSource === 'unavailable' || refresh;
      const allowExternal = needsExternal && externalLookups < (refresh ? 15 : 10);

      const intel = await resolvePublicIpIntelligence(ep.ip, ipIntelDbAdapter, {
        forceRefresh: refresh && allowExternal,
        skipExternal: !allowExternal,
      });
      if (allowExternal && intel && intel.providerSource !== 'rate_limited') {
        externalLookups++;
      }
      if (intel && intel.isPublic) {
        markers.push({
          ip: ep.ip,
          activityCount: ep.activityCount,
          lastObservedAt: ep.lastObservedAt,
          asn: intel.asn,
          isp: intel.isp,
          orgName: intel.orgName,
          countryCode: intel.countryCode,
          countryName: intel.countryName,
          city: intel.city,
          latitude: intel.latitude,
          longitude: intel.longitude,
          providerSource: intel.providerSource,
        });
      }
    }

    res.json({
      disclaimer: 'Approximate public IP registration locations. This does not identify the physical location of a person or device.',
      rateLimit: getGeoIpRateLimitStatus(),
      totalPublicEndpoints: publicEndpoints.length,
      locatedEndpoints: markers.filter((m) => m.latitude !== null && m.longitude !== null).length,
      markers,
    });
  });

  router.get('/ip-intelligence', requireUserAuth, requireTenantAccess('viewer'), async (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const rows = db
      .prepare(
        `SELECT ep.ip, ep.activityCount, ep.lastObservedAt,
          intel.ip_version as ipVersion, intel.is_public as isPublic, intel.asn, intel.isp,
          intel.org_name as orgName, intel.country_code as countryCode, intel.country_name as countryName,
          intel.city, intel.latitude, intel.longitude, intel.provider_source as providerSource,
          intel.last_refreshed_at as lastRefreshedAt
         FROM (
           SELECT ip, SUM(cnt) as activityCount, MAX(lastSeen) as lastObservedAt
           FROM (
             SELECT src_ip as ip, COUNT(*) as cnt, MAX(observed_at) as lastSeen FROM packet_events WHERE organization_id = ? GROUP BY src_ip
             UNION ALL
             SELECT dst_ip as ip, COUNT(*) as cnt, MAX(observed_at) as lastSeen FROM packet_events WHERE organization_id = ? GROUP BY dst_ip
           )
           GROUP BY ip
         ) ep
         LEFT JOIN ip_intelligence intel ON ep.ip = intel.ip
         ORDER BY ep.activityCount DESC
         LIMIT 200`
      )
      .all(orgId, orgId) as any[];

    // Proactively enrich up to 5 uncached top public endpoints so ASN/ISP/country appear immediately
    let enrichedNow = 0;
    const enrichedMap = new Map<string, any>();
    for (const r of rows) {
      const cleanIp = stripCidrSuffix(r.ip);
      if (!isPrivateOrReservedIp(cleanIp) && (!r.providerSource || r.providerSource === 'unavailable') && enrichedNow < 5) {
        const intel = await resolvePublicIpIntelligence(cleanIp, ipIntelDbAdapter);
        if (intel && intel.providerSource !== 'rate_limited') {
          enrichedMap.set(cleanIp, intel);
          enrichedNow++;
        }
      }
    }

    res.json({
      items: rows.map((r) => {
        const cleanIp = stripCidrSuffix(r.ip);
        const fresh = enrichedMap.get(cleanIp);
        return {
          ...r,
          ...(fresh
            ? {
                ipVersion: fresh.ipVersion,
                asn: fresh.asn,
                isp: fresh.isp,
                orgName: fresh.orgName,
                countryCode: fresh.countryCode,
                countryName: fresh.countryName,
                city: fresh.city,
                latitude: fresh.latitude,
                longitude: fresh.longitude,
                providerSource: fresh.providerSource,
                lastRefreshedAt: fresh.lastRefreshedAt,
              }
            : {}),
          ip: cleanIp,
          isPublic: !isPrivateOrReservedIp(cleanIp),
        };
      }),
      rateLimit: getGeoIpRateLimitStatus(),
    });
  });

  router.post('/ip-intelligence/lookup', requireUserAuth, requireTenantAccess('analyst'), async (req: AuthRequest, res) => {
    const rawIp = String(req.body?.ip || '');
    const normalized = normalizeIp(rawIp);
    if (!normalized) {
      return res.status(400).json({ error: 'Valid IPv4 or IPv6 address is required' });
    }
    const intel = await resolvePublicIpIntelligence(normalized, ipIntelDbAdapter, { forceRefresh: true });
    res.json({ intel, rateLimit: getGeoIpRateLimitStatus() });
  });

  // ==========================================
  // SENSOR MANAGEMENT
  // ==========================================
  router.get('/sensors', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const sensors = db
      .prepare(
        `SELECT s.id, s.organization_id as organizationId, s.network_id as networkId, n.name as networkName,
          s.name, s.hostname, s.os_version as osVersion, s.agent_version as agentVersion,
          s.token_prefix as tokenPrefix, s.status, s.capture_running as captureRunning,
          s.interface_available as interfaceAvailable, s.active_interface as activeInterface,
          s.packets_observed as packetsObserved, s.records_parsed as recordsParsed,
          s.records_queued as recordsQueued, s.records_submitted as recordsSubmitted,
          s.records_accepted as recordsAccepted, s.records_rejected as recordsRejected,
          s.last_heartbeat_at as lastHeartbeatAt, s.last_packet_at as lastPacketAt,
          s.last_error as lastError, s.revoked_at as revokedAt, s.created_at as createdAt
         FROM sensors s
         LEFT JOIN networks n ON s.network_id = n.id
         WHERE s.organization_id = ?
         ORDER BY s.created_at DESC`
      )
      .all(orgId);
    res.json({ items: sensors });
  });

  router.post('/sensors', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const schema = z.object({
      name: z.string().min(2).max(120),
      networkId: z.string().max(128).nullable().optional(),
      deploymentMode: z.enum(['host-interface', 'mirror-port', 'gateway', 'access-point']).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Valid sensor name is required' });
    }

    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const now = new Date().toISOString();

    let networkId = parsed.data.networkId || null;
    if (networkId) {
      const net = db.prepare(`SELECT id FROM networks WHERE id = ? AND organization_id = ?`).get(networkId, orgId);
      if (!net) return res.status(404).json({ error: 'Selected network does not belong to this organization' });
    } else {
      const defaultNet = db.prepare(`SELECT id FROM networks WHERE organization_id = ? ORDER BY created_at ASC LIMIT 1`).get(orgId) as any;
      networkId = defaultNet?.id ?? null;
    }

    const { rawToken, tokenHash, tokenPrefix } = generateSensorToken();
    const sensorId = newId('sns');

    db.prepare(
      `INSERT INTO sensors (id, organization_id, network_id, name, token_hash, token_prefix, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'offline', ?, ?)`
    ).run(sensorId, orgId, networkId, parsed.data.name.trim(), tokenHash, tokenPrefix, now, now);

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'sensor.registered', 'sensor', sensorId, {
      name: parsed.data.name.trim(),
      tokenPrefix,
    });

    res.status(201).json({
      sensor: {
        id: sensorId,
        organizationId: orgId,
        networkId,
        name: parsed.data.name.trim(),
        tokenPrefix,
        status: 'offline',
        createdAt: now,
      },
      // Returned ONCE on registration/rotation; never retrievable again
      rawToken,
    });
  });

  router.patch('/sensors/:id', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const sensorId = req.params.id;
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const existing = db.prepare(`SELECT * FROM sensors WHERE id = ? AND organization_id = ?`).get(sensorId, orgId) as any;
    if (!existing) return res.status(404).json({ error: 'Sensor not found' });

    const schema = z.object({
      name: z.string().min(2).max(120).optional(),
      networkId: z.string().max(128).nullable().optional(),
      action: z.enum(['pause', 'resume', 'revoke']).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid sensor update payload' });

    const now = new Date().toISOString();
    let nextStatus = existing.status;
    let revokedAt = existing.revoked_at;

    if (parsed.data.action === 'pause') nextStatus = 'paused';
    if (parsed.data.action === 'resume') nextStatus = existing.last_heartbeat_at ? 'online' : 'offline';
    if (parsed.data.action === 'revoke') {
      nextStatus = 'offline';
      revokedAt = now;
    }

    db.prepare(
      `UPDATE sensors SET
        name = COALESCE(?, name),
        network_id = COALESCE(?, network_id),
        status = ?,
        revoked_at = ?,
        updated_at = ?
       WHERE id = ? AND organization_id = ?`
    ).run(
      parsed.data.name?.trim() ?? null,
      parsed.data.networkId ?? null,
      nextStatus,
      revokedAt,
      now,
      sensorId,
      orgId
    );

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, `sensor.${parsed.data.action || 'updated'}`, 'sensor', sensorId, parsed.data);
    res.json({ ok: true, id: sensorId, status: nextStatus, revokedAt });
  });

  router.post('/sensors/:id/rotate-token', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const sensorId = req.params.id;
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const existing = db.prepare(`SELECT id, name FROM sensors WHERE id = ? AND organization_id = ?`).get(sensorId, orgId) as any;
    if (!existing) return res.status(404).json({ error: 'Sensor not found' });

    const { rawToken, tokenHash, tokenPrefix } = generateSensorToken();
    const now = new Date().toISOString();

    db.prepare(
      `UPDATE sensors SET token_hash = ?, token_prefix = ?, revoked_at = NULL, updated_at = ? WHERE id = ? AND organization_id = ?`
    ).run(tokenHash, tokenPrefix, now, sensorId, orgId);

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'sensor.token_rotated', 'sensor', sensorId, { tokenPrefix });
    res.json({ ok: true, sensorId, tokenPrefix, rawToken });
  });

  router.post('/sensors/:id/import-queue', requireUserAuth, requireTenantAccess('analyst'), async (req: AuthRequest, res) => {
    const sensorId = req.params.id;
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const sensorRow = db
      .prepare(
        `SELECT id, organization_id as organizationId, network_id as networkId, name, status, revoked_at as revokedAt
         FROM sensors
         WHERE id = ? AND organization_id = ?`
      )
      .get(sensorId, orgId) as any;

    if (!sensorRow) return res.status(404).json({ error: 'Sensor not found' });
    if (sensorRow.revokedAt) return res.status(403).json({ error: 'Sensor credential is revoked' });
    if (sensorRow.status === 'paused') return res.status(409).json({ error: 'Sensor is paused' });

    const parsed = ingestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid queue batch payload', details: parsed.error.flatten() });
    }

    try {
      const result = await processIngestBatch(
        {
          id: sensorRow.id,
          organizationId: sensorRow.organizationId,
          name: sensorRow.name,
          status: sensorRow.status,
        },
        parsed.data.events
      );
      writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'sensor.queue_imported', 'sensor', sensorId, {
        accepted: result.accepted,
        duplicates: result.duplicates,
        rejected: result.rejected,
      });
      res.json({
        ok: true,
        sensorId,
        accepted: result.accepted,
        duplicates: result.duplicates,
        rejected: result.rejected,
        alertsTriggered: result.alertsTriggered,
      });
    } catch (err: any) {
      console.error('Queue import failure:', err);
      res.status(500).json({ error: 'Internal queue import failure' });
    }
  });

  router.delete('/sensors/:id', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const sensorId = req.params.id;
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const existing = db.prepare(`SELECT id, name FROM sensors WHERE id = ? AND organization_id = ?`).get(sensorId, orgId) as any;
    if (!existing) return res.status(404).json({ error: 'Sensor not found' });

    db.prepare(`DELETE FROM sensors WHERE id = ? AND organization_id = ?`).run(sensorId, orgId);
    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'sensor.deleted', 'sensor', sensorId, { name: existing.name });
    res.json({ ok: true });
  });

  // ==========================================
  // NETWORK INVENTORY
  // ==========================================
  router.get('/inventory', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const networks = db
      .prepare(`SELECT id, name, cidr, deployment_mode as deploymentMode, description, created_at as createdAt FROM networks WHERE organization_id = ?`)
      .all(orgId);

    const interfaces = db
      .prepare(
        `SELECT ni.id, ni.sensor_id as sensorId, s.name as sensorName, ni.interface_name as interfaceName,
          ni.interface_type as interfaceType, ni.mac_address as macAddress, ni.ip_address as ipAddress,
          ni.is_active as isActive, ni.last_seen_at as lastSeenAt
         FROM network_interfaces ni
         JOIN sensors s ON ni.sensor_id = s.id
         WHERE ni.organization_id = ?
         ORDER BY ni.last_seen_at DESC`
      )
      .all(orgId);

    const hosts = db
      .prepare(
        `SELECT src_ip as ip, COUNT(*) as packetCount, COUNT(DISTINCT dst_ip) as peersContacted, MAX(observed_at) as lastSeenAt
         FROM packet_events
         WHERE organization_id = ?
         GROUP BY src_ip
         ORDER BY packetCount DESC
         LIMIT 100`
      )
      .all(orgId);

    res.json({ networks, interfaces, hosts });
  });

  router.post('/networks', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const schema = z.object({
      name: z.string().min(2).max(120),
      cidr: z.string().max(64).nullable().optional(),
      deploymentMode: z.enum(['host-interface', 'mirror-port', 'gateway', 'access-point']).default('host-interface'),
      description: z.string().max(400).nullable().optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid network definition' });

    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const id = newId('net');
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO networks (id, organization_id, name, cidr, deployment_mode, description, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(id, orgId, parsed.data.name.trim(), parsed.data.cidr ?? null, parsed.data.deploymentMode, parsed.data.description ?? null, now);

    res.status(201).json({ id, ...parsed.data, createdAt: now });
  });

  // ==========================================
  // ALERTS & ALERT RULES
  // ==========================================
  router.get('/alerts', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const items = db
      .prepare(
        `SELECT a.id, a.rule_id as ruleId, a.sensor_id as sensorId, s.name as sensorName,
          a.severity, a.title, a.description, a.status, a.triggered_at as triggeredAt,
          a.acknowledged_at as acknowledgedAt, a.resolved_at as resolvedAt
         FROM alerts a
         LEFT JOIN sensors s ON a.sensor_id = s.id
         WHERE a.organization_id = ?
         ORDER BY a.triggered_at DESC
         LIMIT 200`
      )
      .all(orgId);
    res.json({ items });
  });

  router.patch('/alerts/:id', requireUserAuth, requireTenantAccess('analyst'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const alertId = req.params.id;
    const status = String(req.body?.status || '');
    if (!['acknowledged', 'resolved', 'open'].includes(status)) {
      return res.status(400).json({ error: 'Invalid alert status' });
    }
    const db = getDb();
    const now = new Date().toISOString();
    const result = db
      .prepare(
        `UPDATE alerts SET
          status = ?,
          acknowledged_at = CASE WHEN ? = 'acknowledged' THEN ? ELSE acknowledged_at END,
          resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END
         WHERE id = ? AND organization_id = ?`
      )
      .run(status, status, now, status, now, alertId, orgId);
    if (result.changes === 0) return res.status(404).json({ error: 'Alert not found' });
    res.json({ ok: true, id: alertId, status });
  });

  router.get('/alert-rules', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const items = db
      .prepare(
        `SELECT id, name, rule_type as ruleType, threshold, window_minutes as windowMinutes, severity, enabled, created_at as createdAt
         FROM alert_rules WHERE organization_id = ? ORDER BY created_at DESC`
      )
      .all(orgId);
    res.json({ items });
  });

  router.post('/alert-rules', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const schema = z.object({
      name: z.string().min(2).max(120),
      ruleType: z.enum([
        'sensor_offline',
        'agent_failure',
        'ingestion_failure',
        'traffic_spike',
        'dns_burst',
        'connection_volume',
        'new_public_endpoint',
      ]),
      threshold: z.number().int().min(1).max(1000000),
      windowMinutes: z.number().int().min(1).max(1440).default(5),
      severity: z.enum(['info', 'warning', 'critical']).default('warning'),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid alert rule payload' });

    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const id = newId('rul');
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO alert_rules (id, organization_id, name, rule_type, threshold, window_minutes, severity, enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).run(id, orgId, parsed.data.name.trim(), parsed.data.ruleType, parsed.data.threshold, parsed.data.windowMinutes, parsed.data.severity, now);

    res.status(201).json({ id, ...parsed.data, enabled: true, createdAt: now });
  });

  router.patch('/alert-rules/:id', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const ruleId = req.params.id;
    const db = getDb();
    const existing = db.prepare(`SELECT id FROM alert_rules WHERE id = ? AND organization_id = ?`).get(ruleId, orgId);
    if (!existing) return res.status(404).json({ error: 'Alert rule not found' });

    const enabled = typeof req.body?.enabled === 'boolean' ? (req.body.enabled ? 1 : 0) : null;
    const threshold = typeof req.body?.threshold === 'number' ? req.body.threshold : null;
    db.prepare(`UPDATE alert_rules SET enabled = COALESCE(?, enabled), threshold = COALESCE(?, threshold) WHERE id = ? AND organization_id = ?`).run(
      enabled,
      threshold,
      ruleId,
      orgId
    );
    res.json({ ok: true });
  });

  // ==========================================
  // ANALYTICS & REPORTS
  // ==========================================
  router.get('/analytics', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();

    const volumeOverTime = db
      .prepare(
        `SELECT substr(observed_at, 1, 13) || ':00:00Z' as bucket, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events WHERE organization_id = ? GROUP BY bucket ORDER BY bucket ASC LIMIT 168`
      )
      .all(orgId);

    const bySensor = db
      .prepare(
        `SELECT s.id, s.name, COUNT(p.id) as packets, COALESCE(SUM(p.packet_length), 0) as bytes
         FROM sensors s
         LEFT JOIN packet_events p ON s.id = p.sensor_id
         WHERE s.organization_id = ?
         GROUP BY s.id, s.name
         ORDER BY packets DESC`
      )
      .all(orgId);

    const stunTrends = db
      .prepare(
        `SELECT substr(observed_at, 1, 13) || ':00:00Z' as bucket, category, COUNT(*) as count
         FROM stun_turn_events WHERE organization_id = ? GROUP BY bucket, category ORDER BY bucket ASC LIMIT 168`
      )
      .all(orgId);

    const byProtocol = db
      .prepare(
        `SELECT protocol, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events WHERE organization_id = ? GROUP BY protocol ORDER BY packets DESC`
      )
      .all(orgId);

    const byApplication = db
      .prepare(
        `SELECT app_label as appName, COUNT(*) as packets, SUM(packet_length) as bytes
         FROM packet_events WHERE organization_id = ? GROUP BY app_label ORDER BY packets DESC`
      )
      .all(orgId);

    res.json({ volumeOverTime, bySensor, stunTrends, byProtocol, byApplication });
  });

  router.get('/reports', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const items = db
      .prepare(
        `SELECT id, report_type as reportType, title, summary_json as summaryJson,
          period_start as periodStart, period_end as periodEnd, created_at as createdAt
         FROM reports WHERE organization_id = ? ORDER BY created_at DESC LIMIT 50`
      )
      .all(orgId)
      .map((r: any) => ({ ...r, summary: JSON.parse(r.summaryJson) }));
    res.json({ items });
  });

  router.post('/reports/generate', requireUserAuth, requireTenantAccess('analyst'), (req: AuthRequest, res) => {
    const schema = z.object({
      reportType: z.enum(['daily', 'weekly', 'monthly', 'application', 'protocol', 'sensor_health', 'stun_turn']),
      title: z.string().min(2).max(160).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid report type' });

    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const now = new Date();
    const days = parsed.data.reportType === 'monthly' ? 30 : parsed.data.reportType === 'weekly' ? 7 : 1;
    const periodStart = new Date(now.getTime() - days * 86400 * 1000).toISOString();
    const periodEnd = now.toISOString();

    const totals = db
      .prepare(
        `SELECT COUNT(*) as totalPackets, COALESCE(SUM(packet_length), 0) as totalBytes,
          COUNT(DISTINCT src_ip) as uniqueSrcIps, COUNT(DISTINCT dst_ip) as uniqueDstIps
         FROM packet_events WHERE organization_id = ? AND observed_at >= ?`
      )
      .get(orgId, periodStart) as any;

    const topProtocols = db
      .prepare(
        `SELECT protocol as name, COUNT(*) as count FROM packet_events
         WHERE organization_id = ? AND observed_at >= ? GROUP BY protocol ORDER BY count DESC LIMIT 10`
      )
      .all(orgId, periodStart);

    const topApps = db
      .prepare(
        `SELECT app_label as name, COUNT(*) as count FROM packet_events
         WHERE organization_id = ? AND observed_at >= ? GROUP BY app_label ORDER BY count DESC LIMIT 10`
      )
      .all(orgId, periodStart);

    const stunCounts = db
      .prepare(
        `SELECT category, COUNT(*) as count FROM stun_turn_events
         WHERE organization_id = ? AND observed_at >= ? GROUP BY category`
      )
      .all(orgId, periodStart);

    const sensorHealth = db
      .prepare(
        `SELECT name, status, packets_observed as packetsObserved, last_heartbeat_at as lastHeartbeatAt
         FROM sensors WHERE organization_id = ?`
      )
      .all(orgId);

    const summary = {
      totalPackets: totals?.totalPackets ?? 0,
      totalBytes: totals?.totalBytes ?? 0,
      uniqueSrcIps: totals?.uniqueSrcIps ?? 0,
      uniqueDstIps: totals?.uniqueDstIps ?? 0,
      topProtocols,
      topApps,
      stunCounts,
      sensorHealth,
    };

    const id = newId('rpt');
    const title =
      parsed.data.title?.trim() ||
      `PacketScope ${parsed.data.reportType.replace('_', ' ').toUpperCase()} Report (${periodEnd.slice(0, 10)})`;

    db.prepare(
      `INSERT INTO reports (id, organization_id, report_type, title, generated_by, summary_json, period_start, period_end, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, orgId, parsed.data.reportType, title, req.authUser!.id, JSON.stringify(summary), periodStart, periodEnd, periodEnd);

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'report.generated', 'report', id, {
      reportType: parsed.data.reportType,
    });

    res.status(201).json({ id, reportType: parsed.data.reportType, title, summary, periodStart, periodEnd, createdAt: periodEnd });
  });

  // ==========================================
  // SETTINGS, ADMINISTRATION, RBAC & BACKUP
  // ==========================================
  router.get('/settings', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const settings = db.prepare(`SELECT * FROM organization_settings WHERE organization_id = ?`).get(orgId) as any;
    const retention = db.prepare(`SELECT * FROM retention_policies WHERE organization_id = ?`).get(orgId) as any;
    res.json({ settings, retention });
  });

  router.patch('/settings', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const now = new Date().toISOString();

    const schema = z.object({
      monitoringAuthorizationNote: z.string().min(5).max(500).optional(),
      geoipEnabled: z.boolean().optional(),
      realtimeIntervalMs: z.number().int().min(500).max(30000).optional(),
      maxIngestBatchSize: z.number().int().min(10).max(500).optional(),
      packetEventsDays: z.number().int().min(1).max(3650).optional(),
      flowsDays: z.number().int().min(1).max(3650).optional(),
      stunEventsDays: z.number().int().min(1).max(3650).optional(),
      auditLogsDays: z.number().int().min(30).max(3650).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid settings update' });

    const d = parsed.data;
    db.prepare(
      `UPDATE organization_settings SET
        monitoring_authorization_note = COALESCE(?, monitoring_authorization_note),
        geoip_enabled = COALESCE(?, geoip_enabled),
        realtime_interval_ms = COALESCE(?, realtime_interval_ms),
        max_ingest_batch_size = COALESCE(?, max_ingest_batch_size),
        updated_at = ?
       WHERE organization_id = ?`
    ).run(
      d.monitoringAuthorizationNote ?? null,
      typeof d.geoipEnabled === 'boolean' ? (d.geoipEnabled ? 1 : 0) : null,
      d.realtimeIntervalMs ?? null,
      d.maxIngestBatchSize ?? null,
      now,
      orgId
    );

    db.prepare(
      `UPDATE retention_policies SET
        packet_events_days = COALESCE(?, packet_events_days),
        flows_days = COALESCE(?, flows_days),
        stun_events_days = COALESCE(?, stun_events_days),
        audit_logs_days = COALESCE(?, audit_logs_days),
        updated_at = ?
       WHERE organization_id = ?`
    ).run(d.packetEventsDays ?? null, d.flowsDays ?? null, d.stunEventsDays ?? null, d.auditLogsDays ?? null, now, orgId);

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'settings.updated', 'organization_settings', orgId, d);
    res.json({ ok: true });
  });

  router.get('/members', requireUserAuth, requireTenantAccess('viewer'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const members = db
      .prepare(
        `SELECT u.id as userId, u.email, u.display_name as displayName, r.name as role, m.created_at as joinedAt
         FROM memberships m
         JOIN users u ON m.user_id = u.id
         JOIN roles r ON m.role_id = r.id
         WHERE m.organization_id = ?
         ORDER BY m.created_at ASC`
      )
      .all(orgId);
    res.json({ items: members });
  });

  router.post('/members', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const schema = z.object({
      email: z.string().email().max(254),
      role: z.enum(['admin', 'analyst', 'viewer']),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Valid user email and role required' });

    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const targetUser = db.prepare(`SELECT id, email, display_name FROM users WHERE email = ?`).get(parsed.data.email.toLowerCase()) as any;
    if (!targetUser) {
      return res.status(404).json({ error: 'User account not found. Ask them to register or sign in first.' });
    }

    const roleRow = db.prepare(`SELECT id FROM roles WHERE name = ?`).get(parsed.data.role) as any;
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO memberships (id, organization_id, user_id, role_id, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(organization_id, user_id) DO UPDATE SET role_id = excluded.role_id`
    ).run(newId('mem'), orgId, targetUser.id, roleRow.id, now);

    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'member.role_assigned', 'membership', targetUser.id, {
      email: targetUser.email,
      role: parsed.data.role,
    });
    res.status(201).json({ ok: true, userId: targetUser.id, email: targetUser.email, role: parsed.data.role });
  });

  router.get('/audit-logs', requireUserAuth, requireTenantAccess('admin'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const items = db
      .prepare(
        `SELECT id, actor_email as actorEmail, action, resource_type as resourceType, resource_id as resourceId,
          details_json as detailsJson, created_at as createdAt
         FROM audit_logs WHERE organization_id = ? ORDER BY created_at DESC LIMIT 200`
      )
      .all(orgId);
    res.json({ items });
  });

  router.get('/backup/export', requireUserAuth, requireTenantAccess('owner'), (req: AuthRequest, res) => {
    const orgId = req.tenant!.organizationId;
    const db = getDb();
    const payload = {
      exportedAt: new Date().toISOString(),
      organization: db.prepare(`SELECT * FROM organizations WHERE id = ?`).get(orgId),
      settings: db.prepare(`SELECT * FROM organization_settings WHERE organization_id = ?`).get(orgId),
      retention: db.prepare(`SELECT * FROM retention_policies WHERE organization_id = ?`).get(orgId),
      networks: db.prepare(`SELECT * FROM networks WHERE organization_id = ?`).all(orgId),
      sensors: db
        .prepare(`SELECT id, name, hostname, status, active_interface, packets_observed, created_at FROM sensors WHERE organization_id = ?`)
        .all(orgId),
      alertRules: db.prepare(`SELECT * FROM alert_rules WHERE organization_id = ?`).all(orgId),
      reports: db.prepare(`SELECT * FROM reports WHERE organization_id = ?`).all(orgId),
    };
    writeAuditLog(orgId, req.authUser!.id, req.authUser!.email, 'backup.exported', 'organization', orgId);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="packetscope-backup-${orgId}.json"`);
    res.send(JSON.stringify(payload, null, 2));
  });

  return router;
}

function buildTrafficFilters(orgId: string, query: any) {
  const clauses: string[] = ['p.organization_id = ?'];
  const params: any[] = [orgId];

  if (query.search) {
    const term = `%${String(query.search).trim()}%`;
    clauses.push(
      `(p.src_ip LIKE ? OR p.dst_ip LIKE ? OR p.protocol LIKE ? OR p.app_label LIKE ? OR COALESCE(p.tls_sni, p.dns_query, p.http_host, '') LIKE ?)`
    );
    params.push(term, term, term, term, term);
  }
  if (query.protocol) {
    clauses.push('p.protocol = ?');
    params.push(String(query.protocol));
  }
  if (query.application) {
    clauses.push('p.app_label = ?');
    params.push(String(query.application));
  }
  if (query.sensorId) {
    clauses.push('p.sensor_id = ?');
    params.push(String(query.sensorId));
  }
  if (query.srcIp) {
    clauses.push('p.src_ip LIKE ?');
    params.push(`%${stripCidrSuffix(String(query.srcIp))}%`);
  }
  if (query.dstIp) {
    clauses.push('p.dst_ip LIKE ?');
    params.push(`%${stripCidrSuffix(String(query.dstIp))}%`);
  }
  if (query.startDate) {
    clauses.push('p.observed_at >= ?');
    params.push(String(query.startDate));
  }
  if (query.endDate) {
    clauses.push('p.observed_at <= ?');
    params.push(String(query.endDate));
  }

  return { clauses, params };
}
