import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

let dbInstance: DatabaseSync | null = null;

export function getDbPath(): string {
  if (process.env.PACKETSCOPE_DB_PATH) {
    return process.env.PACKETSCOPE_DB_PATH;
  }
  return path.resolve(process.cwd(), 'data', 'packetscope.db');
}

function quarantineDatabaseFiles(dbPath: string, reason: string): void {
  if (dbPath === ':memory:') return;
  const dir = path.dirname(dbPath);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const recoveryDir = path.join(dir, 'recovery', `${reason}-${stamp}`);
  const candidates = [dbPath, `${dbPath}-wal`, `${dbPath}-shm`];
  let createdDir = false;

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      if (!createdDir) {
        fs.mkdirSync(recoveryDir, { recursive: true });
        createdDir = true;
      }
      const dest = path.join(recoveryDir, path.basename(file));
      try {
        fs.renameSync(file, dest);
      } catch {
        fs.rmSync(file, { force: true });
      }
    }
  }
  if (createdDir) {
    console.warn(`[PacketScope SQLite] Quarantined ${reason} database files to ${recoveryDir}`);
  }
}

function openAndInitializeDb(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
  `);

  if (dbPath !== ':memory:') {
    const check = db.prepare('PRAGMA quick_check').get() as { quick_check?: string } | undefined;
    if (check?.quick_check !== 'ok') {
      db.close();
      throw new Error(`database integrity check failed: ${check?.quick_check || 'unknown'}`);
    }
  }

  initializeSchema(db);
  return db;
}

export function getDb(): DatabaseSync {
  if (dbInstance) return dbInstance;

  const dbPath = getDbPath();
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });

    // An orphaned WAL/SHM with no main .db file causes SQLITE_CORRUPT ("database disk image is malformed")
    const mainExists = fs.existsSync(dbPath);
    const walExists = fs.existsSync(`${dbPath}-wal`) || fs.existsSync(`${dbPath}-shm`);
    if (!mainExists && walExists) {
      quarantineDatabaseFiles(dbPath, 'orphaned-wal');
    }
  }

  try {
    dbInstance = openAndInitializeDb(dbPath);
    return dbInstance;
  } catch (err) {
    if (dbPath === ':memory:') throw err;
    console.error('[PacketScope SQLite] Recovering from damaged database image:', err);
    quarantineDatabaseFiles(dbPath, 'corrupt');
    dbInstance = openAndInitializeDb(dbPath);
    return dbInstance;
  }
}

export function closeDbSafely(): void {
  if (!dbInstance) return;
  try {
    dbInstance.exec('PRAGMA wal_checkpoint(TRUNCATE);');
  } catch {
    // ignore checkpoint errors on shutdown
  }
  try {
    dbInstance.close();
  } catch {
    // ignore close errors
  }
  dbInstance = null;
}

export function resetDbForTests(customPath = ':memory:'): DatabaseSync {
  closeDbSafely();
  process.env.PACKETSCOPE_DB_PATH = customPath;
  return getDb();
}

function initializeSchema(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      uid TEXT UNIQUE,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      owner_user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS permissions (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
      PRIMARY KEY (role_id, permission_id)
    );

    CREATE TABLE IF NOT EXISTS memberships (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id TEXT NOT NULL REFERENCES roles(id),
      created_at TEXT NOT NULL,
      UNIQUE (organization_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);

    CREATE TABLE IF NOT EXISTS networks (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      cidr TEXT,
      deployment_mode TEXT NOT NULL DEFAULT 'host-interface',
      description TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_networks_org ON networks(organization_id);

    CREATE TABLE IF NOT EXISTS sensors (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      network_id TEXT REFERENCES networks(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      hostname TEXT,
      os_version TEXT,
      agent_version TEXT,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'offline',
      capture_running INTEGER NOT NULL DEFAULT 0,
      interface_available INTEGER NOT NULL DEFAULT 0,
      active_interface TEXT,
      packets_observed INTEGER NOT NULL DEFAULT 0,
      records_parsed INTEGER NOT NULL DEFAULT 0,
      records_queued INTEGER NOT NULL DEFAULT 0,
      records_submitted INTEGER NOT NULL DEFAULT 0,
      records_accepted INTEGER NOT NULL DEFAULT 0,
      records_rejected INTEGER NOT NULL DEFAULT 0,
      last_heartbeat_at TEXT,
      last_packet_at TEXT,
      last_error TEXT,
      revoked_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sensors_org_status ON sensors(organization_id, status);

    CREATE TABLE IF NOT EXISTS network_interfaces (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      interface_name TEXT NOT NULL,
      interface_type TEXT,
      mac_address TEXT,
      ip_address TEXT,
      is_active INTEGER NOT NULL DEFAULT 0,
      last_seen_at TEXT NOT NULL,
      UNIQUE (sensor_id, interface_name)
    );

    CREATE TABLE IF NOT EXISTS packet_events (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      event_uid TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      src_ip TEXT NOT NULL,
      dst_ip TEXT NOT NULL,
      src_port INTEGER,
      dst_port INTEGER,
      transport TEXT NOT NULL,
      protocol TEXT NOT NULL,
      packet_length INTEGER NOT NULL,
      dns_query TEXT,
      tls_sni TEXT,
      http_host TEXT,
      app_label TEXT NOT NULL DEFAULT 'Unclassified',
      detection_method TEXT NOT NULL,
      confidence TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
      classification_mode TEXT NOT NULL DEFAULT 'inferred',
      traffic_direction TEXT NOT NULL DEFAULT 'unknown',
      created_at TEXT NOT NULL,
      UNIQUE (sensor_id, event_uid)
    );
    CREATE INDEX IF NOT EXISTS idx_packet_events_org_time ON packet_events(organization_id, observed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_packet_events_org_proto ON packet_events(organization_id, protocol);
    CREATE INDEX IF NOT EXISTS idx_packet_events_org_app ON packet_events(organization_id, app_label);
    CREATE INDEX IF NOT EXISTS idx_packet_events_org_src ON packet_events(organization_id, src_ip);
    CREATE INDEX IF NOT EXISTS idx_packet_events_org_dst ON packet_events(organization_id, dst_ip);

    CREATE TABLE IF NOT EXISTS network_flows (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      flow_key TEXT NOT NULL,
      src_ip TEXT NOT NULL,
      dst_ip TEXT NOT NULL,
      src_port INTEGER,
      dst_port INTEGER,
      transport TEXT NOT NULL,
      protocol TEXT NOT NULL,
      app_label TEXT NOT NULL DEFAULT 'Unclassified',
      confidence TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
      packet_count INTEGER NOT NULL DEFAULT 1,
      byte_count INTEGER NOT NULL DEFAULT 0,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      UNIQUE (organization_id, sensor_id, flow_key)
    );
    CREATE INDEX IF NOT EXISTS idx_flows_org_last_seen ON network_flows(organization_id, last_seen_at DESC);

    CREATE TABLE IF NOT EXISTS protocol_detections (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      packet_event_id TEXT REFERENCES packet_events(id) ON DELETE CASCADE,
      protocol TEXT NOT NULL,
      dissector_confirmed INTEGER NOT NULL DEFAULT 0,
      evidence TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_proto_det_org_time ON protocol_detections(organization_id, observed_at DESC);

    CREATE TABLE IF NOT EXISTS application_detections (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      packet_event_id TEXT REFERENCES packet_events(id) ON DELETE CASCADE,
      flow_id TEXT REFERENCES network_flows(id) ON DELETE SET NULL,
      app_name TEXT NOT NULL,
      evidence_source TEXT NOT NULL,
      confidence TEXT NOT NULL,
      classification_mode TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_app_det_org_time ON application_detections(organization_id, observed_at DESC);

    CREATE TABLE IF NOT EXISTS stun_turn_events (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
      packet_event_id TEXT REFERENCES packet_events(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      message_type TEXT NOT NULL,
      stun_method TEXT,
      stun_class TEXT,
      attributes_meta TEXT,
      src_ip TEXT NOT NULL,
      src_port INTEGER,
      dst_ip TEXT NOT NULL,
      dst_port INTEGER,
      positively_decoded INTEGER NOT NULL DEFAULT 0,
      confidence TEXT NOT NULL,
      evidence TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_stun_org_time ON stun_turn_events(organization_id, observed_at DESC);

    CREATE TABLE IF NOT EXISTS ip_intelligence (
      ip TEXT PRIMARY KEY,
      ip_version INTEGER NOT NULL,
      is_public INTEGER NOT NULL DEFAULT 1,
      asn TEXT,
      isp TEXT,
      org_name TEXT,
      country_code TEXT,
      country_name TEXT,
      city TEXT,
      latitude REAL,
      longitude REAL,
      provider_source TEXT NOT NULL,
      last_refreshed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alert_rules (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      rule_type TEXT NOT NULL,
      threshold INTEGER NOT NULL,
      window_minutes INTEGER NOT NULL DEFAULT 5,
      severity TEXT NOT NULL DEFAULT 'warning',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      rule_id TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
      sensor_id TEXT REFERENCES sensors(id) ON DELETE SET NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      triggered_at TEXT NOT NULL,
      acknowledged_at TEXT,
      resolved_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_org_status ON alerts(organization_id, status, triggered_at DESC);

    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      report_type TEXT NOT NULL,
      title TEXT NOT NULL,
      generated_by TEXT REFERENCES users(id),
      summary_json TEXT NOT NULL,
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      actor_email TEXT,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      details_json TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(organization_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS organization_settings (
      organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
      monitoring_authorization_note TEXT NOT NULL DEFAULT 'Authorized organizational network monitoring only. Packet payloads are never collected.',
      geoip_enabled INTEGER NOT NULL DEFAULT 1,
      realtime_interval_ms INTEGER NOT NULL DEFAULT 1500,
      max_ingest_batch_size INTEGER NOT NULL DEFAULT 500,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS retention_policies (
      organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
      packet_events_days INTEGER NOT NULL DEFAULT 30,
      flows_days INTEGER NOT NULL DEFAULT 90,
      stun_events_days INTEGER NOT NULL DEFAULT 60,
      audit_logs_days INTEGER NOT NULL DEFAULT 365,
      updated_at TEXT NOT NULL
    );
  `);

  // Seed standard RBAC roles and permissions (never fake traffic/sensors)
  const roles = [
    { id: 'role_owner', name: 'owner', description: 'Full organization ownership and billing/tenant governance' },
    { id: 'role_admin', name: 'admin', description: 'Manage sensors, alert rules, members, and policies' },
    { id: 'role_analyst', name: 'analyst', description: 'Investigate traffic, STUN/TURN, geography, alerts, and reports' },
    { id: 'role_viewer', name: 'viewer', description: 'Read-only visibility into authorized dashboards and reports' },
  ];
  const insertRole = db.prepare(`INSERT OR IGNORE INTO roles (id, name, description) VALUES (?, ?, ?)`);
  for (const r of roles) insertRole.run(r.id, r.name, r.description);

  const perms = [
    ['perm_read_telemetry', 'telemetry:read', 'Read traffic, flows, protocols, and STUN/TURN events'],
    ['perm_manage_sensors', 'sensors:manage', 'Register, rotate credentials, pause, and revoke sensors'],
    ['perm_manage_alerts', 'alerts:manage', 'Configure alert rules and resolve alerts'],
    ['perm_manage_org', 'org:manage', 'Manage organization settings, retention policies, and members'],
  ];
  const insertPerm = db.prepare(`INSERT OR IGNORE INTO permissions (id, code, description) VALUES (?, ?, ?)`);
  for (const [id, code, desc] of perms) insertPerm.run(id, code, desc);

  const rp = db.prepare(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`);
  for (const [permId] of perms) {
    rp.run('role_owner', permId);
    rp.run('role_admin', permId);
  }
  rp.run('role_analyst', 'perm_read_telemetry');
  rp.run('role_analyst', 'perm_manage_alerts');
  rp.run('role_viewer', 'perm_read_telemetry');
}

export function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
}
