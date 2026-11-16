-- PacketScope Production PostgreSQL Relational Schema
-- Migration: 0001_initial_postgresql.sql
-- Designed for multi-tenant isolation, time-series traffic indexing, and zero payload storage.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Users
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  uid TEXT UNIQUE, -- Firebase Auth UID when linked via Google SSO
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT, -- PBKDF2-SHA256 for local operator auth; NULL for SSO-only accounts
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Organizations
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Roles & Permissions
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

-- 4. Memberships (Tenant RBAC)
CREATE TABLE IF NOT EXISTS memberships (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);

-- 5. Networks & Interfaces
CREATE TABLE IF NOT EXISTS networks (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  cidr TEXT,
  deployment_mode TEXT NOT NULL DEFAULT 'host-interface', -- host-interface | mirror-port | gateway | access-point
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_networks_org ON networks(organization_id);

-- 6. Sensors (Credentials hashed with SHA-256; plaintext never persisted)
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
  status TEXT NOT NULL DEFAULT 'offline', -- online | offline | warning | error | paused
  capture_running BOOLEAN NOT NULL DEFAULT FALSE,
  interface_available BOOLEAN NOT NULL DEFAULT FALSE,
  active_interface TEXT,
  packets_observed BIGINT NOT NULL DEFAULT 0,
  records_parsed BIGINT NOT NULL DEFAULT 0,
  records_queued BIGINT NOT NULL DEFAULT 0,
  records_submitted BIGINT NOT NULL DEFAULT 0,
  records_accepted BIGINT NOT NULL DEFAULT 0,
  records_rejected BIGINT NOT NULL DEFAULT 0,
  last_heartbeat_at TIMESTAMPTZ,
  last_packet_at TIMESTAMPTZ,
  last_error TEXT,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sensors_org_status ON sensors(organization_id, status);

CREATE TABLE IF NOT EXISTS network_interfaces (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  interface_name TEXT NOT NULL,
  interface_type TEXT, -- ethernet | wifi | virtual
  mac_address TEXT,
  ip_address INET,
  is_active BOOLEAN NOT NULL DEFAULT FALSE,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (sensor_id, interface_name)
);

-- 7. Packet Events (Metadata ONLY — zero payload bytes)
CREATE TABLE IF NOT EXISTS packet_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  event_uid TEXT NOT NULL, -- idempotency key from capture agent
  observed_at TIMESTAMPTZ NOT NULL,
  src_ip INET NOT NULL,
  dst_ip INET NOT NULL,
  src_port INTEGER,
  dst_port INTEGER,
  transport TEXT NOT NULL, -- TCP | UDP | ICMP | OTHER
  protocol TEXT NOT NULL,
  packet_length INTEGER NOT NULL,
  dns_query TEXT,
  tls_sni TEXT,
  http_host TEXT,
  app_label TEXT NOT NULL DEFAULT 'Unclassified',
  detection_method TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'UNCLASSIFIED', -- HIGH | MEDIUM | LOW | UNCLASSIFIED
  classification_mode TEXT NOT NULL DEFAULT 'inferred', -- confirmed | inferred
  traffic_direction TEXT NOT NULL DEFAULT 'unknown', -- outbound | inbound | internal | unknown
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (sensor_id, event_uid)
);
CREATE INDEX IF NOT EXISTS idx_packet_events_org_time ON packet_events(organization_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_packet_events_org_proto ON packet_events(organization_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packet_events_org_app ON packet_events(organization_id, app_label);
CREATE INDEX IF NOT EXISTS idx_packet_events_org_src ON packet_events(organization_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packet_events_org_dst ON packet_events(organization_id, dst_ip);

-- 8. Network Flows
CREATE TABLE IF NOT EXISTS network_flows (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  flow_key TEXT NOT NULL,
  src_ip INET NOT NULL,
  dst_ip INET NOT NULL,
  src_port INTEGER,
  dst_port INTEGER,
  transport TEXT NOT NULL,
  protocol TEXT NOT NULL,
  app_label TEXT NOT NULL DEFAULT 'Unclassified',
  confidence TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
  packet_count BIGINT NOT NULL DEFAULT 1,
  byte_count BIGINT NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  UNIQUE (organization_id, sensor_id, flow_key)
);
CREATE INDEX IF NOT EXISTS idx_flows_org_last_seen ON network_flows(organization_id, last_seen_at DESC);

-- 9. Protocol & Application Detections
CREATE TABLE IF NOT EXISTS protocol_detections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  packet_event_id TEXT REFERENCES packet_events(id) ON DELETE CASCADE,
  protocol TEXT NOT NULL,
  dissector_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  evidence TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL
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
  confidence TEXT NOT NULL, -- HIGH | MEDIUM | LOW | UNCLASSIFIED
  classification_mode TEXT NOT NULL, -- confirmed | inferred
  observed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_app_det_org_time ON application_detections(organization_id, observed_at DESC);

-- 10. STUN / TURN / WebRTC Events
CREATE TABLE IF NOT EXISTS stun_turn_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  packet_event_id TEXT REFERENCES packet_events(id) ON DELETE CASCADE,
  category TEXT NOT NULL, -- confirmed_stun | confirmed_turn | suspected_webrtc | unclassified_udp
  message_type TEXT NOT NULL,
  stun_method TEXT,
  stun_class TEXT,
  attributes_meta TEXT, -- Attribute names ONLY, never payloads
  src_ip INET NOT NULL,
  src_port INTEGER,
  dst_ip INET NOT NULL,
  dst_port INTEGER,
  positively_decoded BOOLEAN NOT NULL DEFAULT FALSE,
  confidence TEXT NOT NULL,
  evidence TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stun_org_time ON stun_turn_events(organization_id, observed_at DESC);

-- 11. Public IP Intelligence Cache
CREATE TABLE IF NOT EXISTS ip_intelligence (
  ip TEXT PRIMARY KEY,
  ip_version INTEGER NOT NULL,
  is_public BOOLEAN NOT NULL DEFAULT TRUE,
  asn TEXT,
  isp TEXT,
  org_name TEXT,
  country_code TEXT,
  country_name TEXT,
  city TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  provider_source TEXT NOT NULL,
  last_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. Alerts & Alert Rules
CREATE TABLE IF NOT EXISTS alert_rules (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  rule_type TEXT NOT NULL, -- sensor_offline | agent_failure | ingestion_failure | traffic_spike | dns_burst | connection_volume | new_public_endpoint
  threshold INTEGER NOT NULL,
  window_minutes INTEGER NOT NULL DEFAULT 5,
  severity TEXT NOT NULL DEFAULT 'warning', -- info | warning | critical
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
  sensor_id TEXT REFERENCES sensors(id) ON DELETE SET NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved
  triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alerts_org_status ON alerts(organization_id, status, triggered_at DESC);

-- 13. Reports, Audit Logs, Organization Settings, Retention Policies
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  report_type TEXT NOT NULL, -- daily | weekly | monthly | application | protocol | sensor_health | stun_turn
  title TEXT NOT NULL,
  generated_by TEXT REFERENCES users(id),
  summary_json JSONB NOT NULL,
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_email TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  details_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS organization_settings (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  monitoring_authorization_note TEXT NOT NULL DEFAULT 'Authorized organizational network monitoring only. Payload capture disabled.',
  geoip_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  realtime_interval_ms INTEGER NOT NULL DEFAULT 1500,
  max_ingest_batch_size INTEGER NOT NULL DEFAULT 500,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS retention_policies (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  packet_events_days INTEGER NOT NULL DEFAULT 30,
  flows_days INTEGER NOT NULL DEFAULT 90,
  stun_events_days INTEGER NOT NULL DEFAULT 60,
  audit_logs_days INTEGER NOT NULL DEFAULT 365,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
