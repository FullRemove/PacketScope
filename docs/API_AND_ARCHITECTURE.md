# PacketScope System Architecture, Data Flow & API Reference

## 1. High-Level Architecture

PacketScope separates data capture, metadata ingestion, network intelligence classification, relational storage, and live visualization into independent layers:

```
┌──────────────────────────────────┐
│  Windows 10/11 Capture Agent     │
│  (PacketScope-Agent.ps1)         │
│  - Single continuous TShark      │
│  - Strict TSV field extraction   │
│  - Zero payload capture          │
│  - Offline disk queue + backoff  │
└───────────────┬──────────────────┘
                │ HTTPS (Bearer ps_live_... sensor token)
                ▼
┌──────────────────────────────────┐
│  PacketScope Backend (server.ts) │
│  - Helmet, CORS, Rate Limiting   │
│  - Zod schema validation         │
│  - SHA-256 sensor authentication │
│  - Firebase / HMAC operator auth │
│  - Tenant RBAC enforcement       │
└───────┬──────────────────┬───────┘
        │                  │
        ▼                  ▼
┌───────────────┐  ┌─────────────────────────────┐
│ Intelligence  │  │ Relational Store            │
│ Engine        │  │ - PostgreSQL DDL (0001)     │
│ - IP / CIDR   │  │ - Runtime SQLite WAL        │
│ - Protocol    │  │ - 20 normalized tables      │
│ - STUN / TURN │  │ - Idempotent event_uid      │
│ - Application │  └──────────────┬──────────────┘
│ - Public Geo  │                 │
└───────┬───────┘                 │
        └──────────┬──────────────┘
                   ▼
     ┌─────────────────────────────┐
     │ WebSocket Broadcast (/ws)   │
     │ & REST API (/api/v1/*)      │
     │ - Strict tenant isolation   │
     └─────────────┬───────────────┘
                   ▼
     ┌─────────────────────────────┐
     │ Operations Dashboard (React)│
     │ - 14 specialized views      │
     │ - d3-geo Natural Earth map  │
     │ - CSV & PDF report exports  │
     └─────────────────────────────┘
```

## 2. Ingestion & Classification Data Flow

1. **Heartbeat (`POST /api/agent/check-in`)**:
   - Sensor authenticates with `Authorization: Bearer ps_live_...` (validated against SHA-256 hash).
   - Server records sensor diagnostic counters (`captureRunning`, `interfaceAvailable`, `packetsObserved`, `recordsParsed`, `recordsQueued`, `recordsSubmitted`, `recordsAccepted`, `recordsRejected`, `lastError`) in `sensor_heartbeats` and updates `sensors.status`.
2. **Metadata Batch Ingestion (`POST /api/agent/ingest`)**:
   - Validates payload schema and ensures batch size stays within configured limits.
   - Strips CIDR suffixes (e.g., `10.33.24.244/32` -> `10.33.24.244`) and ignores invalid/non-metadata fields.
   - Enforces duplicate protection using unique `(organization_id, event_uid)` keys.
   - **Protocol Engine** (`src/intelligence/protocolEngine.ts`):
     - Normalizes transport and dissector protocols (`TCP`, `UDP`, `DNS`, `TLS`, `QUIC`, `HTTP`, `SSDP`, `mDNS`, `DHCP`, `ICMP`, `STUN`, `TURN`, `DTLS`, `RTP`).
     - Decodes RFC 5389 / RFC 5766 16-bit STUN/TURN message types when confirmed by dissector metadata.
     - Explicitly separates `confirmed_stun`, `confirmed_turn`, `suspected_webrtc`, and `unclassified_udp`.
   - **Application Engine** (`src/intelligence/applicationEngine.ts`):
     - Requires concrete multi-indicator evidence (DNS query + TLS SNI + endpoint ASN/org + protocol signals).
     - Assigns confidence tiers `HIGH`, `MEDIUM`, `LOW`, or `UNCLASSIFIED`.
     - Leaves encrypted/ambiguous traffic `UNCLASSIFIED` rather than guessing; never infers Messenger solely from Facebook ASN/IP.
   - **Flow & Alert Pipeline**:
     - Upserts `network_flows`, records `protocol_observations`, `application_detections`, `stun_turn_events`, and `dns_observations`.
     - Evaluates organization alert rules (`alerts`) and emits live tenant-scoped frames over `/ws`.
   - **Public IP Intelligence** (`src/intelligence/ipIntel.ts`):
     - Excludes RFC1918, loopback, link-local, CGNAT (`100.64.0.0/10`), multicast, and IPv6 ULA/reserved addresses from geolocation.
     - Queries public GeoIP (`ipwho.is` with `ip-api.com` fallback) under a 40 lookups/min token-bucket rate limiter and caches results in `ip_intelligence` for 24 hours.

## 3. REST & WebSocket API Endpoints

All REST endpoints are mounted under both `/api/*` and `/api/v1/*`. Live machine-readable OpenAPI 3.1 JSON is served at `GET /api/openapi.json` and `GET /api/v1/openapi.json`.

### Public & Agent Endpoints
- `GET /api/health` — Database readiness and runtime status.
- `GET /api/openapi.json` — OpenAPI 3.1 schema.
- `GET /api/agent/download/script` — Download `PacketScope-Agent.ps1`.
- `GET /api/agent/download/installer` — Download `Install-PacketScopeAgent.ps1`.
- `POST /api/auth/register` / `POST /api/auth/login` / `POST /api/auth/firebase` — Operator authentication.
- `POST /api/agent/check-in` — Sensor heartbeat & diagnostics (Sensor Bearer).
- `POST /api/agent/ingest` — Metadata-only batch ingestion (Sensor Bearer).

### Authenticated Operator Endpoints (`OperatorBearer` + `X-Organization-Id`)
- `GET /api/auth/me` — Current user, organizations, roles, and permissions.
- `GET /api/dashboard/overview` — 24h KPIs, hourly timeline, protocol & app distributions, live feed, top endpoints, sensors, alerts.
- `GET /api/traffic` & `GET /api/traffic/export.csv` — Paginated, searchable, filterable packet metadata & CSV export.
- `GET /api/traffic/flows` — Aggregated network flows.
- `GET /api/applications` — Application classifications with evidence details and confidence breakdown.
- `GET /api/protocols` — Dissector-backed protocol breakdowns and observations.
- `GET /api/stun-turn` — Confirmed STUN, confirmed TURN, suspected WebRTC, and unclassified UDP separation.
- `GET /api/geography` — Approximate cached public IP clusters (with mandatory privacy disclaimer).
- `GET /api/ip-intelligence` & `POST /api/ip-intelligence/lookup` — Cached public IP ASN/ISP/geo intelligence.
- `GET/POST/PATCH/DELETE /api/sensors` — Sensor CRUD, one-time token issuance, rotation, and pause/resume.
- `GET /api/inventory` — Observed hosts, internal vs external classification, ports, and protocols.
- `GET /api/alerts`, `POST /api/alerts/:id/acknowledge`, `POST /api/alerts/:id/resolve`, `GET/POST/PATCH /api/alert-rules` — Alerting and configurable thresholds.
- `GET /api/analytics` — Traffic concentration, hourly timelines, and host metrics.
- `GET/POST /api/reports` & `GET /api/reports/:id` — Persisted summary reports (JSON/CSV/PDF client export).
- `GET/PATCH /api/settings`, `POST /api/organizations`, `GET/POST/PATCH/DELETE /api/organizations/members`, `GET /api/audit-logs`, `GET /api/admin/backup` — Tenant RBAC, retention settings, audit trail, and JSON backup export.
- `WS /ws?token=...&organizationId=...` — Real-time tenant-isolated event stream (`traffic:batch`, `sensor:heartbeat`, `alert:triggered`).
