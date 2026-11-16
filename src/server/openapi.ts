export function getOpenApiSpec(baseUrl: string) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'PacketScope Network Intelligence API',
      version: '1.0.0',
      description:
        'Versioned REST API for authorized PacketScope Windows capture agents, multi-tenant network intelligence, STUN/TURN telemetry, public IP geolocation, alerting, and reporting. Zero packet payloads are ever collected or stored.',
    },
    servers: [{ url: baseUrl || '/' }],
    components: {
      securitySchemes: {
        OperatorBearer: {
          type: 'http',
          scheme: 'bearer',
          description: 'Firebase ID Token or PacketScope Operator Session JWT',
        },
        SensorBearer: {
          type: 'http',
          scheme: 'bearer',
          description: 'Sensor credential token (ps_live_...) hashed with SHA-256 on the server',
        },
      },
    },
    paths: {
      '/api/v1/health': {
        get: { summary: 'System health & database readiness check', responses: { '200': { description: 'Healthy' } } },
      },
      '/api/v1/agent/check-in': {
        post: {
          summary: 'Windows capture agent periodic heartbeat and diagnostics',
          security: [{ SensorBearer: [] }],
          responses: { '200': { description: 'Heartbeat recorded' }, '401': { description: 'Invalid sensor token' } },
        },
      },
      '/api/v1/agent/ingest': {
        post: {
          summary: 'Ingest metadata-only packet batch from authorized sensor',
          security: [{ SensorBearer: [] }],
          responses: { '200': { description: 'Batch processed with accepted/duplicate/rejected counts' } },
        },
      },
      '/api/v1/dashboard/overview': {
        get: {
          summary: 'Organization-scoped real-time KPI overview and chart aggregations',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Overview telemetry' } },
        },
      },
      '/api/v1/traffic': {
        get: {
          summary: 'Paginated, filtered, sortable live packet metadata records',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Traffic list' } },
        },
      },
      '/api/v1/traffic/flows': {
        get: {
          summary: 'Aggregated network flows for the active organization',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Flow summaries' } },
        },
      },
      '/api/v1/applications': {
        get: {
          summary: 'Best-effort application detections with evidence sources and confidence tiers',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Application classifications' } },
        },
      },
      '/api/v1/protocols': {
        get: {
          summary: 'Dissector-backed protocol distribution and observations',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Protocol metrics' } },
        },
      },
      '/api/v1/stun-turn': {
        get: {
          summary: 'Confirmed STUN, confirmed TURN, suspected WebRTC, and unclassified UDP telemetry',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'STUN/TURN intelligence' } },
        },
      },
      '/api/v1/geography': {
        get: {
          summary: 'Approximate cached public IP endpoint locations (excludes private/reserved IPs)',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'Geographic endpoint clusters' } },
        },
      },
      '/api/v1/ip-intelligence': {
        get: {
          summary: 'Cached public IP ASN, ISP, and registration metadata',
          security: [{ OperatorBearer: [] }],
          responses: { '200': { description: 'IP intelligence records' } },
        },
      },
      '/api/v1/sensors': {
        get: { summary: 'List organization sensors', security: [{ OperatorBearer: [] }], responses: { '200': { description: 'Sensors list' } } },
        post: { summary: 'Register new sensor and issue one-time token', security: [{ OperatorBearer: [] }], responses: { '201': { description: 'Sensor created' } } },
      },
      '/api/v1/sensors/{id}': {
        patch: { summary: 'Rename, pause/resume, or reassign sensor', security: [{ OperatorBearer: [] }], responses: { '200': { description: 'Updated' } } },
        delete: { summary: 'Delete sensor and write audit log', security: [{ OperatorBearer: [] }], responses: { '200': { description: 'Deleted' } } },
      },
      '/api/v1/alerts': {
        get: { summary: 'List organization alerts', security: [{ OperatorBearer: [] }], responses: { '200': { description: 'Alerts list' } } },
      },
      '/api/v1/reports': {
        get: { summary: 'List generated network intelligence reports', security: [{ OperatorBearer: [] }], responses: { '200': { description: 'Reports list' } } },
      },
    },
  };
}
