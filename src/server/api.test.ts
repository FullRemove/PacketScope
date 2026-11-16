import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { resetDbForTests } from './db/sqlite';
import { createPacketScopeApp } from '../../server';

function startTestServer() {
  resetDbForTests(':memory:');
  const app = createPacketScopeApp();
  const server = http.createServer(app);
  return new Promise<{ baseUrl: string; close: () => Promise<void> }>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as any;
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

async function apiJson(baseUrl: string, path: string, options: RequestInit = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json };
}

test('PacketScope API: auth, sensor registration, ingestion, STUN/TURN decoding, IP formatting, and strict tenant isolation', async () => {
  const srv = await startTestServer();
  try {
    // 1. Health check
    const health = await apiJson(srv.baseUrl, '/api/health');
    assert.equal(health.status, 200);
    assert.equal(health.json.status, 'healthy');

    // 2. Register Organization A & Organization B operators
    const regA = await apiJson(srv.baseUrl, '/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin-a@packetscope.test',
        password: 'StrongPassword123!',
        displayName: 'Org A Admin',
        organizationName: 'Org Alpha Corp',
      }),
    });
    assert.equal(regA.status, 201);
    const tokenA = regA.json.token;
    const orgAId = regA.json.organizations[0].id;

    const regB = await apiJson(srv.baseUrl, '/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin-b@packetscope.test',
        password: 'StrongPassword123!',
        displayName: 'Org B Admin',
        organizationName: 'Org Beta LLC',
      }),
    });
    assert.equal(regB.status, 201);
    const tokenB = regB.json.token;
    const orgBId = regB.json.organizations[0].id;

    // 3. Register a sensor in Org A
    const createSensor = await apiJson(srv.baseUrl, '/api/sensors', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}`, 'X-Organization-Id': orgAId },
      body: JSON.stringify({ name: 'Win11-Edge-Sensor-01' }),
    });
    assert.equal(createSensor.status, 201);
    const rawSensorToken = createSensor.json.rawToken;
    const sensorId = createSensor.json.sensor.id;
    assert.ok(rawSensorToken.startsWith('ps_live_'));

    // 4. Reject invalid sensor tokens
    const badCheckIn = await apiJson(srv.baseUrl, '/api/agent/check-in', {
      method: 'POST',
      headers: { Authorization: 'Bearer ps_live_invalid_token_1234567890' },
      body: JSON.stringify({ captureRunning: true }),
    });
    assert.equal(badCheckIn.status, 401);

    // 5. Valid agent check-in updates heartbeat & interfaces
    const goodCheckIn = await apiJson(srv.baseUrl, '/api/agent/check-in', {
      method: 'POST',
      headers: { Authorization: `Bearer ${rawSensorToken}` },
      body: JSON.stringify({
        hostname: 'WIN11-NETOPS',
        osVersion: 'Windows 11 Pro 24H2',
        agentVersion: '1.4.0',
        activeInterface: 'Ethernet0',
        captureRunning: true,
        interfaceAvailable: true,
        interfaces: [{ name: 'Ethernet0', type: 'ethernet', ipAddress: '10.33.24.244/32' }],
      }),
    });
    assert.equal(goodCheckIn.status, 200);
    assert.equal(goodCheckIn.json.status, 'online');

    // 6. Ingest legitimate mixed traffic batch (STUN, TURN, DNS, TLS SNI, arbitrary UDP, CIDR-suffixed IP)
    const now = new Date().toISOString();
    const ingest = await apiJson(srv.baseUrl, '/api/agent/ingest', {
      method: 'POST',
      headers: { Authorization: `Bearer ${rawSensorToken}` },
      body: JSON.stringify({
        agentVersion: '1.4.0',
        events: [
          {
            eventUid: 'evt-1',
            observedAt: now,
            srcIp: '10.33.24.244/32',
            dstIp: '74.125.250.129',
            srcPort: 54001,
            dstPort: 19302,
            transport: 'UDP',
            dissectorProtocol: 'STUN',
            packetLength: 96,
            stunType: '0x0001',
            stunAttributes: 'USERNAME, PRIORITY, FINGERPRINT',
          },
          {
            eventUid: 'evt-2',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '52.114.77.22',
            srcPort: 54002,
            dstPort: 3478,
            transport: 'UDP',
            dissectorProtocol: 'STUN',
            packetLength: 148,
            stunType: '0x0003',
          },
          {
            eventUid: 'evt-3',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '157.240.22.53',
            srcPort: 54100,
            dstPort: 443,
            transport: 'TCP',
            dissectorProtocol: 'TLSv1.3',
            packetLength: 517,
            tlsSni: 'web.whatsapp.com',
          },
          {
            eventUid: 'evt-4',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '1.1.1.1',
            srcPort: 55110,
            dstPort: 53,
            transport: 'UDP',
            dissectorProtocol: 'DNS',
            packetLength: 78,
            dnsQuery: 'meet.google.com',
          },
          {
            eventUid: 'evt-5',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '203.0.113.50',
            srcPort: 56000,
            dstPort: 3478,
            transport: 'UDP',
            dissectorProtocol: 'UDP',
            packetLength: 120,
          },
        ],
      }),
    });
    assert.equal(ingest.status, 200);
    assert.equal(ingest.json.accepted, 5);
    assert.equal(ingest.json.duplicates, 0);

    // Duplicate eventUid is idempotent
    const dupIngest = await apiJson(srv.baseUrl, '/api/agent/ingest', {
      method: 'POST',
      headers: { Authorization: `Bearer ${rawSensorToken}` },
      body: JSON.stringify({
        events: [
          {
            eventUid: 'evt-1',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '74.125.250.129',
            srcPort: 54001,
            dstPort: 19302,
            transport: 'UDP',
            dissectorProtocol: 'STUN',
            packetLength: 96,
            stunType: '0x0001',
          },
        ],
      }),
    });
    assert.equal(dupIngest.status, 200);
    assert.equal(dupIngest.json.accepted, 0);
    assert.equal(dupIngest.json.duplicates, 1);

    // 7. Verify Overview & STUN/TURN counters + CIDR stripping
    const overview = await apiJson(srv.baseUrl, '/api/dashboard/overview', {
      headers: { Authorization: `Bearer ${tokenA}`, 'X-Organization-Id': orgAId },
    });
    assert.equal(overview.status, 200);
    assert.equal(overview.json.kpis.packets24h, 5);
    assert.equal(overview.json.kpis.confirmedStunPackets, 1);
    assert.equal(overview.json.kpis.confirmedTurnPackets, 1);
    assert.equal(overview.json.kpis.activeSensors, 1);

    const traffic = await apiJson(srv.baseUrl, '/api/traffic', {
      headers: { Authorization: `Bearer ${tokenA}`, 'X-Organization-Id': orgAId },
    });
    assert.equal(traffic.status, 200);
    assert.equal(traffic.json.total, 5);
    assert.ok(traffic.json.items.every((item: any) => !item.srcIp.includes('/32')));

    // 8. Tenant Isolation: Org B MUST NOT access Org A's data or sensors
    const crossOrgOverview = await apiJson(srv.baseUrl, '/api/dashboard/overview', {
      headers: { Authorization: `Bearer ${tokenB}`, 'X-Organization-Id': orgAId },
    });
    assert.equal(crossOrgOverview.status, 403);

    const orgBOverview = await apiJson(srv.baseUrl, '/api/dashboard/overview', {
      headers: { Authorization: `Bearer ${tokenB}`, 'X-Organization-Id': orgBId },
    });
    assert.equal(orgBOverview.status, 200);
    assert.equal(orgBOverview.json.kpis.packets24h, 0);

    const crossDeleteSensor = await apiJson(srv.baseUrl, `/api/sensors/${sensorId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenB}`, 'X-Organization-Id': orgBId },
    });
    assert.equal(crossDeleteSensor.status, 404);

    // 8b. Authenticated operator offline queue.jsonl batch import & cross-tenant rejection
    const queueImport = await apiJson(srv.baseUrl, `/api/sensors/${sensorId}/import-queue`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}`, 'X-Organization-Id': orgAId },
      body: JSON.stringify({
        events: [
          {
            eventUid: 'queue-evt-1',
            observedAt: now,
            srcIp: '192.168.1.55/32',
            dstIp: '1.1.1.1',
            srcPort: 51200,
            dstPort: 443,
            transport: 'UDP',
            dissectorProtocol: 'QUIC',
            packetLength: 1200,
          },
        ],
      }),
    });
    assert.equal(queueImport.status, 200);
    assert.equal(queueImport.json.accepted, 1);

    const crossQueueImport = await apiJson(srv.baseUrl, `/api/sensors/${sensorId}/import-queue`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}`, 'X-Organization-Id': orgBId },
      body: JSON.stringify({
        events: [
          {
            eventUid: 'queue-evt-2',
            observedAt: now,
            srcIp: '192.168.1.55',
            dstIp: '1.1.1.1',
            transport: 'UDP',
            packetLength: 100,
          },
        ],
      }),
    });
    assert.equal(crossQueueImport.status, 404);

    // 9. Revoking sensor credential blocks subsequent ingestion
    const revoke = await apiJson(srv.baseUrl, `/api/sensors/${sensorId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${tokenA}`, 'X-Organization-Id': orgAId },
      body: JSON.stringify({ action: 'revoke' }),
    });
    assert.equal(revoke.status, 200);

    const postRevokeIngest = await apiJson(srv.baseUrl, '/api/agent/ingest', {
      method: 'POST',
      headers: { Authorization: `Bearer ${rawSensorToken}` },
      body: JSON.stringify({
        events: [
          {
            eventUid: 'evt-6',
            observedAt: now,
            srcIp: '10.33.24.244',
            dstIp: '8.8.8.8',
            transport: 'UDP',
            packetLength: 60,
          },
        ],
      }),
    });
    assert.equal(postRevokeIngest.status, 403);
  } finally {
    await srv.close();
  }
});
