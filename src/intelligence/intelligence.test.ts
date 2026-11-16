import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  stripCidrSuffix,
  isPrivateOrReservedIp,
  normalizeIp,
  inferTrafficDirection,
} from './ipUtils';
import { analyzeProtocol, decodeStunMessageType } from './protocolEngine';
import { classifyApplication } from './applicationEngine';
import { closeDbSafely, resetDbForTests } from '../server/db/sqlite';

test('IP utilities strip CIDR /32 suffixes and exclude private/reserved IPs', () => {
  assert.equal(stripCidrSuffix('10.33.24.244/32'), '10.33.24.244');
  assert.equal(stripCidrSuffix('2001:4860:4860::8888/128'), '2001:4860:4860::8888');
  assert.equal(normalizeIp('192.168.1.15/24'), '192.168.1.15');
  assert.equal(normalizeIp('not-an-ip'), null);

  assert.equal(isPrivateOrReservedIp('10.33.24.244/32'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.5'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.10.1'), true);
  assert.equal(isPrivateOrReservedIp('224.0.0.251'), true);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false);

  assert.equal(inferTrafficDirection('10.0.0.5', '8.8.8.8'), 'outbound');
  assert.equal(inferTrafficDirection('8.8.8.8', '10.0.0.5'), 'inbound');
  assert.equal(inferTrafficDirection('192.168.1.2', '10.0.0.5'), 'internal');
});

test('STUN/TURN decoder accurately distinguishes Binding vs TURN Allocate and rejects arbitrary UDP', () => {
  const bindReq = decodeStunMessageType('0x0001');
  assert.ok(bindReq);
  assert.equal(bindReq.method, 'Binding');
  assert.equal(bindReq.msgClass, 'Request');
  assert.equal(bindReq.isTurn, false);

  const bindResp = decodeStunMessageType('0x0101');
  assert.ok(bindResp);
  assert.equal(bindResp.method, 'Binding');
  assert.equal(bindResp.msgClass, 'Success Response');
  assert.equal(bindResp.isTurn, false);

  const turnAlloc = decodeStunMessageType('0x0003');
  assert.ok(turnAlloc);
  assert.equal(turnAlloc.method, 'Allocate');
  assert.equal(turnAlloc.msgClass, 'Request');
  assert.equal(turnAlloc.isTurn, true);

  // Arbitrary UDP on port 3478 WITHOUT STUN dissection must NOT be labeled confirmed STUN
  const arbitraryUdp = analyzeProtocol({
    observedAt: '2026-11-14T12:00:00Z',
    srcIp: '10.0.0.12',
    dstIp: '198.51.100.44',
    srcPort: 54210,
    dstPort: 3478,
    transport: 'UDP',
    dissectorProtocol: 'UDP',
    packetLength: 140,
  });
  assert.equal(arbitraryUdp.protocol, 'UDP');
  assert.notEqual(arbitraryUdp.stunTurn?.category, 'confirmed_stun');
  assert.equal(arbitraryUdp.stunTurn?.positivelyDecoded, false);
});

test('Protocol engine confirms STUN and TURN on dynamic high UDP ports when dissector decodes it', () => {
  const stunDynamicPort = analyzeProtocol({
    observedAt: '2026-11-14T12:00:01Z',
    srcIp: '10.0.0.12',
    dstIp: '74.125.250.129',
    srcPort: 59123,
    dstPort: 52410,
    transport: 'UDP',
    dissectorProtocol: 'STUN',
    packetLength: 96,
    stunType: '0x0001',
    stunAttributes: 'USERNAME, ICE-CONTROLLING, PRIORITY, MESSAGE-INTEGRITY, FINGERPRINT',
  });
  assert.equal(stunDynamicPort.protocol, 'STUN');
  assert.equal(stunDynamicPort.dissectorConfirmed, true);
  assert.equal(stunDynamicPort.stunTurn?.category, 'confirmed_stun');
  assert.equal(stunDynamicPort.stunTurn?.positivelyDecoded, true);

  const turnAlloc = analyzeProtocol({
    observedAt: '2026-11-14T12:00:02Z',
    srcIp: '10.0.0.12',
    dstIp: '52.114.77.22',
    srcPort: 59124,
    dstPort: 3478,
    transport: 'UDP',
    dissectorProtocol: 'STUN',
    packetLength: 128,
    stunType: '0x0003',
  });
  assert.equal(turnAlloc.protocol, 'TURN');
  assert.equal(turnAlloc.stunTurn?.category, 'confirmed_turn');

  const dtlsMedia = analyzeProtocol({
    observedAt: '2026-11-14T12:00:03Z',
    srcIp: '10.0.0.12',
    dstIp: '52.114.77.22',
    srcPort: 59125,
    dstPort: 50004,
    transport: 'UDP',
    dissectorProtocol: 'DTLSv1.2',
    packetLength: 210,
  });
  assert.equal(dtlsMedia.stunTurn?.category, 'suspected_webrtc');
  assert.equal(dtlsMedia.stunTurn?.positivelyDecoded, false);
});

test('Application engine enforces confidence levels and never infers Messenger from Facebook IP alone', () => {
  const pktTls = {
    observedAt: '2026-11-14T12:00:03Z',
    srcIp: '10.0.0.12',
    dstIp: '157.240.22.53',
    srcPort: 55100,
    dstPort: 443,
    transport: 'TCP',
    dissectorProtocol: 'TLSv1.3',
    packetLength: 517,
    tlsSni: 'web.whatsapp.com',
  };
  const protoTls = analyzeProtocol(pktTls);
  const appWa = classifyApplication(pktTls, protoTls);
  assert.equal(appWa.appName, 'WhatsApp');
  assert.equal(appWa.confidence, 'HIGH');

  // Facebook ASN/Org hint WITHOUT Messenger SNI/DNS must remain UNCLASSIFIED
  const pktFbIpOnly = {
    observedAt: '2026-11-14T12:00:04Z',
    srcIp: '10.0.0.12',
    dstIp: '157.240.22.35',
    srcPort: 55101,
    dstPort: 443,
    transport: 'TCP',
    dissectorProtocol: 'TLSv1.3',
    packetLength: 200,
  };
  const protoFb = analyzeProtocol(pktFbIpOnly);
  const appFb = classifyApplication(pktFbIpOnly, protoFb, 'Meta Platforms, Inc.');
  assert.equal(appFb.appName, 'Unclassified');
  assert.equal(appFb.confidence, 'UNCLASSIFIED');

  const pktSnap = {
    observedAt: '2026-11-14T12:00:05Z',
    srcIp: '10.0.0.12',
    dstIp: '34.120.0.1',
    srcPort: 55102,
    dstPort: 443,
    transport: 'TCP',
    dissectorProtocol: 'TLSv1.3',
    packetLength: 412,
    tlsSni: 'app.snapchat.com',
  };
  assert.equal(classifyApplication(pktSnap, analyzeProtocol(pktSnap)).appName, 'Snapchat');

  const pktSignal = {
    observedAt: '2026-11-14T12:00:06Z',
    srcIp: '10.0.0.12',
    dstIp: '76.223.92.165',
    srcPort: 55103,
    dstPort: 443,
    transport: 'TCP',
    dissectorProtocol: 'TLSv1.3',
    packetLength: 390,
    tlsSni: 'chat.signal.org',
  };
  assert.equal(classifyApplication(pktSignal, analyzeProtocol(pktSignal)).appName, 'Signal');
});

test('SQLite initializer self-heals when orphaned WAL/SHM exists without main db file', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-sqlite-heal-'));
  const dbPath = path.join(tmpDir, 'packetscope.db');
  fs.writeFileSync(`${dbPath}-wal`, Buffer.from('corrupt-orphaned-wal-data'));
  fs.writeFileSync(`${dbPath}-shm`, Buffer.from('corrupt-orphaned-shm-data'));

  try {
    const db = resetDbForTests(dbPath);
    const check = db.prepare('PRAGMA quick_check').get() as { quick_check?: string };
    assert.equal(check?.quick_check, 'ok');
    assert.ok(fs.existsSync(path.join(tmpDir, 'recovery')));
    closeDbSafely();
  } finally {
    resetDbForTests(':memory:');
    closeDbSafely();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
