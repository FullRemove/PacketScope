import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import firebaseConfig from '../../firebase-applet-config.json' with { type: 'json' };
import { getDb, newId } from './db/sqlite.ts';

if (!getApps().length) {
  initializeApp({
    projectId: firebaseConfig.projectId,
  });
}

export const adminAuth = getAuth();

// Ephemeral fallback secret for dev/tests; in production set PACKETSCOPE_SESSION_SECRET
const SESSION_SECRET =
  process.env.PACKETSCOPE_SESSION_SECRET ||
  crypto.createHash('sha256').update(`${firebaseConfig.projectId}:packetscope-session-key`).digest('hex');

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, expectedHex] = storedHash.split(':');
  if (!salt || !expectedHex) return false;
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function hashSensorToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

export function generateSensorToken(): { rawToken: string; tokenHash: string; tokenPrefix: string } {
  const randomPart = crypto.randomBytes(24).toString('base64url');
  const rawToken = `ps_live_${randomPart}`;
  return {
    rawToken,
    tokenHash: hashSensorToken(rawToken),
    tokenPrefix: rawToken.slice(0, 14),
  };
}

export interface SessionPayload {
  userId: string;
  email: string;
  displayName: string;
  exp: number;
}

export function signSessionToken(payload: Omit<SessionPayload, 'exp'>): string {
  const full: SessionPayload = {
    ...payload,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(full)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

export function verifySessionToken(token: string): SessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as SessionPayload;
    if (!parsed.userId || !parsed.email || typeof parsed.exp !== 'number') return null;
    if (Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

export interface AuthenticatedUser {
  id: string;
  uid: string | null;
  email: string;
  displayName: string;
}

export interface TenantContext {
  organizationId: string;
  role: 'owner' | 'admin' | 'analyst' | 'viewer';
}

export interface AuthRequest extends Request {
  authUser?: AuthenticatedUser;
  tenant?: TenantContext;
  sensor?: {
    id: string;
    organizationId: string;
    networkId: string | null;
    name: string;
    status: string;
  };
}

export function upsertUserFromFirebase(uid: string, email: string, displayName: string, emailVerified: boolean): AuthenticatedUser {
  const db = getDb();
  const now = new Date().toISOString();

  const existingByUid = db.prepare(`SELECT id, uid, email, display_name FROM users WHERE uid = ?`).get(uid) as any;
  if (existingByUid) {
    db.prepare(`UPDATE users SET email = ?, display_name = ?, email_verified = ?, updated_at = ? WHERE id = ?`).run(
      email,
      displayName,
      emailVerified ? 1 : 0,
      now,
      existingByUid.id
    );
    return { id: existingByUid.id, uid, email, displayName };
  }

  const existingByEmail = db.prepare(`SELECT id, uid, email, display_name FROM users WHERE email = ?`).get(email) as any;
  if (existingByEmail) {
    db.prepare(`UPDATE users SET uid = ?, display_name = ?, email_verified = ?, updated_at = ? WHERE id = ?`).run(
      uid,
      displayName,
      emailVerified ? 1 : 0,
      now,
      existingByEmail.id
    );
    return { id: existingByEmail.id, uid, email, displayName };
  }

  const id = newId('usr');
  db.prepare(
    `INSERT INTO users (id, uid, email, display_name, password_hash, email_verified, created_at, updated_at)
     VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`
  ).run(id, uid, email, displayName, emailVerified ? 1 : 0, now, now);

  return { id, uid, email, displayName };
}

export async function resolveUserFromToken(token: string): Promise<AuthenticatedUser | null> {
  // 1. Check local HMAC Operator Session JWT first (fast, deterministic)
  const local = verifySessionToken(token);
  if (local) {
    const db = getDb();
    const row = db.prepare(`SELECT id, uid, email, display_name FROM users WHERE id = ?`).get(local.userId) as any;
    if (!row) return null;
    return { id: row.id, uid: row.uid, email: row.email, displayName: row.display_name };
  }

  // 2. Verify Firebase ID Token (Google SSO)
  try {
    const decoded = await adminAuth.verifyIdToken(token);
    const email = decoded.email || `${decoded.uid}@firebase.local`;
    const displayName = decoded.name || email.split('@')[0];
    return upsertUserFromFirebase(decoded.uid, email, displayName, Boolean(decoded.email_verified));
  } catch {
    return null;
  }
}

export const requireUserAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const queryToken = typeof req.query.token === 'string' ? req.query.token : null;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : queryToken;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const user = await resolveUserFromToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid or expired authentication token' });
  }

  req.authUser = user;
  next();
};

export const requireTenantAccess = (minRole: 'viewer' | 'analyst' | 'admin' | 'owner' = 'viewer') => {
  const roleRank = { viewer: 1, analyst: 2, admin: 3, owner: 4 };

  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.authUser) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const headerOrgId = req.headers['x-organization-id'];
    const queryOrgId = req.query.organizationId;
    const orgId = (typeof headerOrgId === 'string' ? headerOrgId : typeof queryOrgId === 'string' ? queryOrgId : '').trim();

    if (!orgId) {
      return res.status(400).json({ error: 'Missing X-Organization-Id header or organizationId parameter' });
    }

    const db = getDb();
    const membership = db
      .prepare(
        `SELECT m.organization_id, r.name as role_name
         FROM memberships m
         JOIN roles r ON m.role_id = r.id
         WHERE m.organization_id = ? AND m.user_id = ?`
      )
      .get(orgId, req.authUser.id) as { organization_id: string; role_name: 'owner' | 'admin' | 'analyst' | 'viewer' } | undefined;

    if (!membership) {
      return res.status(403).json({ error: 'Forbidden: You do not have access to this organization' });
    }

    if (roleRank[membership.role_name] < roleRank[minRole]) {
      return res.status(403).json({ error: `Forbidden: Requires ${minRole} role or higher` });
    }

    req.tenant = {
      organizationId: membership.organization_id,
      role: membership.role_name,
    };
    next();
  };
};

export const requireSensorAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing sensor Bearer credential' });
  }

  const rawToken = authHeader.slice(7).trim();
  if (!rawToken.startsWith('ps_live_') || rawToken.length < 20) {
    return res.status(401).json({ error: 'Malformed sensor credential' });
  }

  const tokenHash = hashSensorToken(rawToken);
  const db = getDb();
  const sensor = db
    .prepare(
      `SELECT id, organization_id, network_id, name, status, revoked_at
       FROM sensors
       WHERE token_hash = ?`
    )
    .get(tokenHash) as any;

  if (!sensor) {
    return res.status(401).json({ error: 'Invalid sensor credential' });
  }

  if (sensor.revoked_at) {
    return res.status(403).json({ error: 'Sensor credential has been revoked' });
  }

  req.sensor = {
    id: sensor.id,
    organizationId: sensor.organization_id,
    networkId: sensor.network_id,
    name: sensor.name,
    status: sensor.status,
  };
  next();
};
