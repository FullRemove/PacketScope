import type { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { resolveUserFromToken } from './auth.ts';
import { getDb } from './db/sqlite.ts';

interface ClientMeta {
  ws: WebSocket;
  userId: string;
  organizationId: string;
}

const orgRooms = new Map<string, Set<ClientMeta>>();

export function attachWebSocketServer(httpServer: HttpServer) {
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', async (ws, req) => {
    try {
      const url = new URL(req.url || '/ws', 'http://localhost');
      const token = url.searchParams.get('token');
      const orgId = url.searchParams.get('organizationId');

      if (!token || !orgId) {
        ws.close(4001, 'Missing token or organizationId');
        return;
      }

      const user = await resolveUserFromToken(token);
      if (!user) {
        ws.close(4003, 'Unauthorized');
        return;
      }

      const db = getDb();
      const member = db
        .prepare(`SELECT 1 FROM memberships WHERE organization_id = ? AND user_id = ?`)
        .get(orgId, user.id);

      if (!member) {
        ws.close(4003, 'Forbidden for organization');
        return;
      }

      const client: ClientMeta = { ws, userId: user.id, organizationId: orgId };
      if (!orgRooms.has(orgId)) {
        orgRooms.set(orgId, new Set());
      }
      orgRooms.get(orgId)!.add(client);

      ws.send(
        JSON.stringify({
          type: 'connection:ready',
          organizationId: orgId,
          timestamp: new Date().toISOString(),
        })
      );

      ws.on('close', () => {
        const room = orgRooms.get(orgId);
        if (room) {
          room.delete(client);
          if (room.size === 0) orgRooms.delete(orgId);
        }
      });
    } catch {
      ws.close(1011, 'WebSocket initialization failed');
    }
  });

  return wss;
}

export function broadcastToOrganization(organizationId: string, eventType: string, payload: unknown) {
  const room = orgRooms.get(organizationId);
  if (!room || room.size === 0) return;

  const message = JSON.stringify({
    type: eventType,
    organizationId,
    timestamp: new Date().toISOString(),
    data: payload,
  });

  for (const client of room) {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  }
}
