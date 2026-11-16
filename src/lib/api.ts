import { useEffect, useRef, useState } from 'react';

export function stripCidr(ip: string | null | undefined): string {
  if (!ip) return '';
  const idx = ip.indexOf('/');
  return idx === -1 ? ip : ip.slice(0, idx);
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exp = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const val = bytes / 1024 ** exp;
  return `${val >= 100 || exp === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[exp]}`;
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const diffSec = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(diffSec)) return 'Unknown';
  if (diffSec < 5) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export class ApiClient {
  private token: string | null = null;
  private orgId: string | null = null;

  setCredentials(token: string | null, orgId: string | null) {
    this.token = token;
    this.orgId = orgId;
  }

  getToken() {
    return this.token;
  }

  getOrgId() {
    return this.orgId;
  }

  async request<T = any>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers as Record<string, string> | undefined),
    };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    if (this.orgId) headers['X-Organization-Id'] = this.orgId;

    const res = await fetch(path, { ...options, headers });
    const text = await res.text();
    let data: any = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    if (!res.ok) {
      throw new Error(data?.error || `Request failed (${res.status})`);
    }
    return data as T;
  }

  async downloadBlob(path: string, filename: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    if (this.orgId) headers['X-Organization-Id'] = this.orgId;
    const res = await fetch(path, { headers });
    if (!res.ok) throw new Error(`Download failed (${res.status})`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }
}

export const apiClient = new ApiClient();

export function usePacketScopeSocket(
  token: string | null,
  orgId: string | null,
  onEvent: (event: { type: string; data: any; timestamp: string }) => void
) {
  const [connected, setConnected] = useState(false);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    if (!token || !orgId) {
      setConnected(false);
      return;
    }

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;
    let backoffMs = 1000;

    const connect = () => {
      if (disposed) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${protocol}//${window.location.host}/ws?token=${encodeURIComponent(token)}&organizationId=${encodeURIComponent(orgId)}`;
      ws = new WebSocket(url);

      ws.onopen = () => {
        backoffMs = 1000;
        setConnected(true);
      };

      ws.onmessage = (evt) => {
        try {
          const parsed = JSON.parse(evt.data);
          onEventRef.current(parsed);
        } catch {
          // ignore malformed frames
        }
      };

      ws.onclose = () => {
        setConnected(false);
        if (!disposed) {
          reconnectTimer = setTimeout(connect, backoffMs);
          backoffMs = Math.min(15000, backoffMs * 2);
        }
      };

      ws.onerror = () => {
        ws?.close();
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
      setConnected(false);
    };
  }, [token, orgId]);

  return connected;
}
