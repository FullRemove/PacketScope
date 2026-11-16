# PacketScope Security, Privacy & Monitoring Governance

## Non-Negotiable Privacy Guarantees
1. **Zero Packet Payload Collection**: Neither the Windows capture agent nor the PacketScope backend collects, transmits, or stores raw packet payloads, private message bodies, call audio/video streams, passwords, session cookies, or files.
2. **Metadata-Only Extraction**: Only transport/network headers and dissector metadata (IP, port, transport, protocol name, packet byte length, DNS query name, TLS ClientHello SNI, HTTP Host header, and STUN/TURN RFC 5389/5766 message type codes & attribute names) are processed.
3. **No Personal Attribution**: Public IP geolocation and STUN/TURN observations identify network infrastructure endpoints (ISPs, CDNs, NAT relays, TURN servers, VPNs). PacketScope **never** claims that an IP address or STUN packet identifies a specific individual, call content, or physical street location.
4. **No Forced Application Claims**: Encrypted traffic lacking reliable DNS/TLS SNI indicators remains `UNCLASSIFIED`. Endpoint ASN/IP ranges (such as Meta/Facebook IP prefixes) are never treated as standalone proof of Messenger or call usage.

## Security Architecture
- **Sensor Credential Hashing**: Sensor Bearer tokens (`ps_live_...`) are displayed once upon creation/rotation and stored solely as SHA-256 hashes (`token_hash`). Tokens are redacted in agent logs (`ps_live_[REDACTED]`).
- **Tenant Isolation**: Every query and WebSocket room enforces organization membership (`memberships`) and role-based access control (`owner`, `admin`, `analyst`, `viewer`). Cross-tenant sensor or traffic queries return `403 Forbidden`.
- **Rate Limiting & Backpressure**: Ingestion endpoints enforce per-minute rate limits (`429`), strict Zod schema validation, max batch size (`500`), and duplicate idempotency (`(sensor_id, event_uid)`).
- **Audit Logging**: Sensor registrations, rotations, revocations, deletions, settings changes, report generation, and RBAC role assignments are written to `audit_logs`.
