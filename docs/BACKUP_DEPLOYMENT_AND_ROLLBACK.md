# PacketScope Deployment, Backup, Recovery & Rollback Guide

## Production Build & Startup
- Install dependencies: `npm ci`
- Type-check & lint: `npm run lint`
- Run automated tests: `npm test`
- Build frontend bundle: `npm run build`
- Start production server (HTTP + WebSocket on port 3000): `npm start` (`NODE_ENV=production node server.ts`)
- Health check endpoint: `GET /api/health` (returns HTTP 200 `{ status: "healthy", database: "connected" }`)

## Database Architecture & Migrations
- Relational PostgreSQL migration for external PostgreSQL deployments: `db/migrations/0001_initial_postgresql.sql` (20 normalized tables with foreign keys and time-based indexes).
- Embedded runtime WAL database (`node:sqlite` at `PACKETSCOPE_DB_PATH` / `./data/packetscope.db`) for zero-external-dependency deployments.
- Firestore security rules (`firestore.rules`) validated with `@firebase/eslint-plugin-security-rules` and deployed via Firebase.

## Backup & Restoration
1. **Organization Configuration Backup**: Administrators (`owner` role) can export organization settings, retention policies, networks, sensor metadata (without credential hashes), alert rules, and reports via `GET /api/backup/export` or the **Administration** view.
2. **Database Snapshot Backup**:
   - SQLite WAL: Perform online hot backup with `sqlite3 data/packetscope.db ".backup data/packetscope-backup-$(date +%F).db"` and encrypt at rest (`gpg` / Cloud KMS).
   - PostgreSQL: `pg_dump --format=custom --file=packetscope-$(date +%F).dump "$DATABASE_URL"`.
3. **Restoration**: Stop the PacketScope service, restore the backup file into `data/packetscope.db` (or `pg_restore` for PostgreSQL), restart `node server.ts`, and verify `/api/health`.

## Rollback Procedure
1. Retain the previous container image / Git release tag (`git tag -l`).
2. Restore the database snapshot taken prior to deployment if schema changes occurred.
3. Redeploy the previous build artifact (`npm run build && npm start`) and confirm `/api/health` returns `200 OK` and sensor heartbeats resume automatically from their local `queue.jsonl` buffers.
