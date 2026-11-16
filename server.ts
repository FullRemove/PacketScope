import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { createApiRouter } from './src/server/routes.ts';
import { attachWebSocketServer } from './src/server/ws.ts';
import { getDb, closeDbSafely } from './src/server/db/sqlite.ts';

dotenv.config();

export function createPacketScopeApp() {
  // Initialize SQLite schema on app boot
  getDb();

  const app = express();
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
    })
  );

  app.use(express.json({ limit: '4mb' }));

  const apiRouter = createApiRouter();
  app.use('/api/v1', apiRouter);
  app.use('/api', apiRouter);

  return app;
}

async function startServer() {
  const app = createPacketScopeApp();
  const httpServer = http.createServer(app);
  attachWebSocketServer(httpServer);

  const distPath = path.resolve(process.cwd(), 'dist');
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(distPath);

  if (isProd) {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  const port = Number(process.env.PORT || 3000);
  httpServer.listen(port, '0.0.0.0', () => {
    console.log(`PacketScope server listening on http://0.0.0.0:${port}`);
  });

  const shutdown = () => {
    closeDbSafely();
    httpServer.close(() => process.exit(0));
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

// Only auto-start HTTP server when run directly (allows importing createPacketScopeApp in tests)
const isDirectRun =
  typeof process.argv[1] === 'string' &&
  (process.argv[1].endsWith('server.ts') || process.argv[1].endsWith('server.js'));

if (isDirectRun) {
  startServer().catch((err) => {
    console.error('Failed to start PacketScope server:', err);
    process.exit(1);
  });
}
