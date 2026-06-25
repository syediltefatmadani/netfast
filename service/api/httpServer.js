const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { API, FILES, SERVICE_VERSION } = require('../config/serviceConfig');
const { writeJson } = require('../storage/localStateStore');
const logger = require('../logging/serviceLogger');

/**
 * Local control API for Electron <-> NetFastService.
 *
 * Transport choice (documented per the brief): a plain Node HTTP server bound to
 * 127.0.0.1 only. This was chosen over a named pipe because it is the simplest
 * cross-process mechanism that works identically whether the service runs as
 * LocalSystem or the script runs in dev, needs no native modules, and is trivial
 * for the Electron main process to call. It is NEVER exposed off the loopback
 * interface.
 *
 * Security model:
 *   - GET endpoints (read-only status) are open on loopback.
 *   - POST endpoints (mutating: challenge start/stop, manual check, heartbeat)
 *     require a bearer token. The token is generated on boot and written to
 *     service-endpoint.json in ProgramData, which only local processes able to
 *     read ProgramData (the NetFast app) can obtain.
 */

let server = null;
let token = null;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) req.destroy(); // guard against abuse
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

function isAuthorized(req) {
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!provided || !token) return false;
  // Constant-time compare to avoid leaking the token via timing.
  const a = Buffer.from(provided);
  const b = Buffer.from(token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function writeEndpointFile(port) {
  const dir = path.dirname(FILES.endpoint);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  writeJson(FILES.endpoint, {
    host: API.host,
    port,
    token,
    pid: process.pid,
    version: SERVICE_VERSION,
    startedAt: new Date().toISOString(),
  });
}

/**
 * @param {object} manager  serviceManager instance (status + controls)
 */
function startApi(manager) {
  token = crypto.randomBytes(24).toString('hex');

  server = http.createServer(async (req, res) => {
    const { method } = req;
    const url = (req.url || '').split('?')[0];

    try {
      // ---- Read-only (no token) ----
      if (method === 'GET' && url === '/health') {
        return json(res, 200, { ok: true, version: SERVICE_VERSION, uptime: process.uptime() });
      }
      if (method === 'GET' && url === '/status') {
        return json(res, 200, manager.getStatus());
      }
      if (method === 'GET' && url === '/protection-status') {
        return json(res, 200, manager.getProtectionStatus());
      }
      if (method === 'GET' && url === '/violations/recent') {
        return json(res, 200, { violations: manager.getRecentViolations(50) });
      }

      // ---- Mutating (token required) ----
      if (method === 'POST') {
        if (!isAuthorized(req)) {
          logger.warn('API', 'Rejected unauthorized POST', { url });
          return json(res, 401, { error: 'unauthorized' });
        }
        const body = await readBody(req);

        if (url === '/challenge/start') {
          const snap = manager.startChallenge({
            challengeId: body.challengeId,
            userId: body.userId,
            authToken: body.authToken,
          });
          return json(res, 200, snap);
        }
        if (url === '/challenge/stop') {
          return json(res, 200, manager.stopChallenge());
        }
        if (url === '/monitoring/check-now') {
          const result = await manager.manualCheck();
          return json(res, 200, result);
        }
        if (url === '/sync/heartbeat') {
          await manager.sendHeartbeatNow?.();
          return json(res, 200, { ok: true });
        }
      }

      return json(res, 404, { error: 'not found' });
    } catch (e) {
      logger.error('API', 'Request handler error', e.message);
      return json(res, 500, { error: 'internal error' });
    }
  });

  return new Promise((resolve, reject) => {
    server.on('error', (e) => {
      logger.error('API', 'HTTP server error', e.message);
      reject(e);
    });
    server.listen(API.port, API.host, () => {
      writeEndpointFile(API.port);
      logger.info('API', `Control API listening on http://${API.host}:${API.port}`);
      resolve({ port: API.port, token });
    });
  });
}

function stopApi() {
  if (server) {
    try {
      server.close();
    } catch {
      /* ignore */
    }
    server = null;
  }
  try {
    if (fs.existsSync(FILES.endpoint)) fs.unlinkSync(FILES.endpoint);
  } catch {
    /* ignore */
  }
}

module.exports = { startApi, stopApi };
