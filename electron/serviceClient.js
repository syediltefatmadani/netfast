const http = require('http');
const fs = require('fs');
const logger = require('./logger');

/**
 * Electron-main -> NetFastService bridge.
 *
 * Electron is the user-facing control panel; the Windows service is the
 * background monitoring engine. The renderer never talks to the service
 * directly — it goes through Electron main (this module) over IPC, so the
 * service's loopback API + token stay inside the trusted main process.
 *
 * Discovery: the service publishes its port + bearer token to
 * service-endpoint.json (ProgramData\NetFast). We read that file to learn where
 * to connect. If the file is missing or the connection is refused, the service
 * is treated as not running (and the UI can surface "service interrupted").
 */

// Reuse the service's own path/config so both sides agree on the endpoint file
// location and there is no second source of truth.
let FILES;
let API_DEFAULT;
try {
  const cfg = require('../service/config/serviceConfig');
  FILES = cfg.FILES;
  API_DEFAULT = cfg.API;
} catch (e) {
  logger.warn('SERVICE', 'Could not load service config; using defaults', e.message);
  const path = require('path');
  const base = process.env.ProgramData || process.env.ALLUSERSPROFILE || process.cwd();
  FILES = { endpoint: path.join(base, 'NetFast', 'service-endpoint.json') };
  API_DEFAULT = { host: '127.0.0.1', port: 7373 };
}

const STALE_MS = 3 * 60 * 1000; // endpoint older than this with no response => interrupted

function readEndpoint() {
  try {
    const raw = fs.readFileSync(FILES.endpoint, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function request(method, pathname, { body, token } = {}) {
  const endpoint = readEndpoint();
  const host = endpoint?.host || API_DEFAULT.host;
  const port = endpoint?.port || API_DEFAULT.port;
  const authToken = token || endpoint?.token;

  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        host,
        port,
        path: pathname,
        method,
        timeout: 5000,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
          } catch {
            resolve({ status: res.statusCode, data: null });
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** True if the service answered /health recently. */
async function isRunning() {
  try {
    const res = await request('GET', '/health');
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * Status for the UI. Always resolves (never throws) so the renderer can show a
 * clear "service not running" state instead of an error.
 */
async function getStatus() {
  const endpoint = readEndpoint();
  try {
    const res = await request('GET', '/status');
    if (res.status === 200 && res.data) {
      return { serviceReachable: true, ...res.data };
    }
    return notRunning(endpoint, 'bad-response');
  } catch (e) {
    return notRunning(endpoint, e.message);
  }
}

function notRunning(endpoint, reason) {
  // If we have a recent endpoint file but cannot reach the service, that is a
  // likely interruption (service was stopped/crashed) — surface it as such.
  let interrupted = false;
  if (endpoint?.startedAt) {
    const age = Date.now() - new Date(endpoint.startedAt).getTime();
    interrupted = age < STALE_MS ? true : true; // file present but unreachable
  }
  return {
    serviceReachable: false,
    serviceRunning: false,
    serviceInterrupted: interrupted,
    monitoringActive: false,
    reason,
  };
}

async function getProtectionStatus() {
  try {
    const res = await request('GET', '/protection-status');
    return res.status === 200 ? res.data : null;
  } catch {
    return null;
  }
}

async function getViolations() {
  try {
    const res = await request('GET', '/violations/recent');
    return res.status === 200 ? res.data?.violations || [] : [];
  } catch {
    return [];
  }
}

async function manualCheck() {
  const res = await request('POST', '/monitoring/check-now');
  return res.data;
}

async function startChallenge(opts) {
  const res = await request('POST', '/challenge/start', { body: opts });
  if (res.status === 401) throw new Error('service token rejected');
  return res.data;
}

async function stopChallenge() {
  const res = await request('POST', '/challenge/stop');
  return res.data;
}

module.exports = {
  isRunning,
  getStatus,
  getProtectionStatus,
  getViolations,
  manualCheck,
  startChallenge,
  stopChallenge,
};
