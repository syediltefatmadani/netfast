const os = require('os');
const path = require('path');

const SERVICE_NAME = 'NetFastService';
const SERVICE_VERSION = '0.2.0';

/**
 * Where the service keeps its local state, logs, and the endpoint/token file the
 * Electron app reads to discover the API. ProgramData is used (not per-user
 * AppData) because a Windows service runs under LocalSystem by default, while
 * the Electron app runs as the logged-in user — both need to reach the same
 * directory. ProgramData is world-readable, which is acceptable here: nothing
 * sensitive beyond a localhost-only API token lives there.
 */
function resolveDataDir() {
  if (process.env.NETFAST_SERVICE_DATA_DIR) return process.env.NETFAST_SERVICE_DATA_DIR;
  const base = process.env.ProgramData || process.env.ALLUSERSPROFILE || os.tmpdir();
  return path.join(base, 'NetFast');
}

const DATA_DIR = resolveDataDir();

const FILES = {
  serviceState: path.join(DATA_DIR, 'service-state.json'),
  protectionStatus: path.join(DATA_DIR, 'protection-status.json'),
  violationsQueue: path.join(DATA_DIR, 'violations-queue.json'),
  heartbeatQueue: path.join(DATA_DIR, 'heartbeat-queue.json'),
  endpoint: path.join(DATA_DIR, 'service-endpoint.json'),
  log: path.join(DATA_DIR, 'service.log'),
};

/**
 * Local control API. Bound to loopback only so it is never exposed off-box.
 * Read-only GETs are open on loopback; mutating POSTs require the bearer token
 * written to FILES.endpoint, which only local processes that can read
 * ProgramData (i.e. the NetFast Electron app) can obtain.
 */
const API = {
  host: '127.0.0.1',
  port: Number(process.env.NETFAST_SERVICE_PORT) || 7373,
};

/** Phase 2 schedule (ms). Heavy checks only run while a challenge is active. */
const INTERVALS = {
  serviceHealthMs: 60 * 1000,
  dnsVerificationMs: 60 * 1000,
  vpnDetectionMs: 60 * 1000,
  hostsFallbackMs: 5 * 60 * 1000,
  dohRiskMs: 5 * 60 * 1000,
  virtualizationMs: 10 * 60 * 1000,
  challengeSyncMs: 5 * 60 * 1000,
  heartbeatMs: 5 * 60 * 1000,
  offlineFlushMs: 2 * 60 * 1000,
};

/** CleanBrowsing Family Filter resolvers — mirrors electron/dnsConstants.js. */
const EXPECTED_DNS = {
  ipv4: ['185.228.168.168', '185.228.169.168'],
  ipv6: ['2a0d:2a00:1::', '2a0d:2a00:2::'],
  dohHost: 'doh.cleanbrowsing.org',
};

const BACKEND = {
  baseUrl: process.env.NETFAST_API_URL || process.env.VITE_API_URL || 'http://localhost:7000',
  requestTimeoutMs: 10 * 1000,
};

const LOG = {
  maxBytes: 5 * 1024 * 1024,
  maxFiles: 5,
};

const QUEUE = {
  maxHeartbeats: 500,
  maxViolations: 1000,
};

module.exports = {
  SERVICE_NAME,
  SERVICE_VERSION,
  DATA_DIR,
  FILES,
  API,
  INTERVALS,
  EXPECTED_DNS,
  BACKEND,
  LOG,
  QUEUE,
};
