const axios = require('axios');
const { BACKEND, SERVICE_VERSION } = require('../config/serviceConfig');
const { VIOLATION_TO_BACKEND_VECTOR } = require('../../shared/types/violation');
const logger = require('../logging/serviceLogger');

/**
 * Single backend communication layer. ALL network calls to the NetFast backend
 * go through here — monitors never call fetch/axios directly. Every method
 * returns a normalized result `{ ok, status, offline, data?, error? }` so the
 * caller (heartbeat client / offline queue) can decide whether to queue & retry.
 *
 * Backend mapping note: the existing backend ingests accountability signals via
 * POST /api/heartbeat (its violationEngine processes any `vectors[*].violated`).
 * There is no dedicated generic violation-ingest endpoint yet, so sendViolation
 * adapts a Violation into a single-vector heartbeat. TODO(phase3): add a
 * first-class POST /api/violations ingest route and switch to it here.
 */

const OFFLINE_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'ETIMEDOUT',
  'ECONNRESET',
  'EAI_AGAIN',
  'ECONNABORTED',
]);

function client(authToken) {
  return axios.create({
    baseURL: `${BACKEND.baseUrl.replace(/\/$/, '')}/api`,
    timeout: BACKEND.requestTimeoutMs,
    headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
  });
}

function normalizeError(err) {
  const offline = OFFLINE_CODES.has(err.code) || !err.response;
  return {
    ok: false,
    offline,
    status: err.response?.status ?? null,
    error: err.response?.data?.message || err.message,
  };
}

/** Translate a heartbeat payload's booleans into the backend's vectors shape. */
function vectorsFromHeartbeat(payload) {
  return {
    dns_filtering: { violated: payload.dnsProtected === false },
    unknown_vpn: { violated: payload.vpnDetected === true, vpnHandlerManaged: false },
    windows_doh: { violated: payload.dohRiskDetected === true },
    hosts_modified: { violated: payload.hostsFileHealthy === false },
    app_tampered: { violated: payload.tamperingDetected === true },
  };
}

async function sendHeartbeat(payload, authToken) {
  if (!authToken) {
    return { ok: false, offline: false, status: 401, error: 'no auth token' };
  }
  if (!payload.challengeId) {
    return { ok: false, offline: false, status: 400, error: 'no challengeId' };
  }
  try {
    const res = await client(authToken).post('/heartbeat', {
      challengeId: payload.challengeId,
      integrityOk: payload.dnsProtected && payload.hostsFileHealthy && !payload.tamperingDetected,
      vectors: vectorsFromHeartbeat(payload),
      serviceVersion: payload.serviceVersion || SERVICE_VERSION,
    });
    return { ok: true, offline: false, status: res.status, data: res.data };
  } catch (err) {
    return normalizeError(err);
  }
}

async function sendViolation(violation, authToken) {
  if (!authToken) {
    return { ok: false, offline: false, status: 401, error: 'no auth token' };
  }
  if (!violation.challengeId) {
    return { ok: false, offline: false, status: 400, error: 'no challengeId' };
  }
  const vector = VIOLATION_TO_BACKEND_VECTOR[violation.type] || 'app_tampered';
  try {
    const res = await client(authToken).post('/heartbeat', {
      challengeId: violation.challengeId,
      integrityOk: false,
      vectors: {
        [vector]: {
          violated: true,
          severity: violation.severity,
          evidence: violation.evidence,
          violationType: violation.type,
          detectedAt: violation.detectedAt,
        },
      },
      serviceVersion: SERVICE_VERSION,
    });
    return { ok: true, offline: false, status: res.status, data: res.data };
  } catch (err) {
    return normalizeError(err);
  }
}

async function fetchChallengeState(challengeId, authToken) {
  if (!challengeId || !authToken) {
    return { ok: false, offline: false, status: 400, error: 'missing challengeId/token' };
  }
  try {
    const res = await client(authToken).get(`/challenge/${challengeId}`);
    return { ok: true, offline: false, status: res.status, data: res.data };
  } catch (err) {
    return normalizeError(err);
  }
}

/** Cheap reachability probe (any HTTP response, even 404, means we're online). */
async function isReachable() {
  try {
    await axios.get(`${BACKEND.baseUrl.replace(/\/$/, '')}/api/health`, { timeout: 4000 });
    return true;
  } catch (err) {
    if (err.response) return true; // server answered (e.g. 404) -> online
    if (OFFLINE_CODES.has(err.code)) return false;
    return false;
  }
}

module.exports = { sendHeartbeat, sendViolation, fetchChallengeState, isReachable };
