const crypto = require('crypto');
const os = require('os');
const { readJson, writeJson } = require('./localStateStore');
const { FILES } = require('../config/serviceConfig');
const { CHALLENGE_STATUS } = require('../../shared/types/serviceStatus');

/**
 * Owns the persisted ServiceLocalState (service-state.json). A single in-memory
 * copy is kept and flushed atomically on every mutation so the service can
 * recover its challenge context after a crash/restart.
 */

let state = null;

function deriveDeviceId() {
  // Stable per-machine id from hostname + first non-internal MAC. Not PII beyond
  // what accountability requires; lets the backend distinguish devices.
  const nets = os.networkInterfaces();
  let mac = '';
  for (const name of Object.keys(nets)) {
    for (const ni of nets[name] || []) {
      if (!ni.internal && ni.mac && ni.mac !== '00:00:00:00:00:00') {
        mac = ni.mac;
        break;
      }
    }
    if (mac) break;
  }
  const seed = `${os.hostname()}|${mac}`;
  return crypto.createHash('sha256').update(seed).digest('hex').slice(0, 32);
}

function defaults() {
  return {
    activeChallengeId: null,
    userId: null,
    challengeStatus: CHALLENGE_STATUS.NONE,
    lastHeartbeatAt: null,
    serviceStartedAt: new Date().toISOString(),
    deviceId: deriveDeviceId(),
    authToken: null,
  };
}

function load() {
  const persisted = readJson(FILES.serviceState, null);
  state = { ...defaults(), ...(persisted || {}) };
  // serviceStartedAt always reflects THIS process start; deviceId is sticky.
  state.serviceStartedAt = new Date().toISOString();
  if (!state.deviceId) state.deviceId = deriveDeviceId();
  flush();
  return state;
}

function get() {
  if (!state) load();
  return state;
}

function flush() {
  try {
    writeJson(FILES.serviceState, state);
  } catch {
    /* best-effort; in-memory state is still authoritative */
  }
}

function update(patch) {
  if (!state) load();
  state = { ...state, ...patch };
  flush();
  return state;
}

module.exports = { load, get, update, flush, deriveDeviceId };
