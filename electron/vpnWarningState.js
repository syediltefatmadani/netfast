const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const { resolveStatePath } = require('./dataPaths');

const STATE_PATH = resolveStatePath('vpn-warning-state.json');
const REAPPLY_MS = 24 * 60 * 60 * 1000;

function ensureDataDir() {
  const dir = path.dirname(STATE_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function emptyState() {
  return {
    userId: null,
    deviceId: null,
    challengeId: null,
    firstVpnDetectedAt: null,
    reapplyDeadlineAt: null,
    warningAcknowledged: false,
    reapplyClickedAt: null,
    challengePaused: false,
    expired: false,
    resolved: false,
    attemptCount: 0,
    hadVpnClearedOnce: false,
    pendingBackendReport: null,
  };
}

function readState() {
  ensureDataDir();
  if (!fs.existsSync(STATE_PATH)) return emptyState();
  try {
    const raw = fs.readFileSync(STATE_PATH, 'utf8');
    return { ...emptyState(), ...JSON.parse(raw) };
  } catch (e) {
    logger.warn('VPN_STATE', 'Could not read vpn-warning-state.json', e.message);
    return emptyState();
  }
}

function writeState(state) {
  ensureDataDir();
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2), 'utf8');
}

function clearState() {
  if (fs.existsSync(STATE_PATH)) fs.unlinkSync(STATE_PATH);
}

function isActiveWarning(state) {
  return Boolean(
    state.challengePaused &&
      state.firstVpnDetectedAt &&
      !state.expired &&
      !state.resolved,
  );
}

function deadlineExpired(state) {
  if (!state.reapplyDeadlineAt) return false;
  return Date.now() >= new Date(state.reapplyDeadlineAt).getTime();
}

function msUntilDeadline(state) {
  if (!state.reapplyDeadlineAt) return 0;
  return Math.max(0, new Date(state.reapplyDeadlineAt).getTime() - Date.now());
}

function initFirstWarning({ userId, deviceId, challengeId }) {
  const now = new Date();
  const deadline = new Date(now.getTime() + REAPPLY_MS);
  const state = {
    userId: userId || null,
    deviceId: deviceId || null,
    challengeId: challengeId || null,
    firstVpnDetectedAt: now.toISOString(),
    reapplyDeadlineAt: deadline.toISOString(),
    warningAcknowledged: false,
    reapplyClickedAt: null,
    challengePaused: true,
    expired: false,
    resolved: false,
    attemptCount: 1,
    pendingBackendReport: {
      vector: 'unknown_vpn',
      severity: 'critical',
      attemptCount: 1,
      actionTaken: 'warning_issued_waiting_for_reapply',
      challengePaused: true,
      reapplyDeadlineAt: deadline.toISOString(),
      refundEligible: false,
      challengeFailed: false,
    },
  };
  writeState(state);
  logger.warn('VPN_STATE', 'First VPN warning — 24h re-apply deadline started', {
    challengeId,
    reapplyDeadlineAt: state.reapplyDeadlineAt,
  });
  return state;
}

function markWarningAcknowledged() {
  const state = readState();
  if (!isActiveWarning(state)) return state;
  state.warningAcknowledged = true;
  writeState(state);
  return state;
}

function markReapplyClicked() {
  const state = readState();
  state.reapplyClickedAt = new Date().toISOString();
  writeState(state);
  return state;
}

function markResolved() {
  const state = readState();
  state.resolved = true;
  state.challengePaused = false;
  state.pendingBackendReport = null;
  writeState(state);
  return state;
}

function markExpired() {
  const state = readState();
  state.expired = true;
  state.challengePaused = false;
  state.pendingBackendReport = {
    vector: 'unknown_vpn',
    severity: 'critical',
    attemptCount: state.attemptCount || 1,
    actionTaken: 'challenge_failed_reapply_deadline_expired',
    challengeFailed: true,
    refundEligible: false,
    enforcementRemoved: true,
    systemRestored: true,
    reason: 'VPN detected and user did not re-apply protection within 24 hours.',
  };
  writeState(state);
  return state;
}

function markSecondAttemptFail() {
  const state = readState();
  state.expired = true;
  state.challengePaused = false;
  state.pendingBackendReport = {
    vector: 'unknown_vpn',
    severity: 'critical',
    attemptCount: 2,
    actionTaken: 'challenge_failed_second_vpn_attempt',
    challengeFailed: true,
    refundEligible: false,
    enforcementRemoved: true,
    systemRestored: true,
    reason: 'Second VPN/proxy attempt detected.',
  };
  writeState(state);
  return state;
}

function consumePendingBackendReport() {
  const state = readState();
  const report = state.pendingBackendReport;
  if (!report) return null;
  state.pendingBackendReport = null;
  writeState(state);
  return report;
}

function syncContext({ userId, deviceId, challengeId }) {
  const state = readState();
  if (!state.firstVpnDetectedAt && !state.challengePaused) return state;
  let changed = false;
  if (userId && state.userId !== userId) {
    state.userId = userId;
    changed = true;
  }
  if (deviceId && state.deviceId !== deviceId) {
    state.deviceId = deviceId;
    changed = true;
  }
  if (challengeId && state.challengeId !== challengeId) {
    state.challengeId = challengeId;
    changed = true;
  }
  if (changed) writeState(state);
  return state;
}

module.exports = {
  STATE_PATH,
  REAPPLY_MS,
  readState,
  writeState,
  clearState,
  isActiveWarning,
  deadlineExpired,
  msUntilDeadline,
  initFirstWarning,
  markWarningAcknowledged,
  markReapplyClicked,
  markResolved,
  markExpired,
  markSecondAttemptFail,
  consumePendingBackendReport,
  syncContext,
};
