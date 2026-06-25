const backend = require('../sync/backendClient');
const serviceState = require('../storage/serviceState');
const { CHALLENGE_STATUS } = require('../../shared/types/serviceStatus');
const logger = require('../logging/serviceLogger');

/**
 * Challenge state monitor. The service must always know whether a challenge is
 * active so the manager can switch between lightweight idle mode and the full
 * monitoring schedule.
 *
 * Local state (service-state.json) is authoritative for "what Electron told us"
 * (start/stop). This monitor additionally re-syncs the canonical status from the
 * backend every few minutes so completion/termination/pause initiated elsewhere
 * is reflected even if Electron never reopens.
 */

/** Set by Electron via POST /challenge/start. */
function startChallenge({ challengeId, userId, authToken }) {
  const next = serviceState.update({
    activeChallengeId: challengeId || null,
    userId: userId || null,
    authToken: authToken || serviceState.get().authToken || null,
    challengeStatus: challengeId ? CHALLENGE_STATUS.ACTIVE : CHALLENGE_STATUS.NONE,
  });
  logger.info('CHALLENGE', 'Challenge monitoring started', {
    challengeId: next.activeChallengeId,
    status: next.challengeStatus,
  });
  return snapshot();
}

/** Set by Electron via POST /challenge/stop (allowed transitions only). */
function stopChallenge() {
  serviceState.update({
    challengeStatus: CHALLENGE_STATUS.NONE,
    activeChallengeId: null,
  });
  logger.info('CHALLENGE', 'Challenge monitoring stopped');
  return snapshot();
}

/** Periodic reconciliation with the backend. */
async function sync() {
  const state = serviceState.get();
  if (!state.activeChallengeId || !state.authToken) {
    return snapshot();
  }

  const res = await backend.fetchChallengeState(state.activeChallengeId, state.authToken);
  if (!res.ok) {
    if (res.offline) {
      logger.warn('CHALLENGE', 'Challenge sync skipped — backend offline');
    } else {
      logger.warn('CHALLENGE', 'Challenge sync failed', { status: res.status, error: res.error });
    }
    return snapshot();
  }

  const remoteStatus = mapRemoteStatus(res.data?.status);
  if (remoteStatus && remoteStatus !== state.challengeStatus) {
    serviceState.update({ challengeStatus: remoteStatus });
    logger.info('CHALLENGE', 'Challenge status changed', {
      from: state.challengeStatus,
      to: remoteStatus,
    });
  }
  return snapshot();
}

function mapRemoteStatus(status) {
  switch (status) {
    case 'active':
      return CHALLENGE_STATUS.ACTIVE;
    case 'paused':
      return CHALLENGE_STATUS.PAUSED;
    case 'completed':
      return CHALLENGE_STATUS.COMPLETED;
    case 'terminated':
    case 'failed':
      return CHALLENGE_STATUS.TERMINATED;
    default:
      return null;
  }
}

function snapshot() {
  const s = serviceState.get();
  return {
    activeChallengeId: s.activeChallengeId,
    userId: s.userId,
    challengeStatus: s.challengeStatus,
    lastHeartbeatAt: s.lastHeartbeatAt,
    serviceStartedAt: s.serviceStartedAt,
  };
}

function isActive() {
  return serviceState.get().challengeStatus === CHALLENGE_STATUS.ACTIVE;
}

module.exports = { startChallenge, stopChallenge, sync, snapshot, isActive, name: 'challenge' };
