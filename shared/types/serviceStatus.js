/**
 * Service status + persisted local state contracts.
 *
 * @typedef {("none"|"active"|"paused"|"completed"|"terminated")} ChallengeStatus
 *
 * Persisted in service-state.json.
 * @typedef {Object} ServiceLocalState
 * @property {string|null} activeChallengeId
 * @property {string|null} userId
 * @property {ChallengeStatus} challengeStatus
 * @property {string|null} lastHeartbeatAt
 * @property {string} serviceStartedAt
 * @property {string} deviceId
 * @property {string|null} authToken          backend JWT, supplied by Electron when a challenge starts
 *
 * Returned from GET /status.
 * @typedef {Object} ServiceStatus
 * @property {boolean} serviceRunning
 * @property {string} serviceVersion
 * @property {string|null} challengeId
 * @property {ChallengeStatus} challengeStatus
 * @property {boolean} monitoringActive
 * @property {string|null} lastHeartbeatAt
 * @property {string|null} lastCheckAt
 * @property {string} serviceStartedAt
 * @property {number} queuedHeartbeats
 * @property {number} queuedViolations
 */

const CHALLENGE_STATUS = Object.freeze({
  NONE: 'none',
  ACTIVE: 'active',
  PAUSED: 'paused',
  COMPLETED: 'completed',
  TERMINATED: 'terminated',
});

/** A challenge that demands the full monitoring schedule (vs. lightweight idle). */
function isMonitoringChallengeStatus(status) {
  return status === CHALLENGE_STATUS.ACTIVE;
}

module.exports = { CHALLENGE_STATUS, isMonitoringChallengeStatus };
