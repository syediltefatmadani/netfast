/**
 * Heartbeat contract sent to the backend every 5 minutes while a challenge is
 * active. Only accountability-integrity signals are included — never browsing
 * history, traffic contents, or personal data.
 *
 * @typedef {Object} HeartbeatPayload
 * @property {string|null} userId
 * @property {string|null} challengeId
 * @property {string} deviceId
 * @property {string} serviceVersion
 * @property {"active"|"paused"|"idle"} status
 * @property {boolean} dnsProtected
 * @property {boolean} vpnDetected
 * @property {boolean} dohRiskDetected
 * @property {boolean} hostsFileHealthy
 * @property {boolean} virtualizationRiskDetected
 * @property {boolean} tamperingDetected
 * @property {string|null} lastViolationAt
 * @property {string} timestamp
 */

function emptyHeartbeat() {
  return {
    userId: null,
    challengeId: null,
    deviceId: '',
    serviceVersion: '',
    status: 'idle',
    dnsProtected: true,
    vpnDetected: false,
    dohRiskDetected: false,
    hostsFileHealthy: true,
    virtualizationRiskDetected: false,
    tamperingDetected: false,
    lastViolationAt: null,
    timestamp: new Date().toISOString(),
  };
}

module.exports = { emptyHeartbeat };
