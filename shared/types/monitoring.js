/**
 * Shared monitoring contracts used by both NetFastService (producer) and the
 * Electron control panel (consumer). These are plain CommonJS modules with JSDoc
 * typedefs because the desktop/service side of this repo is plain JavaScript
 * (only the React renderer is bundled). Keeping the contracts here guarantees
 * the service and Electron agree on the same shape without duplicating it.
 *
 * @typedef {"low"|"medium"|"high"} Confidence
 */

/**
 * @typedef {Object} DnsStatusResult
 * @property {boolean} dnsProtected
 * @property {string[]} activeResolvers
 * @property {string[]} expectedResolvers
 * @property {string} lastCheckedAt
 * @property {string} [issue]
 */

/**
 * @typedef {Object} VpnStatusResult
 * @property {boolean} vpnDetected
 * @property {string[]} detectedVpnNames
 * @property {string[]} networkInterfaces
 * @property {string} lastCheckedAt
 */

/**
 * @typedef {Object} DohStatusResult
 * @property {boolean} dohRiskDetected
 * @property {Confidence} confidence
 * @property {string[]} evidence
 * @property {string} lastCheckedAt
 */

/**
 * @typedef {Object} HostsStatusResult
 * @property {boolean} hostsFileHealthy
 * @property {string} hash
 * @property {string|null} lastModifiedAt
 * @property {string[]} suspiciousEntries
 * @property {string} lastCheckedAt
 */

/**
 * @typedef {Object} VirtualizationStatusResult
 * @property {boolean} virtualizationRiskDetected
 * @property {string[]} detectedSystems
 * @property {Confidence} confidence
 * @property {string} lastCheckedAt
 */

/**
 * Aggregated protection snapshot exposed via GET /protection-status.
 * @typedef {Object} ProtectionStatus
 * @property {boolean} dnsProtected
 * @property {boolean} vpnDetected
 * @property {boolean} dohRiskDetected
 * @property {boolean} hostsFileHealthy
 * @property {boolean} virtualizationRiskDetected
 * @property {"healthy"|"warnings"|"unhealthy"|"unknown"} overallStatus
 * @property {string} lastCheckedAt
 * @property {DnsStatusResult} [dns]
 * @property {VpnStatusResult} [vpn]
 * @property {DohStatusResult} [doh]
 * @property {HostsStatusResult} [hosts]
 * @property {VirtualizationStatusResult} [virtualization]
 */

const OVERALL_STATUS = Object.freeze({
  HEALTHY: 'healthy',
  WARNINGS: 'warnings',
  UNHEALTHY: 'unhealthy',
  UNKNOWN: 'unknown',
});

module.exports = { OVERALL_STATUS };
