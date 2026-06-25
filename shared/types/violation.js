/**
 * Violation contract. The service records and syncs violations; the backend is
 * the final authority on enforcement (terminate/warn). The service must not end
 * a challenge based on a single raw signal unless existing business rules already
 * require it.
 *
 * @typedef {"low"|"medium"|"high"|"critical"} ViolationSeverity
 *
 * @typedef {(
 *   "dns_changed" |
 *   "cleanbrowsing_removed" |
 *   "vpn_detected" |
 *   "doh_risk_detected" |
 *   "hosts_modified" |
 *   "virtualization_detected" |
 *   "service_interrupted" |
 *   "monitoring_offline" |
 *   "permission_or_config_changed"
 * )} ViolationType
 *
 * @typedef {Object} Violation
 * @property {string} id
 * @property {string|null} userId
 * @property {string|null} challengeId
 * @property {string} deviceId
 * @property {ViolationType} type
 * @property {ViolationSeverity} severity
 * @property {string[]} evidence
 * @property {string} detectedAt
 * @property {string|null} syncedAt
 */

const VIOLATION_TYPE = Object.freeze({
  DNS_CHANGED: 'dns_changed',
  CLEANBROWSING_REMOVED: 'cleanbrowsing_removed',
  VPN_DETECTED: 'vpn_detected',
  DOH_RISK_DETECTED: 'doh_risk_detected',
  HOSTS_MODIFIED: 'hosts_modified',
  VIRTUALIZATION_DETECTED: 'virtualization_detected',
  SERVICE_INTERRUPTED: 'service_interrupted',
  MONITORING_OFFLINE: 'monitoring_offline',
  PERMISSION_OR_CONFIG_CHANGED: 'permission_or_config_changed',
});

const SEVERITY = Object.freeze({
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

/** Map each violation type to the maps the backend's violationEngine expects. */
const VIOLATION_TO_BACKEND_VECTOR = Object.freeze({
  dns_changed: 'dns_filtering',
  cleanbrowsing_removed: 'dns_filtering',
  vpn_detected: 'unknown_vpn',
  doh_risk_detected: 'windows_doh',
  hosts_modified: 'hosts_modified',
  virtualization_detected: 'unknown_vpn',
  service_interrupted: 'app_tampered',
  monitoring_offline: 'app_tampered',
  permission_or_config_changed: 'app_tampered',
});

module.exports = { VIOLATION_TYPE, SEVERITY, VIOLATION_TO_BACKEND_VECTOR };
