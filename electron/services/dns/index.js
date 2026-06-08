const {

  DnsStatus,

  mapFinalStatusToDnsStatus,

  isProtectionActive,

  isProtectionWithWarnings,

  shouldAttemptRestore,

  protectionLabelFromStatus,

} = require('./DnsStatus');

const { DohClient, DOH_URL } = require('./DohClient');

const {

  DnsValidator,

  POLICY_TEST_DOMAINS,

  FILTER_TESTS,

  isBlockedResolution,

  queryCleanBrowsingDoH,

  evaluateDomainProtection,

  runDohHealthSummary,

} = require('./DnsValidator');

const { DnsAuditLogger } = require('./DnsAuditLogger');

const { DnsHealthMonitor, getDnsHealthMonitor, CHECK_INTERVAL_MS } = require('./DnsHealthMonitor');

const { pingCleanBrowsingDoH } = require('./dohHealth');

const { formatDomainStatusMessage } = require('./domainProtection');



module.exports = {

  DnsStatus,

  mapFinalStatusToDnsStatus,

  isProtectionActive,

  isProtectionWithWarnings,

  shouldAttemptRestore,

  protectionLabelFromStatus,

  DohClient,

  DOH_URL,

  DnsValidator,

  POLICY_TEST_DOMAINS,

  FILTER_TESTS,

  isBlockedResolution,

  queryCleanBrowsingDoH,

  evaluateDomainProtection,

  runDohHealthSummary,

  pingCleanBrowsingDoH,

  formatDomainStatusMessage,

  DnsAuditLogger,

  DnsHealthMonitor,

  getDnsHealthMonitor,

  CHECK_INTERVAL_MS,

};

