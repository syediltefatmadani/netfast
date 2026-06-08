const { getPolicyMode, getModeLabel } = require('./policyMode');
const { getChromiumDoHPolicyStatus } = require('./browserPolicy');

function getMockVerifyDnsResult() {
  return {
    dnsApplied: true,
    ipv4Locked: true,
    ipv6Locked: true,
    strictMode: false,
    firewallLocked: true,
    firewallCoreLocked: true,
    bypassResolversBlocked: true,
    rogueServers: [],
    dnsIntegrity: true,
    dohConfigured: true,
    firewallIntact: true,
    rogueDns: [],
    filteringActive: true,
    blockedDomains: [],
    unblockedDomains: [],
    ipv4: { intact: true, servers: [], rogue: [] },
    ipv6: { intact: true, servers: [], rogue: [] },
    mock: true,
    audit: {
      intact: true,
      ipv4Locked: true,
      ipv6Locked: true,
      rogueServers: [],
      interfaces: [],
      connected: [],
    },
    dnsHealth: {
      status: 'HEALTHY',
      finalStatus: 'healthy',
      providerMisses: [],
      protectionLabel: 'Protected (dev mock)',
    },
  };
}

function getMockDnsApplyResult() {
  return {
    dnsApplied: true,
    ipv4Locked: true,
    ipv6Locked: true,
    strictMode: false,
    dnsIntegrity: true,
    dohConfigured: true,
    nrptApplied: false,
    nrptError: null,
    rogueServers: [],
    applied: [],
    failed: [],
    adapters: [],
    doh: { ok: true, mock: true },
    mock: true,
  };
}

function getMockFirewallResult() {
  return {
    ok: true,
    firewallLocked: true,
    firewallCoreLocked: true,
    bypassResolversBlocked: true,
    rawDnsBypassBlocked: true,
    firewallExemptionsApplied: true,
    developerExceptionsApplied: false,
    adminRequired: false,
    error: null,
    status: 'Protected',
    succeeded: [],
    failed: [],
    failedCoreRules: [],
    failedBypassRules: [],
    failedOptionalRules: [],
    missingCore: [],
    missingBypass: [],
    hasGlobalBlock: false,
    mock: true,
  };
}

function buildMockLockdownResult(reason = 'dev-mock') {
  const mode = getPolicyMode();
  const browserDoh = getChromiumDoHPolicyStatus();
  return {
    mode,
    modeLabel: getModeLabel(mode),
    dnsApplied: true,
    ipv4Locked: true,
    ipv6Locked: true,
    strictMode: false,
    dnsIntegrity: true,
    dohConfigured: true,
    browserDohLocked: browserDoh?.locked !== false,
    firewallCoreLocked: true,
    bypassResolversBlocked: true,
    rawDnsBypassBlocked: true,
    firewallLocked: true,
    developerExceptionsApplied: false,
    nrptApplied: false,
    nrptError: null,
    failedCoreRules: [],
    failedBypassRules: [],
    failedOptionalRules: [],
    rogueServers: [],
    optionalWarnings: [],
    warnings: ['Development safe mode — enforcement is simulated.'],
    errors: [],
    error: null,
    mongoDiagnostic: null,
    hostsFallbackEnabled: false,
    dockerProtected: 'unknown',
    wslProtected: 'unknown',
    status: 'Protected',
    protectionLabel: 'Protected (dev mock)',
    mock: true,
    reason,
    dns: getMockDnsApplyResult(),
    firewall: getMockFirewallResult(),
    hosts: { ok: true, skipped: true, mock: true },
    audit: getMockVerifyDnsResult().audit,
    fastPath: false,
  };
}

module.exports = {
  getMockVerifyDnsResult,
  getMockDnsApplyResult,
  getMockFirewallResult,
  buildMockLockdownResult,
};
