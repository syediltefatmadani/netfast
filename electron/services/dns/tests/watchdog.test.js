/**
 * Watchdog integrity / filtering separation tests.
 *
 * Strategy:
 *   - For watchdog vector logic: directly exercise the pure vector-computation
 *     by stubbing module.exports on the required modules, since Node CJS caches
 *     the module object — reassigning a property on the cached exports object IS
 *     visible to callers that already hold a reference to the same exports object.
 *   - For networkWatch trigger logic: similarly stub verifyDNS on the dns module.
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');

// Mock dependencies BEFORE requiring the modules under test to prevent OS side-effects
const powershell = require('../../../powershell');
powershell.runEncoded = () => '{"gw":"192.168.1.1","ip":"192.168.1.10","dns":"1.1.1.1"}';

const browserPolicy = require('../../../browserPolicy');
browserPolicy.applyChromiumCleanBrowsingDoH = () => ({ ok: true });
browserPolicy.disableChromiumDoHPolicies = browserPolicy.applyChromiumCleanBrowsingDoH;

const firewall = require('../../../firewall');
firewall.applyDnsFirewall = () => ({ applied: [], failed: [] });
firewall.verifyFirewall = () => ({
  firewallLocked: true,
  firewallCoreLocked: true,
  bypassResolversBlocked: true,
  hasGlobalBlock: false,
  missingCore: [],
  missingBypass: [],
});

const hosts = require('../../../hosts');
hosts.flushDnsCache = () => {};
hosts.syncHostsBlocklist = () => ({ ok: true });
hosts.getHostsPath = () => 'dummy_hosts_path';

const dnsService = require('../../../services/dns');
const healthySummary = {
  knownAdultBlockedByDoh: true,
  criticalUnblockedRestrictedDomains: [],
  providerMisses: [],
  fallbackBlockedMisses: [],
};

function makeHealthReport(overrides = {}) {
  const summary = { ...healthySummary, ...overrides.summary };
  return {
    healthy: overrides.healthy ?? true,
    status: overrides.status ?? 'HEALTHY',
    finalStatus: overrides.finalStatus ?? 'healthy',
    details: overrides.details ?? 'ok',
    providerMisses: summary.providerMisses,
    fallbackBlockedMisses: summary.fallbackBlockedMisses,
    validation: { summary },
    ...overrides,
  };
}

const dummyHealthMonitor = {
  getLastReport: () => makeHealthReport(),
  runHealthCheck: async () => makeHealthReport(),
  runImmediateDnsHealthCheck: async () => makeHealthReport(),
};
dnsService.getDnsHealthMonitor = () => dummyHealthMonitor;

const mongoDns = require('../../../mongoDns');
mongoDns.runMongoDnsDiagnostic = async () => ({
  mongoSrvResolvable: true,
  mongoTxtResolvable: true,
  mongoLookupOk: true,
  error: null,
});
mongoDns.clearAtlasHostsBlock = async () => ({ ok: true, skipped: true });
mongoDns.syncAtlasHostsFromDoh = async () => ({ skipped: true, hostsFallbackEnabled: false });
mongoDns.discoverMongoHostsFromEnvFiles = () => [];
mongoDns.isHostsFallbackEnabled = () => false;

// --- Bring in the real modules (loaded once, cached) -------------------------
const dnsExports = require('../../../dns');
const watchdog   = require('../../../watchdog');
const netwatch   = require('../../../networkWatch');

// --------------------------------------------------------------------------
// Helper: build a minimal verifyDNS result
// --------------------------------------------------------------------------
function makeDnsResult({
  ipv4Locked = true,
  ipv6Locked = true,
  dohConfigured = true,
  firewallLocked = true,
  rogueServers = [],
  filteringActive = true,
} = {}) {
  const dnsApplied = ipv4Locked && ipv6Locked;
  const dnsIntegrity =
    dnsApplied && dohConfigured && firewallLocked && rogueServers.length === 0;
  return {
    dnsApplied,
    ipv4Locked,
    ipv6Locked,
    firewallLocked,
    dnsIntegrity,
    dohConfigured,
    firewallIntact: firewallLocked,
    rogueServers,
    rogueDns: rogueServers,
    filteringActive,
    blockedDomains: filteringActive ? ['pornhat.com'] : [],
    unblockedDomains: filteringActive ? [] : ['pornhat.com'],
    audit: { intact: dnsIntegrity, ipv4Locked, ipv6Locked, rogueServers, rogue: rogueServers },
    ipv4: { intact: ipv4Locked, rogue: rogueServers },
    ipv6: { intact: ipv6Locked, rogue: rogueServers },
    probes: [],
  };
}

// --------------------------------------------------------------------------
describe('Watchdog vector logic — integrity vs filtering', () => {
  let savedVerifyDNS;
  let savedVerifyTeredoDisabled;

  before(() => {
    // Save originals
    savedVerifyDNS          = dnsExports.verifyDNS;
    savedVerifyTeredoDisabled = dnsExports.verifyTeredoDisabled;
    // Stub Teredo so it never does a real netsh call
    dnsExports.verifyTeredoDisabled = () => true;
  });

  after(() => {
    dnsExports.verifyDNS          = savedVerifyDNS;
    dnsExports.verifyTeredoDisabled = savedVerifyTeredoDisabled;
  });

  it('Correct DNS + filtering failed (critical unblocked) => dns_filtering violated', () => {
    dnsExports.verifyDNS = () => makeDnsResult({ filteringActive: false });
    dummyHealthMonitor.getLastReport = () =>
      makeHealthReport({
        healthy: false,
        status: 'FAILED',
        finalStatus: 'failed',
        summary: {
          knownAdultBlockedByDoh: false,
          criticalUnblockedRestrictedDomains: ['pornhat.com'],
          providerMisses: ['pornhat.com'],
          fallbackBlockedMisses: [],
        },
      });

    const check = watchdog.runFullCheck();

    assert.strictEqual(check.vectors.dns_ipv4.violated, false);
    assert.strictEqual(check.vectors.dns_filtering.violated, true);
    dummyHealthMonitor.getLastReport = () => makeHealthReport();
  });

  it('Provider miss handled by fallback => dns_filtering OK, dns_provider_miss warning', () => {
    dnsExports.verifyDNS = () => makeDnsResult({ filteringActive: true });
    dummyHealthMonitor.getLastReport = () =>
      makeHealthReport({
        healthy: true,
        status: 'HEALTHY_WITH_PROVIDER_MISSES',
        finalStatus: 'healthy_with_provider_misses',
        summary: {
          knownAdultBlockedByDoh: true,
          criticalUnblockedRestrictedDomains: [],
          providerMisses: ['pornhat.com'],
          fallbackBlockedMisses: ['pornhat.com'],
        },
      });

    const check = watchdog.runFullCheck();

    assert.strictEqual(check.vectors.dns_filtering.violated, false);
    assert.strictEqual(check.vectors.dns_provider_miss.warning, true);
    assert.strictEqual(check.protectionWithWarningsOnly, true);
    dummyHealthMonitor.getLastReport = () => makeHealthReport();
  });

  it('Rogue DNS => Integrity Failed', () => {
    dnsExports.verifyDNS = () =>
      makeDnsResult({
        ipv4Locked: false,
        ipv6Locked: false,
        rogueServers: [{ adapter: 'Ethernet', server: '1.2.3.4', family: 'IPv4' }],
      });

    const check = watchdog.runFullCheck();

    assert.strictEqual(
      check.vectors.dns_ipv4.violated,
      true,
      'IPv4 Integrity should be violated due to Rogue DNS',
    );
    assert.strictEqual(
      check.vectors.dns_ipv6.violated,
      true,
      'IPv6 Integrity should be violated due to Rogue DNS',
    );
  });

  it('Missing DoH config => windows_doh violated, DNS lock vectors unchanged', () => {
    dnsExports.verifyDNS = () =>
      makeDnsResult({ dohConfigured: false, ipv4Locked: true, ipv6Locked: true });

    const check = watchdog.runFullCheck();

    assert.strictEqual(
      check.vectors.dns_ipv4.violated,
      false,
      'IPv4 lock should remain OK when only DoH config is missing',
    );
    assert.strictEqual(
      check.vectors.windows_doh.violated,
      true,
      'DoH Config vector should be violated',
    );
  });

  it('Legacy verifyDNS filteringActive false without health failure does NOT violate dns_filtering', () => {
    dnsExports.verifyDNS = () =>
      makeDnsResult({ filteringActive: false, ipv4Locked: true, ipv6Locked: true, dohConfigured: true });
    dummyHealthMonitor.getLastReport = () => makeHealthReport();

    const check = watchdog.runFullCheck();

    assert.strictEqual(check.vectors.dns_ipv4.violated, false);
    assert.strictEqual(check.vectors.dns_filtering.violated, false);
  });
});

// --------------------------------------------------------------------------
describe('NetworkWatch re-lockdown trigger logic', () => {
  let savedVerifyDNS;
  let applyDNSCalled;
  let savedApplyDNS;
  let savedNodeEnv;

  before(() => {
    savedNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const { saveChallengeState } = require('../../../challengeState');
    saveChallengeState({ status: 'active', id: 'test-challenge' });

    savedVerifyDNS = dnsExports.verifyDNS;
    savedApplyDNS  = dnsExports.applyDNS;
    // Stub applyDNS globally — runLockdown calls it via the same cached exports
    dnsExports.applyDNS = () => {
      applyDNSCalled = true;
      return { applied: [], failed: [] };
    };
  });

  after(() => {
    dnsExports.verifyDNS = savedVerifyDNS;
    dnsExports.applyDNS  = savedApplyDNS;
    process.env.NODE_ENV = savedNodeEnv;
    const { saveChallengeState } = require('../../../challengeState');
    saveChallengeState(null);
  });

  beforeEach(() => {
    applyDNSCalled = false;
  });

  it('Filtering failure alone must NOT trigger lockdown', async () => {
    // All config valid, only filtering down
    dnsExports.verifyDNS = () =>
      makeDnsResult({
        ipv4Locked: true,
        ipv6Locked: true,
        dohConfigured: true,
        firewallLocked: true,
        filteringActive: false,
      });

    const stop = netwatch.startNetworkWatch(20);
    await new Promise((r) => setTimeout(r, 60));
    stop();

    assert.strictEqual(
      applyDNSCalled,
      false,
      'applyDNS should NOT be called for a filtering-only failure',
    );
  });

  it('Config integrity failure (missing DoH) MUST trigger lockdown', async () => {
    // DoH config is gone — this is a real integrity compromise
    dnsExports.verifyDNS = () =>
      makeDnsResult({
        ipv4Locked: false,
        ipv6Locked: false,
        dohConfigured: false,
        firewallLocked: true,
        filteringActive: true,
      });

    const stop = netwatch.startNetworkWatch(20);
    await new Promise((r) => setTimeout(r, 60));
    stop();

    assert.strictEqual(
      applyDNSCalled,
      true,
      'applyDNS should be called for a config integrity compromise',
    );
  });
});
