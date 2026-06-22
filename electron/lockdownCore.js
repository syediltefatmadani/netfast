/**
 * Blocking system enforcement — runs in a worker thread so execSync / PowerShell
 * cannot freeze the Electron main process UI.
 */
const logger = require('./logger');
const dnsModule = require('./dns');
const { disableIPv6Tunneling } = require('./dns');
const { flushDnsCache } = require('./hosts');
const {
  runFullEnforcementVerification,
  runSafeSiteVerification,
  isAdapterStateCompliant,
} = require('./networkEnforcement');
const { removeRawDnsBlockRules } = require('./dnsBypassFirewall');
const { applyChromiumCleanBrowsingDoH, getChromiumDoHPolicyStatus } = require('./browserPolicy');
const { applyDnsFirewall, verifyFirewall } = require('./firewall');
const { createPhaseTimer, timedPhase } = require('./startupTiming');
const { isRealEnforcementAllowed } = require('./enforcementGuard');
const { buildMockLockdownResult } = require('./mockEnforcement');
const { capturePreLockdownSnapshot } = require('./preLockdownSnapshot');
const {
  getPolicyMode,
  isDeveloperLikeMode,
  logPolicyModeStartup,
} = require('./policyMode');
const { runDockerWslDiagnostics } = require('./dockerWslDetect');
const { validateDeveloperMode } = require('./developerValidation');
const {
  syncAtlasHostsFromDoh,
  runMongoDnsDiagnostic,
  discoverMongoHostsFromEnvFiles,
  clearAtlasHostsBlock,
} = require('./mongoDns');
const { resetHostsBaseline } = require('./watchdog');

function syncHostsIfEnabled() {
  const { isHostsFileEnforcementEnabled, syncHostsBlocklist } = require('./hosts');
  if (!isHostsFileEnforcementEnabled()) {
    return { ok: true, skipped: true, reason: 'hosts_file_enforcement_disabled' };
  }
  const hosts = syncHostsBlocklist();
  if (hosts.ok) resetHostsBaseline();
  return hosts;
}

function isEnforcementCompliant() {
  try {
    const fw = verifyFirewall();
    const dnsOk = isAdapterStateCompliant();
    const dohConfigured = dnsModule.checkDoHConfig();
    return Boolean(fw.firewallLocked && dnsOk && dohConfigured);
  } catch (e) {
    logger.warn('NETWORK', 'Enforcement compliance check failed', e.message);
    return false;
  }
}

function runDeferredEnforcementVerificationSync(reason, firewall) {
  if (!firewall?.rawDnsBypassBlocked) return null;

  let enforcementVerification = null;
  try {
    const verifyTimer = createPhaseTimer('verification-deferred', { reason });
    enforcementVerification = runFullEnforcementVerification();
    verifyTimer.end({ passed: enforcementVerification.passed });
    logger.info('NETWORK', 'Deferred enforcement verification', {
      passed: enforcementVerification.passed,
      resolver: enforcementVerification.resolver?.passed,
      bypass: enforcementVerification.bypass?.passed,
      safeSite: enforcementVerification.safeSite?.passed,
    });
  } catch (e) {
    logger.warn('NETWORK', 'Deferred enforcement verification failed', e.message);
    return null;
  }

  if (enforcementVerification?.safeSite?.passed === false) {
    logger.error(
      'NETWORK',
      'Internet broken after lockdown — safe site verification failed; rolling back global port 53 blocks',
      { safeSite: enforcementVerification.safeSite },
    );
    try {
      removeRawDnsBlockRules();
      const retrySafeSite = runSafeSiteVerification();
      if (retrySafeSite.passed) {
        logger.info('NETWORK', 'Internet restored after rolling back global port 53 blocks', retrySafeSite);
        enforcementVerification.safeSite = retrySafeSite;
        enforcementVerification.passed =
          Boolean(enforcementVerification.resolver?.passed) &&
          Boolean(enforcementVerification.bypass?.passed ?? true) &&
          retrySafeSite.passed;
      }
    } catch (e) {
      logger.execError('NETWORK', 'Failed to roll back global port 53 blocks after broken internet', e);
    }
  }

  return enforcementVerification;
}

async function executeLockdownCore(reason) {
  const lockdownTimer = createPhaseTimer('lockdown-core-total', { reason });
  logPolicyModeStartup();
  logger.info('NETWORK', `Lockdown core (${reason})`, { mode: getPolicyMode() });

  if (!isRealEnforcementAllowed(`lockdown:${reason}`)) {
    const mock = buildMockLockdownResult(reason);
    lockdownTimer.end({ mock: true, status: mock.status });
    return { mock: true, result: mock };
  }

  const snapshotTimer = createPhaseTimer('pre-lockdown-snapshot', { reason });
  capturePreLockdownSnapshot();
  snapshotTimer.end();

  const useFastPath = reason === 'startup' && isEnforcementCompliant();
  if (useFastPath) {
    logger.info('NETWORK', 'Fast path: DNS, DoH, firewall, and adapters already compliant — verify only');
    const audit = dnsModule.getDnsAudit();
    const dns = { ...dnsModule.verifyDNS(), applied: [], failed: [], fastPath: true };
    const firewall = verifyFirewall();
    const tunnel = disableIPv6Tunneling();
    lockdownTimer.end({ fastPath: true });
    return {
      mock: false,
      fastPath: true,
      dns,
      firewall,
      audit,
      browserDoh: getChromiumDoHPolicyStatus(),
      mongoDiagnostic: null,
      dockerWsl: null,
      devValidation: null,
      atlasHosts: { ok: true, skipped: true },
      hosts: { ok: true, skipped: true },
      hostsSync: null,
      tunnel,
    };
  }

  timedPhase('browser-doh-apply', () => applyChromiumCleanBrowsingDoH(), { reason });
  const browserDoh = getChromiumDoHPolicyStatus();

  const dns = timedPhase('dns-enforcement', () => dnsModule.applyDNS(), { reason });
  logger.info('NETWORK', 'DNS adapters configured', {
    applied: dns.applied,
    ipv4Locked: dns.ipv4Locked,
    ipv6Locked: dns.ipv6Locked,
  });

  const atlasHosts = await clearAtlasHostsBlock().catch((e) => {
    logger.warn('NETWORK', 'Clear Atlas hosts block failed', e.message);
    return { ok: false };
  });

  const hostsSync = await syncAtlasHostsFromDoh().catch((e) => {
    logger.warn('NETWORK', 'Atlas hosts sync failed', e.message);
    return { ok: false, error: e.message };
  });

  const firewall = timedPhase('firewall-enforcement', () => applyDnsFirewall(), { reason });
  const hosts = syncHostsIfEnabled();
  flushDnsCache();
  const audit = dnsModule.getDnsAudit();

  const mongoHostnames = discoverMongoHostsFromEnvFiles();
  let mongoDiagnostic = null;
  try {
    mongoDiagnostic = await runMongoDnsDiagnostic(mongoHostnames);
  } catch (e) {
    logger.warn('NETWORK', 'MongoDB DNS diagnostic failed', e.message);
    mongoDiagnostic = {
      mongoSrvResolvable: false,
      mongoTxtResolvable: false,
      mongoLookupOk: false,
      error: e.message,
    };
  }

  let dockerWsl = null;
  let devValidation = null;
  if (isDeveloperLikeMode()) {
    dockerWsl = await runDockerWslDiagnostics({ runProbes: reason === 'startup' }).catch((e) => {
      logger.warn('DEV_MODE', 'Docker/WSL diagnostics failed', e.message);
      return null;
    });
    devValidation = await validateDeveloperMode().catch((e) => {
      logger.warn('DEV_MODE', 'Developer validation failed', e.message);
      return { ok: false, errors: [e.message] };
    });
  }

  const tunnel = disableIPv6Tunneling();

  // Verification probes are slow; run at end of worker so main thread never blocks on them.
  runDeferredEnforcementVerificationSync(reason, firewall);

  lockdownTimer.end({ fastPath: false });

  return {
    mock: false,
    fastPath: false,
    dns,
    firewall,
    audit,
    browserDoh,
    mongoDiagnostic,
    dockerWsl,
    devValidation,
    atlasHosts,
    hosts,
    hostsSync,
    tunnel,
  };
}

module.exports = { executeLockdownCore };
