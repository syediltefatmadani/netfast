const logger = require('./logger');
const { runEncoded } = require('./powershell');
const dnsModule = require('./dns');
const { getDnsHealthMonitor } = require('./services/dns');
const { flushDnsCache } = require('./hosts');
const {
  getAdapterFingerprint,
  runFullEnforcementVerification,
  isAdapterStateCompliant,
} = require('./networkEnforcement');
const { refreshRawDnsBlockRules } = require('./dnsBypassFirewall');
const { applyChromiumCleanBrowsingDoH, getChromiumDoHPolicyStatus } = require('./browserPolicy');
const { applyDnsFirewall, verifyFirewall, ADMIN_PRIVILEGE_MESSAGE } = require('./firewall');
const { createPhaseTimer, timedPhase } = require('./startupTiming');
const { isRealEnforcementAllowed, markRealEnforcementApplied } = require('./enforcementGuard');
const { buildMockLockdownResult } = require('./mockEnforcement');
const { refreshRuntimeExemptions } = require('./processExclusions');
const { refreshDeveloperFirewallRules } = require('./developerFirewall');
const {
  getPolicyMode,
  getModeLabel,
  isDeveloperMode,
  isDeveloperLikeMode,
  getProtectionStatusForMode,
  logPolicyModeStartup,
  buildPolicyStatusSnapshot,
} = require('./policyMode');
const { runDockerWslDiagnostics } = require('./dockerWslDetect');
const { validateDeveloperMode } = require('./developerValidation');
const {
  syncAtlasHostsFromDoh,
  runMongoDnsDiagnostic,
  discoverMongoHostsFromEnvFiles,
  isHostsFallbackEnabled,
  clearAtlasHostsBlock,
  getLastMongoDiagnostic,
} = require('./mongoDns');
const { resetHostsBaseline } = require('./watchdog');

function useHostsBlocklist() {
  const v = (process.env.NETFAST_HOSTS_BLOCK ?? '1').toLowerCase();
  return v !== '0' && v !== 'false' && v !== 'no';
}

function syncHostsIfEnabled() {
  if (!useHostsBlocklist()) return { ok: true, skipped: true };
  const { syncHostsBlocklist } = require('./hosts');
  const hosts = syncHostsBlocklist();
  if (hosts.ok) resetHostsBaseline();
  return hosts;
}

function getNetworkFingerprint() {
  try {
    const out = runEncoded(`
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '127.*' } | Select-Object -First 1).IPAddress
$dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses) -join ','
$adapters = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name) -join ','
[PSCustomObject]@{ gw = $gw; ip = $ip; dns = $dns; adapters = $adapters } | ConvertTo-Json -Compress
`);
    const data = JSON.parse(out.trim());
    const adapterFp = getAdapterFingerprint();
    return {
      gateway: data.gw || '',
      ip: data.ip || '',
      dns: data.dns || '',
      adapters: data.adapters || '',
      adapterFingerprint: adapterFp,
      key: `${data.gw}|${data.ip}|${data.dns}|${data.adapters}|${adapterFp}`,
    };
  } catch (e) {
    logger.warn('NETWORK', 'Could not read network fingerprint', e.message);
    return { gateway: '', ip: '', dns: '', adapters: '', adapterFingerprint: '', key: '' };
  }
}

function deriveProtectionLabel(lockStatus, mongoDiag) {
  return lockStatus.status || 'Not protected';
}

function buildLockdownStatus(dns, firewall, audit, extras = {}) {
  const warnings = [];
  const errors = [];
  const optionalWarnings = [];
  const mode = getPolicyMode();

  if (isDeveloperMode()) {
    warnings.push('Developer mode allows trusted dev tools.');
  }

  if (firewall?.failedOptionalRules?.length) {
    const devFailed = (firewall.failedOptionalRules || []).filter((f) => f.category === 'developer');
    const mongoFailed = (firewall.failedOptionalRules || []).filter((f) => f.category !== 'developer');
    if (mongoFailed.length) {
      optionalWarnings.push(`${mongoFailed.length} optional Mongo firewall rule(s) failed`);
    }
    if (devFailed.length && isDeveloperLikeMode()) {
      optionalWarnings.push(`${devFailed.length} developer firewall rule(s) failed`);
    }
  }
  if (firewall?.hasGlobalBlock) {
    optionalWarnings.push('Legacy global DNS block rules detected');
  }
  if (dns?.nrptError) {
    optionalWarnings.push(dns.nrptError);
  }

  const dnsApplied = Boolean(dns?.dnsApplied ?? (audit?.ipv4Locked && (audit?.ipv6Locked || dns?.strictMode)));
  const ipv4Locked = Boolean(audit?.ipv4Locked ?? dns?.ipv4Locked);
  const ipv6Locked = Boolean(dns?.strictMode ? audit?.ipv4Locked : (audit?.ipv6Locked ?? dns?.ipv6Locked));
  const strictMode = Boolean(dns?.strictMode ?? dns?.enforcement?.strictMode);
  const dohConfigured = Boolean(dns?.dohConfigured ?? dns?.doh?.ok);
  const firewallCoreLocked = Boolean(firewall?.firewallCoreLocked);
  const bypassResolversBlocked = Boolean(firewall?.bypassResolversBlocked);
  const rawDnsBypassBlocked = Boolean(firewall?.rawDnsBypassBlocked);
  const firewallLocked = Boolean(firewall?.firewallLocked);
  const rogueServers = audit?.rogueServers || dns?.rogueServers || [];

  const dnsIntegrity =
    dns?.dnsIntegrity ??
    (dnsApplied && dohConfigured && firewallLocked && rogueServers.length === 0);

  const browserDoh = extras.browserDoh || getChromiumDoHPolicyStatus();
  const dockerWsl = extras.dockerWsl || null;
  const devValidation = extras.devValidation || null;

  const lockStatus = {
    mode,
    modeLabel: getModeLabel(mode),
    dnsApplied,
    ipv4Locked,
    ipv6Locked,
    strictMode,
    dnsIntegrity,
    dohConfigured,
    browserDohLocked: browserDoh?.locked !== false,
    firewallCoreLocked,
    bypassResolversBlocked,
    rawDnsBypassBlocked,
    firewallLocked,
    developerExceptionsApplied: Boolean(firewall?.developerExceptionsApplied),
    nrptApplied: Boolean(dns?.nrptApplied),
    nrptError: dns?.nrptError || null,
    failedCoreRules: firewall?.failedCoreRules || [],
    failedBypassRules: firewall?.failedBypassRules || [],
    failedOptionalRules: firewall?.failedOptionalRules || [],
    rogueServers,
    optionalWarnings,
    warnings: [],
    errors: [],
    error: null,
    mongoDiagnostic: extras.mongoDiagnostic || null,
    hostsFallbackEnabled: isHostsFallbackEnabled(),
    dockerProtected: dockerWsl?.dockerProtected ?? 'unknown',
    wslProtected: dockerWsl?.wslProtected ?? 'unknown',
    dockerWsl,
    devValidation,
  };

  if (!lockStatus.firewallLocked && firewall?.adminRequired) {
    lockStatus.error = ADMIN_PRIVILEGE_MESSAGE;
    errors.push(lockStatus.error);
  } else if (!lockStatus.dnsApplied) {
    lockStatus.error = 'DNS lock incomplete — IPv4 and IPv6 must both use CleanBrowsing servers';
    errors.push(lockStatus.error);
  } else if (!lockStatus.firewallLocked) {
    lockStatus.error = firewall?.error || 'DNS firewall lock incomplete';
    errors.push(lockStatus.error);
  }

  if (optionalWarnings.length) {
    warnings.push(...optionalWarnings);
  }
  const mongoDiag = extras.mongoDiagnostic;
  if (mongoDiag) {
    if (!mongoDiag.srvLookupOk && !mongoDiag.mongoSrvResolvable) {
      warnings.push(`MongoDB SRV lookup failed: ${mongoDiag.error || mongoDiag.failureClass || 'unknown'}`);
    }
    if (mongoDiag.failureClass && mongoDiag.failureClass !== 'ok') {
      optionalWarnings.push(`MongoDB: ${mongoDiag.failureClass}`);
    }
  }

  if (dockerWsl?.dockerDetected && dockerWsl.dockerProtected !== 'true') {
    optionalWarnings.push('Docker protection not verified');
  }
  if (dockerWsl?.wslDetected && dockerWsl.wslProtected !== 'true') {
    optionalWarnings.push('WSL protection not verified');
  }
  if (devValidation && !devValidation.ok && devValidation.errors?.length) {
    for (const err of devValidation.errors) optionalWarnings.push(err);
  }

  lockStatus.warnings = warnings;
  lockStatus.errors = errors;

  const healthReport = getDnsHealthMonitor().getLastReport();
  const healthWarnings =
    healthReport?.hasWarnings || healthReport?.finalStatus === 'healthy_with_provider_misses';

  const lockdownOk = lockStatus.dnsApplied && lockStatus.firewallLocked;
  const hasWarnings = warnings.length > 0 || optionalWarnings.length > 0 || healthWarnings;

  lockStatus.status = getProtectionStatusForMode(lockdownOk, hasWarnings);
  if (!isDeveloperMode() && lockdownOk) {
    if (hasWarnings) lockStatus.status = 'Protected with warnings';
    else lockStatus.status = 'Protected';
  }

  lockStatus.protectionLabel = lockStatus.status;
  lockStatus.policyStatus = buildPolicyStatusSnapshot({
    protectionStatus: lockStatus.status,
    dnsApplied: lockStatus.dnsApplied,
    dohConfigured: lockStatus.dohConfigured,
    browserDohLocked: lockStatus.browserDohLocked,
    firewallCoreLocked: lockStatus.firewallCoreLocked,
    bypassResolversBlocked: lockStatus.bypassResolversBlocked,
    developerExceptionsApplied: lockStatus.developerExceptionsApplied,
    dockerProtected: lockStatus.dockerProtected,
    wslProtected: lockStatus.wslProtected,
  });

  if (lockStatus.error) {
    logger.error('NETWORK', lockStatus.error, lockStatus);
  }

  return lockStatus;
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

async function runLockdown(reason) {
  const lockdownTimer = createPhaseTimer('lockdown-total', { reason });
  logPolicyModeStartup();
  logger.info('NETWORK', `Re-applying lockdown (${reason})`, { mode: getPolicyMode() });

  if (!isRealEnforcementAllowed(`lockdown:${reason}`)) {
    logger.info('DEV_SAFE', `Mock lockdown (${reason}) — no system changes`);
    const mock = buildMockLockdownResult(reason);
    lockdownTimer.end({ mock: true, status: mock.status });
    return mock;
  }

  const useFastPath = reason === 'startup' && isEnforcementCompliant();
  if (useFastPath) {
    logger.info('NETWORK', 'Fast path: DNS, DoH, firewall, and adapters already compliant — verify only');
    const verifyTimer = createPhaseTimer('verification', { reason, fastPath: true });
    const audit = dnsModule.getDnsAudit();
    const dns = { ...dnsModule.verifyDNS(), applied: [], failed: [], fastPath: true };
    const firewall = verifyFirewall();
    verifyTimer.end({ firewallLocked: firewall.firewallLocked, dnsApplied: dns.dnsApplied });

    const lockStatus = buildLockdownStatus(dns, firewall, audit, {
      mongoDiagnostic: getLastMongoDiagnostic(),
      browserDoh: getChromiumDoHPolicyStatus(),
      fastPath: true,
    });

    getDnsHealthMonitor()
      .runImmediateDnsHealthCheck(reason)
      .catch((e) => logger.warn('NETWORK', 'Post-lockdown health check failed', e.message));

    lockdownTimer.end({ fastPath: true, status: lockStatus.status });
    return { ...lockStatus, dns, firewall, hosts: { ok: true, skipped: true }, audit, fastPath: true };
  }

  const browserTimer = createPhaseTimer('browser-doh-policy', { reason });
  timedPhase('browser-doh-apply', () => applyChromiumCleanBrowsingDoH(), { reason });
  const browserDoh = getChromiumDoHPolicyStatus();
  browserTimer.end();

  const dnsTimer = createPhaseTimer('dns-apply', { reason });
  const dns = timedPhase('dns-enforcement', () => dnsModule.applyDNS(), { reason });
  dnsTimer.end({
    applied: dns.applied?.length || 0,
    dnsApplied: dns.dnsApplied,
  });
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

  const firewallTimer = createPhaseTimer('firewall-apply', { reason });
  const firewall = timedPhase('firewall-enforcement', () => applyDnsFirewall(), { reason });
  firewallTimer.end({ firewallLocked: firewall.firewallLocked });

  const hosts = syncHostsIfEnabled();
  flushDnsCache();
  const auditTimer = createPhaseTimer('adapter-scan', { reason });
  const audit = dnsModule.getDnsAudit();
  auditTimer.end({ adapterCount: audit.interfaces?.length || 0 });

  let enforcementVerification = null;
  if (firewall.rawDnsBypassBlocked) {
    try {
      const verifyTimer = createPhaseTimer('verification', { reason });
      enforcementVerification = runFullEnforcementVerification();
      verifyTimer.end({ passed: enforcementVerification.passed });
      logger.info('NETWORK', 'Full enforcement verification', {
        passed: enforcementVerification.passed,
        resolver: enforcementVerification.resolver?.passed,
        bypass: enforcementVerification.bypass?.passed,
        safeSite: enforcementVerification.safeSite?.passed,
      });
    } catch (e) {
      logger.warn('NETWORK', 'Enforcement verification failed', e.message);
    }
  }

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

  const lockStatus = buildLockdownStatus(dns, firewall, audit, {
    mongoDiagnostic,
    browserDoh,
    dockerWsl,
    devValidation,
    enforcementVerification,
  });

  logger.info('NETWORK', 'Post-lockdown validation', {
    mode: lockStatus.mode,
    status: lockStatus.status,
    strictMode: lockStatus.strictMode,
    developerExceptionsApplied: lockStatus.developerExceptionsApplied,
    ipv4Locked: lockStatus.ipv4Locked,
    ipv6Locked: lockStatus.ipv6Locked,
    dnsIntegrity: lockStatus.dnsIntegrity,
    dohConfigured: lockStatus.dohConfigured,
    nrptApplied: lockStatus.nrptApplied,
    nrptError: lockStatus.nrptError,
    rogueServers: lockStatus.rogueServers,
    firewallCoreLocked: lockStatus.firewallCoreLocked,
    bypassResolversBlocked: lockStatus.bypassResolversBlocked,
    rawDnsBypassBlocked: lockStatus.rawDnsBypassBlocked,
    firewallLocked: lockStatus.firewallLocked,
    failedOptionalRules: lockStatus.failedOptionalRules?.length || 0,
    globalBlockRemoved: !firewall.hasGlobalBlock,
    hostsFallbackEnabled: lockStatus.hostsFallbackEnabled,
    atlasHostsCleared: atlasHosts?.skipped !== false,
    mongoDiagnostic,
    warnings: lockStatus.warnings,
    verification: dns.verification || null,
    enforcementVerification,
  });

  if (!lockStatus.dnsApplied || !lockStatus.firewallLocked) {
    logger.warn('NETWORK', 'Lockdown incomplete', lockStatus);
  } else if (lockStatus.protectionLabel === 'Protected with warnings') {
    logger.warn('NETWORK', 'Lockdown complete with warnings', lockStatus);
  } else {
    logger.info('NETWORK', 'Lockdown complete — Protected', lockStatus);
  }

  getDnsHealthMonitor()
    .runImmediateDnsHealthCheck(reason)
    .catch((e) => logger.warn('NETWORK', 'Post-lockdown health check failed', e.message));

  markRealEnforcementApplied();
  lockdownTimer.end({ fastPath: false, status: lockStatus.status });

  return {
    ...lockStatus,
    dns,
    firewall,
    hosts,
    audit,
    hostsSync,
    atlasHosts,
  };
}

function startNetworkWatch(intervalMs = 30000) {
  if (!isRealEnforcementAllowed('network-watch')) {
    logger.info('DEV_SAFE', 'Network watch disabled — mock/safe mode active');
    return () => {};
  }

  let last = getNetworkFingerprint();
  logger.info('NETWORK', 'Watching for network/DNS changes', last);

  const timer = setInterval(() => {
    const { isEnforcementDisabled } = require('./vpnViolationHandler');
    if (isEnforcementDisabled() || !isRealEnforcementAllowed('network-watch-tick')) return;

    try {
      refreshRuntimeExemptions();
      if (isDeveloperLikeMode()) refreshDeveloperFirewallRules();
      refreshRawDnsBlockRules();
    } catch (e) {
      logger.warn('NETWORK', 'Runtime exemption refresh failed', e.message);
    }
    const current = getNetworkFingerprint();
    const dns = dnsModule.verifyDNS();
    const networkChanged = current.key && current.key !== last.key;

    const dnsNotLocked = !dns.ipv4Locked || (!dns.strictMode && !dns.ipv6Locked);
    const rogueDnsDetected = (dns.rogueServers || []).length > 0;
    const dohConfigured = dns.dohConfigured;
    const firewallCompromised = !dns.firewallLocked;

    const configIntegrityViolation =
      dnsNotLocked || rogueDnsDetected || !dohConfigured || firewallCompromised;

    if (!networkChanged && !configIntegrityViolation) return;

    const reason = networkChanged ? 'network-changed' : 'dns-hijacked';

    logger.warn('NETWORK', 'Re-applying lockdown', {
      reason,
      from: last,
      to: current,
      rogue: dns.rogueServers,
      ipv4Locked: dns.ipv4Locked,
      ipv6Locked: dns.ipv6Locked,
      dohConfigured,
      firewallCompromised,
    });
    runLockdown(reason).catch((e) => logger.error('NETWORK', 'Lockdown failed', e.message));
    last = getNetworkFingerprint();
  }, intervalMs);

  return () => clearInterval(timer);
}

module.exports = {
  getNetworkFingerprint,
  runLockdown,
  startNetworkWatch,
  buildLockdownStatus,
  isEnforcementCompliant,
};
