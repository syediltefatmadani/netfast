const logger = require('./logger');
const { runEncoded, runEncodedAsync } = require('./powershell');
const dnsModule = require('./dns');
const { getDnsHealthMonitor } = require('./services/dns');
const {
  getAdapterFingerprint,
  isAdapterStateCompliant,
} = require('./networkEnforcement');
const { refreshRawDnsBlockRules } = require('./dnsBypassFirewall');
const { getChromiumDoHPolicyStatus } = require('./browserPolicy');
const { verifyFirewall, ADMIN_PRIVILEGE_MESSAGE } = require('./firewall');
const { createPhaseTimer } = require('./startupTiming');
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
const {
  isHostsFallbackEnabled,
  getLastMongoDiagnostic,
} = require('./mongoDns');
const { runLockdownInWorker } = require('./lockdownRunner');
const { invalidateDnsStatusCache } = require('./dnsStatusCache');

let activeLockdown = null;
let lastWatchLockdownAt = 0;
const WATCH_LOCKDOWN_COOLDOWN_MS = 60000;

// Event-driven detection (tamperWatch) provides the fast path now, so the timer
// is only a safety-net backstop. If the event sensor fails, we drop back to the
// fast interval so detection coverage is never lost.
const BACKSTOP_INTERVAL_MS = 5 * 60 * 1000;
const FAST_FALLBACK_INTERVAL_MS = 30000;

let watchLast = null;
let watchTimer = null;
let watchActive = false;

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

/** Non-blocking variant of getNetworkFingerprint for the watch/event path. */
async function getNetworkFingerprintAsync() {
  try {
    const out = await runEncodedAsync(`
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

  const ipv4ConfigLocked = Boolean(audit?.ipv4Locked ?? dns?.ipv4Locked ?? dns?.ipv4ConfigLocked);
  const ipv6ConfigLocked = Boolean(
    dns?.strictMode ? audit?.ipv4Locked : (audit?.ipv6Locked ?? dns?.ipv6Locked ?? dns?.ipv6ConfigLocked),
  );
  const strictMode = Boolean(dns?.strictMode ?? dns?.enforcement?.strictMode);
  const functionalDnsProtection = Boolean(
    dns?.functionalDnsProtection ?? dns?.functionalVerification?.functionalDnsProtection,
  );
  const blockedDomainTests =
    dns?.blockedDomainTests || dns?.functionalVerification?.blockedDomainTests || [];
  const dohConfigured = Boolean(dns?.dohConfigured ?? dns?.doh?.ok);
  const firewallCoreLocked = Boolean(firewall?.firewallCoreLocked);
  const bypassResolversBlocked = Boolean(firewall?.bypassResolversBlocked);
  const rawDnsBypassBlocked = Boolean(firewall?.rawDnsBypassBlocked);
  const firewallLocked = Boolean(firewall?.firewallLocked);
  const rogueServers = audit?.rogueServers || dns?.rogueServers || [];

  // Authoritative: functional filtering behavior. Config fields are informational.
  const dnsApplied = functionalDnsProtection;
  const ipv4Locked = ipv4ConfigLocked;
  const ipv6Locked = ipv6ConfigLocked;
  const dnsIntegrity = functionalDnsProtection && firewallLocked;

  const browserDoh = extras.browserDoh || getChromiumDoHPolicyStatus();
  const dockerWsl = extras.dockerWsl || null;
  const devValidation = extras.devValidation || null;

  const lockStatus = {
    mode,
    modeLabel: getModeLabel(mode),
    dnsApplied,
    ipv4Locked,
    ipv6Locked,
    ipv4ConfigLocked,
    ipv6ConfigLocked,
    functionalDnsProtection,
    blockedDomainTests,
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
  } else if (!functionalDnsProtection) {
    lockStatus.error = 'DNS filtering not active — blocked domains are resolving';
    errors.push(lockStatus.error);
  } else if (!lockStatus.firewallLocked) {
    lockStatus.error = firewall?.error || 'DNS firewall lock incomplete';
    errors.push(lockStatus.error);
  }

  if (!ipv4ConfigLocked) {
    warnings.push('Adapter IPv4 DNS is not set to CleanBrowsing (filtering may use forwarded DoH)');
  }
  if (!ipv6ConfigLocked && !strictMode) {
    warnings.push('Adapter IPv6 DNS is not set to CleanBrowsing (informational)');
  }
  if (rogueServers.length > 0) {
    warnings.push(
      `Non-CleanBrowsing DNS on adapter(s): ${rogueServers.map((r) => r.server).join(', ')}`,
    );
  }
  if (!dohConfigured) {
    warnings.push('Windows DoH is not configured for CleanBrowsing');
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

  const lockdownOk = functionalDnsProtection && lockStatus.firewallLocked;
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
  if (activeLockdown) {
    logger.info('NETWORK', `Lockdown already in progress — joining (${reason})`);
    return activeLockdown;
  }

  activeLockdown = runLockdownInner(reason).finally(() => {
    activeLockdown = null;
  });
  return activeLockdown;
}

async function runLockdownInner(reason) {
  const lockdownTimer = createPhaseTimer('lockdown-total', { reason });
  logPolicyModeStartup();
  logger.info('NETWORK', `Re-applying lockdown (${reason})`, { mode: getPolicyMode() });

  if (!isRealEnforcementAllowed(`lockdown:${reason}`)) {
    logger.info('DEV_SAFE', `Mock lockdown (${reason}) — no system changes`);
    const mock = buildMockLockdownResult(reason);
    lockdownTimer.end({ mock: true, status: mock.status });
    return mock;
  }

  invalidateDnsStatusCache();

  let core;
  try {
    core = await runLockdownInWorker(reason);
  } catch (e) {
    lockdownTimer.end({ ok: false, error: e.message });
    throw e;
  }

  if (core.mock) {
    const mock = core.result;
    lockdownTimer.end({ mock: true, status: mock.status });
    return mock;
  }

  const {
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
    fastPath,
  } = core;

  const lockStatus = buildLockdownStatus(dns, firewall, audit, {
    mongoDiagnostic,
    browserDoh,
    dockerWsl,
    devValidation,
    enforcementVerification: 'worker',
    fastPath,
  });

  logger.info('NETWORK', 'Post-lockdown validation', {
    mode: lockStatus.mode,
    status: lockStatus.status,
    strictMode: lockStatus.strictMode,
    ipv4Locked: lockStatus.ipv4Locked,
    ipv6Locked: lockStatus.ipv6Locked,
    dnsIntegrity: lockStatus.dnsIntegrity,
    firewallLocked: lockStatus.firewallLocked,
    rogueServers: lockStatus.rogueServers,
    fastPath: !!fastPath,
    tunnel,
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
  invalidateDnsStatusCache();
  lockdownTimer.end({ fastPath: !!fastPath, status: lockStatus.status, worker: true });

  return {
    ...lockStatus,
    dns,
    firewall,
    hosts,
    audit,
    hostsSync,
    atlasHosts,
    tunnel,
    fastPath,
  };
}

/**
 * One integrity check + conditional re-lockdown. Shared by the backstop timer
 * (`trigger='poll'`) and the event-driven tamper layer (`trigger='event:*'`).
 * Uses fresh, non-blocking data (verifyDNSAsync) so the detector is never stale,
 * and reuses the existing activeLockdown guard + cooldown + runLockdown path.
 */
async function runWatchCheck(trigger = 'poll') {
  const { isEnforcementDisabled } = require('./vpnViolationHandler');
  if (isEnforcementDisabled() || !isRealEnforcementAllowed('network-watch-tick')) return;
  if (activeLockdown) return;

  // Heavy rule housekeeping only on the slow backstop, not on every event.
  if (trigger === 'poll') {
    try {
      refreshRuntimeExemptions();
      if (isDeveloperLikeMode()) refreshDeveloperFirewallRules();
      refreshRawDnsBlockRules();
    } catch (e) {
      logger.warn('NETWORK', 'Runtime exemption refresh failed', e.message);
    }
  }

  const [current, dns] = await Promise.all([
    getNetworkFingerprintAsync(),
    dnsModule.verifyDNSAsync(),
  ]);
  const networkChanged = current.key && watchLast && current.key !== watchLast.key;

  const filteringInactive = !dns.functionalDnsProtection;
  const firewallCompromised = !dns.firewallLocked;
  const dohCompromised = dns.dohConfigured === false;
  const adapterDnsCompromised = !dns.ipv4Locked || !dns.ipv6Locked;
  const configIntegrityViolation =
    firewallCompromised || dohCompromised || adapterDnsCompromised;

  if (!networkChanged && !configIntegrityViolation) {
    watchLast = current;
    return;
  }

  const now = Date.now();
  if (activeLockdown) {
    logger.info('NETWORK', 'Skipping watch re-lockdown — lockdown already running');
    return;
  }
  if (now - lastWatchLockdownAt < WATCH_LOCKDOWN_COOLDOWN_MS) {
    logger.info('NETWORK', 'Skipping watch re-lockdown — cooldown active', {
      msSinceLast: now - lastWatchLockdownAt,
    });
    return;
  }

  const reason = networkChanged ? 'network-changed' : 'dns-hijacked';

  logger.warn('NETWORK', 'Re-applying lockdown', {
    trigger,
    reason,
    from: watchLast,
    to: current,
    rogue: dns.rogueServers,
    functionalDnsProtection: dns.functionalDnsProtection,
    firewallCompromised,
  });
  lastWatchLockdownAt = now;
  await module.exports.runLockdown(reason).catch((e) => logger.error('NETWORK', 'Lockdown failed', e.message));
  watchLast = await getNetworkFingerprintAsync();
}

function scheduleWatch(intervalMs) {
  if (watchTimer) clearInterval(watchTimer);
  watchTimer = setInterval(() => {
    runWatchCheck('poll').catch((e) => logger.error('NETWORK', 'Watch check failed', e.message));
  }, intervalMs);
}

function startNetworkWatch(intervalMs = BACKSTOP_INTERVAL_MS) {
  if (!isRealEnforcementAllowed('network-watch')) {
    logger.info('DEV_SAFE', 'Network watch disabled — mock/safe mode active');
    return () => {};
  }

  watchLast = getNetworkFingerprint();
  watchActive = true;
  logger.info('NETWORK', 'Watching for network/DNS changes (event-driven + backstop)', {
    backstopMs: intervalMs,
    ...watchLast,
  });
  scheduleWatch(intervalMs);

  return () => {
    watchActive = false;
    if (watchTimer) clearInterval(watchTimer);
    watchTimer = null;
  };
}

/**
 * Tighten or relax the backstop poll. Called with `true` when the event sensor
 * is down (revert to fast polling so coverage is preserved) and `false` when
 * events are healthy again.
 */
function setWatchFastFallback(enabled) {
  if (!watchActive || !watchTimer) return;
  const target = enabled ? FAST_FALLBACK_INTERVAL_MS : BACKSTOP_INTERVAL_MS;
  logger.warn('NETWORK', `Watch backstop interval -> ${target}ms (${enabled ? 'event sensor down' : 'events healthy'})`);
  scheduleWatch(target);
}

module.exports = {
  getNetworkFingerprint,
  getNetworkFingerprintAsync,
  runLockdown,
  runWatchCheck,
  startNetworkWatch,
  setWatchFastFallback,
  buildLockdownStatus,
  isEnforcementCompliant,
};
