const { ipcMain } = require('electron');

const logger = require('./logger');

const { verifyDNS } = require('./dns');
const { getVerifyDnsCached, cacheVectorStatus, getCachedVectorStatus } = require('./dnsStatusCache');

const { runFullCheck, getBatteryState } = require('./watchdog');

const {
  getDnsHealthMonitor,
  isProtectionActive,
  shouldAttemptRestore,
  evaluateDomainProtection,
  runDohHealthSummary,
  formatDomainStatusMessage,
  DnsStatus,
} = require('./services/dns');
const { getChromiumDoHPolicyStatus } = require('./browserPolicy');

const { runLockdown, buildLockdownStatus } = require('./networkWatch');
const {
  processVpnCheck,
  reapplyProtection,
  acknowledgeVpnWarning,
  getRuntimeChallengeState,
  consumePendingBackendReport,
  isEnforcementDisabled,
} = require('./vpnViolationHandler');

const { getFallbackStatus, getLastMongoDiagnostic } = require('./mongoDns');
const { getPolicyMode, getModeLabel, isDeveloperMode, buildPolicyStatusSnapshot } = require('./policyMode');
const { getEnforcementStatus } = require('./enforcementState');
const { isRealEnforcementAllowed } = require('./enforcementGuard');
const { saveChallengeState } = require('./challengeState');

let dnsGapStart = null;

const GAP_MS = 2 * 60 * 1000;

const HEALTH_STALE_MS = 120000;

function buildApplyingVectorStatus() {
  const ok = (key) => ({ violated: false, warnings: 0, applying: true, vector: key });
  return {
    dns_filtering: ok('dns_filtering'),
    dns_provider_miss: { violated: false, warning: false, applying: true },
    fallback_blocking: ok('fallback_blocking'),
    dns_ipv4: ok('dns_ipv4'),
    dns_ipv6: ok('dns_ipv6'),
    windows_doh: ok('windows_doh'),
    firefox_doh: ok('firefox_doh'),
    chrome_doh: ok('chrome_doh'),
    ipv6_tunnel: ok('ipv6_tunnel'),
    hosts_modified: ok('hosts_modified'),
    rogue_dns: ok('rogue_dns'),
    unknown_vpn: ok('unknown_vpn'),
  };
}

function buildProtectionUiStatus(config, health) {
  const mode = config.mode || getPolicyMode();

  if (config.enforcementInProgress) {
    return {
      protectionState: 'applying',
      warnings: [],
      errors: [],
      mode,
      modeLabel: config.modeLabel || getModeLabel(mode),
      policyStatus: config.policyStatus || buildPolicyStatusSnapshot({
        protectionStatus: 'Applying protection...',
        dnsApplied: false,
        dohConfigured: false,
        browserDohLocked: false,
        firewallCoreLocked: false,
        bypassResolversBlocked: false,
        developerExceptionsApplied: false,
        dockerProtected: 'unknown',
        wslProtected: 'unknown',
      }),
      developerExceptionsApplied: false,
      dockerProtected: config.dockerProtected ?? 'unknown',
      wslProtected: config.wslProtected ?? 'unknown',
      protectionLabel: 'Applying protection...',
    };
  }

  const warnings = [];
  const errors = [];

  if (!config.ipv4Locked) {
    warnings.push('Adapter IPv4 DNS is not set to CleanBrowsing (informational)');
  }
  if (!config.ipv6Locked) {
    warnings.push('Adapter IPv6 DNS is not set to CleanBrowsing (informational)');
  }
  if (!config.functionalDnsProtection) {
    errors.push('DNS filtering not active — blocked domains are resolving');
  }
  if (!config.firewallLocked) {
    errors.push(config.error || 'DNS firewall is not fully locked');
  }
  if ((config.rogueServers || []).length > 0) {
    warnings.push(
      `Non-CleanBrowsing DNS on adapter(s): ${config.rogueServers.map((r) => r.server).join(', ')}`,
    );
  }
  if (!config.dohConfigured) warnings.push('Windows DoH is not configured for CleanBrowsing');
  if (health && !health.healthy) {
    warnings.push(health.details || `Filtering health: ${health.status}`);
  }

  const { hostsFallbackEnabled, mongoDnsFallbackUsed, hostsFallbackUsed } = getFallbackStatus();
  if (hostsFallbackEnabled && (mongoDnsFallbackUsed || hostsFallbackUsed)) {
    warnings.push('MongoDB Atlas hosts file emergency fallback is active');
  } else if (!hostsFallbackEnabled) {
    /* default — no warning */
  }

  if (config.optionalWarnings?.length) {
    warnings.push(...config.optionalWarnings);
  }

  if (isDeveloperMode()) {
    warnings.push('Developer mode allows trusted dev tools.');
    if (config.dockerProtected === 'unknown' || config.wslProtected === 'unknown') {
      warnings.push('Docker/WSL protection not verified.');
    }
  }

  const mongoDiag = config.mongoDiagnostic || getLastMongoDiagnostic();
  if (mongoDiag && !mongoDiag.mongoSrvResolvable) {
    warnings.push(`MongoDB SRV lookup failed: ${mongoDiag.error || 'querySrv timeout'}`);
  }

  if (health?.providerMisses?.length) {
    warnings.push(
      `CleanBrowsing provider miss on: ${health.providerMisses.join(', ')} (local fallback active)`,
    );
  }
  if (health?.finalStatus === 'healthy_with_provider_misses') {
    warnings.push('DoH primary working; provider misses caught by fallback');
  }
  const filteringOk =
    config.functionalDnsProtection === true ||
    (health ? isProtectionActive(health.status) : false);
  const dnsLocked = config.functionalDnsProtection === true;
  const coreOk =
    dnsLocked &&
    config.firewallLocked &&
    config.firewallCoreLocked &&
    config.bypassResolversBlocked !== false;

  let protectionState = 'inactive';
  const devProtected =
    isDeveloperMode() &&
    coreOk &&
    (config.protectionLabel || '').includes('developer exceptions');

  if (coreOk && filteringOk) {
    protectionState = warnings.length > 0 || devProtected ? 'warnings' : 'protected';
  } else if (coreOk || filteringOk || dnsLocked) {
    protectionState = 'warnings';
  }

  if (coreOk && (warnings.length > 0 || devProtected) && errors.length === 0) {
    protectionState = 'warnings';
  }

  const policyStatus = config.policyStatus || buildPolicyStatusSnapshot({
    protectionStatus: config.protectionLabel,
    dnsApplied: config.dnsApplied,
    dohConfigured: config.dohConfigured,
    browserDohLocked: config.browserDohLocked,
    firewallCoreLocked: config.firewallCoreLocked,
    bypassResolversBlocked: config.bypassResolversBlocked,
    developerExceptionsApplied: config.developerExceptionsApplied,
    dockerProtected: config.dockerProtected,
    wslProtected: config.wslProtected,
  });

  return {
    protectionState,
    warnings,
    errors,
    mode,
    modeLabel: config.modeLabel || getModeLabel(mode),
    policyStatus,
    developerExceptionsApplied: Boolean(config.developerExceptionsApplied),
    dockerProtected: config.dockerProtected ?? 'unknown',
    wslProtected: config.wslProtected ?? 'unknown',
    functionalDnsProtection: config.functionalDnsProtection,
    blockedDomainTests: config.blockedDomainTests || [],
  };
}

ipcMain.handle('get-enforcement-status', async () => getEnforcementStatus());

ipcMain.handle('sync-challenge-state', async (_event, challenge) => {
  const saved = saveChallengeState(challenge);
  logger.info('IPC', 'Challenge state synced', saved);
  return saved;
});

ipcMain.handle('get-dns-status', async () => {
  logger.info('IPC', 'get-dns-status');

  const enforcement = getEnforcementStatus();
  const monitor = getDnsHealthMonitor();
  let health = monitor.getLastReport();
  const stale = !health || Date.now() - health.timestamp > HEALTH_STALE_MS;
  if (stale && !enforcement.inProgress && !isEnforcementDisabled()) {
    logger.info('IPC', 'Refreshing stale DNS health report');
    try {
      health = await monitor.runHealthCheck('ipc-stale');
    } catch (e) {
      logger.warn('IPC', 'Stale health refresh failed', e.message);
    }
  }

  const config = getVerifyDnsCached();
  const lockdown = buildLockdownStatus(
    config,
    {
      firewallLocked: config.firewallLocked,
      firewallCoreLocked: config.firewallCoreLocked,
      bypassResolversBlocked: config.bypassResolversBlocked,
      adminRequired: false,
      failedOptionalRules: [],
      hasGlobalBlock: false,
    },
    config.audit,
    { mongoDiagnostic: getLastMongoDiagnostic() },
  );
  const ui = buildProtectionUiStatus(
    { ...config, ...lockdown, enforcementInProgress: enforcement.inProgress },
    health,
  );

  return {
    ...config,
    ...lockdown,
    ...ui,
    enforcementInProgress: enforcement.inProgress,
    enforcementStatus: enforcement,
    health: health
      ? {
          status: health.status,
          healthy: health.healthy,
          details: health.details,
          timestamp: health.timestamp,
        }
      : null,
    protectionActive: ui.protectionState === 'protected' || lockdown.protectionLabel?.includes('Protected'),
    protectionLabel: lockdown.protectionLabel,
    mode: ui.mode,
    modeLabel: ui.modeLabel,
    policyStatus: ui.policyStatus,
    developerExceptionsApplied: ui.developerExceptionsApplied,
    dockerProtected: ui.dockerProtected,
    wslProtected: ui.wslProtected,
  };
});

ipcMain.handle('get-policy-status', async () => {
  const config = getVerifyDnsCached();
  const lockdown = buildLockdownStatus(
    config,
    {
      firewallLocked: config.firewallLocked,
      firewallCoreLocked: config.firewallCoreLocked,
      bypassResolversBlocked: config.bypassResolversBlocked,
      developerExceptionsApplied: false,
      adminRequired: false,
      failedOptionalRules: [],
      hasGlobalBlock: false,
    },
    config.audit,
    { mongoDiagnostic: getLastMongoDiagnostic() },
  );
  return lockdown.policyStatus || buildPolicyStatusSnapshot({
    protectionStatus: lockdown.protectionLabel,
    dnsApplied: lockdown.dnsApplied,
    dohConfigured: lockdown.dohConfigured,
    browserDohLocked: lockdown.browserDohLocked,
    firewallCoreLocked: lockdown.firewallCoreLocked,
    bypassResolversBlocked: lockdown.bypassResolversBlocked,
    developerExceptionsApplied: lockdown.developerExceptionsApplied,
    dockerProtected: lockdown.dockerProtected,
    wslProtected: lockdown.wslProtected,
  });
});

ipcMain.handle('get-dns-health', async () => {
  const report = await getDnsHealthMonitor().runHealthCheck('ipc-request');
  return report;
});

ipcMain.handle('get-dns-audit-log', async () => {
  const { DnsAuditLogger } = require('./services/dns');
  return new DnsAuditLogger().readRecent(100);
});

ipcMain.handle('get-vpn-challenge-state', async (_event, context = {}) => {
  processVpnCheck(context);
  const runtime = getRuntimeChallengeState();
  const pendingBackendReport = consumePendingBackendReport();
  return { ...runtime, pendingBackendReport };
});

ipcMain.handle('vpn-acknowledge-warning', async () => {
  const state = acknowledgeVpnWarning();
  return { warningAcknowledged: state.warningAcknowledged };
});

ipcMain.handle('vpn-reapply-protection', async (_event, context = {}) => {
  return reapplyProtection(context);
});

ipcMain.handle('get-vector-status', async (_event, context = {}) => {
  logger.info('IPC', 'get-vector-status');
  processVpnCheck(context);

  const enforcement = getEnforcementStatus();
  if (enforcement.inProgress) {
    const cached = getCachedVectorStatus();
    if (cached) return cached;
    return buildApplyingVectorStatus();
  }

  const healthReport = getDnsHealthMonitor().getLastReport();
  const stale = !healthReport || Date.now() - healthReport.timestamp > HEALTH_STALE_MS;

  if (stale && !enforcement.inProgress && !isEnforcementDisabled()) {
    await getDnsHealthMonitor().runHealthCheck('ipc-stale').catch(() => {});
  }

  let check = runFullCheck();
  cacheVectorStatus(check.vectors);

  if (check.vectors.unknown_vpn?.violated) {
    check.vectors.unknown_vpn.reportable = false;
    check.vectors.unknown_vpn.vpnHandlerManaged = true;
  }

  const filteringViolated =
    check.vectors.dns_filtering?.violated || check.dnsHealth?.status === DnsStatus.FAILED;
  const dnsViolated = filteringViolated;

  if (isEnforcementDisabled()) {
    return check.vectors;
  }

  if (dnsViolated && shouldAttemptRestore(check.dnsHealth?.status) && isRealEnforcementAllowed('ipc-auto-restore')) {
    if (!dnsGapStart) {
      dnsGapStart = Date.now();
      const reason = 'filtering-inactive';
      logger.warn('IPC', `DNS protection inactive — attempting restore (reason: ${reason})`);
      await runLockdown(reason);
    } else if (Date.now() - dnsGapStart > GAP_MS) {
      if (filteringViolated) {
        check.vectors.dns_filtering.reportable = true;
      }
    }
  } else if (!dnsViolated && dnsGapStart) {
    logger.info('IPC', 'DNS protection restored');
    dnsGapStart = null;
  }

  return check.vectors;
});

ipcMain.handle('restore-dns', async () => {
  logger.info('IPC', 'restore-dns (manual)');

  const lockdown = await runLockdown('manual-restore');

  await getDnsHealthMonitor().runHealthCheck('manual-restore');

  return {
    success: Boolean(lockdown.dnsApplied && lockdown.firewallLocked),
    ...lockdown,
  };
});

ipcMain.handle('get-battery-state', async () => getBatteryState());

ipcMain.handle('diagnose-domain', async (_event, payload = {}) => {
  const domain = String(payload.domain || '').trim().toLowerCase();
  if (!domain) return { error: 'domain required' };

  const category = payload.category || (payload.restricted ? 'adult' : 'unknown');
  const expectedRestricted =
    payload.expectedRestricted ?? payload.restricted ?? ['adult', 'proxy', 'vpn'].includes(category);

  const evaluation = await evaluateDomainProtection(domain, {
    expectedRestricted,
    category,
    checkHttps: payload.checkHttps !== false,
    applyFallbackOnMiss: payload.applyFallbackOnMiss !== false,
  });

  const { domainListedInHosts } = require('./services/dns/domainProtection');
  const browserDoH = getChromiumDoHPolicyStatus();

  return {
    domain,
    expectedRestricted,
    category,
    cleanBrowsingDohReachable: evaluation.dohReachable,
    dohResolved: evaluation.dohResolved,
    dohBlocked: evaluation.dohBlocked,
    providerMiss: evaluation.providerMiss,
    hostsFallbackPresent: domainListedInHosts(domain),
    httpsReachable: evaluation.httpsReachable,
    finalBlocked: evaluation.finalBlocked,
    blockedBy: evaluation.blockedBy,
    status: evaluation.status,
    statusMessage: formatDomainStatusMessage(evaluation),
    warning: evaluation.warning,
    error: evaluation.error,
    fallbackLayers: evaluation.fallbackLayers,
    browserDoH,
  };
});

ipcMain.handle('health-doh', async () => {
  const summary = await runDohHealthSummary();
  const status = summary.finalStatus;
  return {
    ...summary,
    statusMessage:
      status === 'healthy'
        ? 'DoH reachable; safe domains allowed; known adult blocked by DoH'
        : status === 'healthy_with_provider_misses'
          ? 'DoH reachable; provider misses blocked by fallback'
          : status === 'degraded'
            ? 'DoH unreachable; fallback protecting restricted domains'
            : 'DoH or fallback failed for restricted domains',
  };
});
