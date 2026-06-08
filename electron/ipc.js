const { ipcMain } = require('electron');

const logger = require('./logger');

const { verifyDNS } = require('./dns');

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

  if (!config.ipv4Locked) warnings.push('IPv4 DNS is not locked to CleanBrowsing');
  if (!config.ipv6Locked) warnings.push('IPv6 DNS is not locked to CleanBrowsing');
  if (!config.firewallLocked) {
    errors.push(config.error || 'DNS firewall is not fully locked');
  }
  if ((config.rogueServers || []).length > 0) {
    warnings.push(
      `Rogue DNS server(s) detected: ${config.rogueServers.map((r) => r.server).join(', ')}`,
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

  const filteringOk = health ? isProtectionActive(health.status) : false;
  if (health?.providerMisses?.length) {
    warnings.push(
      `CleanBrowsing provider miss on: ${health.providerMisses.join(', ')} (local fallback active)`,
    );
  }
  if (health?.finalStatus === 'healthy_with_provider_misses') {
    warnings.push('DoH primary working; provider misses caught by fallback');
  }
  const dnsLocked = config.dnsApplied && config.ipv4Locked && config.ipv6Locked;
  const coreOk =
    dnsLocked &&
    config.firewallLocked &&
    config.firewallCoreLocked &&
    config.bypassResolversBlocked !== false &&
    (config.rogueServers || []).length === 0;

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
  if (stale) {
    logger.info('IPC', 'Refreshing stale DNS health report');
    try {
      health = await monitor.runHealthCheck('ipc-stale');
    } catch (e) {
      logger.warn('IPC', 'Stale health refresh failed', e.message);
    }
  }

  const config = verifyDNS();
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
  const config = verifyDNS();
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

  const healthReport = getDnsHealthMonitor().getLastReport();
  const stale = !healthReport || Date.now() - healthReport.timestamp > HEALTH_STALE_MS;

  if (stale && !isEnforcementDisabled()) {
    await getDnsHealthMonitor().runHealthCheck('ipc-stale').catch(() => {});
  }

  let check = runFullCheck();

  if (check.vectors.unknown_vpn?.violated) {
    check.vectors.unknown_vpn.reportable = false;
    check.vectors.unknown_vpn.vpnHandlerManaged = true;
  }

  const configViolated =
    check.vectors.dns_ipv4.violated ||
    check.vectors.dns_ipv6.violated ||
    check.vectors.windows_doh?.violated;

  const filteringViolated =
    check.vectors.dns_filtering?.violated || check.dnsHealth?.status === DnsStatus.FAILED;
  const dnsViolated = configViolated || filteringViolated;

  if (isEnforcementDisabled()) {
    return check.vectors;
  }

  if (dnsViolated && shouldAttemptRestore(check.dnsHealth?.status) && isRealEnforcementAllowed('ipc-auto-restore')) {
    if (!dnsGapStart) {
      dnsGapStart = Date.now();
      const reason = configViolated ? 'dns-hijacked' : 'filtering-inactive';
      logger.warn('IPC', `DNS protection inactive — attempting restore (reason: ${reason})`);
      await runLockdown(reason);
    } else if (Date.now() - dnsGapStart > GAP_MS) {
      if (configViolated) {
        check.vectors.dns_ipv4.reportable = true;
        check.vectors.dns_ipv6.reportable = true;
        if (check.vectors.windows_doh) check.vectors.windows_doh.reportable = true;
      }
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
