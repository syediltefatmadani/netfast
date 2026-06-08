const os = require('os');
const crypto = require('crypto');
const logger = require('./logger');
const { checkUnknownVpn } = require('./vpnDetect');
const { runFullCheck } = require('./watchdog');
const { verifyDNS } = require('./dns');
const { runLockdown } = require('./networkWatch');
const { getDnsHealthMonitor, isProtectionActive } = require('./services/dns');
const { getChromiumDoHPolicyStatus } = require('./browserPolicy');
const { restorePreNetfastSystemState } = require('./systemRestore');
const {
  readState,
  isActiveWarning,
  deadlineExpired,
  msUntilDeadline,
  initFirstWarning,
  markWarningAcknowledged,
  markReapplyClicked,
  markResolved,
  markExpired,
  markSecondAttemptFail,
  consumePendingBackendReport,
  syncContext,
  clearState,
  writeState,
} = require('./vpnWarningState');

let enforcementDisabled = false;
let networkWatchStop = null;
let lastVpnActive = false;
let challengeFailed = false;

function getDeviceId() {
  const id = `${os.hostname()}-${os.userInfo().username}`;
  return crypto.createHash('sha256').update(id).digest('hex').slice(0, 16);
}

function setNetworkWatchStop(stopFn) {
  networkWatchStop = stopFn;
}

function stopEnforcementLoops() {
  enforcementDisabled = true;
  try {
    getDnsHealthMonitor().stop();
  } catch {
    /* not started */
  }
  if (typeof networkWatchStop === 'function') {
    networkWatchStop();
    networkWatchStop = null;
  }
  logger.info('VPN', 'Watchdog/network re-lockdown loops stopped');
}

function isEnforcementDisabled() {
  return enforcementDisabled || challengeFailed;
}

function isChallengeFailed() {
  return challengeFailed;
}

function validateFullProtection() {
  const vpn = checkUnknownVpn();
  if (vpn.violated) {
    return {
      ok: false,
      vpnStillActive: true,
      message: 'VPN is still active. Disable it before re-applying protection.',
    };
  }

  const dns = verifyDNS();
  const check = runFullCheck();
  const health = getDnsHealthMonitor().getLastReport();
  const filteringOk = health ? isProtectionActive(health.status) : false;
  const browserDoh = getChromiumDoHPolicyStatus();

  const failures = [];
  if (!dns.ipv4Locked || !dns.ipv6Locked) failures.push('DNS not locked');
  if (!dns.dohConfigured) failures.push('Windows DoH not configured');
  if (!dns.firewallLocked || !dns.firewallCoreLocked) failures.push('Firewall not locked');
  if (dns.bypassResolversBlocked === false) failures.push('Bypass resolvers not blocked');
  if (!filteringOk || check.vectors.dns_filtering?.violated) {
    failures.push('Restricted content filtering not active');
  }
  if (check.vectors.firefox_doh?.violated || check.vectors.chrome_doh?.violated) {
    failures.push('Browser DoH not locked');
  }

  if (failures.length) {
    return { ok: false, vpnStillActive: false, message: failures.join('; '), failures };
  }

  return {
    ok: true,
    vpnStillActive: false,
    dns,
    check,
    browserDoh,
  };
}

function failChallenge(reason, stateUpdater) {
  challengeFailed = true;
  stopEnforcementLoops();
  const state = stateUpdater();
  const restore = restorePreNetfastSystemState(reason);
  return {
    challengeFailed: true,
    refundEligible: false,
    enforcementRemoved: true,
    systemRestored: restore.systemRestored,
    restoreWarnings: restore.warnings,
    pendingBackendReport: state.pendingBackendReport,
    status: 'Challenge failed',
    challengeActive: false,
    canContinue: false,
  };
}

/**
 * Rising-edge VPN detection while challenge is active.
 */
function processVpnCheck(context = {}) {
  syncContext({
    userId: context.userId,
    deviceId: context.deviceId || getDeviceId(),
    challengeId: context.challengeId,
  });

  if (challengeFailed) {
    return { handled: true, challengeFailed: true };
  }

  const state = readState();
  const vpn = checkUnknownVpn();
  const vpnActive = vpn.violated;

  if (isActiveWarning(state)) {
    if (deadlineExpired(state)) {
      const result = failChallenge('vpn-reapply-deadline-expired', () => markExpired());
      clearState();
      return { handled: true, ...result, action: 'deadline_expired' };
    }
    if (vpnActive && !lastVpnActive && state.hadVpnClearedOnce) {
      const result = failChallenge('second-vpn-attempt-during-warning', () => markSecondAttemptFail());
      clearState();
      lastVpnActive = vpnActive;
      return { handled: true, ...result, action: 'second_attempt' };
    }
    if (!vpnActive && lastVpnActive) {
      const s = readState();
      s.hadVpnClearedOnce = true;
      writeState(s);
    }
    lastVpnActive = vpnActive;
    return {
      handled: false,
      vpnWarningActive: true,
      vpnActive,
      showModal: !state.warningAcknowledged || vpnActive,
      msRemaining: msUntilDeadline(state),
    };
  }

  if (state.resolved && state.attemptCount >= 1 && vpnActive && !lastVpnActive) {
    const result = failChallenge('second-vpn-attempt', () => markSecondAttemptFail());
    clearState();
    lastVpnActive = vpnActive;
    return { handled: true, ...result, action: 'second_attempt' };
  }

  if (vpnActive && !lastVpnActive) {
    if (state.attemptCount >= 1 && state.resolved) {
      const result = failChallenge('second-vpn-attempt', () => markSecondAttemptFail());
      clearState();
      lastVpnActive = vpnActive;
      return { handled: true, ...result, action: 'second_attempt' };
    }

    if (state.attemptCount >= 1 && !state.resolved) {
      lastVpnActive = vpnActive;
      return {
        handled: false,
        vpnWarningActive: true,
        vpnActive: true,
        showModal: true,
        msRemaining: msUntilDeadline(state),
      };
    }

    const newState = initFirstWarning({
      userId: context.userId,
      deviceId: context.deviceId || getDeviceId(),
      challengeId: context.challengeId,
    });
    lastVpnActive = vpnActive;
    return {
      handled: true,
      action: 'first_warning',
      vpnWarningActive: true,
      showModal: true,
      pendingBackendReport: newState.pendingBackendReport,
      msRemaining: msUntilDeadline(newState),
      adapters: vpn.adapters,
    };
  }

  if (!vpnActive) lastVpnActive = false;
  return { handled: false, vpnActive };
}

function checkDeadlineOnStartup(context = {}) {
  const state = readState();
  syncContext({
    userId: context.userId,
    deviceId: context.deviceId || getDeviceId(),
    challengeId: context.challengeId,
  });

  if (!state.firstVpnDetectedAt || state.resolved || state.expired) {
    return { checked: true, action: 'none' };
  }

  if (isActiveWarning(state) && deadlineExpired(state)) {
    const result = failChallenge('vpn-reapply-deadline-expired-startup', () => markExpired());
    clearState();
    return { checked: true, action: 'deadline_expired', ...result };
  }

  if (isActiveWarning(state)) {
    return {
      checked: true,
      action: 'warning_active',
      vpnWarningActive: true,
      msRemaining: msUntilDeadline(state),
    };
  }

  return { checked: true, action: 'none' };
}

async function reapplyProtection(context = {}) {
  const state = readState();
  if (!isActiveWarning(state) && !state.challengePaused) {
    return { ok: false, message: 'No active VPN warning to resolve.' };
  }

  if (deadlineExpired(state)) {
    const result = failChallenge('vpn-reapply-deadline-expired', () => markExpired());
    clearState();
    return { ok: false, ...result };
  }

  markReapplyClicked();

  const vpnCheck = checkUnknownVpn();
  if (vpnCheck.violated) {
    return {
      ok: false,
      vpnStillActive: true,
      message: 'VPN is still active. Disable it before re-applying protection.',
      challengePaused: true,
    };
  }

  enforcementDisabled = false;
  await runLockdown('vpn-reapply');
  await getDnsHealthMonitor().runHealthCheck('vpn-reapply');

  const validation = validateFullProtection();
  if (!validation.ok) {
    return {
      ok: false,
      vpnStillActive: Boolean(validation.vpnStillActive),
      message: validation.message || 'Protection validation failed after re-apply.',
      challengePaused: true,
    };
  }

  markResolved();
  lastVpnActive = false;

  try {
    const { startNetworkWatch } = require('./networkWatch');
    if (!networkWatchStop) {
      setNetworkWatchStop(startNetworkWatch());
    }
    getDnsHealthMonitor().start();
  } catch (e) {
    logger.warn('VPN', 'Could not restart monitoring loops after re-apply', e.message);
  }

  logger.info('VPN', 'Protection re-applied — challenge resumed');

  return {
    ok: true,
    message: 'Protection re-applied successfully.',
    status: 'Protected',
    challengeActive: true,
    challengePaused: false,
    canContinue: true,
    attemptCount: 1,
  };
}

function acknowledgeVpnWarning() {
  return markWarningAcknowledged();
}

function getRuntimeChallengeState() {
  const state = readState();

  if (challengeFailed) {
    return {
      status: 'Challenge failed',
      challengeActive: false,
      challengePaused: false,
      canContinue: false,
      refundEligible: false,
      protectionState: 'inactive',
    };
  }

  if (isActiveWarning(state)) {
    return {
      status: 'VPN warning — protection re-apply required',
      challengeActive: false,
      challengePaused: true,
      canContinue: false,
      refundEligible: false,
      protectionState: 'vpn_warning',
      reapplyDeadlineAt: state.reapplyDeadlineAt,
      msRemaining: msUntilDeadline(state),
      warningAcknowledged: state.warningAcknowledged,
      showModal: !state.warningAcknowledged,
      firstVpnDetectedAt: state.firstVpnDetectedAt,
    };
  }

  return {
    status: 'Protected',
    challengeActive: true,
    challengePaused: false,
    canContinue: true,
    protectionState: 'protected',
  };
}

function resetVpnHandlerForTests() {
  enforcementDisabled = false;
  challengeFailed = false;
  lastVpnActive = false;
  networkWatchStop = null;
}

module.exports = {
  processVpnCheck,
  checkDeadlineOnStartup,
  reapplyProtection,
  acknowledgeVpnWarning,
  getRuntimeChallengeState,
  consumePendingBackendReport,
  validateFullProtection,
  stopEnforcementLoops,
  isEnforcementDisabled,
  isChallengeFailed,
  setNetworkWatchStop,
  resetVpnHandlerForTests,
  getDeviceId,
};
