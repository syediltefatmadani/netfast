const logger = require('./logger');
const { getSavedChallengeStateSync } = require('./challengeState');

let realEnforcementApplied = false;

function isDevEnvironment() {
  return process.env.NODE_ENV === 'development';
}

function isDevSafeMode() {
  const isDev = isDevEnvironment();
  const enforcementDisabled = process.env.NETFAST_DISABLE_ENFORCEMENT === 'true';
  const allowRealEnforcement = process.env.NETFAST_ALLOW_REAL_ENFORCEMENT === 'true';
  return isDev && (enforcementDisabled || !allowRealEnforcement);
}

function isRealEnforcementAllowed(operationName = 'enforcement') {
  const isDev = isDevEnvironment();
  const enforcementDisabled = process.env.NETFAST_DISABLE_ENFORCEMENT === 'true';
  const allowRealEnforcement = process.env.NETFAST_ALLOW_REAL_ENFORCEMENT === 'true';

  if (isDev) {
    if (enforcementDisabled || !allowRealEnforcement) return false;
    logger.warn('DEV_ENFORCE', `Real enforcement allowed for: ${operationName}`);
    return true;
  }

  const challenge = getSavedChallengeStateSync();
  if (challenge?.status !== 'active') return false;
  return true;
}

function assertRealEnforcementAllowed(operationName) {
  if (isRealEnforcementAllowed(operationName)) return true;
  logger.info('DEV_SAFE', `Skipped dangerous operation: ${operationName}`);
  return false;
}

function shouldRunStartupLockdown(challenge = getSavedChallengeStateSync()) {
  if (isDevSafeMode()) return false;

  const isDev = isDevEnvironment();
  const allowRealEnforcement = process.env.NETFAST_ALLOW_REAL_ENFORCEMENT === 'true';
  if (isDev && allowRealEnforcement) return true;

  return challenge?.status === 'active';
}

function logStartupEnforcementPolicy(challenge = getSavedChallengeStateSync()) {
  logger.info('STARTUP', 'Enforcement policy', {
    env: process.env.NODE_ENV || 'production',
    NETFAST_DISABLE_ENFORCEMENT: process.env.NETFAST_DISABLE_ENFORCEMENT || 'unset',
    NETFAST_ALLOW_REAL_ENFORCEMENT: process.env.NETFAST_ALLOW_REAL_ENFORCEMENT || 'unset',
    devSafeMode: isDevSafeMode(),
    realEnforcementAllowed: shouldRunStartupLockdown(challenge),
    challengeStatus: challenge?.status || 'none',
    challengeId: challenge?.id || null,
  });

  if (isDevSafeMode()) {
    logger.info('DEV_SAFE', 'Real enforcement disabled. Skipping DNS/firewall/browser lockdown.');
  } else if (!shouldRunStartupLockdown(challenge)) {
    logger.info('STARTUP', 'No active challenge — skipping lockdown.');
  } else if (isDevEnvironment() && process.env.NETFAST_ALLOW_REAL_ENFORCEMENT === 'true') {
    logger.warn('DEV_ENFORCE', 'REAL ENFORCEMENT ENABLED — system DNS/firewall/browser settings will be modified.');
  }
}

function markRealEnforcementApplied() {
  realEnforcementApplied = true;
}

function wasRealEnforcementApplied() {
  return realEnforcementApplied;
}

function shouldRunQuitCleanup() {
  return wasRealEnforcementApplied() && isRealEnforcementAllowed('quit-cleanup');
}

module.exports = {
  isDevEnvironment,
  isDevSafeMode,
  isRealEnforcementAllowed,
  assertRealEnforcementAllowed,
  shouldRunStartupLockdown,
  logStartupEnforcementPolicy,
  markRealEnforcementApplied,
  wasRealEnforcementApplied,
  shouldRunQuitCleanup,
};
