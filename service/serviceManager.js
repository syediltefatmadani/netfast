const crypto = require('crypto');
const { INTERVALS, FILES, SERVICE_VERSION, QUEUE } = require('./config/serviceConfig');
const { readJson, writeJson } = require('./storage/localStateStore');
const serviceState = require('./storage/serviceState');
const logger = require('./logging/serviceLogger');

const dnsMonitor = require('./monitors/dnsMonitor');
const vpnMonitor = require('./monitors/vpnMonitor');
const hostsMonitor = require('./monitors/hostsMonitor');
const dohMonitor = require('./monitors/dohMonitor');
const virtualizationMonitor = require('./monitors/virtualizationMonitor');
const challengeMonitor = require('./monitors/challengeMonitor');

const heartbeatClient = require('./sync/heartbeatClient');
const { OVERALL_STATUS } = require('../shared/types/monitoring');
const { VIOLATION_TYPE, SEVERITY } = require('../shared/types/violation');
const { emptyHeartbeat } = require('../shared/types/heartbeat');

/**
 * ServiceManager — the single owner of NetFastService's monitoring lifecycle.
 *
 * It is the ONLY place that schedules timers, guaranteeing no duplicate intervals
 * ever stack up. It runs in two modes:
 *   - idle   (no active challenge): only a lightweight health tick + challenge
 *            sync run, so CPU stays near zero.
 *   - active (challenge active): the full Phase 2 schedule (DNS/VPN/DoH/hosts/
 *            virtualization checks, heartbeats, offline-queue flush).
 *
 * Checks are state-change driven: a monitor result only produces a log line or a
 * violation when it differs from the last known state, never on every tick.
 */

const RECENT_VIOLATIONS_MAX = 50;

let running = false;
const timers = new Map();
let hostsWatchStop = null;
let currentMode = 'idle';
let lastCheckAt = null;

// Aggregated protection snapshot (persisted for fast reads + crash recovery).
let protection = readJson(FILES.protectionStatus, null) || emptyProtection();
let recentViolations = (readJson(FILES.violationsQueue, []) || [])
  .map((q) => q.violation)
  .filter(Boolean)
  .slice(-RECENT_VIOLATIONS_MAX);

function emptyProtection() {
  return {
    dnsProtected: true,
    vpnDetected: false,
    dohRiskDetected: false,
    hostsFileHealthy: true,
    virtualizationRiskDetected: false,
    overallStatus: OVERALL_STATUS.UNKNOWN,
    lastCheckedAt: null,
    dns: null,
    vpn: null,
    doh: null,
    hosts: null,
    virtualization: null,
  };
}

// ---------------------------------------------------------------------------
// Timer plumbing — every interval is registered by name so re-registering can
// never create a duplicate (it clears the previous one first).
// ---------------------------------------------------------------------------
function setTimer(name, ms, fn) {
  clearTimer(name);
  const handle = setInterval(() => {
    Promise.resolve()
      .then(fn)
      .catch((e) => logger.error('ERROR', `Timer "${name}" threw`, e.message));
  }, ms);
  if (handle.unref) handle.unref();
  timers.set(name, handle);
}

function clearTimer(name) {
  const h = timers.get(name);
  if (h) {
    clearInterval(h);
    timers.delete(name);
  }
}

function clearMonitorTimers() {
  for (const name of [...timers.keys()]) {
    if (name !== 'serviceHealth' && name !== 'challengeSync') clearTimer(name);
  }
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------
function makeViolation(type, severity, evidence) {
  const s = serviceState.get();
  return {
    id: crypto.randomUUID(),
    userId: s.userId,
    challengeId: s.activeChallengeId,
    deviceId: s.deviceId,
    type,
    severity,
    evidence: Array.isArray(evidence) ? evidence : [String(evidence)],
    detectedAt: new Date().toISOString(),
    syncedAt: null,
  };
}

async function raiseViolation(type, severity, evidence) {
  const violation = makeViolation(type, severity, evidence);
  recentViolations.push(violation);
  if (recentViolations.length > RECENT_VIOLATIONS_MAX) {
    recentViolations = recentViolations.slice(-RECENT_VIOLATIONS_MAX);
  }
  logger.warn('VIOLATION', `${type}: ${violation.evidence.join('; ')}`, { severity });
  const s = serviceState.get();
  // Record (and sync/queue) only when a challenge is active and we have a token;
  // otherwise keep it in the in-memory recent list for visibility but don't spam
  // the backend with violations that have no challenge context.
  if (s.activeChallengeId && s.authToken) {
    try {
      await heartbeatClient.recordViolation(violation, s.authToken);
    } catch (e) {
      logger.warn('VIOLATION', 'recordViolation failed', e.message);
    }
  }
}

// ---------------------------------------------------------------------------
// Individual checks — each updates the protection snapshot and raises a
// violation only on a meaningful transition.
// ---------------------------------------------------------------------------
async function checkDns() {
  const res = await dnsMonitor.check();
  const was = protection.dnsProtected;
  protection.dns = res;
  protection.dnsProtected = res.dnsProtected;
  if (was !== false && res.dnsProtected === false) {
    logger.warn('DNS', 'Status changed: protection no longer detected', { issue: res.issue });
    await raiseViolation(
      VIOLATION_TYPE.DNS_CHANGED,
      SEVERITY.HIGH,
      [res.issue || 'DNS protection not detected'],
    );
  } else if (was === false && res.dnsProtected === true) {
    logger.info('DNS', 'CleanBrowsing protection recovered');
  }
  finalizeCheck();
  return res;
}

async function checkVpn() {
  const res = await vpnMonitor.check();
  const was = protection.vpnDetected;
  protection.vpn = res;
  protection.vpnDetected = res.vpnDetected;
  if (!was && res.vpnDetected) {
    await raiseViolation(VIOLATION_TYPE.VPN_DETECTED, SEVERITY.HIGH, [
      `VPN/tunnel adapter detected: ${res.detectedVpnNames.join(', ') || 'unknown'}`,
    ]);
  } else if (was && !res.vpnDetected) {
    logger.info('VPN', 'Status changed: no VPN/tunnel adapter active');
  }
  finalizeCheck();
  return res;
}

async function checkDoh() {
  const res = await dohMonitor.check();
  const was = protection.dohRiskDetected;
  protection.doh = res;
  protection.dohRiskDetected = res.dohRiskDetected;
  if (!was && res.dohRiskDetected) {
    await raiseViolation(VIOLATION_TYPE.DOH_RISK_DETECTED, SEVERITY.MEDIUM, res.evidence);
  } else if (was && !res.dohRiskDetected) {
    logger.info('DOH', 'Status changed: no DoH risk evidence');
  }
  finalizeCheck();
  return res;
}

async function checkHosts(res = hostsMonitor.check()) {
  const prevHash = protection.hosts?.hash;
  const was = protection.hostsFileHealthy;
  protection.hosts = res;
  protection.hostsFileHealthy = res.hostsFileHealthy;
  const changed = prevHash !== undefined && prevHash !== res.hash;
  if (was !== false && res.hostsFileHealthy === false) {
    await raiseViolation(VIOLATION_TYPE.HOSTS_MODIFIED, SEVERITY.HIGH, [
      `Hosts file integrity issue: ${res.suspiciousEntries.join('; ') || 'modified'}`,
    ]);
  } else if (changed && res.hostsFileHealthy) {
    // Content changed but still healthy — log it (could be a legitimate edit).
    logger.info('HOSTS', 'Hosts file changed (no suspicious entries)');
  } else if (was === false && res.hostsFileHealthy) {
    logger.info('HOSTS', 'Hosts file integrity restored');
  }
  finalizeCheck();
  return res;
}

async function checkVirtualization() {
  const res = await virtualizationMonitor.check();
  const was = protection.virtualizationRiskDetected;
  protection.virtualization = res;
  protection.virtualizationRiskDetected = res.virtualizationRiskDetected;
  if (!was && res.virtualizationRiskDetected) {
    await raiseViolation(VIOLATION_TYPE.VIRTUALIZATION_DETECTED, SEVERITY.LOW, [
      `Virtualization present: ${res.detectedSystems.join(', ')}`,
    ]);
  }
  finalizeCheck();
  return res;
}

function computeOverall() {
  if (!protection.lastCheckedAt) return OVERALL_STATUS.UNKNOWN;
  if (protection.dnsProtected === false || protection.hostsFileHealthy === false) {
    return OVERALL_STATUS.UNHEALTHY;
  }
  if (
    protection.vpnDetected ||
    protection.dohRiskDetected ||
    protection.virtualizationRiskDetected
  ) {
    return OVERALL_STATUS.WARNINGS;
  }
  return OVERALL_STATUS.HEALTHY;
}

function finalizeCheck() {
  lastCheckAt = new Date().toISOString();
  protection.lastCheckedAt = lastCheckAt;
  protection.overallStatus = computeOverall();
  try {
    writeJson(FILES.protectionStatus, protection);
  } catch {
    /* best-effort */
  }
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------
function buildHeartbeat() {
  const s = serviceState.get();
  const hb = emptyHeartbeat();
  return {
    ...hb,
    userId: s.userId,
    challengeId: s.activeChallengeId,
    deviceId: s.deviceId,
    serviceVersion: SERVICE_VERSION,
    status: challengeMonitor.isActive() ? 'active' : 'idle',
    dnsProtected: protection.dnsProtected,
    vpnDetected: protection.vpnDetected,
    dohRiskDetected: protection.dohRiskDetected,
    hostsFileHealthy: protection.hostsFileHealthy,
    virtualizationRiskDetected: protection.virtualizationRiskDetected,
    tamperingDetected: protection.hostsFileHealthy === false,
    lastViolationAt: recentViolations.length
      ? recentViolations[recentViolations.length - 1].detectedAt
      : null,
    timestamp: new Date().toISOString(),
  };
}

async function sendHeartbeat() {
  if (!challengeMonitor.isActive()) return;
  const s = serviceState.get();
  const payload = buildHeartbeat();
  await heartbeatClient.sendHeartbeat(payload, s.authToken);
  serviceState.update({ lastHeartbeatAt: payload.timestamp });
}

async function flushQueues() {
  const s = serviceState.get();
  try {
    await heartbeatClient.flush(s.authToken);
  } catch (e) {
    logger.warn('SYNC', 'Queue flush failed', e.message);
  }
}

// ---------------------------------------------------------------------------
// Scheduling / mode management
// ---------------------------------------------------------------------------
async function runChallengeSync() {
  await challengeMonitor.sync();
  reconcileMode();
}

/** Switch the active timer set to match the current challenge status. */
function reconcileMode() {
  const desired = challengeMonitor.isActive() ? 'active' : 'idle';
  if (desired === currentMode && running) return;
  currentMode = desired;

  clearMonitorTimers();
  if (desired === 'active') {
    logger.info('SERVICE', 'Entering ACTIVE monitoring mode (challenge active)');
    setTimer('dns', INTERVALS.dnsVerificationMs, checkDns);
    setTimer('vpn', INTERVALS.vpnDetectionMs, checkVpn);
    setTimer('doh', INTERVALS.dohRiskMs, checkDoh);
    setTimer('hostsFallback', INTERVALS.hostsFallbackMs, () => checkHosts());
    setTimer('virtualization', INTERVALS.virtualizationMs, checkVirtualization);
    setTimer('heartbeat', INTERVALS.heartbeatMs, sendHeartbeat);
    setTimer('offlineFlush', INTERVALS.offlineFlushMs, flushQueues);
    // Kick off an immediate full pass so status is fresh as soon as a challenge starts.
    manualCheck().catch((e) => logger.error('ERROR', 'Initial active check failed', e.message));
    sendHeartbeat().catch(() => {});
  } else {
    logger.info('SERVICE', 'Entering IDLE mode (no active challenge)');
    // Idle keeps only the hosts watch (cheap, event-driven) for integrity, plus
    // the always-on serviceHealth + challengeSync timers.
  }
}

async function serviceHealthTick() {
  // Lightweight liveness tick. Keeps lastCheckAt warm and lets us notice an
  // unreadable hosts file even while idle, without any expensive system calls.
  if (currentMode === 'idle') {
    protection.lastCheckedAt = new Date().toISOString();
  }
}

function start() {
  if (running) {
    logger.info('SERVICE', 'start() ignored — already running');
    return getStatus();
  }
  running = true;
  serviceState.load();
  logger.info('SERVICE', 'NetFastService monitoring starting', { version: SERVICE_VERSION });

  // Always-on timers (run in both modes).
  setTimer('serviceHealth', INTERVALS.serviceHealthMs, serviceHealthTick);
  setTimer('challengeSync', INTERVALS.challengeSyncMs, runChallengeSync);

  // Event-driven hosts integrity watch (debounced) — runs in idle + active.
  hostsWatchStop = hostsMonitor.startWatch((res) => {
    checkHosts(res).catch((e) => logger.error('ERROR', 'Hosts change handler failed', e.message));
  });

  // Establish initial mode + an initial challenge sync.
  runChallengeSync().catch((e) => logger.error('ERROR', 'Initial challenge sync failed', e.message));
  reconcileMode();
  return getStatus();
}

function stop() {
  if (!running) return getStatus();
  running = false;
  for (const name of [...timers.keys()]) clearTimer(name);
  if (typeof hostsWatchStop === 'function') {
    try {
      hostsWatchStop();
    } catch {
      /* already stopped */
    }
    hostsWatchStop = null;
  }
  serviceState.flush();
  logger.info('SERVICE', 'NetFastService monitoring stopped');
  return getStatus();
}

/** Run every monitor once, regardless of mode (used by POST /monitoring/check-now). */
async function manualCheck() {
  logger.info('SERVICE', 'Manual verification requested');
  await Promise.allSettled([
    checkDns(),
    checkVpn(),
    checkDoh(),
    checkHosts(),
    checkVirtualization(),
  ]);
  return getProtectionStatus();
}

// ---------------------------------------------------------------------------
// Status readers (consumed by the HTTP API)
// ---------------------------------------------------------------------------
function getStatus() {
  const s = serviceState.get();
  const q = heartbeatClient.queueSizes();
  return {
    serviceRunning: running,
    serviceVersion: SERVICE_VERSION,
    challengeId: s.activeChallengeId,
    challengeStatus: s.challengeStatus,
    monitoringActive: currentMode === 'active',
    lastHeartbeatAt: s.lastHeartbeatAt,
    lastCheckAt,
    serviceStartedAt: s.serviceStartedAt,
    queuedHeartbeats: q.heartbeats,
    queuedViolations: q.violations,
  };
}

function getProtectionStatus() {
  return {
    dnsProtected: protection.dnsProtected,
    vpnDetected: protection.vpnDetected,
    dohRiskDetected: protection.dohRiskDetected,
    hostsFileHealthy: protection.hostsFileHealthy,
    virtualizationRiskDetected: protection.virtualizationRiskDetected,
    overallStatus: protection.overallStatus,
    lastCheckedAt: protection.lastCheckedAt,
    details: {
      dns: protection.dns,
      vpn: protection.vpn,
      doh: protection.doh,
      hosts: protection.hosts,
      virtualization: protection.virtualization,
    },
  };
}

function getRecentViolations(limit = 50) {
  return recentViolations.slice(-Math.max(1, limit)).reverse();
}

module.exports = {
  start,
  stop,
  manualCheck,
  startChallenge: (opts) => {
    const snap = challengeMonitor.startChallenge(opts);
    reconcileMode();
    return snap;
  },
  stopChallenge: () => {
    const snap = challengeMonitor.stopChallenge();
    reconcileMode();
    return snap;
  },
  getStatus,
  getProtectionStatus,
  getRecentViolations,
  sendHeartbeatNow: sendHeartbeat,
  isRunning: () => running,
};
