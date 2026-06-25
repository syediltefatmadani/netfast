const logger = require('../logger');
const { startNetworkWatch, runWatchCheck, setWatchFastFallback } = require('../networkWatch');
const { startTamperWatch } = require('../tamperWatch');
const { getDnsHealthMonitor } = require('../services/dns');
const { invalidateDnsStatusCache } = require('../dnsStatusCache');
const { getEnforcementStatus } = require('../enforcementState');
const { setNetworkWatchStop } = require('../vpnViolationHandler');
const { broadcast } = require('../rendererBroadcast');

/**
 * MonitorManager — single owner of NetFast's background monitoring lifecycle.
 *
 * The actual detection engines already live in the main process
 * (networkWatch = DNS/hosts/adapter/firewall integrity, tamperWatch = event-driven
 * OS change sensor, DnsHealthMonitor = DoH/filtering health). This manager exists
 * so there is ONE place that starts/stops them, guarantees they are never started
 * twice (which would create duplicate timers + redundant PowerShell), exposes a
 * single status snapshot, and pushes status changes to the renderer over IPC.
 *
 * Monitoring is intentionally event-driven first with slow timer backstops, so it
 * stays near idle while no violation is happening (see RECOMMENDED_INTERVALS for
 * the Phase 1 target cadence each engine satisfies).
 */

// Phase 1 target cadence. The engines below already implement these via an
// event-driven sensor + a 5-minute backstop, so we surface the intent here for
// status/visibility rather than spinning up additional polling loops.
const RECOMMENDED_INTERVALS = {
  dnsVerificationMs: 60 * 1000,
  vpnDetectionMs: 60 * 1000,
  hostsVerificationMs: 30 * 1000,
  challengeSyncMs: 5 * 60 * 1000,
  bypassDetectionMs: 60 * 1000,
};

let running = false;
let networkWatchStop = null;
let tamperStop = null;
let lastStatusKey = null;
const statusListeners = new Set();

/** Subscribe a main-process listener (e.g. tray) to status changes. */
function addStatusListener(cb) {
  if (typeof cb === 'function') statusListeners.add(cb);
  return () => statusListeners.delete(cb);
}

/**
 * React to an event from the tamper sensor. A dead sensor falls back to fast
 * polling so detection coverage is never silently lost; all other events trigger
 * an immediate, cooldown-guarded re-verification instead of waiting for the next
 * backstop tick.
 */
function handleTamperEvent({ vector }) {
  if (vector === 'sensor_down') {
    logger.warn('MONITOR', 'Event sensor unavailable — reverting to fast polling backstop');
    setWatchFastFallback(true);
    return;
  }
  logger.info('MONITOR', `Tamper event (${vector}) — re-verifying enforcement`);
  invalidateDnsStatusCache();
  runWatchCheck(`event:${vector}`).catch((e) =>
    logger.error('MONITOR', 'Event-triggered watch check failed', e.message),
  );
}

function start() {
  if (running) {
    // Idempotent: repeated start() calls (e.g. opening/closing the window) must
    // never stack a second set of timers/watchers on top of the live ones.
    logger.info('MONITOR', 'Start requested but monitoring already running — ignoring');
    return getStatus();
  }

  running = true;

  networkWatchStop = startNetworkWatch();
  // Keep the VPN handler in sync so it can stop/restart the same watch without
  // creating a competing instance.
  setNetworkWatchStop(networkWatchStop);

  tamperStop = startTamperWatch({ onTamper: handleTamperEvent });

  getDnsHealthMonitor({
    onStatusChange: (report) => {
      if (!report.healthy) {
        logger.warn('MONITOR', 'Protection inactive', {
          status: report.status,
          details: report.details,
        });
      }
      emitStatus();
    },
  }).start();

  logger.info('MONITOR', 'Background monitoring started', RECOMMENDED_INTERVALS);
  emitStatus(true);
  return getStatus();
}

function stop() {
  if (!running) return getStatus();
  running = false;

  if (typeof networkWatchStop === 'function') {
    try {
      networkWatchStop();
    } catch {
      /* already stopped */
    }
  }
  networkWatchStop = null;
  setNetworkWatchStop(null);

  if (typeof tamperStop === 'function') {
    try {
      tamperStop();
    } catch {
      /* already stopped */
    }
  }
  tamperStop = null;

  try {
    getDnsHealthMonitor().stop();
  } catch {
    /* not started */
  }

  logger.info('MONITOR', 'Background monitoring stopped');
  emitStatus(true);
  return getStatus();
}

function restart() {
  logger.info('MONITOR', 'Restarting monitoring');
  stop();
  return start();
}

function isRunning() {
  return running;
}

function getStatus() {
  const enforcement = getEnforcementStatus();
  let report = null;
  try {
    report = getDnsHealthMonitor().getLastReport();
  } catch {
    /* monitor not yet constructed */
  }

  return {
    running,
    enforcementInProgress: enforcement.inProgress,
    protectionLabel:
      enforcement.protectionLabel || report?.protectionLabel || (running ? 'Monitoring' : 'Not monitoring'),
    healthy: report?.healthy ?? null,
    lastCheckAt: report?.timestamp || null,
    intervals: RECOMMENDED_INTERVALS,
  };
}

/**
 * Broadcast a status snapshot to all renderer windows, but only when something
 * meaningful changed (or force=true) so we never spam identical updates.
 */
function emitStatus(force = false) {
  const status = getStatus();
  const key = `${status.running}|${status.enforcementInProgress}|${status.protectionLabel}|${status.healthy}`;
  if (!force && key === lastStatusKey) return;
  lastStatusKey = key;
  try {
    broadcast('monitoring:statusChanged', status);
  } catch (e) {
    logger.warn('MONITOR', 'Failed to broadcast status change', e.message);
  }
  for (const cb of statusListeners) {
    try {
      cb(status);
    } catch (e) {
      logger.warn('MONITOR', 'Status listener threw', e.message);
    }
  }
}

module.exports = {
  start,
  stop,
  restart,
  isRunning,
  getStatus,
  emitStatus,
  addStatusListener,
  RECOMMENDED_INTERVALS,
};
