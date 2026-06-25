const backend = require('./backendClient');
const { OfflineQueue } = require('./offlineQueue');
const { FILES, QUEUE } = require('../config/serviceConfig');
const logger = require('../logging/serviceLogger');

/**
 * Coordinates outbound sync: heartbeats and violations. Tries to send
 * immediately; on an offline/transient failure the item is persisted to its
 * offline queue and retried on the next flush. This is the only place that
 * touches both queues, keeping the rest of the service oblivious to retry logic.
 */

const heartbeatQueue = new OfflineQueue(FILES.heartbeatQueue, QUEUE.maxHeartbeats, 'heartbeat');
const violationQueue = new OfflineQueue(FILES.violationsQueue, QUEUE.maxViolations, 'violation');

/** Send a heartbeat now; queue it if the backend is unreachable. */
async function sendHeartbeat(payload, authToken) {
  const res = await backend.sendHeartbeat(payload, authToken);
  if (res.ok) {
    logger.info('HEARTBEAT', 'Heartbeat sent', { challengeId: payload.challengeId });
    return { sent: true, queued: false };
  }
  if (res.offline) {
    heartbeatQueue.enqueue({ id: `hb_${payload.timestamp}`, payload });
    logger.warn('HEARTBEAT', 'Backend offline — heartbeat queued', {
      queued: heartbeatQueue.size(),
    });
    return { sent: false, queued: true };
  }
  // Non-offline failure (e.g. no token yet / 4xx): still queue so an active
  // challenge's heartbeats aren't silently lost while auth is being set up.
  heartbeatQueue.enqueue({ id: `hb_${payload.timestamp}`, payload });
  logger.warn('HEARTBEAT', 'Heartbeat not accepted — queued', { status: res.status, error: res.error });
  return { sent: false, queued: true };
}

/** Record a violation: attempt immediate send, queue on failure. */
async function recordViolation(violation, authToken) {
  const res = await backend.sendViolation(violation, authToken);
  if (res.ok) {
    logger.info('VIOLATION', `Synced ${violation.type}`, { id: violation.id });
    return { sent: true, queued: false };
  }
  violationQueue.enqueue({ id: violation.id, violation });
  logger.warn('VIOLATION', `Could not sync ${violation.type} — queued`, {
    offline: res.offline,
    queued: violationQueue.size(),
  });
  return { sent: false, queued: true };
}

/** Flush both queues if the backend is reachable. Returns counts. */
async function flush(authToken) {
  if (heartbeatQueue.size() === 0 && violationQueue.size() === 0) {
    return { heartbeats: 0, violations: 0, skipped: true };
  }
  const reachable = await backend.isReachable();
  if (!reachable) {
    return { heartbeats: 0, violations: 0, skipped: true, offline: true };
  }
  const v = await violationQueue.flush((item) => backend.sendViolation(item.violation, authToken));
  const h = await heartbeatQueue.flush((item) => backend.sendHeartbeat(item.payload, authToken));
  return { heartbeats: h.flushed, violations: v.flushed, skipped: false };
}

function queueSizes() {
  return { heartbeats: heartbeatQueue.size(), violations: violationQueue.size() };
}

module.exports = { sendHeartbeat, recordViolation, flush, queueSizes };
