const PREFIX = '[NetFast]';

// In-memory ring buffer so the renderer can pull recent structured logs over IPC
// (monitoring:getLogs) without tailing a file. Bounded so it can never grow
// unboundedly while the app runs in the background.
const RING_CAPACITY = 500;
const ring = [];

function pushRing(level, tag, message, detail) {
  ring.push({
    ts: Date.now(),
    level,
    tag,
    message,
    detail: detail === undefined ? undefined : safeDetail(detail),
  });
  if (ring.length > RING_CAPACITY) ring.splice(0, ring.length - RING_CAPACITY);
}

// Details can contain circular refs (e.g. error objects); keep the ring buffer
// JSON-serialisable so it survives the IPC boundary.
function safeDetail(detail) {
  if (detail === null || typeof detail !== 'object') return detail;
  try {
    return JSON.parse(JSON.stringify(detail));
  } catch {
    return String(detail);
  }
}

function stamp() {
  return new Date().toISOString();
}

function log(level, tag, message, detail) {
  pushRing(level, tag, message, detail);
  const head = `${PREFIX} ${stamp()} [${tag}] ${message}`;
  if (detail !== undefined) {
    console[level](head, detail);
  } else {
    console[level](head);
  }
}

module.exports = {
  info: (tag, message, detail) => log('log', tag, message, detail),
  warn: (tag, message, detail) => log('warn', tag, message, detail),
  error: (tag, message, detail) => log('error', tag, message, detail),
  execError: (tag, message, err) => {
    const detail = {
      message: err.message,
      stderr: err.stderr?.toString?.()?.trim() || undefined,
      stdout: err.stdout?.toString?.()?.trim() || undefined,
      status: err.status,
    };
    if (detail.stderr?.toLowerCase().includes('elevation')) {
      detail.hint = 'Run NetFast as Administrator to change system DNS and tunnel settings.';
    }
    log('error', tag, message, detail);
  },
  /** Most-recent-last list of recent log entries (optionally filtered by tag). */
  getRecentLogs: (limit = 200, tags = null) => {
    const tagSet = Array.isArray(tags) && tags.length ? new Set(tags) : null;
    const filtered = tagSet ? ring.filter((e) => tagSet.has(e.tag)) : ring;
    return filtered.slice(-Math.max(1, limit));
  },
};
