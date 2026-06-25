const { execFile } = require('child_process');
const logger = require('../logging/serviceLogger');

/**
 * Read-only command runner for service monitors.
 *
 * Why this exists instead of reusing electron/powershell.js: that helper gates
 * every PowerShell call behind the enforcement guard and returns MOCK output in
 * dev / when no challenge is active. The service's detection is read-only and
 * harmless (enumerating adapters, reading DNS config), so it must always run the
 * REAL command to report accurate status. This runner therefore never mocks.
 *
 * It also keeps the service lightweight: a short-lived in-memory cache prevents
 * the same expensive query from running multiple times within its TTL, and every
 * call has a hard timeout so a hung child process can never wedge a monitor.
 */

const DEFAULT_TIMEOUT_MS = 15000;
const cache = new Map();

function now() {
  return Date.now();
}

/** Run an arbitrary executable; resolves with trimmed stdout, rejects on error. */
function run(file, args, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      { encoding: 'utf8', timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          err.stdout = (stdout || '').toString();
          err.stderr = (stderr || '').toString();
          reject(err);
          return;
        }
        resolve((stdout || '').toString().trim());
      },
    );
  });
}

/** Run a PowerShell script via -EncodedCommand (UTF-16LE base64) — no profile. */
function runPowerShell(script, opts = {}) {
  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return run('powershell', ['-NoProfile', '-NonInteractive', '-EncodedCommand', b64], opts);
}

/**
 * Cache wrapper: run `producer()` at most once per `ttlMs` for a given key.
 * Concurrent callers within the window share the same in-flight promise.
 */
async function cached(key, ttlMs, producer) {
  const hit = cache.get(key);
  if (hit && now() - hit.at < ttlMs) {
    return hit.inflight ? hit.inflight : hit.value;
  }

  const inflight = Promise.resolve()
    .then(producer)
    .then((value) => {
      cache.set(key, { at: now(), value, inflight: null });
      return value;
    })
    .catch((err) => {
      cache.delete(key);
      throw err;
    });

  cache.set(key, { at: now(), value: hit?.value, inflight });
  return inflight;
}

function invalidate(key) {
  if (key) cache.delete(key);
  else cache.clear();
}

/** Parse PowerShell ConvertTo-Json output (single object or array) safely. */
function parseJsonList(out) {
  const text = (out || '').trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    logger.warn('SERVICE', 'Failed to parse command JSON', e.message);
    return [];
  }
}

module.exports = { run, runPowerShell, cached, invalidate, parseJsonList };
