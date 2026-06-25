const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const logger = require('../logging/serviceLogger');

/**
 * Hosts file monitor — integrity of C:\Windows\System32\drivers\etc\hosts.
 *
 * Uses efficient event-driven watching (fs.watch, debounced) plus a periodic
 * fallback check from the scheduler, so we never poll the file aggressively.
 * Reports a content hash + last-modified time so the manager can detect a change
 * and raise a `hosts_modified` violation, and flags suspicious entries that
 * redirect hostnames to remote (non-loopback) IPs — the classic trick for
 * faking a "blocked site is unreachable" check.
 */

const HOSTS_PATH =
  process.env.NETFAST_HOSTS_PATH ||
  path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');

const DEBOUNCE_MS = 1500;

function hashContent(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function isLoopbackOrZero(ip) {
  return (
    ip === '127.0.0.1' ||
    ip === '0.0.0.0' ||
    ip === '::1' ||
    ip === '::' ||
    ip.startsWith('127.')
  );
}

// Hostnames commonly mapped to a LAN IP by legitimate tooling (Docker Desktop,
// etc.). These are reported elsewhere (virtualization monitor) and are not a
// browsing-bypass signal, so we don't flag them as suspicious hosts edits.
const BENIGN_HOSTNAME = /(^|\.)docker\.internal$|^kubernetes\.docker\.internal$/i;

/** Lines that map a *non-benign* hostname to a *remote* IP look like a redirect. */
function findSuspiciousEntries(content) {
  const suspicious = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const ip = parts[0];
    if (isLoopbackOrZero(ip)) continue;
    const hostnames = parts.slice(1).filter((h) => !h.startsWith('#'));
    const allBenign = hostnames.length > 0 && hostnames.every((h) => BENIGN_HOSTNAME.test(h));
    if (!allBenign) suspicious.push(line);
  }
  return suspicious;
}

function check() {
  const lastCheckedAt = new Date().toISOString();
  try {
    const stat = fs.statSync(HOSTS_PATH);
    const content = fs.readFileSync(HOSTS_PATH, 'utf8');
    const suspiciousEntries = findSuspiciousEntries(content);
    return {
      hostsFileHealthy: suspiciousEntries.length === 0,
      hash: hashContent(content),
      lastModifiedAt: stat.mtime.toISOString(),
      suspiciousEntries,
      lastCheckedAt,
    };
  } catch (e) {
    logger.warn('HOSTS', 'Could not read hosts file', e.message);
    return {
      hostsFileHealthy: false,
      hash: '',
      lastModifiedAt: null,
      suspiciousEntries: [`unreadable: ${e.message}`],
      lastCheckedAt,
    };
  }
}

/**
 * Watch the hosts file for changes. Returns a stop() function. The callback is
 * debounced so a burst of fs events (editors often write twice) yields one
 * re-check.
 */
function startWatch(onChange) {
  let timer = null;
  let watcher = null;
  const fire = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try {
        onChange(check());
      } catch (e) {
        logger.warn('HOSTS', 'Watch callback failed', e.message);
      }
    }, DEBOUNCE_MS);
  };

  try {
    watcher = fs.watch(HOSTS_PATH, { persistent: false }, fire);
    watcher.on('error', (e) => logger.warn('HOSTS', 'File watcher error', e.message));
    logger.info('HOSTS', 'Watching hosts file for changes', { path: HOSTS_PATH });
  } catch (e) {
    logger.warn('HOSTS', 'Could not watch hosts file (fallback polling only)', e.message);
  }

  return () => {
    clearTimeout(timer);
    if (watcher) {
      try {
        watcher.close();
      } catch {
        /* already closed */
      }
    }
  };
}

module.exports = { check, startWatch, HOSTS_PATH, name: 'hosts' };
