const logger = require('./logger');
const { verifyDNS, verifyDNSAsync } = require('./dns');
const { getEnforcementStatus } = require('./enforcementState');
const { getMockVerifyDnsResult } = require('./mockEnforcement');
const { isRealEnforcementAllowed } = require('./enforcementGuard');
const { broadcast } = require('./rendererBroadcast');

const CACHE_MS = 20000;

let cached = null;
let cachedAt = 0;
let verifyInflight = null;

let lastCheck = null;
let lastCheckAt = 0;
let vectorInflight = null;

/**
 * Renderer signal: a background revalidation just produced fresh data. The
 * renderer re-fetches via the normal IPC handlers, which now return instantly
 * from cache (no PowerShell on the request path). Kept payload-free so this
 * module stays decoupled from the UI status shape built in ipc.js.
 */
function emitStatusRefreshed() {
  try {
    broadcast('status-refreshed');
  } catch {
    /* no windows yet */
  }
}

function invalidateDnsStatusCache() {
  cached = null;
  cachedAt = 0;
  lastCheck = null;
  lastCheckAt = 0;
  try {
    require('./functionalDnsVerification').invalidateFunctionalDnsCache();
  } catch {
    /* optional */
  }
}

function enforcementInProgressResult() {
  const enforcement = getEnforcementStatus();
  if (cached) return cached;
  if (enforcement.lockdown) return enforcement.lockdown;
  if (!isRealEnforcementAllowed('verifyDNS-cache')) return getMockVerifyDnsResult();
  return {
    dnsApplied: false,
    ipv4Locked: false,
    ipv6Locked: false,
    functionalDnsProtection: false,
    blockedDomainTests: [],
    firewallLocked: false,
    dohConfigured: false,
    rogueServers: [],
    dnsIntegrity: false,
    protectionLabel: 'Applying protection...',
  };
}

function isVerifyFresh() {
  return cached && Date.now() - cachedAt < CACHE_MS;
}

/** Single-flight async refresh of the DNS verify snapshot. */
function refreshVerifyDns() {
  if (verifyInflight) return verifyInflight;
  const compute = isRealEnforcementAllowed('verifyDNS')
    ? verifyDNSAsync()
    : Promise.resolve(getMockVerifyDnsResult());
  verifyInflight = compute
    .then((result) => {
      cached = result;
      cachedAt = Date.now();
      emitStatusRefreshed();
      return result;
    })
    .catch((e) => {
      logger.warn('DNS_CACHE', 'Background DNS verify refresh failed', e.message);
      return cached;
    })
    .finally(() => {
      verifyInflight = null;
    });
  return verifyInflight;
}

/**
 * Immediate (non-blocking) snapshot for the IPC path: serves cached/stale data
 * right away and revalidates in the background. Falls back to verifyDNS() (sync)
 * only on a true cold start where no cached value exists yet — that single first
 * call accepts the cost so the handler still has data to return.
 */
function getVerifyDnsCached({ force = false } = {}) {
  const enforcement = getEnforcementStatus();
  if (enforcement.inProgress) return enforcementInProgressResult();

  if (!force && isVerifyFresh()) return cached;

  // Stale or forced but we have data: serve it now, revalidate in background.
  if (cached) {
    refreshVerifyDns();
    return cached;
  }

  // Cold start: kick the async refresh and synchronously seed the cache once so
  // the very first IPC reply is real. Subsequent calls are always served async.
  refreshVerifyDns();
  cached = isRealEnforcementAllowed('verifyDNS') ? verifyDNS() : getMockVerifyDnsResult();
  cachedAt = Date.now();
  return cached;
}

/**
 * Async snapshot — awaits the first compute on a cold cache (off the main
 * thread), otherwise behaves like getVerifyDnsCached (instant + background
 * revalidate). Preferred by IPC handlers.
 */
async function getVerifyDnsCachedAsync({ force = false } = {}) {
  const enforcement = getEnforcementStatus();
  if (enforcement.inProgress) return enforcementInProgressResult();

  if (!force && isVerifyFresh()) return cached;
  if (cached) {
    refreshVerifyDns();
    return cached;
  }
  return refreshVerifyDns();
}

function cacheVectorStatus(vectors) {
  lastCheck = { ...(lastCheck || {}), vectors };
  lastCheckAt = Date.now();
}

function getCachedVectorStatus() {
  if (!lastCheck?.vectors) return null;
  if (Date.now() - lastCheckAt > CACHE_MS * 2) return null;
  return lastCheck.vectors;
}

function isVectorFresh() {
  return lastCheck && Date.now() - lastCheckAt < CACHE_MS;
}

/** Single-flight async refresh of the full watchdog check (vectors + health). */
function refreshVectorStatus() {
  if (vectorInflight) return vectorInflight;
  const { runFullCheckAsync } = require('./watchdog');
  vectorInflight = runFullCheckAsync()
    .then((check) => {
      lastCheck = check;
      lastCheckAt = Date.now();
      emitStatusRefreshed();
      return check;
    })
    .catch((e) => {
      logger.warn('DNS_CACHE', 'Background vector refresh failed', e.message);
      return lastCheck;
    })
    .finally(() => {
      vectorInflight = null;
    });
  return vectorInflight;
}

/**
 * Async full-check snapshot for the vector-status IPC path. Returns the complete
 * runFullCheck result (vectors + dnsHealth + battery) so callers keep their
 * auto-restore logic. Serves the cached check instantly when fresh and
 * revalidates in the background; awaits the run only on a cold cache.
 */
async function getVectorCheckCachedAsync({ force = false } = {}) {
  if (!force && isVectorFresh()) return lastCheck;
  if (lastCheck) {
    refreshVectorStatus();
    return lastCheck;
  }
  return refreshVectorStatus();
}

module.exports = {
  getVerifyDnsCached,
  getVerifyDnsCachedAsync,
  invalidateDnsStatusCache,
  cacheVectorStatus,
  getCachedVectorStatus,
  getVectorCheckCachedAsync,
  refreshVerifyDns,
  refreshVectorStatus,
  CACHE_MS,
};
