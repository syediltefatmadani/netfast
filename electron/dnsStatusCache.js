const { verifyDNS } = require('./dns');
const { getEnforcementStatus } = require('./enforcementState');
const { getMockVerifyDnsResult } = require('./mockEnforcement');
const { isRealEnforcementAllowed } = require('./enforcementGuard');

const CACHE_MS = 20000;
let cached = null;
let cachedAt = 0;
let lastVectors = null;
let lastVectorsAt = 0;

function invalidateDnsStatusCache() {
  cached = null;
  cachedAt = 0;
  lastVectors = null;
  lastVectorsAt = 0;
  try {
    require('./functionalDnsVerification').invalidateFunctionalDnsCache();
  } catch {
    /* optional */
  }
}

function getVerifyDnsCached({ force = false } = {}) {
  const enforcement = getEnforcementStatus();

  if (enforcement.inProgress) {
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

  if (!force && cached && Date.now() - cachedAt < CACHE_MS) {
    return cached;
  }

  if (!isRealEnforcementAllowed('verifyDNS')) {
    cached = getMockVerifyDnsResult();
  } else {
    cached = verifyDNS();
  }
  cachedAt = Date.now();
  return cached;
}

function cacheVectorStatus(vectors) {
  lastVectors = vectors;
  lastVectorsAt = Date.now();
}

function getCachedVectorStatus() {
  if (!lastVectors) return null;
  if (Date.now() - lastVectorsAt > CACHE_MS * 2) return null;
  return lastVectors;
}

module.exports = {
  getVerifyDnsCached,
  invalidateDnsStatusCache,
  cacheVectorStatus,
  getCachedVectorStatus,
  CACHE_MS,
};
