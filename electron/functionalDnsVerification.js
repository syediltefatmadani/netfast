const logger = require('./logger');
const { resolveDnsName, resolveDnsNameAsync } = require('./dnsResolve');
const {
  isBlockedARecord,
  isBlockedAAAARecord,
  isRealPublicIpv4,
  isRealPublicIpv6,
} = require('./networkEnforcement');
const { RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS } = require('./services/dns/filterTests');

/** Full diagnostic list (all slow adult domains) — use only for explicit CLI/manual tests. */
const FUNCTIONAL_BLOCKED_DOMAINS = ['reddit.com', 'pornhat.one', 'xvideos.com'];

const CACHE_MS = 30000;
let cachedResult = null;
let cachedAt = 0;

function isNxDomainOrBlockedError(error) {
  const msg = String(error || '').toLowerCase();
  return /dns name does not exist|does not exist|nxdomain|no such host|name does not exist|non-existent domain|could not be found|no records found/i.test(
    msg,
  );
}

function classifyBlockedDomainTest(domain, resolveResult) {
  const records = resolveResult?.records || [];
  const aRecords = records.filter((r) => r.type === 'A').map((r) => r.address);
  const aaaaRecords = records.filter((r) => r.type === 'AAAA').map((r) => r.address);

  const leaked =
    aRecords.some(isRealPublicIpv4) || aaaaRecords.some(isRealPublicIpv6);
  if (leaked) {
    return {
      domain,
      blocked: false,
      result: `leaked: ${[...aRecords, ...aaaaRecords].join(', ')}`,
    };
  }

  if (resolveResult?.timedOut) {
    return { domain, blocked: true, result: 'timeout (treated as blocked)' };
  }

  if (!resolveResult?.ok) {
    const err = resolveResult?.error || 'resolution failed';
    if (isNxDomainOrBlockedError(err)) {
      return { domain, blocked: true, result: err };
    }
    return { domain, blocked: true, result: err };
  }

  if (aRecords.length === 0 && aaaaRecords.length === 0) {
    return { domain, blocked: true, result: 'no A/AAAA records' };
  }

  const sinkholed =
    (aRecords.length === 0 || aRecords.every(isBlockedARecord)) &&
    (aaaaRecords.length === 0 || aaaaRecords.every(isBlockedAAAARecord));
  if (sinkholed) {
    const addrs = [...aRecords, ...aaaaRecords].filter(Boolean);
    return {
      domain,
      blocked: true,
      result: addrs.length ? `sinkholed: ${addrs.join(', ')}` : 'no usable records',
    };
  }

  return {
    domain,
    blocked: false,
    result: `resolved: ${[...aRecords, ...aaaaRecords].join(', ')}`,
  };
}

function runFunctionalDnsVerification({
  timeoutSec = 8,
  domains = RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS,
  force = false,
} = {}) {
  if (!force && cachedResult && Date.now() - cachedAt < CACHE_MS) {
    return cachedResult;
  }

  const blockedDomainTests = [];
  for (const domain of domains) {
    const resolveResult = resolveDnsName(domain, { timeoutSec });
    blockedDomainTests.push(classifyBlockedDomainTest(domain, resolveResult));
  }

  return buildFunctionalResult(blockedDomainTests);
}

function buildFunctionalResult(blockedDomainTests, { runtimeMode = true } = {}) {
  const functionalDnsProtection =
    blockedDomainTests.length > 0 && blockedDomainTests.every((t) => t.blocked);

  const result = {
    functionalDnsProtection,
    blockedDomainTests,
    passed: functionalDnsProtection,
    testedAt: Date.now(),
    runtimeMode,
    skippedAdultProbes: runtimeMode,
  };

  logger.info('DNS', 'Functional DNS verification', {
    functionalDnsProtection,
    tests: blockedDomainTests.map((t) => ({ domain: t.domain, blocked: t.blocked, result: t.result })),
  });

  cachedResult = result;
  cachedAt = Date.now();
  return result;
}

/** Non-blocking variant — resolves the probe domains off the main thread. */
async function runFunctionalDnsVerificationAsync({
  timeoutSec = 8,
  domains = RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS,
  force = false,
} = {}) {
  if (!force && cachedResult && Date.now() - cachedAt < CACHE_MS) {
    return cachedResult;
  }

  const blockedDomainTests = [];
  for (const domain of domains) {
    const resolveResult = await resolveDnsNameAsync(domain, { timeoutSec });
    blockedDomainTests.push(classifyBlockedDomainTest(domain, resolveResult));
  }

  return buildFunctionalResult(blockedDomainTests);
}

function invalidateFunctionalDnsCache() {
  cachedResult = null;
  cachedAt = 0;
}

module.exports = {
  FUNCTIONAL_BLOCKED_DOMAINS,
  RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS,
  classifyBlockedDomainTest,
  runFunctionalDnsVerification,
  runFunctionalDnsVerificationAsync,
  invalidateFunctionalDnsCache,
};
