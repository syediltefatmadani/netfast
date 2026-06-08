const logger = require('./logger');
const { FILTER_TESTS } = require('./services/dns/filterTests');
const { evaluateDomainProtection } = require('./services/dns');
const { verifyFirewall, BYPASS_RESOLVERS } = require('./firewall');
const { isDeveloperLikeMode } = require('./policyMode');

const DEV_SERVICE_DOMAINS = ['registry.npmjs.org', 'github.com'];

async function checkDomainAllowed(domain) {
  const evaluation = await evaluateDomainProtection(domain, {
    expectedRestricted: false,
    category: 'safe',
    checkHttps: false,
    applyFallbackOnMiss: false,
  });
  return {
    domain,
    allowed: !evaluation.finalBlocked,
    dohReachable: evaluation.dohReachable,
    error: evaluation.error,
  };
}

async function checkDomainBlocked(domain) {
  const evaluation = await evaluateDomainProtection(domain, {
    expectedRestricted: true,
    category: 'adult',
    checkHttps: false,
    applyFallbackOnMiss: true,
  });
  return {
    domain,
    blocked: evaluation.finalBlocked,
    blockedBy: evaluation.blockedBy,
    error: evaluation.error,
  };
}

function checkBypassResolversBlocked() {
  const fw = verifyFirewall();
  return {
    bypassResolversBlocked: Boolean(fw.bypassResolversBlocked),
    firewallCoreLocked: Boolean(fw.firewallCoreLocked),
    missingBypass: fw.missingBypass || [],
    resolverCount: BYPASS_RESOLVERS.length,
  };
}

async function validateDeveloperMode() {
  if (!isDeveloperLikeMode()) {
    return { skipped: true, ok: true };
  }

  const results = {
    safeDomainsAllowed: [],
    adultDomainsBlocked: [],
    devServicesReachable: [],
    bypassResolversBlocked: null,
    ok: true,
    errors: [],
  };

  for (const domain of FILTER_TESTS.safeAllowed) {
    const check = await checkDomainAllowed(domain);
    results.safeDomainsAllowed.push(check);
    if (!check.allowed) {
      results.ok = false;
      results.errors.push(`${domain} should be allowed in developer mode`);
    }
  }

  for (const domain of FILTER_TESTS.knownAdultBlocked.slice(0, 1)) {
    const check = await checkDomainBlocked(domain);
    results.adultDomainsBlocked.push(check);
    if (!check.blocked) {
      results.ok = false;
      results.errors.push(`${domain} must remain blocked in developer mode`);
    }
  }

  const bypass = checkBypassResolversBlocked();
  results.bypassResolversBlocked = bypass;
  if (!bypass.bypassResolversBlocked) {
    results.ok = false;
    results.errors.push('Known bypass DNS resolvers are not fully blocked');
  }

  for (const domain of DEV_SERVICE_DOMAINS) {
    const check = await checkDomainAllowed(domain);
    results.devServicesReachable.push(check);
    if (!check.allowed) {
      results.errors.push(`Developer service ${domain} not reachable via protection layers`);
    }
  }

  if (results.ok) {
    logger.info('DEV_MODE', 'Restricted content validation passed');
  } else {
    logger.warn('DEV_MODE', 'Developer mode validation issues', { errors: results.errors });
  }

  return results;
}

module.exports = {
  validateDeveloperMode,
  checkDomainAllowed,
  checkDomainBlocked,
  checkBypassResolversBlocked,
};
