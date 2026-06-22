const { queryCleanBrowsingDoH, pingCleanBrowsingDoH } = require('./dohHealth');
const { FILTER_TESTS, expandDomainVariants } = require('./filterTests');

const STATUS_MESSAGES = {
  blocked_by_doh: 'Blocked by CleanBrowsing DoH',
  blocked_by_fallback:
    'Blocked by local fallback — CleanBrowsing provider miss detected',
  allowed: 'Allowed',
  error: 'Protection check error',
  not_blocked_critical: 'Not blocked — provider miss and fallback failed',
  degraded_fallback:
    'Protected with warning — DoH health unreachable, fallback active',
};

function useHostsBlockEnabled() {
  return getHostsHelpers().isHostsFileEnforcementEnabled() && getHostsHelpers().useHostsBlocklist();
}

function getHostsHelpers() {
  return require('../../hosts');
}

function domainListedInHosts(domain) {
  if (!useHostsBlockEnabled()) return false;
  try {
    const { getHostsPath, MARKER_BEGIN, MARKER_END } = getHostsHelpers();
    const fs = require('fs');
    const hostsPath = getHostsPath();
    if (!fs.existsSync(hostsPath)) return false;
    const content = fs.readFileSync(hostsPath, 'utf8');
    const begin = content.indexOf(MARKER_BEGIN);
    const end = content.indexOf(MARKER_END);
    if (begin === -1 || end === -1) return false;
    const section = content.slice(begin, end).toLowerCase();
    const variants = expandDomainVariants(domain);
    return variants.some((v) => {
      const re = new RegExp(`\\s${v.replace(/\./g, '\\.')}(\\s|$)`, 'i');
      return re.test(section);
    });
  } catch {
    return false;
  }
}

function systemResolverBlocks(domain) {
  const { runEncoded } = require('../../powershell');
  const script = `
$domain = '${domain.replace(/'/g, "''")}'
try {
  $addrs = [System.Net.Dns]::GetHostAddresses($domain)
  ($addrs | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
} catch {
  'ERR:' + $_.Exception.GetType().Name
}
`;
  try {
    const out = runEncoded(script).trim();
    if (!out || /^ERR:/i.test(out)) return true;
    const addrs = out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!addrs.length) return true;
    return addrs.every((a) => {
      const lower = a.toLowerCase();
      return (
        lower === '0.0.0.0' ||
        lower === '127.0.0.1' ||
        lower === '::' ||
        lower === '::1'
      );
    });
  } catch {
    return false;
  }
}

async function checkHttpsReachable(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(`https://${domain}/`, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
    });
    return { reachable: res.ok || (res.status >= 300 && res.status < 500), status: res.status };
  } catch {
    return { reachable: false, status: null };
  } finally {
    clearTimeout(timer);
  }
}

function mergeDohQuery(aRecord, aaaaRecord) {
  const reachable = aRecord.reachable || aaaaRecord.reachable;
  const blocked = aRecord.blocked || aaaaRecord.blocked;
  const resolved =
    (aRecord.resolved && aRecord.answers.length > 0) ||
    (aaaaRecord.resolved && aaaaRecord.answers.length > 0);
  let responseType = 'unknown';
  if (blocked) responseType = 'blocked';
  else if (aRecord.nxdomain || aaaaRecord.nxdomain) responseType = 'nxdomain';
  else if (resolved) responseType = 'resolved';
  else if (aRecord.responseType === 'timeout' || aaaaRecord.responseType === 'timeout') {
    responseType = 'timeout';
  } else if (aRecord.error || aaaaRecord.error) responseType = 'error';

  return {
    dohChecked: true,
    dohReachable: reachable,
    dohResolved: resolved,
    dohBlocked: blocked,
    dohStatus: aRecord.status ?? aaaaRecord.status,
    dohResponseType: responseType,
    dohAnswers: [...(aRecord.answers || []), ...(aaaaRecord.answers || [])],
    dohError: aRecord.error || aaaaRecord.error,
  };
}

function collectFallbackLayers(domain, httpsResult) {
  const layers = [];
  if (domainListedInHosts(domain)) layers.push('hosts_supplement');
  if (systemResolverBlocks(domain)) layers.push('system_resolver');
  if (httpsResult && !httpsResult.reachable) layers.push('https_unreachable');
  return layers;
}

/**
 * Layered domain protection evaluation (DoH primary, fallback secondary).
 * @param {string} domain
 * @param {{ expectedRestricted?: boolean, category?: string, checkHttps?: boolean, applyFallbackOnMiss?: boolean, dohClient?: object }} [options]
 */
async function evaluateDomainProtection(domain, options = {}) {
  const {
    expectedRestricted = false,
    category = 'unknown',
    checkHttps = false,
    applyFallbackOnMiss = false,
  } = options;

  const result = {
    domain,
    category,
    dohChecked: false,
    dohReachable: false,
    dohResolved: false,
    dohBlocked: false,
    dohStatus: null,
    dohResponseType: 'unknown',
    providerMiss: false,
    fallbackChecked: false,
    fallbackBlocked: false,
    fallbackLayers: [],
    httpsChecked: false,
    httpsReachable: null,
    finalBlocked: false,
    blockedBy: [],
    status: 'allowed',
    warning: null,
    error: null,
  };

  const aRecord = await queryCleanBrowsingDoH(domain, 'A', { dohClient: options.dohClient });
  const aaaaRecord = await queryCleanBrowsingDoH(domain, 'AAAA', {
    dohClient: options.dohClient,
  });
  Object.assign(result, mergeDohQuery(aRecord, aaaaRecord));

  if (!result.dohReachable) {
    result.error = result.dohError || 'CleanBrowsing DoH unreachable';
    result.fallbackChecked = true;
    const httpsEarly = checkHttps ? await checkHttpsReachable(domain) : null;
    if (checkHttps) {
      result.httpsChecked = true;
      result.httpsReachable = httpsEarly?.reachable ?? false;
    }
    result.fallbackLayers = collectFallbackLayers(domain, httpsEarly);
    result.fallbackBlocked = result.fallbackLayers.length > 0;
    if (expectedRestricted && result.fallbackBlocked) {
      result.finalBlocked = true;
      result.blockedBy = [...result.fallbackLayers];
      result.status = 'blocked_by_fallback';
      result.warning = STATUS_MESSAGES.degraded_fallback;
      return result;
    }
    if (expectedRestricted) {
      result.status = 'error';
      return result;
    }
    result.status = 'allowed';
    return result;
  }

  if (expectedRestricted && result.dohBlocked) {
    result.finalBlocked = true;
    result.blockedBy = ['cleanbrowsing_doh'];
    result.status = 'blocked_by_doh';
    return result;
  }

  if (expectedRestricted && !result.dohBlocked) {
    result.providerMiss = true;
    result.fallbackChecked = true;

    let httpsResult = null;
    if (checkHttps) {
      result.httpsChecked = true;
      httpsResult = await checkHttpsReachable(domain);
      result.httpsReachable = httpsResult.reachable;
    }

    result.fallbackLayers = collectFallbackLayers(domain, httpsResult);
    result.fallbackBlocked = result.fallbackLayers.length > 0;

    if (!result.fallbackBlocked && applyFallbackOnMiss && useHostsBlockEnabled()) {
      const restrictedCategories = new Set(['adult', 'proxy', 'vpn']);
      if (restrictedCategories.has(category)) {
        const { ensureHostsBlockedDomains } = getHostsHelpers();
        const hostsResult = await ensureHostsBlockedDomains(
          expandDomainVariants(domain),
          'provider_miss',
        );
        if (hostsResult.added?.length || hostsResult.alreadyPresent?.length) {
          result.fallbackLayers = collectFallbackLayers(domain, httpsResult);
          result.fallbackBlocked = result.fallbackLayers.length > 0;
          if (result.fallbackBlocked) {
            result.blockedBy = result.fallbackLayers.includes('hosts_supplement')
              ? ['hosts_supplement']
              : [...result.fallbackLayers];
          }
        }
        if (checkHttps && !httpsResult) {
          result.httpsChecked = true;
          httpsResult = await checkHttpsReachable(domain);
          result.httpsReachable = httpsResult.reachable;
          if (!httpsResult.reachable && !result.fallbackLayers.includes('https_unreachable')) {
            result.fallbackLayers.push('https_unreachable');
            result.fallbackBlocked = true;
          }
        }
      }
    }

    if (result.fallbackBlocked) {
      result.finalBlocked = true;
      result.blockedBy =
        result.blockedBy.length > 0 ? result.blockedBy : [...result.fallbackLayers];
      result.status = 'blocked_by_fallback';
      result.warning = STATUS_MESSAGES.blocked_by_fallback;
      return result;
    }

    result.status = 'allowed';
    result.error = STATUS_MESSAGES.not_blocked_critical;
    result.warning = 'Restricted domain reachable via DoH and fallback inactive';
    return result;
  }

  if (!expectedRestricted && result.dohResolved && !result.dohBlocked) {
    result.status = 'allowed';
    return result;
  }

  if (!expectedRestricted && result.dohBlocked) {
    result.warning = 'Safe domain unexpectedly blocked by DoH';
    result.status = 'error';
    return result;
  }

  result.status = 'allowed';
  return result;
}

function formatDomainStatusMessage(evaluation) {
  if (evaluation.status === 'blocked_by_doh') return STATUS_MESSAGES.blocked_by_doh;
  if (evaluation.status === 'blocked_by_fallback') return STATUS_MESSAGES.blocked_by_fallback;
  if (evaluation.status === 'allowed' && evaluation.providerMiss) {
    return STATUS_MESSAGES.not_blocked_critical;
  }
  if (evaluation.warning) return evaluation.warning;
  if (evaluation.status === 'allowed') return STATUS_MESSAGES.allowed;
  return evaluation.error || STATUS_MESSAGES.error;
}

async function runDohHealthSummary(opts = {}) {
  const ping = await pingCleanBrowsingDoH(opts);
  const dohReachable = ping.reachable === true;

  const safeResults = [];
  for (const domain of FILTER_TESTS.safeAllowed) {
    safeResults.push(
      await evaluateDomainProtection(domain, {
        expectedRestricted: false,
        category: 'safe',
        dohClient: opts.dohClient,
      }),
    );
  }

  const adultResults = [];
  for (const domain of FILTER_TESTS.knownAdultBlocked) {
    adultResults.push(
      await evaluateDomainProtection(domain, {
        expectedRestricted: true,
        category: 'adult',
        checkHttps: false,
        applyFallbackOnMiss: false,
        dohClient: opts.dohClient,
      }),
    );
  }

  const missResults = [];
  for (const domain of FILTER_TESTS.providerMissCandidates) {
    missResults.push(
      await evaluateDomainProtection(domain, {
        expectedRestricted: true,
        category: 'adult',
        checkHttps: true,
        applyFallbackOnMiss: useHostsBlockEnabled(),
        dohClient: opts.dohClient,
      }),
    );
  }

  const safeDomainAllowed = safeResults.every(
    (r) => r.dohReachable && r.status === 'allowed' && !r.dohBlocked,
  );
  const knownAdultBlockedByDoh = adultResults.every(
    (r) => r.dohBlocked && r.status === 'blocked_by_doh',
  );

  const providerMisses = missResults.filter((r) => r.providerMiss).map((r) => r.domain);
  const fallbackBlockedMisses = missResults.filter(
    (r) => r.providerMiss && r.finalBlocked && r.status === 'blocked_by_fallback',
  );
  const criticalUnblockedRestrictedDomains = [
    ...adultResults.filter((r) => !r.finalBlocked).map((r) => r.domain),
    ...missResults.filter((r) => r.providerMiss && !r.finalBlocked).map((r) => r.domain),
  ];

  let finalStatus = 'failed';
  if (criticalUnblockedRestrictedDomains.length > 0) {
    finalStatus = 'failed';
  } else if (!dohReachable) {
    const restrictedStillBlocked =
      adultResults.every((r) => r.finalBlocked) &&
      missResults.every((r) => !r.providerMiss || r.finalBlocked);
    finalStatus = restrictedStillBlocked ? 'degraded' : 'failed';
  } else if (knownAdultBlockedByDoh && safeDomainAllowed) {
    if (providerMisses.length === 0) {
      finalStatus = 'healthy';
    } else if (fallbackBlockedMisses.length === providerMisses.length) {
      finalStatus = 'healthy_with_provider_misses';
    } else {
      finalStatus = 'failed';
    }
  } else {
    finalStatus = 'degraded';
  }

  const cleanBrowsingPrimaryWorking =
    dohReachable && knownAdultBlockedByDoh && safeDomainAllowed;

  return {
    dohReachable,
    cleanBrowsingPrimaryWorking,
    safeDomainAllowed,
    knownAdultBlockedByDoh,
    providerMisses,
    fallbackBlockedMisses: fallbackBlockedMisses.map((r) => r.domain),
    criticalUnblockedRestrictedDomains,
    finalStatus,
    safeResults,
    adultResults,
    missResults,
    ping,
  };
}

module.exports = {
  evaluateDomainProtection,
  formatDomainStatusMessage,
  runDohHealthSummary,
  domainListedInHosts,
  systemResolverBlocks,
  checkHttpsReachable,
  STATUS_MESSAGES,
  useHostsBlockEnabled,
};
