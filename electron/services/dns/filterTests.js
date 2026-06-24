/** CleanBrowsing validation domains — do not use facebook.com as adult-filter test. */
const FILTER_TESTS = {
  safeAllowed: ['google.com', 'microsoft.com'],
  knownAdultBlocked: ['pornhub.com', 'xvideos.com'],
  providerMissCandidates: ['pornhat.com', 'pornhat.one'],
};

/** Live blocked-domain probes for app runtime (IPC, verifyDNS) — slow adult domains omitted. */
const RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS = ['reddit.com'];

/** Skip slow adult DoH/system probes during normal app operation; CLI diagnostics use full lists. */
const RUNTIME_SKIP_ADULT_POLICY_PROBES = true;

const DOH_FAMILY_BASE = 'https://doh.cleanbrowsing.org/doh/family-filter';
const DOH_WIRE_URL = `${DOH_FAMILY_BASE}/dns-query`;

/** HTTP statuses that mean the DoH endpoint is reachable (not a network failure). */
const DOH_REACHABLE_HTTP_STATUSES = new Set([200, 400, 405, 415]);

function expandDomainVariants(domain) {
  const base = String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/^www\./, '');
  if (!base) return [];
  return [base, `www.${base}`];
}

module.exports = {
  FILTER_TESTS,
  RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS,
  RUNTIME_SKIP_ADULT_POLICY_PROBES,
  DOH_FAMILY_BASE,
  DOH_WIRE_URL,
  DOH_REACHABLE_HTTP_STATUSES,
  expandDomainVariants,
};
