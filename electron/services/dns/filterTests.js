/** CleanBrowsing validation domains — do not use facebook.com as adult-filter test. */
const FILTER_TESTS = {
  safeAllowed: ['google.com', 'microsoft.com'],
  knownAdultBlocked: ['pornhub.com', 'xvideos.com'],
  providerMissCandidates: ['pornhat.com', 'pornhat.one'],
};

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
  DOH_FAMILY_BASE,
  DOH_WIRE_URL,
  DOH_REACHABLE_HTTP_STATUSES,
  expandDomainVariants,
};
