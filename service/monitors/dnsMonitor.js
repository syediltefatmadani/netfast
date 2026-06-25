const dns = require('dns');
const { runPowerShell, cached, parseJsonList } = require('../util/commandRunner');
const { EXPECTED_DNS, INTERVALS } = require('../config/serviceConfig');
const logger = require('../logging/serviceLogger');

/**
 * DNS monitor — answers "is the required protection DNS still active?".
 *
 * Per the Phase 2 brief we combine TWO signals and never claim 100% certainty:
 *   1. System configuration check — the adapters' configured DNS servers
 *      (Get-DnsClientServerAddress). Fast, but can be bypassed by DoH etc.
 *   2. Real DNS verification — actually resolve a known-restricted domain. With
 *      CleanBrowsing Family Filter active it is blocked (0.0.0.0 / no usable
 *      answer); if it resolves to a real public IP, filtering is not in effect.
 *
 * dnsProtected is true only when at least one strong signal confirms protection;
 * any uncertainty is surfaced in `issue`.
 */

const LIST_DNS_SCRIPT = `
$rows = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses } |
  ForEach-Object { $_.ServerAddresses }
$rows | Sort-Object -Unique | ConvertTo-Json -Compress
`;

// A domain CleanBrowsing's Family Filter blocks. Used only as a protection
// probe — not browsing data, never logged as user activity.
const RESTRICTED_PROBE = 'pornhub.com';

async function readConfiguredResolvers() {
  return cached('dns:configured', INTERVALS.dnsVerificationMs - 1000, async () => {
    const out = await runPowerShell(LIST_DNS_SCRIPT, { timeoutMs: 10000 });
    const list = parseJsonList(out)
      .map((v) => String(v).trim())
      .filter(Boolean);
    return Array.from(new Set(list));
  });
}

function expectedResolvers() {
  return [...EXPECTED_DNS.ipv4, ...EXPECTED_DNS.ipv6];
}

/** Resolve a restricted probe through the system resolver. */
function resolveRestricted() {
  return new Promise((resolve) => {
    const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 1 });
    resolver
      .resolve4(RESTRICTED_PROBE)
      .then((addrs) => resolve({ ok: true, addrs }))
      .catch((err) => resolve({ ok: false, code: err.code }));
  });
}

function isBlockedResult(res) {
  if (!res.ok) {
    // NXDOMAIN / NODATA / SERVFAIL all indicate the resolver refused it.
    return ['ENOTFOUND', 'ENODATA', 'ESERVFAIL', 'NXDOMAIN'].includes(res.code);
  }
  // A filtered answer is 0.0.0.0 or empty; a real answer means NOT blocked.
  const real = (res.addrs || []).filter((a) => a && a !== '0.0.0.0');
  return real.length === 0;
}

async function check() {
  const lastCheckedAt = new Date().toISOString();
  const expected = expectedResolvers();
  let activeResolvers = [];
  let configMatch = false;
  let issue;

  try {
    activeResolvers = await readConfiguredResolvers();
    const expectedSet = new Set(expected.map((x) => x.toLowerCase()));
    const nonExpected = activeResolvers.filter((r) => !expectedSet.has(r.toLowerCase()));
    configMatch = activeResolvers.length > 0 && nonExpected.length === 0;
    if (!configMatch && activeResolvers.length > 0) {
      issue = `Active resolvers include non-CleanBrowsing entries: ${nonExpected.join(', ')}`;
    }
  } catch (e) {
    issue = `Could not read system DNS configuration: ${e.message}`;
  }

  // Real verification is the stronger signal; it catches both "config still
  // points at CleanBrowsing but something is rewriting answers" and the reverse.
  let verificationBlocked = null;
  try {
    verificationBlocked = isBlockedResult(await resolveRestricted());
  } catch {
    verificationBlocked = null;
  }

  let dnsProtected;
  if (verificationBlocked === true) {
    dnsProtected = true;
  } else if (verificationBlocked === false) {
    dnsProtected = false;
    issue = issue
      ? `${issue}; restricted domain resolved (filtering not active)`
      : 'Restricted domain resolved — DNS filtering does not appear active';
  } else {
    // Verification inconclusive: fall back to config match, flag uncertainty.
    dnsProtected = configMatch;
    if (!issue && !configMatch) issue = 'DNS protection could not be confirmed (uncertain)';
  }

  return {
    dnsProtected,
    activeResolvers,
    expectedResolvers: expected,
    lastCheckedAt,
    ...(issue ? { issue } : {}),
  };
}

module.exports = { check, name: 'dns' };
