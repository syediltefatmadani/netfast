const { runEncoded } = require('../../powershell');

const { DohClient } = require('./DohClient');

const { DnsStatus, mapFinalStatusToDnsStatus } = require('./DnsStatus');

const { FILTER_TESTS } = require('./filterTests');

const { pingCleanBrowsingDoH, queryCleanBrowsingDoH } = require('./dohHealth');

const {

  evaluateDomainProtection,

  runDohHealthSummary,

} = require('./domainProtection');



const POLICY_TEST_DOMAINS = [

  ...FILTER_TESTS.knownAdultBlocked,

  ...FILTER_TESTS.providerMissCandidates,

];



const BLOCK_SIGNALS = [

  '0.0.0.0',

  '127.0.0.1',

  '::',

  '::1',

  'restricted.',

  'rpz.',

  'blocked',

  'cleanbrowsing',

];



function isBlockedResolution({ rcode, addresses, raw }) {

  if (rcode === 3) return true;

  if (!addresses?.length && rcode !== 0) return true;

  for (const addr of addresses || []) {

    const a = String(addr).toLowerCase();

    if (a === '0.0.0.0' || a === '127.0.0.1' || a === '::' || a === '::1') return true;

    if (a.includes('restricted.') || a.includes('rpz.') || a.includes('cleanbrowsing')) {

      return true;

    }

  }

  const text = `${raw || ''}`.toLowerCase();

  if (/blocked|nxdomain|refused/.test(text)) return true;

  return false;

}



function normalizeAddresses(parsed) {

  const addrs = [];

  for (const a of parsed.answers || []) {

    if (a.value) addrs.push(a.value);

  }

  return addrs;

}



class DnsValidator {

  /**

   * @param {{ dohClient?: DohClient }} [deps]

   */

  constructor(deps = {}) {

    this.doh = deps.dohClient || new DohClient();

  }



  async resolveViaDoh(domain) {

    const structured = await queryCleanBrowsingDoH(domain, 'A', { dohClient: this.doh });

    return {

      domain,

      channel: 'doh',

      rcode: structured.status,

      addresses: structured.answers,

      blocked: structured.blocked,

      resolved: structured.resolved,

      reachable: structured.reachable,

      error: structured.error,

      responseType: structured.responseType,

    };

  }



  resolveViaSystem(domain) {

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

      const addresses = out

        .split(/\r?\n/)

        .map((s) => s.trim())

        .filter(Boolean);

      return {

        domain,

        channel: 'system',

        addresses,

        blocked: isBlockedResolution({ rcode: 0, addresses, raw: out }),

        error: /^ERR:/i.test(out) ? out : undefined,

      };

    } catch (e) {

      return {

        domain,

        channel: 'system',

        addresses: [],

        blocked: false,

        error: e.message,

      };

    }

  }



  /** Legacy shape — uses layered evaluator; ok means finally blocked for restricted domains. */

  async verifyDomainBlocked(domain, category = 'adult') {

    const evaluation = await evaluateDomainProtection(domain, {

      expectedRestricted: true,

      category,

      checkHttps: true,

      applyFallbackOnMiss: true,

      dohClient: this.doh,

    });

    const doh = {

      domain,

      channel: 'doh',

      addresses: evaluation.dohAnswers || [],

      blocked: evaluation.dohBlocked,

      error: evaluation.dohError,

    };

    const system = this.resolveViaSystem(domain);

    const ok = evaluation.finalBlocked;

    let reason = evaluation.status;

    if (!evaluation.dohBlocked && evaluation.providerMiss) reason = 'provider_miss_fallback';

    return { domain, ok, reason, doh, system, evaluation };

  }



  async runPolicyTests() {

    const results = [];

    for (const domain of FILTER_TESTS.knownAdultBlocked) {

      results.push(await this.verifyDomainBlocked(domain, 'adult'));

    }

    for (const domain of FILTER_TESTS.providerMissCandidates) {

      results.push(await this.verifyDomainBlocked(domain, 'adult'));

    }

    const failures = results.filter((r) => !r.ok);

    return { results, failures, ok: failures.length === 0 };

  }



  async runConsistencyTests() {

    const mismatches = [];

    for (const domain of FILTER_TESTS.providerMissCandidates.slice(0, 2)) {

      const doh = await this.resolveViaDoh(domain);

      const system = this.resolveViaSystem(domain);

      if (doh.error || system.error) continue;

      const dohAllowed = !doh.blocked && doh.addresses.length > 0;

      const systemAllowed = !system.blocked && system.addresses.length > 0;

      if (dohAllowed && !systemAllowed && dohAllowed !== systemAllowed) {

        mismatches.push({ domain, doh, system, kind: 'fallback_active' });

      } else if (dohAllowed === systemAllowed && dohAllowed) {

        mismatches.push({ domain, doh, system, kind: 'both_allowed' });

      }

    }

    const critical = mismatches.filter((m) => m.kind === 'both_allowed');

    return { mismatches, ok: critical.length === 0 };

  }



  async checkDohConnectivity() {

    try {

      const pingResult = await pingCleanBrowsingDoH({ dohClient: this.doh });

      const ok = pingResult.reachable === true;

      return {

        ok,

        status: ok ? DnsStatus.HEALTHY : DnsStatus.CLEANBROWSING_UNREACHABLE,

        httpStatus: pingResult.status,

        details: pingResult.error || pingResult.message,

        reachable: pingResult.reachable,

      };

    } catch (e) {

      return { ok: false, status: DnsStatus.NETWORK_ERROR, error: e.message, reachable: false };

    }

  }



  /**

   * Layered health: DoH primary, fallback secondary. Provider misses with working fallback are not failures.

   */

  async runFullValidation() {

    try {

      const summary = await runDohHealthSummary({ dohClient: this.doh });

      const status = mapFinalStatusToDnsStatus(summary.finalStatus);



      const detailsByStatus = {

        [DnsStatus.HEALTHY]: 'DoH reachable; known adult domains blocked by CleanBrowsing',

        [DnsStatus.HEALTHY_WITH_PROVIDER_MISSES]:

          'DoH reachable; provider miss(es) caught by local fallback',

        [DnsStatus.DEGRADED]:

          'DoH unreachable — fallback blocking active for restricted domains',

        [DnsStatus.FAILED]: `Restricted domain(s) reachable: ${summary.criticalUnblockedRestrictedDomains.join(', ') || 'unknown'}`,

      };



      if (summary.finalStatus === 'failed' && summary.criticalUnblockedRestrictedDomains.length) {

        return {

          status: DnsStatus.FAILED,

          details: detailsByStatus[DnsStatus.FAILED],

          connectivity: { ok: summary.dohReachable, reachable: summary.dohReachable },

          policy: await this.runPolicyTests(),

          consistency: null,

          summary,

        };

      }



      if (!summary.dohReachable) {

        const policy = await this.runPolicyTests();

        const stillProtected = policy.ok;

        return {

          status: stillProtected ? DnsStatus.DEGRADED : DnsStatus.CLEANBROWSING_UNREACHABLE,

          details: stillProtected

            ? detailsByStatus[DnsStatus.DEGRADED]

            : 'CleanBrowsing DoH unreachable and fallback did not block restricted domains',

          connectivity: { ok: false, reachable: false },

          policy,

          consistency: null,

          summary,

        };

      }



      const consistency = await this.runConsistencyTests();

      if (!consistency.ok) {

        const bothAllowed = consistency.mismatches.filter((m) => m.kind === 'both_allowed');

        if (bothAllowed.length) {

          return {

            status: DnsStatus.FAILED,

            details: 'Restricted domain allowed by both DoH and system resolver',

            connectivity: { ok: true, reachable: true },

            policy: await this.runPolicyTests(),

            consistency,

            summary,

          };

        }

      }



      if (!summary.knownAdultBlockedByDoh) {

        const failedAdult = summary.adultResults

          .filter((r) => !r.dohBlocked)

          .map((r) => r.domain);

        return {

          status: DnsStatus.FILTERING_INACTIVE,

          details: `CleanBrowsing did not block known adult test domain(s): ${failedAdult.join(', ')}`,

          connectivity: { ok: true, reachable: true },

          policy: await this.runPolicyTests(),

          consistency,

          summary,

        };

      }



      if (!summary.safeDomainAllowed) {

        return {

          status: DnsStatus.TAMPERING_SUSPECTED,

          details: 'Safe test domain blocked or unreachable via DoH',

          connectivity: { ok: true, reachable: true },

          policy: await this.runPolicyTests(),

          consistency,

          summary,

        };

      }



      return {

        status,

        details: detailsByStatus[status] || summary.finalStatus,

        connectivity: { ok: true, reachable: true },

        policy: await this.runPolicyTests(),

        consistency,

        summary,

      };

    } catch (e) {

      return {

        status: DnsStatus.NETWORK_ERROR,

        details: e.message,

        connectivity: null,

        policy: null,

        consistency: null,

        summary: null,

      };

    }

  }

}



module.exports = {

  DnsValidator,

  POLICY_TEST_DOMAINS,

  FILTER_TESTS,

  isBlockedResolution,

  queryCleanBrowsingDoH,

  evaluateDomainProtection,

  runDohHealthSummary,

};

