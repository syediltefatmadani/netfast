const { describe, it } = require('node:test');
const assert = require('node:assert');
const { isBlockedDohResult, classifyResponseType } = require('../dohHealth');
const {
  expandDomainVariants,
  RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS,
  RUNTIME_SKIP_ADULT_POLICY_PROBES,
} = require('../filterTests');
const { runDohHealthSummary } = require('../domainProtection');

describe('dohHealth helpers', () => {
  it('treats NXDOMAIN as blocked', () => {
    assert.strictEqual(isBlockedDohResult({ rcode: 3, answers: [], blocked: false }), true);
  });

  it('classifies resolved answers', () => {
    assert.strictEqual(
      classifyResponseType({ rcode: 0, answers: ['1.2.3.4'], blocked: false }),
      'resolved',
    );
  });
});

describe('filterTests', () => {
  it('expands www variants', () => {
    assert.deepStrictEqual(expandDomainVariants('pornhat.com'), [
      'pornhat.com',
      'www.pornhat.com',
    ]);
  });

  it('exports runtime probe defaults', () => {
    assert.deepStrictEqual(RUNTIME_FUNCTIONAL_BLOCKED_DOMAINS, ['reddit.com']);
    assert.equal(RUNTIME_SKIP_ADULT_POLICY_PROBES, true);
  });
});

describe('runDohHealthSummary', () => {
  it('skips adult domain loops when skipAdultDomainProbes is true', async () => {
    const adultDomains = [];
    const original = require('../dohHealth').queryCleanBrowsingDoH;
    const originalPing = require('../dohHealth').pingCleanBrowsingDoH;
    require('../dohHealth').pingCleanBrowsingDoH = async () => ({
      reachable: true,
      ok: true,
      status: 200,
    });
    require('../dohHealth').queryCleanBrowsingDoH = async (domain) => {
      if (
        domain.includes('pornhub') ||
        domain.includes('xvideos') ||
        domain.includes('pornhat')
      ) {
        adultDomains.push(domain);
      }
      return {
        reachable: true,
        resolved: true,
        blocked: false,
        status: 0,
        answers: ['8.8.8.8'],
        responseType: 'resolved',
      };
    };

    try {
      const summary = await runDohHealthSummary({ skipAdultDomainProbes: true });
      assert.equal(summary.skipAdultDomainProbes, true);
      assert.equal(adultDomains.length, 0);
      assert.equal(summary.adultResults.length, 0);
      assert.equal(summary.missResults.length, 0);
      assert.equal(summary.finalStatus, 'healthy');
    } finally {
      require('../dohHealth').queryCleanBrowsingDoH = original;
      require('../dohHealth').pingCleanBrowsingDoH = originalPing;
    }
  });
});
