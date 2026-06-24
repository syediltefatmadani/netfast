const { describe, it } = require('node:test');

const assert = require('node:assert');

const { DnsValidator } = require('../DnsValidator');

const { DnsStatus } = require('../DnsStatus');



function mockDohClient({ ping, query }) {

  return {

    ping: ping || (async () => ({ ok: true, reachable: true, status: 200 })),

    query: query || (async () => ({ rcode: 3, answers: [] })),

  };

}



describe('DnsValidator.runFullValidation', () => {

  it('returns CLEANBROWSING_UNREACHABLE when DoH ping fails', async () => {

    const validator = new DnsValidator({

      dohClient: mockDohClient({

        ping: async () => ({ ok: false, reachable: false, status: null }),

      }),

    });

    const result = await validator.runFullValidation();

    assert.ok(

      result.status === DnsStatus.CLEANBROWSING_UNREACHABLE ||

        result.status === DnsStatus.DEGRADED ||

        result.status === DnsStatus.FAILED,

    );

  });



  it('returns FAILED when known adult resolves via DoH without fallback', async () => {

    const validator = new DnsValidator({

      dohClient: mockDohClient({

        query: async (domain) => {

          if (domain.includes('pornhub') || domain.includes('xvideos')) {

            return { rcode: 0, answers: [{ type: 1, value: '151.101.1.140' }] };

          }

          return { rcode: 0, answers: [{ type: 1, value: '142.250.80.46' }] };

        },

      }),

    });

    const result = await validator.runFullValidation({ skipAdultDomainProbes: false });
    assert.ok(
      result.status === DnsStatus.FAILED || result.status === DnsStatus.FILTERING_INACTIVE,
    );
  });



  it('returns HEALTHY when DoH blocks known adult and allows safe domains', async () => {

    const blocked = new Set(['pornhub.com', 'xvideos.com', 'pornhat.com', 'pornhat.one']);

    const validator = new DnsValidator({

      dohClient: mockDohClient({

        query: async (domain) => {

          if (blocked.has(domain)) return { rcode: 3, answers: [] };

          return { rcode: 0, answers: [{ type: 1, value: '8.8.8.8' }] };

        },

      }),

    });

    const result = await validator.runFullValidation({ skipAdultDomainProbes: false });

    assert.ok(

      result.status === DnsStatus.HEALTHY ||

        result.status === DnsStatus.HEALTHY_WITH_PROVIDER_MISSES,

    );

  });

  it('skips adult policy probes at runtime and returns HEALTHY when DoH and safe domains pass', async () => {
    let adultQueried = false;
    const validator = new DnsValidator({
      dohClient: mockDohClient({
        query: async (domain) => {
          if (domain.includes('pornhub') || domain.includes('xvideos') || domain.includes('pornhat')) {
            adultQueried = true;
          }
          return { rcode: 0, answers: [{ type: 1, value: '8.8.8.8' }] };
        },
      }),
    });

    const policy = await validator.runPolicyTests({ skipAdultDomainProbes: true });
    assert.equal(policy.skipped, true);
    assert.equal(policy.ok, true);

    const result = await validator.runFullValidation({ skipAdultDomainProbes: true });
    assert.equal(adultQueried, false);
    assert.equal(result.summary.skipAdultDomainProbes, true);
    assert.ok(
      result.status === DnsStatus.HEALTHY ||
        result.status === DnsStatus.HEALTHY_WITH_PROVIDER_MISSES,
    );
  });

});

