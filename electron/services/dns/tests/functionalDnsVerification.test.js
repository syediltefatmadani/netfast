const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { classifyBlockedDomainTest } = require('../../../functionalDnsVerification');

describe('functionalDnsVerification', () => {
  it('treats NXDOMAIN as blocked', () => {
    const result = classifyBlockedDomainTest('reddit.com', {
      ok: false,
      error: 'DNS name does not exist',
      records: [],
    });
    assert.equal(result.blocked, true);
    assert.match(result.result, /does not exist/i);
  });

  it('treats sinkhole addresses as blocked', () => {
    const result = classifyBlockedDomainTest('reddit.com', {
      ok: true,
      records: [
        { type: 'A', address: '0.0.0.0' },
        { type: 'AAAA', address: '::' },
      ],
    });
    assert.equal(result.blocked, true);
  });

  it('treats real public IPs as leaked', () => {
    const result = classifyBlockedDomainTest('reddit.com', {
      ok: true,
      records: [{ type: 'A', address: '142.250.70.46' }],
    });
    assert.equal(result.blocked, false);
    assert.match(result.result, /leaked/i);
  });

  it('treats timeout as blocked for restricted domains', () => {
    const result = classifyBlockedDomainTest('pornhat.one', {
      ok: false,
      timedOut: true,
      records: [],
    });
    assert.equal(result.blocked, true);
  });
});
