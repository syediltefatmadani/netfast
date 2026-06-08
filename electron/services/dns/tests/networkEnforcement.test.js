const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  isBlockedARecord,
  isBlockedAAAARecord,
  isRealPublicIpv6,
  isRealPublicIpv4,
  evaluateDomainVerification,
  evaluateDirectDnsBypass,
  containsPublicDns,
  PUBLIC_DNS_IPV4,
} = require('../../../networkEnforcement');

describe('networkEnforcement helpers', () => {
  it('detects blocked A records', () => {
    assert.equal(isBlockedARecord('0.0.0.0'), true);
    assert.equal(isBlockedARecord('127.0.0.1'), true);
    assert.equal(isBlockedARecord('142.250.80.46'), false);
  });

  it('detects blocked AAAA records', () => {
    assert.equal(isBlockedAAAARecord('::'), true);
    assert.equal(isBlockedAAAARecord('::1'), true);
    assert.equal(isBlockedAAAARecord('2a00:1450:4001:808::200e'), false);
  });

  it('identifies real public IPv6 leaks', () => {
    assert.equal(isRealPublicIpv6('::'), false);
    assert.equal(isRealPublicIpv6('fe80::1'), false);
    assert.equal(isRealPublicIpv6('2a00:1450:4001:808::200e'), true);
  });

  it('identifies real public IPv4 leaks', () => {
    assert.equal(isRealPublicIpv4('0.0.0.0'), false);
    assert.equal(isRealPublicIpv4('192.168.1.1'), false);
    assert.equal(isRealPublicIpv4('142.250.80.46'), true);
  });

  it('flags public DNS servers', () => {
    assert.equal(containsPublicDns(['8.8.8.8', '185.228.168.168']), true);
    assert.equal(containsPublicDns(['185.228.168.168', '185.228.169.168']), false);
    assert(PUBLIC_DNS_IPV4.has('1.1.1.1'));
  });

  it('evaluates fully blocked domain verification', () => {
    const result = evaluateDomainVerification(
      'reddit.com',
      { ok: true, records: [{ type: 'A', address: '0.0.0.0' }, { type: 'AAAA', address: '::' }] },
      { blocked: true, error: 'could not resolve host' },
    );
    assert.equal(result.ipv4Ok, true);
    assert.equal(result.ipv6Ok, true);
    assert.equal(result.fullyBlocked, true);
  });

  it('detects IPv6 leak in verification', () => {
    const result = evaluateDomainVerification(
      'reddit.com',
      {
        ok: true,
        records: [
          { type: 'A', address: '0.0.0.0' },
          { type: 'AAAA', address: '2a00:1450:4001:808::200e' },
        ],
      },
      { blocked: false },
    );
    assert.equal(result.ipv4Ok, true);
    assert.equal(result.ipv6Ok, false);
    assert.equal(result.aaaaLeaked, true);
  });

  it('detects adapter needing fix when public DNS present', () => {
    const { adapterNeedsDnsFix } = require('../../../networkEnforcement');
    assert.equal(
      adapterNeedsDnsFix({
        ipv4Dns: ['8.8.8.8', '8.8.4.4'],
        ipv6Dns: ['2a0d:2a00:1::', '2a0d:2a00:2::'],
      }),
      true,
    );
    assert.equal(
      adapterNeedsDnsFix({
        ipv4Dns: ['185.228.168.168', '185.228.169.168'],
        ipv6Dns: ['2a0d:2a00:1::', '2a0d:2a00:2::'],
      }),
      false,
    );
  });

  it('treats direct DNS timeout as blocked bypass', () => {
    const result = evaluateDirectDnsBypass('reddit.com', '8.8.8.8', {
      ok: false,
      timedOut: true,
      records: [],
    });
    assert.equal(result.blocked, true);
    assert.equal(result.leaked, false);
  });

  it('detects direct DNS leak when real IPs returned', () => {
    const result = evaluateDirectDnsBypass('reddit.com', '2a0d:2a00:1::', {
      ok: true,
      records: [{ type: 'A', address: '142.250.80.46' }],
    });
    assert.equal(result.blocked, false);
    assert.equal(result.leaked, true);
  });
});
