const { describe, it } = require('node:test');
const assert = require('node:assert');
const { encodeQuery, parseResponse } = require('../DohClient');
const { isBlockedResolution } = require('../DnsValidator');

describe('DNS wire format', () => {
  it('encodeQuery produces buffer with correct QDCOUNT', () => {
    const buf = encodeQuery('example.com');
    assert.ok(buf.length > 12);
    assert.strictEqual(buf[5], 1);
  });

  it('parseResponse handles NXDOMAIN', () => {
    const query = encodeQuery('test.invalid');
    const fake = Buffer.alloc(query.length);
    query.copy(fake, 0, 0, 12);
    fake[3] = 3;
    const parsed = parseResponse(fake);
    assert.strictEqual(parsed.rcode, 3);
    assert.strictEqual(isBlockedResolution({ rcode: 3, addresses: [] }), true);
  });
});

describe('isBlockedResolution', () => {
  it('detects sinkhole IPs', () => {
    assert.strictEqual(isBlockedResolution({ rcode: 0, addresses: ['0.0.0.0'] }), true);
  });

  it('detects live CDN as not blocked', () => {
    assert.strictEqual(
      isBlockedResolution({ rcode: 0, addresses: ['104.26.4.214'] }),
      false,
    );
  });
});
