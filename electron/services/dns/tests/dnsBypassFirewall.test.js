const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { RAW_DNS_BLOCK_RULES } = require('../../../dnsBypassFirewall');

describe('dnsBypassFirewall', () => {
  it('defines four raw DNS block rules on ports 53 and 853', () => {
    assert.equal(RAW_DNS_BLOCK_RULES.length, 4);
    const names = RAW_DNS_BLOCK_RULES.map((r) => r.displayName);
    assert(names.includes('NetFast Block Direct DNS UDP 53'));
    assert(names.includes('NetFast Block Direct DNS TCP 53'));
    assert(names.includes('NetFast Block DNS-over-TLS TCP 853'));
    assert(names.includes('NetFast Block DNS-over-QUIC UDP 853'));
  });

  it('does not block TCP 443', () => {
    for (const rule of RAW_DNS_BLOCK_RULES) {
      assert.notEqual(rule.remotePort, 443);
    }
  });
});
