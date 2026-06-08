const { describe, it } = require('node:test');
const assert = require('node:assert');
const { isBlockedDohResult, classifyResponseType } = require('../dohHealth');
const { expandDomainVariants } = require('../filterTests');

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
});
