const { test } = require('node:test');
const assert = require('node:assert');

// Ensure dev-safe / no real enforcement so startTamperWatch is a guaranteed
// no-op and never spawns PowerShell during the test.
process.env.NETFAST_DISABLE_ENFORCEMENT = 'true';
delete process.env.NETFAST_ALLOW_REAL_ENFORCEMENT;

const { parseSensorLines, startTamperWatch } = require('./tamperWatch');

test('parseSensorLines parses complete NDJSON events', () => {
  const { events, rest } = parseSensorLines(
    '{"vector":"dns"}\n{"vector":"firewall"}\n',
  );
  assert.deepStrictEqual(
    events.map((e) => e.vector),
    ['dns', 'firewall'],
  );
  assert.strictEqual(rest, '');
});

test('parseSensorLines carries a trailing partial line into rest', () => {
  const first = parseSensorLines('{"vector":"dns"}\n{"vector":"fire');
  assert.deepStrictEqual(first.events.map((e) => e.vector), ['dns']);
  assert.strictEqual(first.rest, '{"vector":"fire');

  // Next chunk completes the partial line.
  const second = parseSensorLines(first.rest + 'wall"}\n');
  assert.deepStrictEqual(second.events.map((e) => e.vector), ['firewall']);
  assert.strictEqual(second.rest, '');
});

test('parseSensorLines ignores blank and non-JSON lines', () => {
  const { events } = parseSensorLines('\n  \nnot json\n{"vector":"hosts"}\n');
  assert.deepStrictEqual(events.map((e) => e.vector), ['hosts']);
});

test('parseSensorLines drops objects without a vector field', () => {
  const { events } = parseSensorLines('{"foo":1}\n{"vector":"registry_doh"}\n');
  assert.deepStrictEqual(events.map((e) => e.vector), ['registry_doh']);
});

test('startTamperWatch is a no-op (no spawn) when real enforcement is disabled', () => {
  let called = false;
  const stop = startTamperWatch({ onTamper: () => { called = true; } });
  assert.strictEqual(typeof stop, 'function');
  stop(); // must not throw
  assert.strictEqual(called, false);
});
