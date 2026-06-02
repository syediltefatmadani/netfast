const Challenge = require('../models/Challenge');
const ViolationLog = require('../models/ViolationLog');
const { sendViolationEmail, sendTerminationEmail } = require('./emailService');
const { triggerRefundForfeiture } = require('./paymentService');

const VECTOR_GROUPS = {
  dns_reset: ['dns_ipv4', 'dns_ipv6'],
  doh_browser: ['firefox_doh', 'chrome_doh'],
};

function resolveGroup(vector) {
  for (const [group, members] of Object.entries(VECTOR_GROUPS)) {
    if (members.includes(vector)) return group;
  }
  return vector;
}

async function processViolation(challengeId, vector, evidence) {
  const challenge = await Challenge.findById(challengeId);
  if (!challenge || challenge.status !== 'active') return;

  const key = resolveGroup(vector);
  const state = challenge.vectors[key] || challenge.vectors[vector];
  if (!state) return;

  const entry = { timestamp: Date.now(), evidence, vector };

  if (state.warnings === 0) {
    state.warnings = 1;
    state.log.push({ ...entry, action: 'warning' });
    challenge.markModified('vectors');
    await challenge.save();
    await ViolationLog.create({
      challengeId,
      userId: challenge.userId,
      vector,
      action: 'warning',
      evidence,
    });
    await sendViolationEmail(challenge, vector, evidence);
  } else {
    state.warnings = 2;
    state.terminated = true;
    state.log.push({ ...entry, action: 'termination' });
    challenge.status = 'terminated';
    challenge.terminatedAt = Date.now();
    challenge.terminationVector = vector;
    challenge.depositStatus = 'forfeited';
    challenge.markModified('vectors');
    await challenge.save();
    await ViolationLog.create({
      challengeId,
      userId: challenge.userId,
      vector,
      action: 'termination',
      evidence,
    });
    await sendTerminationEmail(challenge, vector, evidence);
    await triggerRefundForfeiture(challenge);
  }
}

module.exports = { processViolation };
