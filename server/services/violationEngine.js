const Challenge = require('../models/Challenge');
const ViolationLog = require('../models/ViolationLog');
const { sendViolationEmail, sendTerminationEmail } = require('./emailService');
const { triggerRefundForfeiture } = require('./paymentService');

const VECTOR_GROUPS = {
  dns_reset: ['dns_ipv4', 'dns_ipv6', 'dns_filtering'],
  doh_browser: ['firefox_doh', 'chrome_doh'],
};

function resolveGroup(vector) {
  for (const [group, members] of Object.entries(VECTOR_GROUPS)) {
    if (members.includes(vector)) return group;
  }
  return vector;
}

async function terminateChallenge(challenge, vector, evidence, entry) {
  const key = resolveGroup(vector);
  const state = challenge.vectors[key] || challenge.vectors[vector];
  if (state) {
    state.warnings = Math.max(state.warnings || 0, 2);
    state.terminated = true;
    state.log.push({ ...entry, action: 'termination' });
  }
  challenge.status = 'terminated';
  challenge.terminatedAt = Date.now();
  challenge.terminationVector = vector;
  challenge.depositStatus = 'forfeited';
  challenge.markModified('vectors');
  await challenge.save();
  await ViolationLog.create({
    challengeId: challenge._id,
    userId: challenge.userId,
    vector,
    action: 'termination',
    evidence,
  });
  await sendTerminationEmail(challenge, vector, evidence);
  await triggerRefundForfeiture(challenge);
}

/**
 * VPN-specific violation flow (24h re-apply window, second attempt = immediate fail).
 */
async function processVpnViolation(challengeId, evidence) {
  const challenge = await Challenge.findById(challengeId);
  if (!challenge) return { skipped: true, reason: 'challenge_not_found' };
  if (challenge.status !== 'active' && !evidence.challengeFailed) {
    return { skipped: true, reason: 'challenge_not_active' };
  }

  const vector = 'unknown_vpn';
  const key = resolveGroup(vector);
  const state = challenge.vectors[key] || challenge.vectors[vector];
  if (!state) return { skipped: true, reason: 'no_vector_state' };

  const entry = { timestamp: Date.now(), evidence, vector };
  const actionTaken = evidence.actionTaken || '';

  if (evidence.challengeFailed) {
    await terminateChallenge(challenge, vector, evidence, entry);
    return { action: 'terminated', actionTaken };
  }

  if (actionTaken === 'warning_issued_waiting_for_reapply') {
    if (state.warnings >= 1) {
      return { action: 'already_warned', actionTaken };
    }
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
    return { action: 'warning', actionTaken };
  }

  return { skipped: true, reason: 'unknown_action', actionTaken };
}

async function processViolation(challengeId, vector, evidence) {
  if (vector === 'unknown_vpn' && evidence?.actionTaken) {
    return processVpnViolation(challengeId, evidence);
  }
  if (vector === 'unknown_vpn' && evidence?.vpnHandlerManaged) {
    return { skipped: true, reason: 'vpn_handler_managed' };
  }

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

module.exports = { processViolation, processVpnViolation };
