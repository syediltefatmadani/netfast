export async function getChallenge(challengeId) {
  return {
    id: challengeId || 'mock-challenge-001',
    status: 'active',
    day: 14,
    totalDays: 30,
    deposit: 500,
    tier: 'Commit',
    identityStatement: 'I am a focused person who controls their mind.',
    accountabilityPartner: 'mentor@example.com',
    vpnExemption: null,
    createdAt: Date.now() - 14 * 86400000,
  };
}

export async function createChallenge(payload) {
  return { id: 'mock-challenge-001', ...payload };
}

export async function sendHeartbeat(payload) {
  return { received: true };
}
