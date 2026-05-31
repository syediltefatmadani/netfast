export async function getViolationLog(challengeId) {
  return [
    {
      id: 'v1',
      vector: 'firefox_doh',
      vectorLabel: 'Firefox DNS-over-HTTPS',
      timestamp: Date.now() - 2 * 86400000,
      action: 'warning',
      evidence: { batteryPercent: 91, onAC: true, note: 'DoH mode 2 detected in prefs.js' },
    },
  ];
}

export async function reportViolation(challengeId, vector, evidence) {
  return { recorded: true };
}
