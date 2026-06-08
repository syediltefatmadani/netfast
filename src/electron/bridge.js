export const electronBridge = {
  getDNSStatus: async () => {
    if (window.electron) return await window.electron.invoke('get-dns-status');
    return {
      ipv4: { intact: true },
      ipv6: { intact: true },
      protectionActive: true,
      health: { status: 'HEALTHY', healthy: true },
      timestamp: Date.now(),
    };
  },
  getDnsHealth: async () => {
    if (window.electron) return await window.electron.invoke('get-dns-health');
    return { status: 'HEALTHY', healthy: true, details: 'dev mock' };
  },
  getDnsAuditLog: async () => {
    if (window.electron) return await window.electron.invoke('get-dns-audit-log');
    return [];
  },
  getVpnChallengeState: async (context) => {
    if (window.electron) return await window.electron.invoke('get-vpn-challenge-state', context);
    return {
      status: 'Protected',
      challengeActive: true,
      challengePaused: false,
      canContinue: true,
    };
  },
  vpnAcknowledgeWarning: async () => {
    if (window.electron) return await window.electron.invoke('vpn-acknowledge-warning');
    return { warningAcknowledged: true };
  },
  vpnReapplyProtection: async (context) => {
    if (window.electron) return await window.electron.invoke('vpn-reapply-protection', context);
    return { ok: true };
  },
  getVectorStatus: async (context) => {
    if (window.electron) return await window.electron.invoke('get-vector-status', context);
    return {
      dns_filtering: { warnings: 0 },
      dns_ipv4: { warnings: 0 },
      dns_ipv6: { warnings: 0 },
      firefox_doh: { warnings: 1 },
      chrome_doh: { warnings: 0 },
      windows_doh: { warnings: 0 },
      ipv6_tunnel: { warnings: 0 },
      hosts_modified: { warnings: 0 },
      rogue_dns: { warnings: 0 },
      unknown_vpn: { warnings: 0 },
      watchdog_killed: { warnings: 0 },
      app_tampered: { warnings: 0 },
    };
  },
  triggerDNSRestore: async () => {
    if (window.electron) return await window.electron.invoke('restore-dns');
    return { success: true };
  },
  getBatteryState: async () => {
    if (window.electron) return await window.electron.invoke('get-battery-state');
    return { percent: 87, onAC: true };
  },
  syncChallengeState: async (challenge) => {
    if (window.electron) return await window.electron.invoke('sync-challenge-state', challenge);
    return null;
  },
};
