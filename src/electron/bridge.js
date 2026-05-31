export const electronBridge = {
  getDNSStatus: async () => {
    if (typeof window !== 'undefined' && window.electron) return await window.electron.invoke('get-dns-status');
    return {
      ipv4: { intact: true, servers: ['185.228.168.10', '185.228.169.11'] },
      ipv6: { intact: true, servers: ['2a0d:2a00:1::', '2a0d:2a00:2::'] },
      teredo: { disabled: true },
      timestamp: Date.now(),
    };
  },

  getVectorStatus: async () => {
    if (typeof window !== 'undefined' && window.electron) return await window.electron.invoke('get-vector-status');
    return {
      dns_ipv4:        { warnings: 0, lastChecked: Date.now() },
      dns_ipv6:        { warnings: 0, lastChecked: Date.now() },
      firefox_doh:     { warnings: 1, lastChecked: Date.now() },
      chrome_doh:      { warnings: 0, lastChecked: Date.now() },
      windows_doh:     { warnings: 0, lastChecked: Date.now() },
      ipv6_tunnel:     { warnings: 0, lastChecked: Date.now() },
      hosts_modified:  { warnings: 0, lastChecked: Date.now() },
      rogue_dns:       { warnings: 0, lastChecked: Date.now() },
      unknown_vpn:     { warnings: 0, lastChecked: Date.now() },
      watchdog_killed: { warnings: 0, lastChecked: Date.now() },
      app_tampered:    { warnings: 0, lastChecked: Date.now() },
    };
  },

  triggerDNSRestore: async () => {
    if (typeof window !== 'undefined' && window.electron) return await window.electron.invoke('restore-dns');
    return { success: true, mock: true };
  },

  getBatteryState: async () => {
    if (typeof window !== 'undefined' && window.electron) return await window.electron.invoke('get-battery-state');
    return { percent: 87, onAC: true };
  },
};
