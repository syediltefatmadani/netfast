export const electronBridge = {
  getDNSStatus: async () => {
    if (window.electron) return await window.electron.invoke('get-dns-status');
    return { ipv4: { intact: true }, ipv6: { intact: true }, timestamp: Date.now() };
  },
  getVectorStatus: async () => {
    if (window.electron) return await window.electron.invoke('get-vector-status');
    return {
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
};
