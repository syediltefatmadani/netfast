const DAY = 86400000;
const NOW = Date.now();

const EVENTS = [
  {
    id: 'v1',
    vector: 'firefox_doh',
    vectorLabel: 'Firefox DNS-over-HTTPS',
    timestamp: NOW - 2 * DAY - 3 * 3600000,
    action: 'warning',
    severity: 'warning',
    evidence: {
      batteryPercent: 91,
      onAC: true,
      note: 'network.trr.mode = 2 detected in prefs.js',
      processSnapshot: ['firefox.exe (PID 7421)', 'firefox.exe (PID 7422)'],
      dnsResolver: '1.1.1.1 (Cloudflare DoH)',
      filePath: 'C:\\Users\\alex\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xk2.default\\prefs.js',
      diff: '- user_pref("network.trr.mode", 0);\n+ user_pref("network.trr.mode", 2);',
    },
  },
  {
    id: 'v2',
    vector: 'hosts_modified',
    vectorLabel: 'Hosts File Integrity',
    timestamp: NOW - 5 * DAY - 11 * 3600000,
    action: 'warning',
    severity: 'warning',
    evidence: {
      batteryPercent: 47,
      onAC: false,
      note: 'Two entries added to system hosts file',
      processSnapshot: ['notepad.exe (PID 1284, elevated)'],
      filePath: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
      diff: '+ 0.0.0.0 reddit.com\n+ 0.0.0.0 www.reddit.com',
    },
  },
  {
    id: 'v3',
    vector: 'unknown_vpn',
    vectorLabel: 'VPN/Proxy Detection',
    timestamp: NOW - 8 * DAY - 6 * 3600000,
    action: 'warning',
    severity: 'critical',
    evidence: {
      batteryPercent: 78,
      onAC: true,
      note: 'TAP-Windows adapter detected with active route',
      processSnapshot: ['openvpn.exe (PID 9923)', 'nordvpn-service.exe (PID 5511)'],
      dnsResolver: '103.86.96.100 (NordVPN)',
    },
  },
  {
    id: 'v4',
    vector: 'chrome_doh',
    vectorLabel: 'Chrome Secure DNS',
    timestamp: NOW - 12 * DAY - 2 * 3600000,
    action: 'warning',
    severity: 'warning',
    evidence: {
      batteryPercent: 88,
      onAC: true,
      note: 'Secure DNS policy reverted to "automatic"',
      processSnapshot: ['chrome.exe (PID 4412)'],
      filePath: 'HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\DnsOverHttpsMode',
    },
  },
  {
    id: 'v5',
    vector: 'watchdog_killed',
    vectorLabel: 'Watchdog Process',
    timestamp: NOW - 18 * DAY - 9 * 3600000,
    action: 'warning',
    severity: 'critical',
    evidence: {
      batteryPercent: 12,
      onAC: false,
      note: 'NetFastService.exe terminated for 47 seconds',
      processSnapshot: ['taskkill.exe (PID 3301)'],
    },
  },
];

export async function getViolationLog(challengeId) {
  return EVENTS;
}

export async function reportViolation(challengeId, vector, evidence) {
  return { recorded: true };
}
