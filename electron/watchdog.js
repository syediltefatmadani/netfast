const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./logger');
const { verifyDNS, verifyTeredoDisabled } = require('./dns');
const { getHostsPath } = require('./hosts');

let hostsHash = null;

function resetHostsBaseline() {
  hostsHash = null;
}

const hash = (f) => crypto.createHash('md5').update(fs.readFileSync(f)).digest('hex');

const ROGUE_DNS_ALLOW = new Set([
  'svchost.exe',
  'System',
  'dns.exe',
  'lsass.exe',
  'services.exe',
]);

function readJsonFile(filePath) {
  let raw = fs.readFileSync(filePath, 'utf8');
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  return JSON.parse(raw);
}

function localPortFromNetstatAddr(addr) {
  if (!addr || addr === '*:*') return null;
  const m = addr.match(/:(\d+)$/);
  return m ? m[1] : null;
}

const VECTOR_LABELS = {
  dns_ipv4: 'IPv4 DNS Integrity',
  dns_ipv6: 'IPv6 DNS Integrity',
  firefox_doh: 'Firefox Secure DNS',
  chrome_doh: 'Chrome Secure DNS',
  ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity',
  rogue_dns: 'DNS Port Monitor',
};

function logVector(key, result) {
  const label = VECTOR_LABELS[key] || key;
  const status = result.violated ? 'VIOLATED' : 'OK';
  const extra = result.process ? { process: result.process } : undefined;
  logger.info('WATCHDOG', `${label}: ${status}`, extra);
}

function checkFirefoxDoH() {
  try {
    const p = path.join(process.env.APPDATA, 'Mozilla', 'Firefox', 'Profiles');
    if (!fs.existsSync(p)) {
      logger.info('WATCHDOG', 'Firefox Secure DNS: OK (no Firefox profiles)');
      return { violated: false };
    }
    for (const profile of fs.readdirSync(p)) {
      const prefs = path.join(p, profile, 'prefs.js');
      if (!fs.existsSync(prefs)) continue;
      const content = fs.readFileSync(prefs, 'utf8');
      if (content.includes('"network.trr.mode", 2') || content.includes('"network.trr.mode", 3')) {
        return { violated: true, profile };
      }
    }
    return { violated: false };
  } catch (e) {
    logger.execError('WATCHDOG', 'Firefox DoH check error', e);
    return { violated: false };
  }
}

function checkChromiumDoH() {
  const files = [
    { browser: 'Chrome', path: path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\User Data\\Default\\Preferences') },
    { browser: 'Edge', path: path.join(process.env.LOCALAPPDATA, 'Microsoft\\Edge\\User Data\\Default\\Preferences') },
  ];
  for (const { browser, path: f } of files) {
    try {
      if (!fs.existsSync(f)) continue;
      const data = readJsonFile(f);
      const mode = data?.dns_over_https?.mode;
      if (mode && mode !== 'off') return { violated: true, browser, mode };
      logger.info('WATCHDOG', `${browser} Secure DNS: OK`, { mode: mode || 'off' });
    } catch (e) {
      logger.warn('WATCHDOG', `${browser} DoH check skipped`, e.message);
    }
  }
  return { violated: false };
}

function checkRogueDNS() {
  try {
    const out = execSync('netstat -ano', { encoding: 'utf8' });
    const listeners = [];
    for (const line of out.split('\n')) {
      if (!line.includes('LISTENING')) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length < 4) continue;
      const localAddr = parts[1];
      const port = localPortFromNetstatAddr(localAddr);
      if (port !== '53') continue;
      const pid = parts[parts.length - 1];
      listeners.push({ localAddr, pid });
    }
    logger.info('WATCHDOG', 'DNS port 53 listeners', { count: listeners.length, listeners });
    for (const { localAddr, pid } of listeners) {
      const name = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { encoding: 'utf8' })
        .split(',')[0]
        .replace(/"/g, '');
      const base = name.toLowerCase();
      const allowed = [...ROGUE_DNS_ALLOW].some((a) => base === a.toLowerCase() || base.includes('svchost'));
      if (!allowed) return { violated: true, process: name, pid, localAddr };
    }
    return { violated: false };
  } catch {
    logger.info('WATCHDOG', 'DNS Port Monitor: OK (no listeners on :53)');
    return { violated: false };
  }
}

function checkHostsFile() {
  const hostsPath = getHostsPath();
  try {
    if (!fs.existsSync(hostsPath)) {
      logger.warn('WATCHDOG', 'Hosts file not found — cannot enforce blocklist', { path: hostsPath });
      return { violated: true, reason: 'hosts_unavailable' };
    }
    const current = hash(hostsPath);
    if (!hostsHash) {
      hostsHash = current;
      logger.info('WATCHDOG', 'Hosts baseline stored', {
        path: hostsPath,
        hash: hostsHash.slice(0, 8) + '…',
      });
      return { violated: false };
    }
    const violated = current !== hostsHash;
    if (violated) {
      logger.warn('WATCHDOG', 'Hosts file changed', {
        path: hostsPath,
        baseline: hostsHash.slice(0, 8) + '…',
        current: current.slice(0, 8) + '…',
      });
    }
    return { violated };
  } catch (e) {
    logger.execError('WATCHDOG', 'Hosts check failed', e);
    return { violated: false, skipped: true };
  }
}

function getBatteryState() {
  try {
    const out = execSync(
      'powershell "(Get-WmiObject Win32_Battery | Select-Object EstimatedChargeRemaining, BatteryStatus) | ConvertTo-Json"',
      { encoding: 'utf8' },
    );
    const b = JSON.parse(out);
    const state = { percent: b.EstimatedChargeRemaining, onAC: b.BatteryStatus === 2 };
    logger.info('WATCHDOG', 'Battery', state);
    return state;
  } catch {
    logger.info('WATCHDOG', 'Battery: unavailable (desktop or no WMI battery)');
    return { percent: null, onAC: null };
  }
}

function runFullCheck() {
  logger.info('WATCHDOG', '——— Full integrity check ———');
  const dns = verifyDNS();
  const battery = getBatteryState();

  const vectors = {
    dns_ipv4: { violated: !dns.ipv4.intact },
    dns_ipv6: { violated: !dns.ipv6.intact },
    firefox_doh: checkFirefoxDoH(),
    chrome_doh: checkChromiumDoH(),
    ipv6_tunnel: { violated: !verifyTeredoDisabled() },
    hosts_modified: checkHostsFile(),
    rogue_dns: checkRogueDNS(),
  };

  for (const [key, result] of Object.entries(vectors)) {
    logVector(key, result);
  }

  const integrityOk = !Object.values(vectors).some((v) => v.violated);
  logger.info('WATCHDOG', `Check complete — integrity ${integrityOk ? 'OK' : 'FAILED'}`);

  return {
    integrityOk,
    vectors,
    ...battery,
    timestamp: Date.now(),
  };
}

module.exports = { runFullCheck, getBatteryState, resetHostsBaseline };
