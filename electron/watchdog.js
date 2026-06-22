const { execSync } = require('child_process');
const { execAsync } = require('./asyncExec');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./logger');
const dnsModule = require('./dns');
const { isHostsFileEnforcementEnabled, getHostsPath } = require('./hosts');
const { getDnsHealthMonitor, isProtectionActive } = require('./services/dns');

let hostsHash = null;

function resetHostsBaseline() {
  hostsHash = null;
}

const hash = (f) => crypto.createHash('md5').update(fs.readFileSync(f)).digest('hex');

const { getWatchdogAllowedProcessNames } = require('./processExclusions');
const { checkUnknownVpn, checkUnknownVpnAsync } = require('./vpnDetect');

const ROGUE_DNS_ALLOW = new Set([
  'svchost.exe',
  'System',
  'dns.exe',
  'lsass.exe',
  'services.exe',
  ...getWatchdogAllowedProcessNames(),
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
  dns_filtering: 'Filtering Effectiveness',
  dns_provider_miss: 'CleanBrowsing Provider Miss',
  fallback_blocking: 'Local Fallback Blocking',
  dns_ipv4: 'DNS Integrity',
  dns_ipv6: 'IPv6 DNS Integrity',
  windows_doh: 'DoH Configuration',
  firefox_doh: 'Firefox Secure DNS',
  chrome_doh: 'Chrome Secure DNS',
  ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity',
  rogue_dns: 'DNS Port Monitor',
  unknown_vpn: 'VPN/Proxy Detection',
};

function logVector(key, result) {
  const label = VECTOR_LABELS[key] || key;
  const status = result.violated ? 'VIOLATED' : 'OK';
  let extra;
  if (result.process) extra = { process: result.process };
  else if (result.adapters?.length) {
    extra = { adapters: result.adapters.map((a) => `${a.name} (${a.description})`) };
  }
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
      const modeOn =
        content.includes('"network.trr.mode", 2') || content.includes('"network.trr.mode", 3');
      if (modeOn) {
        const trrUriMatch = content.match(/"network\.trr\.uri",\s*"([^"]+)"/);
        const uri = trrUriMatch ? trrUriMatch[1] : '';
        const { isCleanBrowsingDohTemplate } = require('./browserPolicy');
        if (!isCleanBrowsingDohTemplate(uri)) {
          return { violated: true, profile, uri: uri || 'unknown' };
        }
      }
    }
    return { violated: false };
  } catch (e) {
    logger.execError('WATCHDOG', 'Firefox DoH check error', e);
    return { violated: false };
  }
}

function checkChromiumDoH() {
  const { isCleanBrowsingDohTemplate } = require('./browserPolicy');
  const files = [
    { browser: 'Chrome', path: path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\User Data\\Default\\Preferences') },
    { browser: 'Edge', path: path.join(process.env.LOCALAPPDATA, 'Microsoft\\Edge\\User Data\\Default\\Preferences') },
  ];
  for (const { browser, path: f } of files) {
    try {
      if (!fs.existsSync(f)) continue;
      const data = readJsonFile(f);
      const doh = data?.dns_over_https || {};
      const mode = doh.mode || 'off';
      const templates = doh.templates || doh.template || '';
      const ok =
        mode === 'off' ||
        (isCleanBrowsingDohTemplate(templates) &&
          (mode === 'secure' || mode === 'automatic'));
      if (!ok) {
        return {
          violated: true,
          browser,
          mode,
          templates,
          reason: 'non_cleanbrowsing_doh',
        };
      }
      logger.info('WATCHDOG', `${browser} Secure DNS: OK`, { mode, templates: templates || 'default' });
    } catch (e) {
      logger.warn('WATCHDOG', `${browser} DoH check skipped`, e.message);
    }
  }
  return { violated: false };
}

function parseDns53Listeners(out) {
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
  return listeners;
}

function isAllowedDnsProcess(name) {
  const base = name.toLowerCase();
  return [...ROGUE_DNS_ALLOW].some((a) => base === a.toLowerCase() || base.includes('svchost'));
}

function processNameFromTasklistCsv(csv) {
  return csv.split(',')[0].replace(/"/g, '');
}

function checkRogueDNS() {
  try {
    const listeners = parseDns53Listeners(execSync('netstat -ano', { encoding: 'utf8' }));
    logger.info('WATCHDOG', 'DNS port 53 listeners', { count: listeners.length, listeners });
    for (const { localAddr, pid } of listeners) {
      const name = processNameFromTasklistCsv(
        execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { encoding: 'utf8' }),
      );
      if (!isAllowedDnsProcess(name)) return { violated: true, process: name, pid, localAddr };
    }
    return { violated: false };
  } catch {
    logger.info('WATCHDOG', 'DNS Port Monitor: OK (no listeners on :53)');
    return { violated: false };
  }
}

/** Non-blocking variant of checkRogueDNS for the read/verify UI path. */
async function checkRogueDNSAsync() {
  try {
    const listeners = parseDns53Listeners(await execAsync('netstat -ano'));
    logger.info('WATCHDOG', 'DNS port 53 listeners', { count: listeners.length, listeners });
    for (const { localAddr, pid } of listeners) {
      const name = processNameFromTasklistCsv(
        await execAsync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`),
      );
      if (!isAllowedDnsProcess(name)) return { violated: true, process: name, pid, localAddr };
    }
    return { violated: false };
  } catch {
    logger.info('WATCHDOG', 'DNS Port Monitor: OK (no listeners on :53)');
    return { violated: false };
  }
}

function checkHostsFile() {
  if (!isHostsFileEnforcementEnabled()) {
    return { violated: false, skipped: true, reason: 'hosts_monitoring_disabled' };
  }
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

const BATTERY_SCRIPT =
  '(Get-WmiObject Win32_Battery | Select-Object EstimatedChargeRemaining, BatteryStatus) | ConvertTo-Json';

function parseBatteryState(out) {
  const b = JSON.parse(out);
  const state = { percent: b.EstimatedChargeRemaining, onAC: b.BatteryStatus === 2 };
  logger.info('WATCHDOG', 'Battery', state);
  return state;
}

function getBatteryState() {
  try {
    return parseBatteryState(
      execSync(`powershell "${BATTERY_SCRIPT}"`, { encoding: 'utf8' }),
    );
  } catch {
    logger.info('WATCHDOG', 'Battery: unavailable (desktop or no WMI battery)');
    return { percent: null, onAC: null };
  }
}

/** Non-blocking variant of getBatteryState for the read/verify UI path. */
async function getBatteryStateAsync() {
  try {
    return parseBatteryState(await execAsync(`powershell "${BATTERY_SCRIPT}"`));
  } catch {
    logger.info('WATCHDOG', 'Battery: unavailable (desktop or no WMI battery)');
    return { percent: null, onAC: null };
  }
}

/**
 * Assemble the integrity-check result from already-gathered probes. Shared by
 * the sync runFullCheck and the non-blocking runFullCheckAsync so the vector
 * logic stays identical regardless of how the probes were collected.
 */
function buildFullCheckResult({ dns, battery, hostsState, firefoxDoh, chromeDoh, teredoDisabled, rogueDns, unknownVpn }) {
  const probes = dns.probes || [];
  const filterProbe = probes.find((p) => p.label?.includes('CleanBrowsing'));
  if (filterProbe && !filterProbe.blocked) {
    logger.warn('WATCHDOG', 'CleanBrowsing filter probe failed — sites may be reachable', filterProbe);
  }

  const healthReport = getDnsHealthMonitor().getLastReport();
  const summary = healthReport?.validation?.summary;
  const criticalUnblocked = (summary?.criticalUnblockedRestrictedDomains || []).length > 0;
  const knownAdultBlockedByDoh = summary?.knownAdultBlockedByDoh ?? false;
  const providerMisses = summary?.providerMisses || healthReport?.providerMisses || [];
  const fallbackBlockedMisses =
    summary?.fallbackBlockedMisses || healthReport?.fallbackBlockedMisses || [];
  const filteringActive = dns.filteringActive;

  const dnsFilteringViolated =
    criticalUnblocked ||
    (!knownAdultBlockedByDoh &&
      !(healthReport?.healthy) &&
      fallbackBlockedMisses.length < providerMisses.length);

  const vectors = {
    dns_filtering: {
      violated: !dns.functionalDnsProtection,
      status: healthReport?.status,
      details: healthReport?.details,
      finalStatus: healthReport?.finalStatus,
      criticalUnblocked: summary?.criticalUnblockedRestrictedDomains || [],
      blockedDomainTests: dns.blockedDomainTests || [],
    },
    dns_provider_miss: {
      violated: false,
      warning: providerMisses.length > 0,
      severity: 'warning',
      vector: 'dns_filtering_provider_miss',
      domains: providerMisses,
      fallbackBlocked: fallbackBlockedMisses,
    },
    fallback_blocking: {
      violated: false,
      active: fallbackBlockedMisses.length > 0,
      layers: fallbackBlockedMisses.length ? ['hosts_supplement'] : [],
    },
    dns_ipv4: {
      violated: !dns.functionalDnsProtection,
      configLocked: dns.ipv4Locked,
      rogue: (dns.rogueServers || []).filter((r) => r.family === 'IPv4'),
      dohStatus: healthReport?.status,
    },
    dns_ipv6: {
      violated: !dns.functionalDnsProtection,
      configLocked: dns.ipv6Locked,
      rogue: (dns.rogueServers || []).filter((r) => r.family === 'IPv6'),
    },
    windows_doh: {
      violated: !dns.dohConfigured,
      status: healthReport?.status,
    },
    firefox_doh: firefoxDoh,
    chrome_doh: chromeDoh,
    ipv6_tunnel: { violated: !teredoDisabled },
    hosts_modified: hostsState,
    rogue_dns: rogueDns,
    unknown_vpn: unknownVpn,
  };

  for (const [key, result] of Object.entries(vectors)) {
    if (key === 'dns_provider_miss' || key === 'fallback_blocking') {
      if (result.warning || result.active) {
        logger.info('WATCHDOG', `${VECTOR_LABELS[key]}: ${result.warning ? 'WARNING' : 'ACTIVE'}`, {
          domains: result.domains,
          layers: result.layers,
        });
      }
      continue;
    }
    logVector(key, result);
  }

  const integrityOk = !Object.entries(vectors)
    .filter(
      ([k]) =>
        k !== 'dns_provider_miss' &&
        k !== 'fallback_blocking' &&
        !(k === 'hosts_modified' && vectors.hosts_modified?.reason === 'hosts_unavailable'),
    )
    .some(([, v]) => v.violated);

  const protectionWithWarningsOnly =
    integrityOk && providerMisses.length > 0 && !criticalUnblocked;

  logger.info(
    'WATCHDOG',
    `Check complete — ${protectionWithWarningsOnly ? 'OK (provider misses handled by fallback)' : integrityOk ? 'integrity OK' : 'integrity FAILED'}`,
  );

  return {
    integrityOk,
    protectionWithWarningsOnly,
    vectors,
    blockProbes: probes,
    dnsHealth: healthReport,
    ...battery,
    timestamp: Date.now(),
  };
}

function runFullCheck() {
  logger.info('WATCHDOG', '——— Full integrity check ———');
  return buildFullCheckResult({
    dns: dnsModule.verifyDNS(),
    battery: getBatteryState(),
    hostsState: checkHostsFile(),
    firefoxDoh: checkFirefoxDoH(),
    chromeDoh: checkChromiumDoH(),
    teredoDisabled: dnsModule.verifyTeredoDisabled(),
    rogueDns: checkRogueDNS(),
    unknownVpn: checkUnknownVpn(),
  });
}

/**
 * Non-blocking full integrity check for the UI/IPC path. Runs the blocking
 * probes (verifyDNS, battery, netstat/tasklist, teredo, VPN scan) off the main
 * thread; fs-based checks (Firefox/Chrome/hosts) stay sync since they are fast.
 */
async function runFullCheckAsync() {
  logger.info('WATCHDOG', '——— Full integrity check (async) ———');
  const [dns, battery, teredoDisabled, rogueDns, unknownVpn] = await Promise.all([
    dnsModule.verifyDNSAsync(),
    getBatteryStateAsync(),
    dnsModule.verifyTeredoDisabledAsync(),
    checkRogueDNSAsync(),
    checkUnknownVpnAsync(),
  ]);
  return buildFullCheckResult({
    dns,
    battery,
    hostsState: checkHostsFile(),
    firefoxDoh: checkFirefoxDoH(),
    chromeDoh: checkChromiumDoH(),
    teredoDisabled,
    rogueDns,
    unknownVpn,
  });
}

module.exports = {
  runFullCheck,
  runFullCheckAsync,
  getBatteryState,
  getBatteryStateAsync,
  resetHostsBaseline,
};
