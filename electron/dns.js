const { execSync } = require('child_process');
const logger = require('./logger');
const { runEncoded, runEncodedAsync } = require('./powershell');
const { execAsync } = require('./asyncExec');
const { assertRealEnforcementAllowed, isRealEnforcementAllowed } = require('./enforcementGuard');
const { getMockDnsApplyResult, getMockVerifyDnsResult } = require('./mockEnforcement');
const { verifyFirewall, verifyFirewallAsync } = require('./firewall');
const { applyMongoNrptRules } = require('./mongoDns');
const { DNS, ALLOWED_IPV4_DNS, ALLOWED_IPV6_DNS } = require('./dnsConstants');
const {
  getActiveAdapters,
  applyNetworkEnforcement,
} = require('./networkEnforcement');
const {
  runFunctionalDnsVerification,
  runFunctionalDnsVerificationAsync,
  invalidateFunctionalDnsCache,
} = require('./functionalDnsVerification');

function run(cmd, tag) {
  logger.info(tag, `> ${cmd}`);
  return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

function runDns(cmd, tag) {
  try {
    const out = run(cmd, tag);
    return { ok: true, output: out };
  } catch (e) {
    logger.execError(tag, `Command failed: ${cmd}`, e);
    return { ok: false, error: e.message };
  }
}

function normalizeIpv6(addr) {
  return (addr || '').trim().toLowerCase().replace(/\/\d+$/, '');
}

function ipv6MatchesAllowed(addr) {
  const n = normalizeIpv6(addr);
  for (const allowed of ALLOWED_IPV6_DNS) {
    if (n === normalizeIpv6(allowed)) return true;
  }
  if (n.startsWith('fe80:') || n.startsWith('fec0:')) return true;
  return false;
}

function isAllowedIpv4Server(addr) {
  if (!addr) return true;
  const a = addr.trim();
  return ALLOWED_IPV4_DNS.has(a);
}

function isAllowedIpv6Server(addr) {
  if (!addr) return true;
  return ipv6MatchesAllowed(addr);
}

function interfaceHasCleanBrowsingIpv4(ipv4List) {
  return (ipv4List || []).includes(DNS.ipv4.primary) && (ipv4List || []).includes(DNS.ipv4.secondary);
}

function interfaceHasCleanBrowsingIpv6(ipv6List) {
  const list = ipv6List || [];
  const norms = list.map(normalizeIpv6);
  return (
    norms.includes(normalizeIpv6(DNS.ipv6.primary)) &&
    norms.includes(normalizeIpv6(DNS.ipv6.secondary))
  );
}

function getConnectedAdapters() {
  const active = getActiveAdapters();
  const adapters = active.map((a) => a.interfaceAlias);

  try {
    const { getActiveTunnelAdapters } = require('./vpnDetect');
    const tunnels = getActiveTunnelAdapters();
    if (tunnels.length) {
      logger.info('DNS', 'Active adapters', {
        connected: adapters,
        vpnTunnels: tunnels.map((t) => `${t.name} (${t.description})`),
      });
    } else {
      logger.info('DNS', 'Active adapters', adapters);
    }
  } catch {
    logger.info('DNS', 'Active adapters', adapters);
  }

  return adapters;
}

function buildDnsAuditFromInterfaces(interfaces, enforcementTargetRows) {
  const { findAdaptersWithRogueDns } = require('./networkEnforcement');
  const rogueServers = [];
  let ipv4Locked = true;
  let ipv6Locked = true;

  const connected = getConnectedAdapters();
  const enforcementTargets = (enforcementTargetRows || []).map((a) => a.interfaceAlias || a.name);
  const targetIfaces = interfaces.filter((i) => enforcementTargets.includes(i.name));

  for (const iface of interfaces) {
    for (const s of iface.ipv4 || []) {
      if (!isAllowedIpv4Server(s)) {
        rogueServers.push({ adapter: iface.name, server: s, family: 'IPv4', status: iface.status });
      }
    }
    for (const s of iface.ipv6 || []) {
      if (!isAllowedIpv6Server(s)) {
        rogueServers.push({ adapter: iface.name, server: s, family: 'IPv6', status: iface.status });
      }
    }
  }

  if (connected.length === 0 && enforcementTargets.length === 0) {
    ipv4Locked = false;
    ipv6Locked = false;
  } else {
    for (const iface of targetIfaces) {
      if (!interfaceHasCleanBrowsingIpv4(iface.ipv4)) {
        ipv4Locked = false;
        logger.warn('DNS', `IPv4 not locked on "${iface.name}" (${iface.status})`, { servers: iface.ipv4 });
      }
      if (!interfaceHasCleanBrowsingIpv6(iface.ipv6)) {
        ipv6Locked = false;
        logger.warn('DNS', `IPv6 not locked on "${iface.name}" (${iface.status})`, { servers: iface.ipv6 });
      }
    }
    if (targetIfaces.length === 0) {
      ipv4Locked = false;
      ipv6Locked = false;
    }
  }

  const remainingRogues = findAdaptersWithRogueDns();
  if (remainingRogues.length) {
    ipv4Locked = false;
    ipv6Locked = false;
  }

  const intact = ipv4Locked && ipv6Locked && rogueServers.length === 0;

  return {
    intact,
    ipv4Locked,
    ipv6Locked,
    rogue: rogueServers,
    rogueServers,
    interfaces,
    connected,
    enforcementTargets,
    remainingRogues: remainingRogues.map((a) => a.interfaceAlias),
  };
}

const DNS_AUDIT_SCRIPT = `
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.InterfaceDescription -notmatch 'Loopback|Software Loopback|Microsoft Loopback' -and
  $_.Name -notmatch 'Loopback'
}
$rows = foreach ($a in $adapters) {
  $v4 = (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  $v6 = (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
  [PSCustomObject]@{ name = $a.Name; status = $a.Status; ipv4 = @($v4); ipv6 = @($v6) }
}
$rows | ConvertTo-Json -Compress
`;

function dnsAuditFromCachedTargets() {
  const { getCachedAdapterScan } = require('./networkEnforcement');
  const cachedTargets = getCachedAdapterScan();
  if (!cachedTargets?.length) return null;
  const interfaces = cachedTargets.map((a) => ({
    name: a.interfaceAlias,
    status: a.status,
    ipv4: a.ipv4Dns || [],
    ipv6: a.ipv6Dns || [],
  }));
  return buildDnsAuditFromInterfaces(interfaces, cachedTargets);
}

function emptyDnsAudit() {
  return {
    intact: false,
    ipv4Locked: false,
    ipv6Locked: false,
    rogue: [],
    rogueServers: [],
    interfaces: [],
    connected: [],
  };
}

/** Per-interface DNS + rogue servers (e.g. router 10.x pushed by DHCP). */
function getDnsAudit() {
  try {
    const cached = dnsAuditFromCachedTargets();
    if (cached) return cached;

    const { getEnforcementTargetAdapters } = require('./networkEnforcement');
    const out = runEncoded(DNS_AUDIT_SCRIPT);
    const parsed = JSON.parse(out.trim() || '[]');
    const interfaces = Array.isArray(parsed) ? parsed : [parsed];
    return buildDnsAuditFromInterfaces(interfaces, getEnforcementTargetAdapters());
  } catch (e) {
    logger.execError('DNS', 'DNS audit failed', e);
    return emptyDnsAudit();
  }
}

/** Non-blocking variant of getDnsAudit for the read/verify UI path. */
async function getDnsAuditAsync() {
  try {
    const cached = dnsAuditFromCachedTargets();
    if (cached) return cached;

    const { getEnforcementTargetAdapters } = require('./networkEnforcement');
    const out = await runEncodedAsync(DNS_AUDIT_SCRIPT);
    const parsed = JSON.parse(out.trim() || '[]');
    const interfaces = Array.isArray(parsed) ? parsed : [parsed];
    return buildDnsAuditFromInterfaces(interfaces, getEnforcementTargetAdapters());
  } catch (e) {
    logger.execError('DNS', 'DNS audit failed', e);
    return emptyDnsAudit();
  }
}

/** Route DNS through CleanBrowsing DoH (harder for ISP to hijack port 53). */
function configureWindowsDoH() {
  if (!assertRealEnforcementAllowed('Add-DnsClientDohServerAddress')) {
    logger.info('DEV_SAFE', 'Mock Windows DoH configuration success');
    return { ok: true, mock: true };
  }
  logger.info('DNS', 'Configuring Windows DNS-over-HTTPS (CleanBrowsing Family)');
  const script = `
$tpl = '${DNS.dohTemplate}'
$servers = @('${DNS.ipv4.primary}', '${DNS.ipv4.secondary}', '${DNS.ipv6.primary}', '${DNS.ipv6.secondary}')
Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
  Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -ErrorAction SilentlyContinue
}
foreach ($s in $servers) {
  Add-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $tpl -AllowFallbackToUdp $false -ErrorAction SilentlyContinue
}
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableAutoDoh' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
'ok'
`;
  try {
    runEncoded(script);
    logger.info('DNS', 'Windows DoH configured for CleanBrowsing Family');
    return { ok: true };
  } catch (e) {
    logger.execError('DNS', 'Windows DoH configuration failed', e);
    return { ok: false, error: e.message };
  }
}

function applyDNS() {
  if (!assertRealEnforcementAllowed('applyDNS')) {
    logger.info('DEV_SAFE', 'Mock DNS enforcement success');
    return getMockDnsApplyResult();
  }
  logger.info('DNS', 'Applying CleanBrowsing Family Filter to all active adapters', DNS);
  const { createPhaseTimer } = require('./startupTiming');
  const dohTimer = createPhaseTimer('windows-doh');
  const doh = configureWindowsDoH();
  dohTimer.end({ ok: doh.ok });
  const nrpt = applyMongoNrptRules();

  const enforcement = applyNetworkEnforcement();
  const adapters = enforcement.adapters || [];

  if (adapters.length === 0) {
    logger.warn('DNS', 'No active adapters found — skipping apply');
    return {
      dnsApplied: false,
      ipv4Locked: false,
      ipv6Locked: false,
      applied: [],
      failed: [],
      adapters: [],
      doh,
      nrptApplied: Boolean(nrpt.nrptApplied),
      nrptError: nrpt.nrptError || null,
      enforcement,
      strictMode: false,
      verification: null,
    };
  }

  if (enforcement.rolledBack) {
    return {
      dnsApplied: false,
      ipv4Locked: false,
      ipv6Locked: false,
      applied: [],
      failed: enforcement.failed || [],
      adapters: [],
      doh,
      nrptApplied: Boolean(nrpt.nrptApplied),
      nrptError: nrpt.nrptError || null,
      enforcement,
      strictMode: enforcement.strictMode,
      verification: enforcement.verification,
      error: 'DNS enforcement rolled back after partial failure',
    };
  }

  const audit = getDnsAudit();
  const dohConfigured = doh?.ok !== false && checkDoHConfig();
  const strictMode = Boolean(enforcement.strictMode);
  const ipv4ConfigLocked = audit.ipv4Locked;
  const ipv6ConfigLocked = strictMode ? audit.ipv4Locked : audit.ipv6Locked;
  const functional = runFunctionalDnsVerification({ timeoutSec: 8 });
  const dnsApplied = functional.functionalDnsProtection;

  const status = {
    dnsApplied,
    ipv4Locked: ipv4ConfigLocked,
    ipv6Locked: ipv6ConfigLocked,
    ipv4ConfigLocked,
    ipv6ConfigLocked,
    functionalDnsProtection: functional.functionalDnsProtection,
    blockedDomainTests: functional.blockedDomainTests,
    strictMode,
    dnsIntegrity: functional.functionalDnsProtection,
    dohConfigured,
    nrptApplied: Boolean(nrpt.nrptApplied),
    nrptError: nrpt.nrptError || null,
    rogueServers: audit.rogueServers,
    applied: enforcement.applied || [],
    failed: enforcement.failed || [],
    adapters: enforcement.applied || [],
    doh,
    audit,
    enforcement,
    verification: enforcement.verification,
    functionalVerification: functional,
  };
  if (status.dohConfigured && (status.rogueServers || []).length === 0) {
    status.dnsIntegrity = functional.functionalDnsProtection;
  }

  if (strictMode) {
    logger.info('DNS', 'Strict fallback active — IPv6 bindings disabled, IPv4 CleanBrowsing enforced');
  }

  if (!functional.functionalDnsProtection) {
    logger.error('DNS', 'Functional DNS filtering verification failed after apply', {
      blockedDomainTests: functional.blockedDomainTests,
      ipv4ConfigLocked,
      ipv6ConfigLocked,
    });
  } else if (!ipv4ConfigLocked || !ipv6ConfigLocked) {
    logger.warn('DNS', 'Filtering active via functional test; adapter DNS config is indirect', {
      ipv4ConfigLocked,
      ipv6ConfigLocked,
      blockedDomainTests: functional.blockedDomainTests,
    });
    logger.info('DNS', 'DNS filtering applied successfully (functional)', {
      adapters: status.applied,
      strictMode,
      functionalDnsProtection: true,
    });
  } else {
    logger.info('DNS', 'DNS lock applied successfully', {
      adapters: status.applied,
      strictMode,
      ipv4: [DNS.ipv4.primary, DNS.ipv4.secondary],
      ipv6: strictMode ? 'disabled (strict fallback)' : [DNS.ipv6.primary, DNS.ipv6.secondary],
      verification: enforcement.verification
        ? { ipv4Ok: enforcement.verification.ipv4Ok, ipv6Ok: enforcement.verification.ipv6Ok }
        : null,
    });
  }

  return status;
}

function isBlockedResolverOutput(output) {
  const text = (output || '').trim();
  if (!text || /^ERR:/i.test(text)) return true;
  const addrs = text.split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
  if (addrs.length === 0) return true;
  return addrs.every(
    (a) =>
      a === '0.0.0.0' ||
      a === '127.0.0.1' ||
      a === '::' ||
      a === '::1' ||
      a.includes('restricted.') ||
      a.includes('rpz.'),
  );
}

/** Uses Windows resolver (hosts file + DNS client), not nslookup. */
function lookupViaSystemResolver(domain) {
  const script = `
$domain = '${domain.replace(/'/g, "''")}'
try {
  $addrs = [System.Net.Dns]::GetHostAddresses($domain)
  ($addrs | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
} catch {
  'ERR:' + $_.Exception.GetType().Name
}
`;
  return runEncoded(script);
}

const DOH_CONFIG_CHECK_SCRIPT = `
$doh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddress -in @('${DNS.ipv4.primary}', '${DNS.ipv4.secondary}', '${DNS.ipv6.primary}', '${DNS.ipv6.secondary}') }
$reg = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue).EnableAutoDoh
$required = @('${DNS.ipv4.primary}', '${DNS.ipv4.secondary}')
$ok = $true
foreach ($addr in $required) {
  if (-not ($doh.ServerAddress -contains $addr)) { $ok = $false }
}
foreach ($d in $doh) {
  if ($d.DohTemplate -ne '${DNS.dohTemplate}') { $ok = $false }
  if ($d.AllowFallbackToUdp -eq $true) { $ok = $false }
}
if ($reg -ne 2) { $ok = $false }
[PSCustomObject]@{ ok = $ok; count = $doh.Count; reg = $reg } | ConvertTo-Json -Compress
`;

function checkDoHConfig() {
  if (!isRealEnforcementAllowed('checkDoHConfig')) return true;
  try {
    const parsed = JSON.parse(runEncoded(DOH_CONFIG_CHECK_SCRIPT).trim());
    return parsed.ok === true;
  } catch (e) {
    logger.execError('DNS', 'DoH config check failed', e);
    return false;
  }
}

/** Non-blocking variant of checkDoHConfig for the read/verify UI path. */
async function checkDoHConfigAsync() {
  if (!isRealEnforcementAllowed('checkDoHConfig')) return true;
  try {
    const parsed = JSON.parse((await runEncodedAsync(DOH_CONFIG_CHECK_SCRIPT)).trim());
    return parsed.ok === true;
  } catch (e) {
    logger.execError('DNS', 'DoH config check failed', e);
    return false;
  }
}

function loadStrictMode() {
  try {
    const { loadBackup } = require('./networkEnforcement');
    return Boolean(loadBackup()?.strictMode);
  } catch {
    return false;
  }
}

function verifyDnsFailureResult() {
  return {
    dnsApplied: false,
    ipv4Locked: false,
    ipv6Locked: false,
    functionalDnsProtection: false,
    blockedDomainTests: [],
    firewallLocked: false,
    rogueServers: [],
    dnsIntegrity: false,
    dohConfigured: false,
    firewallIntact: false,
    rogueDns: [],
    filteringActive: false,
    blockedDomains: [],
    unblockedDomains: [],
    ipv4: { intact: false },
    ipv6: { intact: false },
  };
}

/** Assemble the verifyDNS result from already-gathered checks (sync + async share this). */
function buildVerifyDnsResult({ audit, dohConfigured, fw, functional, strictMode }) {
  const firewallLocked = fw.firewallLocked;
  const ipv4ConfigLocked = audit.ipv4Locked;
    const ipv6ConfigLocked = strictMode ? ipv4ConfigLocked : audit.ipv6Locked;
    const functionalDnsProtection = functional.functionalDnsProtection;
    const dnsApplied = functionalDnsProtection;
    const rogueServers = audit.rogueServers;
    const dnsIntegrity = functionalDnsProtection && firewallLocked;

    const { getDnsHealthMonitor, isProtectionActive } = require('./services/dns');
    const health = getDnsHealthMonitor().getLastReport();
    const probes =
      health?.validation?.policy?.results?.map((r) => {
        const ev = r.evaluation;
        return {
          domain: r.domain,
          label: ev?.providerMiss
            ? 'Provider miss (DoH allowed, fallback may block)'
            : 'CleanBrowsing family filter (DoH)',
          blocked: ev?.finalBlocked ?? r.ok,
          dohBlocked: ev?.dohBlocked ?? false,
          providerMiss: ev?.providerMiss ?? false,
          blockedBy: ev?.blockedBy ?? (r.ok ? ['cleanbrowsing_doh'] : []),
          status: ev?.status ?? r.reason,
          channel: 'doh',
        };
      }) || [];

    const result = {
      dnsApplied,
      ipv4Locked: ipv4ConfigLocked,
      ipv6Locked: ipv6ConfigLocked,
      ipv4ConfigLocked,
      ipv6ConfigLocked,
      functionalDnsProtection,
      blockedDomainTests: functional.blockedDomainTests,
      strictMode,
      firewallLocked,
      firewallCoreLocked: fw.firewallCoreLocked,
      bypassResolversBlocked: fw.bypassResolversBlocked,
      rogueServers,
      dnsIntegrity,
      dohConfigured,
      firewallIntact: firewallLocked,
      rogueDns: rogueServers,
      filteringActive: functionalDnsProtection || (health ? isProtectionActive(health.status) : false),
      blockedDomains: functional.blockedDomainTests.filter((t) => t.blocked).map((t) => t.domain),
      unblockedDomains: functional.blockedDomainTests.filter((t) => !t.blocked).map((t) => t.domain),
      ipv4: { intact: ipv4ConfigLocked, servers: audit.interfaces, rogue: rogueServers },
      ipv6: { intact: ipv6ConfigLocked, servers: audit.interfaces, rogue: rogueServers },
      expected: DNS,
      probes,
      audit,
      functionalVerification: functional,
      dnsHealth: health
        ? {
            status: health.status,
            finalStatus: health.finalStatus,
            providerMisses: health.providerMisses,
            protectionLabel: health.protectionLabel,
          }
        : null,
    };

    if (rogueServers.length) {
      logger.warn('DNS', 'Rogue DNS servers detected (informational)', rogueServers);
    }
    if (!ipv6ConfigLocked) {
      logger.warn('DNS', 'IPv6 adapter DNS is not set to CleanBrowsing (informational)');
    }
    if (!functionalDnsProtection) {
      logger.error('DNS', 'Functional DNS filtering failed — blocked domains are resolving', {
        blockedDomainTests: functional.blockedDomainTests,
      });
    }
    logger.info('DNS', 'Verify DNS', {
      dnsApplied,
      functionalDnsProtection,
      ipv4ConfigLocked,
      ipv6ConfigLocked,
      strictMode,
      firewallLocked,
      dnsIntegrity,
      dohConfigured,
      rogueCount: rogueServers.length,
    });
    return result;
}

function verifyDNS() {
  if (!isRealEnforcementAllowed('verifyDNS')) {
    return getMockVerifyDnsResult();
  }
  try {
    return buildVerifyDnsResult({
      audit: getDnsAudit(),
      dohConfigured: checkDoHConfig(),
      fw: verifyFirewall(),
      functional: runFunctionalDnsVerification({ timeoutSec: 8 }),
      strictMode: loadStrictMode(),
    });
  } catch (e) {
    logger.execError('DNS', 'Verify DNS failed', e);
    return verifyDnsFailureResult();
  }
}

/**
 * Non-blocking verifyDNS for the read/verify UI path. Runs the audit, DoH check,
 * firewall verify, and functional probes off the main thread (in parallel where
 * independent). Returns the identical result shape as verifyDNS.
 */
async function verifyDNSAsync() {
  if (!isRealEnforcementAllowed('verifyDNS')) {
    return getMockVerifyDnsResult();
  }
  try {
    const [audit, dohConfigured, fw, functional] = await Promise.all([
      getDnsAuditAsync(),
      checkDoHConfigAsync(),
      verifyFirewallAsync(),
      runFunctionalDnsVerificationAsync({ timeoutSec: 8 }),
    ]);
    return buildVerifyDnsResult({ audit, dohConfigured, fw, functional, strictMode: loadStrictMode() });
  } catch (e) {
    logger.execError('DNS', 'Verify DNS failed', e);
    return verifyDnsFailureResult();
  }
}

function disableIPv6Tunneling() {
  if (!assertRealEnforcementAllowed('netsh-tunnel-disable')) {
    logger.info('DEV_SAFE', 'Mock IPv6 tunnel disable success');
    return [{ tunnel: 'teredo', ok: true, mock: true }];
  }
  logger.info('TUNNEL', 'Disabling IPv6 tunnel interfaces (teredo, 6to4, isatap)');
  const results = [];
  for (const t of ['teredo', '6to4', 'isatap']) {
    try {
      const out = run(`netsh interface ${t} set state disabled`, 'TUNNEL');
      logger.info('TUNNEL', `${t} disabled`, out.trim().slice(0, 120) || 'ok');
      results.push({ tunnel: t, ok: true });
    } catch (e) {
      logger.execError('TUNNEL', `Failed to disable ${t}`, e);
      results.push({ tunnel: t, ok: false });
    }
  }
  return results;
}

function verifyTeredoDisabled() {
  try {
    const out = execSync('netsh interface teredo show state', { encoding: 'utf8' });
    const disabled = out.toLowerCase().includes('disabled');
    logger.info('TUNNEL', 'Teredo state', { disabled, snippet: out.trim().split('\n')[0] });
    return disabled;
  } catch (e) {
    logger.execError('TUNNEL', 'Teredo verify failed', e);
    return false;
  }
}

/** Non-blocking variant of verifyTeredoDisabled for the read/verify UI path. */
async function verifyTeredoDisabledAsync() {
  try {
    const out = await execAsync('netsh interface teredo show state');
    const disabled = out.toLowerCase().includes('disabled');
    logger.info('TUNNEL', 'Teredo state', { disabled, snippet: out.trim().split('\n')[0] });
    return disabled;
  } catch (e) {
    logger.execError('TUNNEL', 'Teredo verify failed', e);
    return false;
  }
}

module.exports = {
  applyDNS,
  verifyDNS,
  verifyDNSAsync,
  getDnsAudit,
  getDnsAuditAsync,
  disableIPv6Tunneling,
  verifyTeredoDisabled,
  verifyTeredoDisabledAsync,
  configureWindowsDoH,
  checkDoHConfig,
  checkDoHConfigAsync,
  invalidateFunctionalDnsCache,
  DNS,
  ALLOWED_IPV4_DNS,
  ALLOWED_IPV6_DNS,
};
