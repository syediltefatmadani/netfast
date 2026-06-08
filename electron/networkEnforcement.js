const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const logger = require('./logger');
const { runEncoded } = require('./powershell');
const { flushDnsCache } = require('./hosts');
const { DNS } = require('./dnsConstants');
const { resolveStatePath } = require('./dataPaths');
const { assertRealEnforcementAllowed, wasRealEnforcementApplied } = require('./enforcementGuard');

const BACKUP_PATH = resolveStatePath('enforcement-network-backup.json');

let lastAdapterScan = null;
let lastAdapterScanAt = 0;
const ADAPTER_SCAN_CACHE_MS = 5000;

const PUBLIC_DNS_IPV4 = new Set([
  '8.8.8.8',
  '8.8.4.4',
  '1.1.1.1',
  '1.0.0.1',
  '9.9.9.9',
  '208.67.222.222',
  '208.67.220.220',
]);

const VERIFICATION_DOMAINS = ['reddit.com', 'pornhat.one'];
const SAFE_VERIFICATION_DOMAIN = 'google.com';
const DIRECT_DNS_TEST_SERVERS = [
  { server: '8.8.8.8', label: 'Google IPv4' },
  { server: '2a0d:2a00:1::', label: 'CleanBrowsing IPv6' },
];

const LOOPBACK_PATTERN = /loopback|isatap|teredo|6to4/i;

function ensureDataDir() {
  const dir = path.dirname(BACKUP_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function isBlockedARecord(value) {
  if (!value) return true;
  const v = String(value).trim().toLowerCase();
  return v === '0.0.0.0' || v === '127.0.0.1';
}

function isBlockedAAAARecord(value) {
  if (!value) return true;
  const v = String(value).trim().toLowerCase();
  return v === '::' || v === '::1';
}

function isRealPublicIpv6(addr) {
  const v = String(addr || '')
    .trim()
    .toLowerCase()
    .replace(/\/\d+$/, '');
  if (!v || isBlockedAAAARecord(v)) return false;
  if (v.startsWith('fe80:') || v.startsWith('fec0:') || v.startsWith('fc') || v.startsWith('fd')) {
    return false;
  }
  return true;
}

function isRealPublicIpv4(addr) {
  const v = String(addr || '').trim();
  if (!v || isBlockedARecord(v)) return false;
  if (v.startsWith('10.') || v.startsWith('192.168.') || v.startsWith('127.')) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v)) return false;
  return true;
}

function containsPublicDns(servers) {
  return (servers || []).some((s) => PUBLIC_DNS_IPV4.has(String(s).trim()));
}

function loadBackup() {
  try {
    if (!fs.existsSync(BACKUP_PATH)) return null;
    return JSON.parse(fs.readFileSync(BACKUP_PATH, 'utf8'));
  } catch (e) {
    logger.warn('ENFORCE', 'Could not read enforcement backup', e.message);
    return null;
  }
}

function saveBackup(backup) {
  ensureDataDir();
  fs.writeFileSync(BACKUP_PATH, JSON.stringify(backup, null, 2), 'utf8');
}

function normalizeAdapterRow(row) {
  if (!row?.interfaceAlias) return null;
  if (LOOPBACK_PATTERN.test(row.interfaceDescription || '') || LOOPBACK_PATTERN.test(row.interfaceAlias || '')) {
    return null;
  }
  return row;
}

function queryAdapterDnsRows(filterScript) {
  const out = runEncoded(`
$rows = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { ${filterScript} } | ForEach-Object {
  $v4 = @( (Get-DnsClientServerAddress -InterfaceAlias $_.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses )
  $v6 = @( (Get-DnsClientServerAddress -InterfaceAlias $_.Name -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses )
  $v6Binding = Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  $metric = (Get-NetIPInterface -InterfaceAlias $_.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
  [PSCustomObject]@{
    interfaceAlias = $_.Name
    interfaceDescription = $_.InterfaceDescription
    status = $_.Status
    ipv4Dns = $v4
    ipv6Dns = $v6
    ipv6BindingEnabled = [bool]($v6Binding -and $v6Binding.Enabled)
    interfaceMetric = $metric
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`);
  const parsed = JSON.parse(out.trim() || '[]');
  const rows = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  return rows.map(normalizeAdapterRow).filter(Boolean);
}

/** Adapters with Status = Up (primary internet path). */
function getActiveAdapters() {
  try {
    return queryAdapterDnsRows(`
  $_.Status -eq 'Up' -and
  $_.InterfaceDescription -notmatch 'Loopback|Software Loopback|Microsoft Loopback' -and
  $_.Name -notmatch 'Loopback'
`);
  } catch (e) {
    logger.execError('ENFORCE', 'Active adapter enumeration failed', e);
    return [];
  }
}

function interfaceHasCleanBrowsingIpv4(ipv4List) {
  const list = ipv4List || [];
  return list.includes(DNS.ipv4.primary) && list.includes(DNS.ipv4.secondary);
}

function interfaceHasCleanBrowsingIpv6(ipv6List) {
  const list = ipv6List || [];
  const norms = list.map((s) => String(s).trim().toLowerCase());
  return (
    norms.includes(DNS.ipv6.primary.toLowerCase()) && norms.includes(DNS.ipv6.secondary.toLowerCase())
  );
}

function adapterNeedsDnsFix(adapter, { strictMode = false } = {}) {
  const hasPublic = containsPublicDns(adapter.ipv4Dns);
  const ipv4Ok = interfaceHasCleanBrowsingIpv4(adapter.ipv4Dns);
  const ipv6Ok = strictMode || interfaceHasCleanBrowsingIpv6(adapter.ipv6Dns);
  return hasPublic || !ipv4Ok || !ipv6Ok;
}

/**
 * All adapters that must receive CleanBrowsing DNS:
 * - Status = Up
 * - VPN/tunnel adapters (TAP/Wintun/WireGuard/etc.) even when Disconnected — pre-seed before VPN connects
 * - Any non-loopback adapter still holding public DNS
 */
function getEnforcementTargetAdapters(options = {}) {
  const { isVpnLikeAdapter } = require('./vpnDetect');
  const strictMode = Boolean(options.strictMode);
  try {
    const all = queryAdapterDnsRows(`
  $_.InterfaceDescription -notmatch 'Loopback|Software Loopback|Microsoft Loopback' -and
  $_.Name -notmatch 'Loopback'
`);
    const byAlias = new Map();

    for (const adapter of all) {
      const isUp = adapter.status === 'Up';
      const isVpnTunnel = isVpnLikeAdapter(adapter.interfaceAlias, adapter.interfaceDescription);
      const needsFix = adapterNeedsDnsFix(adapter, { strictMode });
      if (isUp || isVpnTunnel || needsFix) {
        byAlias.set(adapter.interfaceAlias, adapter);
      }
    }

    return [...byAlias.values()];
  } catch (e) {
    logger.execError('ENFORCE', 'Enforcement target enumeration failed', e);
    return getActiveAdapters();
  }
}

function findAdaptersWithRogueDns(options = {}) {
  return getEnforcementTargetAdapters(options).filter((a) => adapterNeedsDnsFix(a, options));
}

function mergeAdapterIntoBackup(adapters) {
  const backup = loadBackup() || {
    savedAt: new Date().toISOString(),
    strictMode: false,
    adapters: [],
  };
  const byAlias = new Map((backup.adapters || []).map((a) => [a.interfaceAlias, a]));
  const now = new Date().toISOString();

  for (const adapter of adapters) {
    if (!byAlias.has(adapter.interfaceAlias)) {
      byAlias.set(adapter.interfaceAlias, {
        interfaceAlias: adapter.interfaceAlias,
        interfaceDescription: adapter.interfaceDescription,
        ipv4Dns: [...(adapter.ipv4Dns || [])],
        ipv6Dns: [...(adapter.ipv6Dns || [])],
        ipv6BindingEnabled: adapter.ipv6BindingEnabled !== false,
        interfaceMetric: adapter.interfaceMetric ?? null,
        savedAt: now,
      });
    }
  }

  backup.adapters = [...byAlias.values()];
  backup.savedAt = now;
  saveBackup(backup);
  return backup;
}

function logPreEnforcementState(adapters) {
  const { getActiveTunnelAdapters } = require('./vpnDetect');
  const vpnAdapters = getActiveTunnelAdapters();
  logger.info('ENFORCE', 'Pre-enforcement adapter state', {
    activeAdapters: adapters.map((a) => ({
      alias: a.interfaceAlias,
      description: a.interfaceDescription,
      ipv4Dns: a.ipv4Dns,
      ipv6Dns: a.ipv6Dns,
      ipv6Enabled: a.ipv6BindingEnabled,
      hasPublicDns: containsPublicDns(a.ipv4Dns),
    })),
    vpnAdapters: vpnAdapters.map((v) => `${v.name} (${v.description})`),
  });
}

function applyDnsViaNetsh(adapterName, { strictMode = false } = {}) {
  if (!assertRealEnforcementAllowed('netsh-dns-set')) {
    return {
      adapter: adapterName,
      ipv4Ok: true,
      ipv6Ok: strictMode || true,
      strictMode,
      method: 'mock',
      mock: true,
    };
  }
  const quoted = `"${adapterName.replace(/"/g, '\\"')}"`;
  const result = { adapter: adapterName, ipv4Ok: false, ipv6Ok: strictMode, strictMode, method: 'netsh' };
  try {
    execSync(`netsh interface ipv4 set dns name=${quoted} static ${DNS.ipv4.primary} primary`, {
      stdio: 'pipe',
    });
    execSync(`netsh interface ipv4 add dns name=${quoted} ${DNS.ipv4.secondary} index=2`, {
      stdio: 'pipe',
    });
    result.ipv4Ok = true;
  } catch (e) {
    result.ipv4Error = e.message;
  }

  if (!strictMode) {
    try {
      execSync(`netsh interface ipv6 set dnsservers name=${quoted} static ${DNS.ipv6.primary} primary`, {
        stdio: 'pipe',
      });
      execSync(`netsh interface ipv6 add dnsservers name=${quoted} ${DNS.ipv6.secondary} index=2`, {
        stdio: 'pipe',
      });
      result.ipv6Ok = true;
    } catch (e) {
      result.ipv6Error = e.message;
    }
  }

  return result;
}

function buildBatchedDnsApplyScript(targets, { strictMode = false } = {}) {
  const ipv4 = [DNS.ipv4.primary, DNS.ipv4.secondary];
  const ipv6 = [DNS.ipv6.primary, DNS.ipv6.secondary];
  const targetBlocks = targets.map((name) => {
    const alias = name.replace(/'/g, "''");
    const v6Block = strictMode
      ? `$v6Result = @{ ok = $true; skipped = $true; error = $null }`
      : `$v6Result = @{ ok = $false; skipped = $false; error = $null }
try {
  netsh interface ipv6 set dnsservers name="${name.replace(/"/g, '\\"')}" static ${DNS.ipv6.primary} primary | Out-Null
  netsh interface ipv6 add dnsservers name="${name.replace(/"/g, '\\"')}" ${DNS.ipv6.secondary} index=2 | Out-Null
  $v6Result.ok = $true
} catch {
  $v6Result.error = $_.Exception.Message
}`;
    return `
$alias = '${alias}'
$v4Result = @{ ok = $false; error = $null }
${v6Block}
try {
  Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @('${ipv4.join("','")}') -ErrorAction Stop
  $v4Result.ok = $true
} catch {
  $v4Result.error = $_.Exception.Message
}
if (-not $v4Result.ok) {
  try {
    netsh interface ipv4 set dns name="${name.replace(/"/g, '\\"')}" static ${DNS.ipv4.primary} primary | Out-Null
    netsh interface ipv4 add dns name="${name.replace(/"/g, '\\"')}" ${DNS.ipv4.secondary} index=2 | Out-Null
    $v4Result.ok = $true
    $v4Result.error = $null
  } catch {
    $v4Result.error = $_.Exception.Message
  }
}
if (-not $strictMode -and -not $v6Result.ok) {
  try {
    netsh interface ipv6 set dnsservers name="${name.replace(/"/g, '\\"')}" static ${DNS.ipv6.primary} primary | Out-Null
    netsh interface ipv6 add dnsservers name="${name.replace(/"/g, '\\"')}" ${DNS.ipv6.secondary} index=2 | Out-Null
    $v6Result.ok = $true
    $v6Result.error = $null
  } catch {
    $v6Result.error = $_.Exception.Message
  }
}
$results += [PSCustomObject]@{
  adapter = $alias
  ipv4Ok = [bool]$v4Result.ok
  ipv6Ok = [bool]($v6Result.ok -or $v6Result.skipped)
  ipv4Error = $v4Result.error
  ipv6Error = $v6Result.error
  strictMode = $${strictMode ? 'true' : 'false'}
  method = 'batched'
}`;
  });

  return `
$ErrorActionPreference = 'Continue'
$strictMode = $${strictMode ? 'true' : 'false'}
$results = @()
${targetBlocks.join('\n')}
Clear-DnsClientCache -ErrorAction SilentlyContinue
$results | ConvertTo-Json -Compress
`;
}

function applyDnsToTargets(adapterNames, { strictMode = false, adapterRows = null } = {}) {
  if (!adapterNames.length) return { applied: [], failed: [] };

  const rowsByAlias = new Map((adapterRows || []).map((a) => [a.interfaceAlias, a]));
  const toApply = adapterNames.filter((name) => {
    const row = rowsByAlias.get(name);
    if (!row) return true;
    return adapterNeedsDnsFix(row, { strictMode });
  });

  if (!toApply.length) {
    logger.info('ENFORCE', 'All target adapters already have correct DNS — skipping apply', {
      adapters: adapterNames,
    });
    return { applied: adapterNames, failed: [], skipped: true };
  }

  try {
    const out = runEncoded(buildBatchedDnsApplyScript(toApply, { strictMode }));
    const parsed = JSON.parse(out.trim() || '[]');
    const results = Array.isArray(parsed) ? parsed : [parsed];
    const applied = [];
    const failed = [];

    for (const result of results) {
      if (result.ipv4Ok && result.ipv6Ok) applied.push(result.adapter);
      else {
        const fallback = applyDnsViaNetsh(result.adapter, { strictMode });
        if (fallback.ipv4Ok && fallback.ipv6Ok) applied.push(result.adapter);
        else failed.push({ ...result, ...fallback });
      }
    }

    const alreadyOk = adapterNames.filter((n) => !toApply.includes(n));
    return { applied: [...new Set([...alreadyOk, ...applied])], failed };
  } catch (e) {
    logger.execError('ENFORCE', 'Batched DNS apply failed — falling back per adapter', e);
    const applied = [];
    const failed = [];
    for (const name of toApply) {
      const result = applyDnsToAdapter(name, { strictMode });
      if (result.ipv4Ok && result.ipv6Ok) applied.push(name);
      else failed.push(result);
    }
    const alreadyOk = adapterNames.filter((n) => !toApply.includes(n));
    return { applied: [...new Set([...alreadyOk, ...applied])], failed };
  }
}

function applyDnsToAdapter(adapterName, { strictMode = false } = {}) {
  const { applied, failed } = applyDnsToTargets([adapterName], { strictMode });
  if (applied.includes(adapterName)) {
    return {
      adapter: adapterName,
      ipv4Ok: true,
      ipv6Ok: true,
      strictMode,
      method: 'batched',
    };
  }
  return failed[0] || {
    adapter: adapterName,
    ipv4Ok: false,
    ipv6Ok: false,
    strictMode,
    method: 'failed',
  };
}

function sweepRogueAdapterDns({ strictMode = false, maxPasses = 2 } = {}) {
  const retried = [];
  for (let pass = 0; pass < maxPasses; pass++) {
    const rogues = findAdaptersWithRogueDns({ strictMode });
    if (!rogues.length) break;
    logger.warn('ENFORCE', `Rogue/public DNS detected — sweep pass ${pass + 1}`, {
      adapters: rogues.map((a) => ({
        alias: a.interfaceAlias,
        status: a.status,
        ipv4Dns: a.ipv4Dns,
        ipv6Dns: a.ipv6Dns,
      })),
    });
    mergeAdapterIntoBackup(rogues);
    for (const adapter of rogues) {
      applyDnsToAdapter(adapter.interfaceAlias, { strictMode });
      retried.push(adapter.interfaceAlias);
    }
    clearDnsCacheFull();
  }
  return [...new Set(retried)];
}

function clearDnsCacheFull() {
  const flush = flushDnsCache();
  try {
    runEncoded('Clear-DnsClientCache -ErrorAction SilentlyContinue');
    logger.info('ENFORCE', 'Windows DNS client cache cleared via Clear-DnsClientCache');
  } catch (e) {
    logger.warn('ENFORCE', 'Clear-DnsClientCache failed', e.message);
  }
  return flush;
}

function resolveDnsName(domain) {
  const safeDomain = domain.replace(/'/g, "''");
  const script = `
$domain = '${safeDomain}'
$records = @()
try {
  $results = Resolve-DnsName -Name $domain -ErrorAction Stop
  foreach ($r in $results) {
    if ($r.Type -eq 'A' -or $r.Type -eq 'AAAA') {
      $records += [PSCustomObject]@{ type = $r.Type; address = $r.IPAddress.ToString() }
    }
  }
  [PSCustomObject]@{ ok = $true; error = $null; records = $records }
} catch {
  [PSCustomObject]@{ ok = $false; error = $_.Exception.Message; records = @() }
} | ConvertTo-Json -Compress -Depth 4
`;
  try {
    const out = runEncoded(script);
    return JSON.parse(out.trim());
  } catch (e) {
    return { ok: false, error: e.message, records: [] };
  }
}

function curlHead(domain) {
  const url = `https://${domain}`;
  try {
    execSync(`curl.exe -I --max-time 12 --connect-timeout 8 "${url}"`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { domain, blocked: false, error: null };
  } catch (e) {
    const msg = (e.stderr || e.message || '').toString();
    const blocked =
      /could not resolve host|getaddrinfo|name resolution|failed to connect|connection refused|timed out/i.test(
        msg,
      ) || e.status !== 0;
    return { domain, blocked, error: msg.trim().slice(0, 300) || e.message };
  }
}

function evaluateDomainVerification(domain, resolveResult, curlResult) {
  const records = resolveResult?.records || [];
  const aRecords = records.filter((r) => r.type === 'A').map((r) => r.address);
  const aaaaRecords = records.filter((r) => r.type === 'AAAA').map((r) => r.address);

  const aBlocked =
    !resolveResult?.ok ||
    aRecords.length === 0 ||
    aRecords.every(isBlockedARecord);
  const aaaaBlocked =
    !resolveResult?.ok ||
    aaaaRecords.length === 0 ||
    aaaaRecords.every(isBlockedAAAARecord);
  const aaaaLeaked = aaaaRecords.some(isRealPublicIpv6);
  const aLeaked = aRecords.some(isRealPublicIpv4);

  const curlBlocked = curlResult?.blocked === true;

  const ipv4Ok = aBlocked && !aLeaked;
  const ipv6Ok = aaaaBlocked && !aaaaLeaked;
  const fullyBlocked = ipv4Ok && ipv6Ok && (curlBlocked || !curlResult);

  return {
    domain,
    aRecords,
    aaaaRecords,
    aBlocked,
    aaaaBlocked,
    aLeaked,
    aaaaLeaked,
    curlBlocked,
    ipv4Ok,
    ipv6Ok,
    fullyBlocked,
    resolveError: resolveResult?.error || null,
    curlError: curlResult?.error || null,
  };
}

function resolveDnsNameWithServer(domain, server) {
  const safeDomain = domain.replace(/'/g, "''");
  const safeServer = server.replace(/'/g, "''");
  const script = `
$domain = '${safeDomain}'
$server = '${safeServer}'
$result = $null
try {
  $job = Start-Job -ScriptBlock {
    param($d, $s)
    Resolve-DnsName -Name $d -Server $s -DnsOnly -ErrorAction Stop
  } -ArgumentList $domain, $server
  $done = Wait-Job $job -Timeout 6
  if (-not $done) {
    Stop-Job $job -Force -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $result = [PSCustomObject]@{ ok = $false; timedOut = $true; error = 'timeout'; records = @() }
  } else {
    $results = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $records = @()
    foreach ($r in @($results)) {
      if ($r.Type -eq 'A' -or $r.Type -eq 'AAAA') {
        $records += [PSCustomObject]@{ type = $r.Type; address = $r.IPAddress.ToString() }
      }
    }
    $result = [PSCustomObject]@{ ok = $true; timedOut = $false; error = $null; records = $records }
  }
} catch {
  $result = [PSCustomObject]@{ ok = $false; timedOut = $false; error = $_.Exception.Message; records = @() }
}
$result | ConvertTo-Json -Compress -Depth 4
`;
  try {
    const out = runEncoded(script);
    return JSON.parse(out.trim());
  } catch (e) {
    return { ok: false, error: e.message, records: [], timedOut: false };
  }
}

function runNslookup(domain) {
  try {
    const out = execSync(`nslookup ${domain}`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 8000,
    });
    return { domain, ok: true, output: out, blocked: false };
  } catch (e) {
    const msg = (e.stderr || e.stdout || e.message || '').toString();
    const blocked =
      /timed out|can't find|non-existent|failed|refused|no response|server failed/i.test(msg) ||
      e.status !== 0;
    return { domain, ok: false, output: msg.trim().slice(0, 400), blocked, error: e.message };
  }
}

function evaluateDirectDnsBypass(domain, server, resolveResult) {
  const records = resolveResult?.records || [];
  const aRecords = records.filter((r) => r.type === 'A').map((r) => r.address);
  const aaaaRecords = records.filter((r) => r.type === 'AAAA').map((r) => r.address);
  const timedOut = resolveResult?.timedOut === true;
  const errored = !resolveResult?.ok || Boolean(resolveResult?.error);
  const leaked =
    aRecords.some(isRealPublicIpv4) || aaaaRecords.some(isRealPublicIpv6);
  const blocked = timedOut || errored || !leaked;

  return {
    domain,
    server,
    blocked,
    leaked,
    timedOut,
    error: resolveResult?.error || null,
    aRecords,
    aaaaRecords,
  };
}

function runDirectDnsBypassVerification() {
  const directQueries = [];
  let bypassBlocked = true;

  for (const domain of VERIFICATION_DOMAINS) {
    for (const { server, label } of DIRECT_DNS_TEST_SERVERS) {
      const resolveResult = resolveDnsNameWithServer(domain, server);
      const evaluation = evaluateDirectDnsBypass(domain, server, resolveResult);
      evaluation.serverLabel = label;
      directQueries.push(evaluation);
      if (!evaluation.blocked) bypassBlocked = false;
    }
  }

  const nslookupResults = VERIFICATION_DOMAINS.map((domain) => {
    const result = runNslookup(domain);
    const blocked = result.blocked || /0\.0\.0\.0|127\.0\.0\.1|^Address:\s*$/m.test(result.output || '');
    if (!blocked && /Address:\s*(?!0\.0\.0\.0|127\.)/.test(result.output || '')) {
      result.leaked = true;
      bypassBlocked = false;
    } else {
      result.leaked = false;
    }
    result.blocked = blocked || result.leaked !== true;
    return result;
  });

  const verification = {
    directQueries,
    nslookupResults,
    bypassBlocked,
    passed: bypassBlocked,
  };

  logger.info('ENFORCE', 'Direct DNS bypass verification', {
    bypassBlocked,
    directQueries: directQueries.map((q) => ({
      domain: q.domain,
      server: q.server,
      blocked: q.blocked,
      leaked: q.leaked,
      timedOut: q.timedOut,
    })),
    nslookup: nslookupResults.map((n) => ({
      domain: n.domain,
      blocked: n.blocked,
      leaked: n.leaked,
    })),
  });

  return verification;
}

function runSafeSiteVerification() {
  const resolveResult = resolveDnsName(SAFE_VERIFICATION_DOMAIN);
  const curlResult = curlHead(SAFE_VERIFICATION_DOMAIN);
  const records = resolveResult?.records || [];
  const aRecords = records.filter((r) => r.type === 'A').map((r) => r.address);
  const resolves = resolveResult?.ok && aRecords.some(isRealPublicIpv4);
  const reachable = curlResult?.blocked === false;

  const result = {
    domain: SAFE_VERIFICATION_DOMAIN,
    resolves,
    reachable,
    aRecords,
    passed: resolves && reachable,
    resolveError: resolveResult?.error || null,
    curlError: curlResult?.error || null,
  };

  logger.info('ENFORCE', 'Safe site verification', result);
  return result;
}

function runFullEnforcementVerification(options = {}) {
  const includeBypass = options.includeBypass !== false;
  const resolver = runResolverVerification();
  const bypass = includeBypass ? runDirectDnsBypassVerification() : null;
  const safeSite = runSafeSiteVerification();

  const passed =
    resolver.passed &&
    (bypass ? bypass.passed : true) &&
    safeSite.passed;

  return {
    passed,
    resolver,
    bypass,
    safeSite,
  };
}

function logPreEnforcementFirewallState() {
  try {
    const { listRawDnsBlockRuleStatus } = require('./dnsBypassFirewall');
    const rules = listRawDnsBlockRuleStatus();
    logger.info('ENFORCE', 'Pre-enforcement firewall rules (raw DNS blocks)', rules);
  } catch (e) {
    logger.warn('ENFORCE', 'Could not read firewall rule state', e.message);
  }
}

function runResolverVerification() {
  const results = [];
  let ipv4Ok = true;
  let ipv6Ok = true;

  for (const domain of VERIFICATION_DOMAINS) {
    const resolveResult = resolveDnsName(domain);
    const curlResult = curlHead(domain);
    const evaluation = evaluateDomainVerification(domain, resolveResult, curlResult);
    results.push(evaluation);
    if (!evaluation.ipv4Ok) ipv4Ok = false;
    if (!evaluation.ipv6Ok) ipv6Ok = false;
  }

  const verification = {
    domains: results,
    ipv4Ok,
    ipv6Ok,
    allBlocked: results.every((r) => r.fullyBlocked || (r.ipv4Ok && r.ipv6Ok)),
    passed: ipv4Ok && ipv6Ok,
  };

  logger.info('ENFORCE', 'Resolver verification', {
    ipv4Ok,
    ipv6Ok,
    allBlocked: verification.allBlocked,
    domains: results.map((r) => ({
      domain: r.domain,
      a: r.aRecords,
      aaaa: r.aaaaRecords,
      curlBlocked: r.curlBlocked,
      ipv4Ok: r.ipv4Ok,
      ipv6Ok: r.ipv6Ok,
    })),
  });

  return verification;
}

function disableIpv6OnAdapters(adapterNames) {
  const results = [];
  for (const name of adapterNames) {
    const alias = name.replace(/'/g, "''");
    try {
      runEncoded(`
$binding = Get-NetAdapterBinding -Name '${alias}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if ($binding -and $binding.Enabled) {
  Disable-NetAdapterBinding -Name '${alias}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop
}
'ok'
`);
      results.push({ adapter: name, ok: true });
      logger.info('ENFORCE', `IPv6 binding disabled on "${name}" (strict fallback)`);
    } catch (e) {
      logger.execError('ENFORCE', `Failed to disable IPv6 on "${name}"`, e);
      results.push({ adapter: name, ok: false, error: e.message });
    }
  }
  return results;
}

function enableIpv6OnAdapters(adapterEntries) {
  const results = [];
  for (const entry of adapterEntries) {
    if (!entry.ipv6BindingEnabled) continue;
    const alias = entry.interfaceAlias.replace(/'/g, "''");
    try {
      runEncoded(`
$binding = Get-NetAdapterBinding -Name '${alias}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if ($binding -and -not $binding.Enabled) {
  Enable-NetAdapterBinding -Name '${alias}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop
}
'ok'
`);
      results.push({ adapter: entry.interfaceAlias, ok: true });
    } catch (e) {
      logger.warn('ENFORCE', `Failed to re-enable IPv6 on "${entry.interfaceAlias}"`, e.message);
      results.push({ adapter: entry.interfaceAlias, ok: false, error: e.message });
    }
  }
  return results;
}

function restoreAdapterDns(entry) {
  const alias = entry.interfaceAlias.replace(/'/g, "''");
  const quoted = `"${entry.interfaceAlias.replace(/"/g, '\\"')}"`;
  const v4 = (entry.ipv4Dns || []).filter(Boolean);
  const v6 = (entry.ipv6Dns || []).filter(Boolean);

  try {
    if (v4.length > 0) {
      runEncoded(`
Set-DnsClientServerAddress -InterfaceAlias '${alias}' -ServerAddresses @(${v4.map((s) => `'${s}'`).join(',')}) -ErrorAction SilentlyContinue
`);
    } else {
      runEncoded(
        `Set-DnsClientServerAddress -InterfaceAlias '${alias}' -ResetServerAddresses -ErrorAction SilentlyContinue`,
      );
    }

    if (v6.length > 0) {
      runEncoded(`
netsh interface ipv6 set dnsservers name=${quoted} static ${v6[0]} primary | Out-Null
${v6.slice(1).map((s, i) => `netsh interface ipv6 add dnsservers name=${quoted} ${s} index=${i + 2} | Out-Null`).join('\n')}
`);
    } else {
      runEncoded(`netsh interface ipv6 set dnsservers name=${quoted} source=dhcp | Out-Null`);
    }
    return { adapter: entry.interfaceAlias, ok: true };
  } catch (e) {
    logger.warn('ENFORCE', `Restore DNS failed for "${entry.interfaceAlias}"`, e.message);
    return { adapter: entry.interfaceAlias, ok: false, error: e.message };
  }
}

function restoreEnforcementBackup(reason = 'challenge-ended') {
  if (!wasRealEnforcementApplied() && !assertRealEnforcementAllowed('restoreEnforcementBackup')) {
    logger.info('DEV_SAFE', 'Skipped enforcement backup restore — enforcement was not applied');
    return { ok: true, skipped: true, mock: true, reason };
  }
  logger.info('ENFORCE', `Restoring enforcement backup (${reason})`);
  const backup = loadBackup();
  if (!backup?.adapters?.length) {
    logger.warn('ENFORCE', 'No enforcement backup found — skipping adapter restore');
    return { ok: false, reason: 'no_backup' };
  }

  const dnsResults = backup.adapters.map(restoreAdapterDns);
  const ipv6Results = enableIpv6OnAdapters(backup.adapters);
  clearDnsCacheFull();

  backup.strictMode = false;
  saveBackup(backup);

  const ok = dnsResults.every((r) => r.ok);
  logger.info('ENFORCE', 'Enforcement backup restored', {
    reason,
    dnsRestored: dnsResults.filter((r) => r.ok).length,
    dnsFailed: dnsResults.filter((r) => !r.ok).map((r) => r.adapter),
    ipv6ReEnabled: ipv6Results.filter((r) => r.ok).length,
  });

  return { ok, dnsResults, ipv6Results, reason };
}

function logDohBypassRisks() {
  const risks = [];
  try {
    const { getChromiumDoHPolicyStatus } = require('./browserPolicy');
    const browser = getChromiumDoHPolicyStatus();
    if (browser?.strategy !== 'cleanbrowsing_template') {
      risks.push({ source: 'chromium', detail: browser?.statusMessage || 'non-CleanBrowsing policy' });
    }
  } catch {
    /* optional */
  }

  try {
    const out = runEncoded(`
$doh = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddress + ' -> ' + $_.DohTemplate })
$reg = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue).EnableAutoDoh
[PSCustomObject]@{ doh = $doh; enableAutoDoh = $reg } | ConvertTo-Json -Compress
`);
    const parsed = JSON.parse(out.trim());
    const cbServers = new Set([
      DNS.ipv4.primary,
      DNS.ipv4.secondary,
      DNS.ipv6.primary,
      DNS.ipv6.secondary,
    ]);
    const nonCb = (parsed.doh || []).filter((line) => {
      const addr = String(line).split(' -> ')[0];
      return addr && !cbServers.has(addr);
    });
    if (nonCb.length) {
      risks.push({ source: 'windows_doh', detail: nonCb.join('; ') });
    }
  } catch {
    /* optional */
  }

  if (risks.length) {
    logger.warn('ENFORCE', 'DoH bypass risks detected', risks);
  } else {
    logger.info('ENFORCE', 'DoH bypass check: no obvious risks');
  }
  return risks;
}

function rollbackFromBackup(backup) {
  if (!backup?.adapters?.length) return { ok: false, reason: 'no_backup' };
  logger.warn('ENFORCE', 'Rolling back partial enforcement from backup');
  return restoreEnforcementBackup('enforcement-failed-rollback');
}

/**
 * Apply IPv4+IPv6 CleanBrowsing DNS to all active adapters, verify with Windows resolver,
 * and fall back to strict mode (disable IPv6 bindings) when IPv6 enforcement cannot be verified.
 */
function applyNetworkEnforcement() {
  if (!assertRealEnforcementAllowed('applyNetworkEnforcement')) {
    logger.info('DEV_SAFE', 'Mock network enforcement success');
    return {
      ok: true,
      adapters: [],
      applied: [],
      failed: [],
      strictMode: false,
      verification: { ipv4Ok: true, ipv6Ok: true, passed: true, mock: true },
      mock: true,
    };
  }
  const backup = loadBackup() || {
    savedAt: new Date().toISOString(),
    strictMode: false,
    adapters: [],
  };
  let strictMode = Boolean(backup.strictMode);
  let targets = getEnforcementTargetAdapters({ strictMode });
  const activeUp = getActiveAdapters();

  if (!activeUp.length && !targets.length) {
    logger.warn('ENFORCE', 'No active adapters — skipping enforcement');
    return {
      ok: false,
      adapters: [],
      applied: [],
      failed: [],
      strictMode: false,
      verification: null,
      reason: 'no_active_adapters',
    };
  }

  if (!targets.length) targets = activeUp;

  logPreEnforcementState(targets);
  logPreEnforcementFirewallState();
  logDohBypassRisks();

  mergeAdapterIntoBackup(targets);
  const adapterNames = targets.map((a) => a.interfaceAlias);
  lastAdapterScan = targets;
  lastAdapterScanAt = Date.now();

  let { applied, failed } = applyDnsToTargets(adapterNames, { strictMode, adapterRows: targets });
  clearDnsCacheFull();
  const sweepRetried = sweepRogueAdapterDns({ strictMode });
  if (sweepRetried.length) {
    const sweepRows = getEnforcementTargetAdapters({ strictMode });
    const afterSweep = applyDnsToTargets(sweepRetried, { strictMode, adapterRows: sweepRows });
    applied = [...new Set([...applied, ...afterSweep.applied])];
    failed = failed.filter((f) => !afterSweep.applied.includes(f.adapter)).concat(afterSweep.failed);
  }

  let verification = runResolverVerification();
  let ipv6NeedsFallback = !verification.ipv6Ok && !strictMode;

  if (ipv6NeedsFallback) {
    logger.warn('ENFORCE', 'IPv6 DNS verification failed — switching to strict fallback (disable IPv6 bindings)', {
      verification,
    });
    strictMode = true;
    backup.strictMode = true;
    saveBackup(backup);

    const disableResults = disableIpv6OnAdapters(adapterNames);
    for (const name of adapterNames) {
      applyDnsToAdapter(name, { strictMode: true });
    }
    clearDnsCacheFull();
    verification = runResolverVerification();
    verification.strictFallbackApplied = true;
    verification.ipv6DisableResults = disableResults;
  }

  const remainingRogues = findAdaptersWithRogueDns({ strictMode });
  const auditAdapters = getEnforcementTargetAdapters({ strictMode });
  logger.info('ENFORCE', 'Post-enforcement adapter state', {
    strictMode,
    remainingRogues: remainingRogues.map((a) => ({
      alias: a.interfaceAlias,
      status: a.status,
      ipv4Dns: a.ipv4Dns,
      ipv6Dns: a.ipv6Dns,
    })),
    adapters: auditAdapters.map((a) => ({
      alias: a.interfaceAlias,
      ipv4Dns: a.ipv4Dns,
      ipv6Dns: a.ipv6Dns,
      ipv6Enabled: a.ipv6BindingEnabled,
    })),
    verification: {
      ipv4Ok: verification.ipv4Ok,
      ipv6Ok: verification.ipv6Ok || strictMode,
      passed: verification.passed || (verification.ipv4Ok && strictMode),
    },
    flushOk: true,
  });

  if (failed.length) {
    logger.error('ENFORCE', 'DNS apply failed on one or more adapters', failed);
    rollbackFromBackup(backup);
    return {
      ok: false,
      adapters: adapterNames,
      applied,
      failed,
      strictMode,
      verification,
      reason: 'adapter_apply_failed',
      rolledBack: true,
    };
  }

  const ok =
    verification.ipv4Ok &&
    (verification.ipv6Ok || strictMode) &&
    failed.length === 0 &&
    remainingRogues.length === 0;
  if (!ok) {
    logger.error('ENFORCE', 'Enforcement verification failed after apply', {
      verification,
      failed,
      remainingRogues: remainingRogues.map((a) => a.interfaceAlias),
    });
  }

  return {
    ok,
    adapters: adapterNames,
    applied,
    failed,
    strictMode,
    verification,
    remainingRogues,
    backupPath: BACKUP_PATH,
  };
}

function getAdapterFingerprint() {
  const adapters = getEnforcementTargetAdapters();
  return adapters
    .map((a) => `${a.interfaceAlias}|${a.status}|${(a.ipv4Dns || []).join(',')}|${(a.ipv6Dns || []).join(',')}|${a.ipv6BindingEnabled}`)
    .sort()
    .join(';');
}

function getCachedAdapterScan(maxAgeMs = ADAPTER_SCAN_CACHE_MS) {
  if (lastAdapterScan && Date.now() - lastAdapterScanAt <= maxAgeMs) {
    return lastAdapterScan;
  }
  return null;
}

function isAdapterStateCompliant(options = {}) {
  const strictMode = Boolean(options.strictMode ?? loadBackup()?.strictMode);
  const targets = getEnforcementTargetAdapters({ strictMode });
  if (!targets.length) return false;
  return targets.every((adapter) => !adapterNeedsDnsFix(adapter, { strictMode }));
}

module.exports = {
  BACKUP_PATH,
  PUBLIC_DNS_IPV4,
  VERIFICATION_DOMAINS,
  SAFE_VERIFICATION_DOMAIN,
  DIRECT_DNS_TEST_SERVERS,
  getActiveAdapters,
  getEnforcementTargetAdapters,
  findAdaptersWithRogueDns,
  loadBackup,
  mergeAdapterIntoBackup,
  applyDnsToAdapter,
  applyNetworkEnforcement,
  restoreEnforcementBackup,
  runResolverVerification,
  runDirectDnsBypassVerification,
  runSafeSiteVerification,
  runFullEnforcementVerification,
  resolveDnsNameWithServer,
  evaluateDirectDnsBypass,
  clearDnsCacheFull,
  disableIpv6OnAdapters,
  enableIpv6OnAdapters,
  logDohBypassRisks,
  getAdapterFingerprint,
  getCachedAdapterScan,
  isAdapterStateCompliant,
  adapterNeedsDnsFix,
  interfaceHasCleanBrowsingIpv4,
  interfaceHasCleanBrowsingIpv6,
  isBlockedARecord,
  isBlockedAAAARecord,
  isRealPublicIpv6,
  isRealPublicIpv4,
  evaluateDomainVerification,
  containsPublicDns,
};
