const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;
const logger = require('./logger');
const { runEncoded } = require('./powershell');
const { assertRealEnforcementAllowed, wasRealEnforcementApplied } = require('./enforcementGuard');
const { isExclusionEnabled } = require('./processExclusions');
const { syncMongoHostsEntries } = require('./hosts');
const { DohClient } = require('./services/dns/DohClient');

const NRPT_RULE_PREFIX = 'NetFast-Mongo-';
const MONGO_NAMESPACES = ['.mongodb.net', '.mongodb.com'];
const MONGO_NRPT_SERVERS = ['185.228.168.168', '185.228.169.168'];

const MONGO_INFRA_DOH_URLS = ['https://doh.cleanbrowsing.org/doh/family-filter/dns-query'];

const DEFAULT_MONGO_ENV_PATHS = [
  path.join('D:', 'shelfmerch', 'shelfmerch-printify-clone', 'backend', '.env'),
  path.join('D:', 'focuslock', 'netfast', '.env'),
];

const DIAG_TIMEOUT_MS = 15000;
const TCP_PROBE_TIMEOUT_MS = 8000;

let mongoDnsFallbackUsed = false;
let hostsFallbackUsed = false;
let lastMongoDiagnostic = null;

function isHostsFallbackEnabled() {
  const v = (process.env.MONGO_HOSTS_FALLBACK || 'false').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

function getMongoAuxResolvers() {
  return [];
}

function extractMongoHost(mongoUrl) {
  if (!mongoUrl || typeof mongoUrl !== 'string') return null;
  const withAuth = mongoUrl.match(/mongodb(?:\+srv)?:\/\/[^/]+@([^/?:#]+)/i);
  if (withAuth) return withAuth[1].toLowerCase();
  const bare = mongoUrl.match(/mongodb(?:\+srv)?:\/\/([^/?:#]+)/i);
  return bare ? bare[1].toLowerCase() : null;
}

function getMongoEnvPaths() {
  const fromEnv = (process.env.NETFAST_MONGO_ENV_PATHS || '')
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean);
  return [...new Set([...fromEnv, ...DEFAULT_MONGO_ENV_PATHS])].filter((p) => fs.existsSync(p));
}

function discoverMongoHostsFromEnvFiles() {
  const hosts = new Set();
  for (const envPath of getMongoEnvPaths()) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const m = trimmed.match(/^(?:MONGO(?:DB)?_(?:URL|URI)|MONGODB_URI)\s*=\s*(.+)$/i);
        if (!m) continue;
        const host = extractMongoHost(m[1].trim().replace(/^["']|["']$/g, ''));
        if (host && (host.includes('mongodb.net') || host.includes('mongodb.com'))) {
          hosts.add(host);
        }
      }
      logger.info('MONGO_DNS', 'Scanned env for Atlas hosts', { envPath, hosts: [...hosts] });
    } catch (e) {
      logger.warn('MONGO_DNS', `Could not read ${envPath}`, e.message);
    }
  }
  return [...hosts];
}

function classifyNrptError(err) {
  const msg = `${err.message || ''} ${err.stderr?.toString() || ''} ${err.stdout?.toString() || ''}`;
  const lower = msg.toLowerCase();
  if (
    lower.includes('foreach-object') &&
    (lower.includes('namespace') || lower.includes('parameter cannot be found'))
  ) {
    return { type: 'syntax_error', message: 'NRPT apply failed — PowerShell parameter or syntax error.' };
  }
  if (lower.includes("parameter name 'namespace'") && lower.includes('removednsclientnrptrule')) {
    return { type: 'syntax_error', message: 'NRPT apply failed — PowerShell parameter or syntax error.' };
  }
  if (
    lower.includes('elevation') ||
    lower.includes('run as administrator') ||
    lower.includes('access is denied') ||
    lower.includes('permissiondenied') ||
    lower.includes('administrative privileges on the machine') ||
    lower.includes('win32 5')
  ) {
    return { type: 'admin_required', message: 'NRPT apply failed — Administrator privileges required.' };
  }
  if (
    lower.includes('is not recognized as the name of a cmdlet') ||
    lower.includes('commandnotfoundexception')
  ) {
    return {
      type: 'cmdlet_missing',
      message: 'NRPT apply failed — DnsClient NRPT cmdlets are not available on this Windows version.',
    };
  }
  if (
    lower.includes('parameter cannot be found') ||
    lower.includes('parameterbindingexception') ||
    lower.includes('cannot bind') ||
    lower.includes('ambiguous')
  ) {
    return { type: 'syntax_error', message: 'NRPT apply failed — PowerShell parameter or syntax error.' };
  }
  return { type: 'unknown', message: `NRPT apply failed — Unknown error: ${err.message}` };
}

const NRPT_APPLY_SCRIPT = `
$prefix = '${NRPT_RULE_PREFIX}'
$namespaces = @('.mongodb.net', '.mongodb.com')
$servers = @('185.228.168.168', '185.228.169.168')

function Test-CleanBrowsingNrpt($rule) {
  $have = @($rule.NameServers)
  foreach ($s in $servers) {
    if ($have -notcontains $s) { return $false }
  }
  return $true
}

$existing = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
  ($_.DisplayName -like "$prefix*") -or ($_.Comment -like "$prefix*")
})

$ErrorActionPreference = 'Stop'
$added = @()
$i = 0
$keptIds = @()

foreach ($ns in $namespaces) {
  $i++
  $label = "$prefix$i"
  $match = $existing | Where-Object { @($_.Namespace)[0] -eq $ns } | Select-Object -First 1

  if ($match -and (Test-CleanBrowsingNrpt $match)) {
    $keptIds += @($match.Name)[0]
    $added += @{
      namespace = $ns
      comment = $match.Comment
      servers = $servers
      existing = $true
    }
    continue
  }

  if ($match) {
    $ruleId = @($match.Name)[0]
    if ($ruleId) {
      Remove-DnsClientNrptRule -Name $ruleId -Force -ErrorAction SilentlyContinue
    }
  }

  Add-DnsClientNrptRule \`
    -Namespace $ns \`
    -NameServers $servers \`
    -Comment $label

  $added += @{
    namespace = $ns
    comment = $label
    servers = $servers
    existing = $false
  }
}

foreach ($rule in $existing) {
  $ruleId = @($rule.Name)[0]
  if ($ruleId -and ($keptIds -notcontains $ruleId)) {
    Remove-DnsClientNrptRule -Name $ruleId -Force -ErrorAction SilentlyContinue
  }
}

@{
  ok = $true
  rules = $added
} | ConvertTo-Json -Compress
`;

const NRPT_REMOVE_SCRIPT = `
$prefix = '${NRPT_RULE_PREFIX}'
$oldRules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
  ($_.DisplayName -like "$prefix*") -or ($_.Comment -like "$prefix*")
}
foreach ($rule in $oldRules) {
  $ruleId = @($rule.Name)[0]
  if ($ruleId) {
    Remove-DnsClientNrptRule -Name $ruleId -Force -ErrorAction SilentlyContinue
  }
}
'ok'
`;

function applyMongoNrptRules() {
  if (!assertRealEnforcementAllowed('NRPT-apply')) {
    logger.info('DEV_SAFE', 'Mock NRPT apply success');
    return { ok: true, skipped: true, nrptApplied: false, nrptError: null, mock: true };
  }
  if (!isExclusionEnabled()) {
    logger.info('MONGO_DNS', 'MongoDB NRPT skipped (NETFAST_MONGO_EXEMPT=0)');
    return { ok: true, skipped: true, nrptApplied: false, nrptError: null };
  }

  try {
    const out = runEncoded(NRPT_APPLY_SCRIPT);
    const parsed = JSON.parse(out.trim());
    logger.info('MONGO_DNS', 'NRPT rules applied for Atlas (CleanBrowsing)', parsed);
    return { ok: true, ...parsed, nrptApplied: true, nrptError: null };
  } catch (e) {
    const classified = classifyNrptError(e);
    logger.warn('MONGO_DNS', classified.message, {
      errorType: classified.type,
      detail: e.message,
    });
    return {
      ok: false,
      error: classified.message,
      errorType: classified.type,
      nrptApplied: false,
      nrptError: classified.message,
    };
  }
}

function removeMongoNrptRules() {
  if (!wasRealEnforcementApplied() && !assertRealEnforcementAllowed('NRPT-remove')) {
    logger.info('DEV_SAFE', 'Skipped NRPT removal — enforcement was not applied');
    return;
  }
  try {
    runEncoded(NRPT_REMOVE_SCRIPT);
    logger.info('MONGO_DNS', 'NRPT rules removed');
  } catch (e) {
    logger.warn('MONGO_DNS', 'NRPT remove failed', e.message);
  }
}

function verifyMongoNrptRules() {
  if (!isExclusionEnabled()) return true;
  try {
    const out = runEncoded(`
$expected = @(${MONGO_NAMESPACES.map((n) => `'${n}'`).join(',')})
$rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -like '${NRPT_RULE_PREFIX}*') -or ($_.Comment -like '${NRPT_RULE_PREFIX}*') }
$found = @($rules.Namespace)
$ok = ($expected | ForEach-Object { $found -contains $_ }) -notcontains $false
[PSCustomObject]@{ ok = $ok; count = @($rules).Count } | ConvertTo-Json -Compress
`);
    const parsed = JSON.parse(out.trim());
    return parsed.ok === true;
  } catch {
    return false;
  }
}

function probeTcpPort(host, port, timeoutMs = TCP_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    try {
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

function classifyMongoFailure(result) {
  if (result.srvLookupOk && result.txtLookupOk && result.shardLookupOk && result.tcp27017Reachable) {
    return 'ok';
  }
  if (!result.srvLookupOk) return 'DNS SRV failed';
  if (!result.txtLookupOk) return 'TXT failed';
  if (!result.shardLookupOk) return 'shard lookup failed';
  if (!result.tcp27017Reachable) {
    if (result.atlasConnectionLikely === false) return 'Atlas IP whitelist likely issue';
    return 'TCP 27017 failed';
  }
  if (result.error && /firewall|blocked|refused/i.test(result.error)) return 'firewall blocked';
  return 'unknown';
}

/**
 * Uses system DNS (Windows adapter / CleanBrowsing) — required for mongodb+srv SRV/TXT.
 */
async function runMongoDnsDiagnostic(hostnames = []) {
  const list = hostnames.length ? hostnames : discoverMongoHostsFromEnvFiles();
  const hostname = list[0] || 'shelfmerch.6uk2ux2.mongodb.net';
  const srvName = `_mongodb._tcp.${hostname}`;

  const result = {
    hostname,
    srvName,
    srvLookupOk: false,
    txtLookupOk: false,
    shardLookupOk: false,
    tcp27017Reachable: false,
    atlasConnectionLikely: false,
    mongoSrvResolvable: false,
    mongoTxtResolvable: false,
    mongoLookupOk: false,
    error: null,
    failureClass: null,
    srvRecords: 0,
    txtRecords: 0,
    shardHost: null,
    shardPort: 27017,
  };

  const errors = [];
  let srvRecords = [];

  try {
    srvRecords = await Promise.race([
      dns.resolveSrv(srvName),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('SRV lookup timed out')), DIAG_TIMEOUT_MS),
      ),
    ]);
    result.srvLookupOk = Array.isArray(srvRecords) && srvRecords.length > 0;
    result.mongoSrvResolvable = result.srvLookupOk;
    result.srvRecords = srvRecords?.length || 0;
  } catch (e) {
    errors.push(`SRV: ${e.message}`);
  }

  try {
    const txt = await Promise.race([
      dns.resolveTxt(hostname),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('TXT lookup timed out')), DIAG_TIMEOUT_MS),
      ),
    ]);
    result.txtLookupOk = Array.isArray(txt) && txt.length > 0;
    result.mongoTxtResolvable = result.txtLookupOk;
    result.txtRecords = txt?.length || 0;
  } catch (e) {
    errors.push(`TXT: ${e.message}`);
  }

  let shardHost = null;
  let shardPort = 27017;
  if (srvRecords.length > 0) {
    const primary = srvRecords[0];
    shardHost = String(primary.name || primary.host || '').replace(/\.$/, '');
    shardPort = Number(primary.port) || 27017;
    result.shardHost = shardHost;
    result.shardPort = shardPort;
    try {
      await Promise.race([
        dns.lookup(shardHost),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('shard lookup timed out')), DIAG_TIMEOUT_MS),
        ),
      ]);
      result.shardLookupOk = true;
      result.mongoLookupOk = true;
    } catch (e) {
      errors.push(`shard lookup: ${e.message}`);
    }
  } else {
    try {
      await Promise.race([
        dns.lookup(hostname),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('lookup timed out')), DIAG_TIMEOUT_MS),
        ),
      ]);
      result.mongoLookupOk = true;
      shardHost = hostname;
      result.shardHost = hostname;
    } catch (e) {
      errors.push(`lookup: ${e.message}`);
    }
  }

  if (shardHost) {
    try {
      const reachable = await probeTcpPort(shardHost, shardPort);
      result.tcp27017Reachable = reachable;
      result.atlasConnectionLikely = reachable && result.srvLookupOk && result.txtLookupOk;
    } catch (e) {
      errors.push(`TCP ${shardPort}: ${e.message}`);
    }
  }

  if (errors.length) result.error = errors.join('; ');
  result.failureClass = classifyMongoFailure(result);

  lastMongoDiagnostic = result;

  logger.info('MONGO_DNS', 'MongoDB Atlas DNS diagnostic', result);
  return result;
}

function getLastMongoDiagnostic() {
  return lastMongoDiagnostic;
}

async function clearAtlasHostsBlock() {
  mongoDnsFallbackUsed = false;
  hostsFallbackUsed = false;
  const { isHostsFileEnforcementEnabled } = require('./hosts');
  if (!isHostsFileEnforcementEnabled()) {
    return { ok: true, skipped: true, reason: 'hosts_file_enforcement_disabled' };
  }
  return syncMongoHostsEntries([]);
}

/** Emergency only when MONGO_HOSTS_FALLBACK=true */
async function syncAtlasHostsFromDoh(extraHostnames = []) {
  const { isHostsFileEnforcementEnabled } = require('./hosts');
  if (!isHostsFileEnforcementEnabled()) {
    return {
      ok: true,
      skipped: true,
      reason: 'hosts_file_enforcement_disabled',
      hostsFallbackEnabled: false,
      mongoDnsFallbackUsed: false,
      hostsFallbackUsed: false,
    };
  }
  const hostsFallbackEnabled = isHostsFallbackEnabled();
  logger.info('MONGO_DNS', 'Atlas hosts handling', {
    hostsFallbackEnabled,
    note: hostsFallbackEnabled
      ? 'Emergency hosts fallback enabled'
      : 'Default: Windows DNS only (mongodb+srv SRV/TXT)',
  });

  if (!hostsFallbackEnabled) {
    const cleared = await clearAtlasHostsBlock();
    return {
      ...cleared,
      skipped: true,
      reason: 'hosts_fallback_disabled',
      hostsFallbackEnabled: false,
      mongoDnsFallbackUsed: false,
      hostsFallbackUsed: false,
    };
  }

  if (!isExclusionEnabled()) {
    return { ok: true, skipped: true, hostsFallbackEnabled: true };
  }

  const hostnames = [...new Set([...discoverMongoHostsFromEnvFiles(), ...extraHostnames])];
  if (hostnames.length === 0) {
    return { ok: true, skipped: true, reason: 'no_hosts', hostsFallbackEnabled: true };
  }

  const entries = [];
  const seenHostIp = new Set();

  for (const hostname of hostnames) {
    try {
      const srv = await dns.resolveSrv(`_mongodb._tcp.${hostname}`);
      for (const rec of srv) {
        const target = String(rec.name || rec.host || '').replace(/\.$/, '');
        if (!target) continue;
        try {
          const [v4, v6] = await Promise.allSettled([
            dns.resolve4(target),
            dns.resolve6(target),
          ]);
          if (v4.status === 'fulfilled') {
            for (const ip of v4.value) {
              const key = `${target}|${ip}`;
              if (!seenHostIp.has(key)) {
                seenHostIp.add(key);
                entries.push({ hostname: target, ip });
              }
            }
          }
          if (v6.status === 'fulfilled') {
            for (const ip of v6.value) {
              const key = `${target}|${ip}`;
              if (!seenHostIp.has(key)) {
                seenHostIp.add(key);
                entries.push({ hostname: target, ip });
              }
            }
          }
        } catch (targetErr) {
          logger.warn('MONGO_DNS', `Shard resolve failed for ${target}`, targetErr.message);
        }
      }
    } catch (e) {
      logger.warn('MONGO_DNS', `Emergency SRV failed for ${hostname}`, e.message);
    }
  }

  if (entries.length === 0) {
    mongoDnsFallbackUsed = true;
    return {
      ok: false,
      error: 'no_resolved_entries',
      hostnames,
      hostsFallbackEnabled: true,
      mongoDnsFallbackUsed: true,
      hostsFallbackUsed: false,
    };
  }

  const result = syncMongoHostsEntries(entries);
  mongoDnsFallbackUsed = true;
  hostsFallbackUsed = result.ok === true && !result.skipped;
  logger.warn('MONGO_DNS', 'Emergency hosts fallback written', {
    entries: entries.length,
    hosts: entries.map((e) => e.hostname),
  });
  return {
    ...result,
    hostnames,
    entries,
    hostsFallbackEnabled: true,
    mongoDnsFallbackUsed: true,
    hostsFallbackUsed,
  };
}

function getFallbackStatus() {
  return {
    mongoDnsFallbackUsed,
    hostsFallbackUsed,
    hostsFallbackEnabled: isHostsFallbackEnabled(),
  };
}

module.exports = {
  NRPT_RULE_PREFIX,
  MONGO_NAMESPACES,
  MONGO_NRPT_SERVERS,
  getMongoAuxResolvers,
  extractMongoHost,
  discoverMongoHostsFromEnvFiles,
  applyMongoNrptRules,
  syncAtlasHostsFromDoh,
  removeMongoNrptRules,
  verifyMongoNrptRules,
  runMongoDnsDiagnostic,
  getLastMongoDiagnostic,
  clearAtlasHostsBlock,
  getFallbackStatus,
  isHostsFallbackEnabled,
};
