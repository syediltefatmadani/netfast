const logger = require('./logger');
const { runEncoded } = require('./powershell');

const ADMIN_PRIVILEGE_MESSAGE =
  'DNS firewall lock requires Administrator privileges. Please restart NetFast as Administrator.';

/** Outbound port blocks — stop raw DNS / DoT / DoQ bypass (DoH on 443 stays allowed). */
const RAW_DNS_BLOCK_RULES = [
  {
    displayName: 'NetFast Block Direct DNS UDP 53',
    protocol: 'UDP',
    remotePort: 53,
  },
  {
    displayName: 'NetFast Block Direct DNS TCP 53',
    protocol: 'TCP',
    remotePort: 53,
  },
  {
    displayName: 'NetFast Block DNS-over-TLS TCP 853',
    protocol: 'TCP',
    remotePort: 853,
  },
  {
    displayName: 'NetFast Block DNS-over-QUIC UDP 853',
    protocol: 'UDP',
    remotePort: 853,
  },
];

function isAdminElevationError(msg) {
  const lower = (msg || '').toLowerCase();
  return (
    lower.includes('elevation') ||
    lower.includes('run as administrator') ||
    lower.includes('access is denied')
  );
}

function listRawDnsBlockRuleStatus() {
  try {
    const namesJson = JSON.stringify(RAW_DNS_BLOCK_RULES.map((r) => r.displayName));
    const out = runEncoded(`
$names = '${namesJson.replace(/'/g, "''")}' | ConvertFrom-Json
$rows = foreach ($n in $names) {
  $rule = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($rule) {
    $fp = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      displayName = $n
      exists = $true
      enabled = ($rule.Enabled -eq 'True')
      action = $rule.Action
      direction = $rule.Direction
      protocol = $fp.Protocol
      remotePort = $fp.RemotePort
    }
  } else {
    [PSCustomObject]@{ displayName = $n; exists = $false; enabled = $false }
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`);
    const parsed = JSON.parse(out.trim() || '[]');
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    logger.warn('FIREWALL', 'Could not list raw DNS block rules', e.message);
    return RAW_DNS_BLOCK_RULES.map((r) => ({
      displayName: r.displayName,
      exists: false,
      enabled: false,
    }));
  }
}

function removeRawDnsBlockRules() {
  let removed = 0;
  for (const rule of RAW_DNS_BLOCK_RULES) {
    try {
      runEncoded(`
Remove-NetFirewallRule -DisplayName '${rule.displayName.replace(/'/g, "''")}' -ErrorAction SilentlyContinue
`);
      removed++;
      logger.info('FIREWALL', `Removed raw DNS block rule: ${rule.displayName}`);
    } catch (e) {
      logger.warn('FIREWALL', `Could not remove rule "${rule.displayName}"`, e.message);
    }
  }
  return { removed, ok: true };
}

function ensureSingleRawDnsBlockRule(rule) {
  const name = rule.displayName.replace(/'/g, "''");
  const script = `
$ErrorActionPreference = 'Stop'
$name = '${name}'
$protocol = '${rule.protocol}'
$port = ${rule.remotePort}
$existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
  if ($existing.Enabled -ne 'True') {
    Enable-NetFirewallRule -DisplayName $name -ErrorAction Stop | Out-Null
  }
  $result = [PSCustomObject]@{ displayName = $name; ok = $true; created = $false; enabled = $true }
} else {
  New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block -Protocol $protocol -RemotePort $port -ErrorAction Stop | Out-Null
  $result = [PSCustomObject]@{ displayName = $name; ok = $true; created = $true; enabled = $true }
}
$result | ConvertTo-Json -Compress
`;
  try {
    const out = runEncoded(script);
    return JSON.parse(out.trim());
  } catch (e) {
    const msg = e.message || '';
    return {
      displayName: rule.displayName,
      ok: false,
      error: msg,
      adminRequired: isAdminElevationError(msg),
    };
  }
}

function applyRawDnsBlockRules() {
  logger.info('FIREWALL', 'Applying raw DNS bypass block rules (ports 53 / 853 outbound)');
  const before = listRawDnsBlockRuleStatus();
  logger.info('FIREWALL', 'Existing raw DNS block rules (before)', before);

  const applied = [];
  const failed = [];
  let adminRequired = false;

  for (const rule of RAW_DNS_BLOCK_RULES) {
    const result = ensureSingleRawDnsBlockRule(rule);
    if (result.ok) {
      applied.push({
        displayName: rule.displayName,
        created: result.created === true,
        enabled: true,
      });
      logger.info('FIREWALL', `Raw DNS block rule OK: ${rule.displayName}`, {
        created: result.created,
      });
    } else {
      failed.push(result);
      if (result.adminRequired) adminRequired = true;
      logger.error('FIREWALL', `Raw DNS block rule FAILED: ${rule.displayName}`, result);
      break;
    }
  }

  if (failed.length) {
    logger.error('FIREWALL', 'Raw DNS block apply failed midway — rolling back partial rules');
    removeRawDnsBlockRules();
    return {
      ok: false,
      rawDnsBypassBlocked: false,
      applied: [],
      failed,
      adminRequired,
      error: adminRequired
        ? ADMIN_PRIVILEGE_MESSAGE
        : `Raw DNS firewall rules incomplete (${failed.length} failed)`,
      rolledBack: true,
    };
  }

  const verify = verifyRawDnsBlockRules();
  const after = listRawDnsBlockRuleStatus();
  logger.info('FIREWALL', 'Raw DNS block rules (after)', after);

  return {
    ok: verify.allEnabled,
    rawDnsBypassBlocked: verify.allEnabled,
    applied,
    failed: [],
    adminRequired: false,
    error: verify.allEnabled ? null : 'Raw DNS block rules missing or disabled after apply',
    verify,
    before,
    after,
  };
}

function verifyRawDnsBlockRules() {
  const status = listRawDnsBlockRuleStatus();
  const missing = status.filter((r) => !r.exists).map((r) => r.displayName);
  const disabled = status.filter((r) => r.exists && !r.enabled).map((r) => r.displayName);
  const allEnabled = missing.length === 0 && disabled.length === 0;
  return {
    allEnabled,
    rules: status,
    missing,
    disabled,
  };
}

function refreshRawDnsBlockRules() {
  const verify = verifyRawDnsBlockRules();
  if (verify.allEnabled) return { ok: true, refreshed: false, verify };
  logger.warn('FIREWALL', 'Raw DNS block rules missing/disabled — re-applying', verify);
  return { ...applyRawDnsBlockRules(), refreshed: true };
}

module.exports = {
  RAW_DNS_BLOCK_RULES,
  applyRawDnsBlockRules,
  removeRawDnsBlockRules,
  verifyRawDnsBlockRules,
  refreshRawDnsBlockRules,
  listRawDnsBlockRuleStatus,
};
