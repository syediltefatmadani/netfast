const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const { runEncoded } = require('./powershell');
const { resolveStatePath } = require('./dataPaths');
const { assertRealEnforcementAllowed } = require('./enforcementGuard');

const SNAPSHOT_PATH = resolveStatePath('pre-lockdown-snapshot.json');

function ensureDataDir() {
  const dir = path.dirname(SNAPSHOT_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function captureAdapterDns() {
  try {
    const out = runEncoded(`
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
$rows = foreach ($a in $adapters) {
  $v4 = @( (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses )
  $v6 = @( (Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses )
  $v6Binding = Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    name = $a.Name
    description = $a.InterfaceDescription
    ipv4 = $v4
    ipv6 = $v6
    ipv6BindingEnabled = [bool]($v6Binding -and $v6Binding.Enabled)
  }
}
$rows | ConvertTo-Json -Compress
`);
    const parsed = JSON.parse(out.trim() || '[]');
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    logger.warn('SNAPSHOT', 'Adapter DNS capture failed', e.message);
    return [];
  }
}

function captureWindowsDoh() {
  try {
    const out = runEncoded(`
$doh = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ server = $_.ServerAddress; template = $_.DohTemplate; allowUdp = $_.AllowFallbackToUdp }
})
$reg = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue).EnableAutoDoh
[PSCustomObject]@{ doh = $doh; enableAutoDoh = $reg } | ConvertTo-Json -Compress -Depth 4
`);
    return JSON.parse(out.trim() || '{}');
  } catch (e) {
    logger.warn('SNAPSHOT', 'Windows DoH capture failed', e.message);
    return { doh: [], enableAutoDoh: null };
  }
}

function captureTunnelState() {
  const tunnels = ['teredo', '6to4', 'isatap'];
  const state = [];
  const { execSync } = require('child_process');
  for (const t of tunnels) {
    try {
      const out = execSync(`netsh interface ${t} show state`, { encoding: 'utf8' });
      const disabled = out.toLowerCase().includes('disabled');
      state.push({ name: t, disabled });
    } catch {
      state.push({ name: t, disabled: true });
    }
  }
  return state;
}

function capturePreLockdownSnapshot() {
  if (!assertRealEnforcementAllowed('capturePreLockdownSnapshot')) {
    logger.info('DEV_SAFE', 'Skipped pre-lockdown snapshot capture');
    return loadSnapshot() || { hasSnapshot: false, mock: true };
  }
  ensureDataDir();
  if (fs.existsSync(SNAPSHOT_PATH)) {
    try {
      const existing = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, 'utf8'));
      if (existing?.hasSnapshot) {
        logger.info('SNAPSHOT', 'Pre-lockdown snapshot already exists — skipping capture');
        return existing;
      }
    } catch {
      /* re-capture */
    }
  }

  const snapshot = {
    hasSnapshot: true,
    capturedAt: new Date().toISOString(),
    adapters: captureAdapterDns(),
    windowsDoh: captureWindowsDoh(),
    tunnels: captureTunnelState(),
  };

  fs.writeFileSync(SNAPSHOT_PATH, JSON.stringify(snapshot, null, 2), 'utf8');
  logger.info('SNAPSHOT', 'Pre-lockdown snapshot captured', {
    adapters: snapshot.adapters.length,
    dohEntries: (snapshot.windowsDoh?.doh || []).length,
  });
  return snapshot;
}

function loadSnapshot() {
  try {
    if (!fs.existsSync(SNAPSHOT_PATH)) return null;
    return JSON.parse(fs.readFileSync(SNAPSHOT_PATH, 'utf8'));
  } catch (e) {
    logger.warn('SNAPSHOT', 'Could not read snapshot', e.message);
    return null;
  }
}

function restoreAdapterDnsFromSnapshot(snapshot) {
  const adapters = snapshot?.adapters || [];
  if (!adapters.length) return { ok: false, reason: 'no_adapter_data' };

  let restored = 0;
  for (const iface of adapters) {
    try {
      const v4 = (iface.ipv4 || []).filter(Boolean);
      const v6 = (iface.ipv6 || []).filter(Boolean);
      const name = iface.name.replace(/'/g, "''");
      if (v4.length === 0 && v6.length === 0) continue;

      const quoted = `"${iface.name.replace(/"/g, '\\"')}"`;
      if (v4.length > 0) {
        runEncoded(`
$alias = '${name}'
Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @(${v4.map((s) => `'${s}'`).join(',')}) -ErrorAction SilentlyContinue
`);
      } else {
        runEncoded(
          `Set-DnsClientServerAddress -InterfaceAlias '${name}' -ResetServerAddresses -ErrorAction SilentlyContinue`,
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

      if (iface.ipv6BindingEnabled === true) {
        runEncoded(`
$binding = Get-NetAdapterBinding -Name '${name}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if ($binding -and -not $binding.Enabled) {
  Enable-NetAdapterBinding -Name '${name}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue
}
`);
      } else if (iface.ipv6BindingEnabled === false) {
        runEncoded(`
$binding = Get-NetAdapterBinding -Name '${name}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if ($binding -and $binding.Enabled) {
  Disable-NetAdapterBinding -Name '${name}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue
}
`);
      }

      restored++;
    } catch (e) {
      logger.warn('SNAPSHOT', `Restore DNS failed for ${iface.name}`, e.message);
    }
  }
  return { ok: restored > 0, restored };
}

function restoreWindowsDohFromSnapshot(snapshot) {
  const dohState = snapshot?.windowsDoh;
  if (!dohState) return { ok: false, reason: 'no_doh_data' };

  try {
    const entries = dohState.doh || [];
    const enableAutoDoh = dohState.enableAutoDoh;
    const entriesJson = JSON.stringify(entries).replace(/'/g, "''");
    runEncoded(`
$entries = '${entriesJson}' | ConvertFrom-Json
$cleanBrowsing = @('185.228.168.168','185.228.169.168','2a0d:2a00:1::','2a0d:2a00:2::')
Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object { $cleanBrowsing -contains $_.ServerAddress } | ForEach-Object {
  Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -ErrorAction SilentlyContinue
}
foreach ($e in $entries) {
  if ($e.server) {
    Add-DnsClientDohServerAddress -ServerAddress $e.server -DohTemplate ($e.template) -AllowFallbackToUdp ([bool]$e.allowUdp) -ErrorAction SilentlyContinue
  }
}
if ($null -ne ${enableAutoDoh === null ? '$null' : enableAutoDoh}) {
  Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableAutoDoh' -Value ${enableAutoDoh ?? 0} -Type DWord -Force -ErrorAction SilentlyContinue
}
'ok'
`);
    return { ok: true };
  } catch (e) {
    logger.warn('SNAPSHOT', 'Windows DoH restore failed', e.message);
    return { ok: false, error: e.message };
  }
}

function restoreTunnelsFromSnapshot(snapshot) {
  const tunnels = snapshot?.tunnels || [];
  const { execSync } = require('child_process');
  const results = [];
  for (const t of tunnels) {
    if (t.disabled) continue;
    try {
      execSync(`netsh interface ${t.name} set state enabled`, { encoding: 'utf8' });
      results.push({ name: t.name, ok: true });
    } catch (e) {
      results.push({ name: t.name, ok: false, error: e.message });
    }
  }
  return results;
}

function removeCleanBrowsingDohOnly() {
  try {
    runEncoded(`
$cleanBrowsing = @('185.228.168.168','185.228.169.168','2a0d:2a00:1::','2a0d:2a00:2::')
Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object { $cleanBrowsing -contains $_.ServerAddress } | ForEach-Object {
  Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -ErrorAction SilentlyContinue
}
'ok'
`);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

module.exports = {
  SNAPSHOT_PATH,
  capturePreLockdownSnapshot,
  loadSnapshot,
  restoreAdapterDnsFromSnapshot,
  restoreWindowsDohFromSnapshot,
  restoreTunnelsFromSnapshot,
  removeCleanBrowsingDohOnly,
};
