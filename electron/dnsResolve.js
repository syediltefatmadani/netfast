const { runEncoded, runEncodedAsync } = require('./powershell');

/**
 * System DNS resolution helpers for the functional-filtering verification.
 *
 * networkEnforcement.js has its own internal resolveDnsName for the apply path;
 * this module provides the same capability (sync + a non-blocking async variant)
 * for the read/verify UI path without dragging the large enforcement module onto
 * the hot path. The PowerShell script matches the enforcement version: it runs
 * Resolve-DnsName inside a job with a hard timeout so a slow lookup can't hang.
 */

function buildResolveDnsScript(domain, timeoutSec) {
  const safeDomain = domain.replace(/'/g, "''");
  return `
$domain = '${safeDomain}'
$timeoutSec = ${Math.max(2, Math.min(timeoutSec, 30))}
$records = @()
$result = $null
try {
  $job = Start-Job -ScriptBlock {
    param($d)
    Resolve-DnsName -Name $d -ErrorAction Stop
  } -ArgumentList $domain
  $done = Wait-Job $job -Timeout $timeoutSec
  if (-not $done) {
    Stop-Job $job -Force -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $result = [PSCustomObject]@{ ok = $false; timedOut = $true; error = 'timeout'; records = @() }
  } else {
    $results = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
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
}

function resolveDnsName(domain, { timeoutSec = 15 } = {}) {
  try {
    return JSON.parse(runEncoded(buildResolveDnsScript(domain, timeoutSec)).trim());
  } catch (e) {
    return { ok: false, error: e.message, records: [] };
  }
}

/** Non-blocking variant of resolveDnsName for the read/verify UI path. */
async function resolveDnsNameAsync(domain, { timeoutSec = 15 } = {}) {
  try {
    return JSON.parse((await runEncodedAsync(buildResolveDnsScript(domain, timeoutSec))).trim());
  } catch (e) {
    return { ok: false, error: e.message, records: [] };
  }
}

module.exports = { resolveDnsName, resolveDnsNameAsync, buildResolveDnsScript };
