const { runPowerShell, cached, parseJsonList } = require('../util/commandRunner');
const { INTERVALS } = require('../config/serviceConfig');
const logger = require('../logging/serviceLogger');

/**
 * Virtualization / alternate-environment monitor — DETECT AND REPORT ONLY.
 *
 * Detects the *presence* of environments a user could use to sidestep host-level
 * protection (WSL, Hyper-V, VirtualBox, VMware, Docker Desktop). It never blocks
 * or disables these tools — their presence is reported as a risk signal with a
 * confidence level, nothing more.
 *
 * Detection is intentionally cheap: a single PowerShell pass enumerates
 * services, optional Windows features, and known virtual adapters, run at most
 * every 10 minutes (and only while a challenge is active).
 */

const DETECT_SCRIPT = `
$services = Get-Service -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'vmms|VBoxService|vmware|com.docker.service|LxssManager' } |
  ForEach-Object { @{ name = $_.Name; status = "$($_.Status)" } }
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceDescription -match 'Hyper-V|VirtualBox|VMware|Docker|WSL' } |
  ForEach-Object { $_.InterfaceDescription }
[PSCustomObject]@{
  services = @($services)
  adapters = @($adapters)
} | ConvertTo-Json -Compress -Depth 4
`;

const SIGNATURES = [
  { match: /LxssManager|WSL/i, label: 'WSL' },
  { match: /vmms|Hyper-V/i, label: 'Hyper-V' },
  { match: /VBox|VirtualBox/i, label: 'VirtualBox' },
  { match: /vmware/i, label: 'VMware' },
  { match: /docker/i, label: 'Docker Desktop' },
];

function classify(haystack, detected) {
  for (const sig of SIGNATURES) {
    if (sig.match.test(haystack) && !detected.includes(sig.label)) {
      detected.push(sig.label);
    }
  }
}

async function check() {
  const lastCheckedAt = new Date().toISOString();
  const detected = [];

  try {
    const out = await cached('virt:scan', INTERVALS.virtualizationMs - 1000, () =>
      runPowerShell(DETECT_SCRIPT, { timeoutMs: 12000 }),
    );
    const parsed = parseJsonList(out)[0] || {};
    const services = Array.isArray(parsed.services) ? parsed.services : [];
    const adapters = Array.isArray(parsed.adapters) ? parsed.adapters : [];
    for (const s of services) classify(`${s.name}`, detected);
    for (const a of adapters) classify(`${a}`, detected);
  } catch (e) {
    logger.warn('VIRTUALIZATION', 'Detection scan failed', e.message);
  }

  let confidence = 'low';
  if (detected.length >= 2) confidence = 'high';
  else if (detected.length === 1) confidence = 'medium';

  return {
    virtualizationRiskDetected: detected.length > 0,
    detectedSystems: detected,
    confidence,
    lastCheckedAt,
  };
}

module.exports = { check, name: 'virtualization' };
