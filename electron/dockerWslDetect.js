const { execSync } = require('child_process');
const logger = require('./logger');
const { runEncoded } = require('./powershell');
const { isDeveloperLikeMode } = require('./policyMode');

const PROBE_TIMEOUT_MS = 20000;

function runCommand(cmd, timeoutMs = PROBE_TIMEOUT_MS) {
  try {
    const out = execSync(cmd, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });
    return { ok: true, stdout: out.trim(), stderr: '' };
  } catch (e) {
    return {
      ok: false,
      stdout: e.stdout?.toString?.()?.trim() || '',
      stderr: e.stderr?.toString?.()?.trim() || '',
      error: e.message,
    };
  }
}

function detectDockerDesktop() {
  try {
    const out = runEncoded(`
$svc = Get-Service -Name 'com.docker.service' -ErrorAction SilentlyContinue
$proc = Get-Process -Name 'Docker Desktop','com.docker.backend' -ErrorAction SilentlyContinue
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.InterfaceDescription -like '*Docker*' -or $_.Name -like 'vEthernet (Docker*'
}
[PSCustomObject]@{
  serviceRunning = ($svc -and $svc.Status -eq 'Running')
  processRunning = ($proc.Count -gt 0)
  virtualAdapters = @($adapters | ForEach-Object { $_.Name })
  installed = [bool]($svc -or $proc -or $adapters)
} | ConvertTo-Json -Compress
`);
    return JSON.parse(out.trim());
  } catch (e) {
    return { installed: false, serviceRunning: false, processRunning: false, virtualAdapters: [], error: e.message };
  }
}

function detectWsl() {
  try {
    const version = runCommand('wsl --status', 8000);
    const list = runCommand('wsl -l -v', 8000);
    const installed = version.ok || list.ok;
    const running = (list.stdout || '').toLowerCase().includes('running');
    return {
      installed,
      running,
      versionOutput: version.stdout || version.stderr || '',
      listOutput: list.stdout || list.stderr || '',
    };
  } catch (e) {
    return { installed: false, running: false, error: e.message };
  }
}

function parseNslookupBlocked(output) {
  const text = (output || '').toLowerCase();
  if (!text) return null;
  if (text.includes("can't find") || text.includes('non-existent') || text.includes('nxdomain')) {
    return true;
  }
  if (text.includes('address:') || text.includes('addresses:')) {
    const lines = text.split('\n');
    for (const line of lines) {
      if (!line.includes('address')) continue;
      const ip = line.replace(/.*address[es]*:\s*/i, '').trim();
      if (
        ip &&
        ip !== '0.0.0.0' &&
        ip !== '127.0.0.1' &&
        !ip.startsWith('::') &&
        !ip.includes('restricted.')
      ) {
        return false;
      }
    }
    return true;
  }
  return null;
}

async function runDockerProbes() {
  const results = {
    dockerDnsOk: null,
    dockerInternetOk: null,
    dockerRestrictedBlocked: null,
    probesRun: false,
  };

  const docker = detectDockerDesktop();
  if (!docker.installed && !docker.processRunning) {
    return { ...results, dockerDetected: false };
  }

  logger.info('DEV_MODE', 'Docker detected', docker);
  results.probesRun = true;
  results.dockerDetected = true;

  const google = runCommand('docker run --rm alpine nslookup google.com', PROBE_TIMEOUT_MS);
  results.dockerDnsOk = google.ok && !parseNslookupBlocked(google.stdout);
  results.dockerInternetOk = google.ok && results.dockerDnsOk;

  const adult = runCommand('docker run --rm alpine nslookup pornhub.com', PROBE_TIMEOUT_MS);
  if (adult.ok) {
    const blocked = parseNslookupBlocked(adult.stdout);
    results.dockerRestrictedBlocked = blocked === true;
  } else {
    results.dockerRestrictedBlocked = null;
  }

  const curl = runCommand('docker run --rm curlimages/curl -I https://google.com', PROBE_TIMEOUT_MS);
  if (curl.ok && /HTTP\/\d(?:\.\d)?\s+[23]/.test(curl.stdout)) {
    results.dockerInternetOk = true;
  }

  return results;
}

async function runWslProbes() {
  const results = {
    wslDnsOk: null,
    wslInternetOk: null,
    wslRestrictedBlocked: null,
    resolvConf: null,
    probesRun: false,
  };

  const wsl = detectWsl();
  if (!wsl.installed) {
    return { ...results, wslDetected: false };
  }

  logger.info('DEV_MODE', 'WSL detected', wsl);
  results.probesRun = true;
  results.wslDetected = true;

  const resolv = runCommand('wsl cat /etc/resolv.conf', 8000);
  results.resolvConf = resolv.ok ? resolv.stdout : resolv.stderr || resolv.error;

  const google = runCommand('wsl nslookup google.com', PROBE_TIMEOUT_MS);
  results.wslDnsOk = google.ok && !parseNslookupBlocked(google.stdout);
  results.wslInternetOk = google.ok && results.wslDnsOk;

  const adult = runCommand('wsl nslookup pornhub.com', PROBE_TIMEOUT_MS);
  if (adult.ok) {
    results.wslRestrictedBlocked = parseNslookupBlocked(adult.stdout) === true;
  }

  return results;
}

function deriveProtectionFlag(detected, dnsOk, restrictedBlocked) {
  if (!detected) return 'unknown';
  if (dnsOk === null && restrictedBlocked === null) return 'unknown';
  if (restrictedBlocked === false) return 'false';
  if (restrictedBlocked === true && dnsOk === true) return 'true';
  if (restrictedBlocked === true) return 'true';
  return 'false';
}

async function runDockerWslDiagnostics({ runProbes = true } = {}) {
  if (!isDeveloperLikeMode()) {
    return {
      dockerDetected: false,
      wslDetected: false,
      dockerProtected: 'unknown',
      wslProtected: 'unknown',
      skipped: true,
    };
  }

  const dockerState = detectDockerDesktop();
  const wslState = detectWsl();

  let dockerProbes = { dockerDetected: dockerState.installed || dockerState.processRunning };
  let wslProbes = { wslDetected: wslState.installed };

  if (runProbes) {
    try {
      dockerProbes = { ...dockerProbes, ...(await runDockerProbes()) };
    } catch (e) {
      logger.warn('DEV_MODE', 'Docker probe failed', e.message);
    }
    try {
      wslProbes = { ...wslProbes, ...(await runWslProbes()) };
    } catch (e) {
      logger.warn('DEV_MODE', 'WSL probe failed', e.message);
    }
  }

  const dockerProtected = deriveProtectionFlag(
    dockerProbes.dockerDetected,
    dockerProbes.dockerDnsOk,
    dockerProbes.dockerRestrictedBlocked,
  );
  const wslProtected = deriveProtectionFlag(
    wslProbes.wslDetected,
    wslProbes.wslDnsOk,
    wslProbes.wslRestrictedBlocked,
  );

  return {
    docker: dockerState,
    wsl: wslState,
    dockerDetected: Boolean(dockerProbes.dockerDetected),
    wslDetected: Boolean(wslProbes.wslDetected),
    dockerDnsOk: dockerProbes.dockerDnsOk ?? null,
    dockerInternetOk: dockerProbes.dockerInternetOk ?? null,
    dockerRestrictedBlocked: dockerProbes.dockerRestrictedBlocked ?? null,
    wslDnsOk: wslProbes.wslDnsOk ?? null,
    wslInternetOk: wslProbes.wslInternetOk ?? null,
    wslRestrictedBlocked: wslProbes.wslRestrictedBlocked ?? null,
    wslResolvConf: wslProbes.resolvConf ?? null,
    dockerProtected,
    wslProtected,
  };
}

module.exports = {
  detectDockerDesktop,
  detectWsl,
  runDockerProbes,
  runWslProbes,
  runDockerWslDiagnostics,
  deriveProtectionFlag,
};
