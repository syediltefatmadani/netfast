const { spawn } = require('child_process');
const fs = require('fs');
const logger = require('./logger');
const { isRealEnforcementAllowed } = require('./enforcementGuard');
const { getHostsPath } = require('./hosts');

/**
 * Event-driven tamper sensor.
 *
 * Instead of polling Windows every few seconds (spawning fresh powershell.exe
 * each time), this starts ONE long-lived PowerShell process that subscribes to
 * OS change notifications and streams one JSON line per event on stdout. The
 * Electron main thread stays idle (~0% CPU) until something actually changes,
 * then reacts immediately. A hosts-file fs.watch covers the one vector that has
 * a native Node push event.
 *
 * Emitted vectors: 'dns' | 'adapter' | 'firewall' | 'registry_doh' | 'hosts'
 * plus 'sensor_down' when the PowerShell sensor can't stay up (so the caller can
 * fall back to fast polling — a dead sensor must never be a silent blind spot).
 */

const DEBOUNCE_MS = 750;
const INITIAL_BACKOFF_MS = 2000;
const MAX_BACKOFF_MS = 30000;
const STABLE_RESET_MS = 60000;
const SENSOR_DOWN_AFTER = 4;

// A single persistent sensor. Push events (.NET NetworkChange, hosts fs.watch)
// fire in <1s; the WMI/CIM ones use a 5s internal poll (WITHIN 5) — still ~0
// process cost vs. respawning powershell every cycle.
const SENSOR_SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Emit($vector) {
  $line = [PSCustomObject]@{ vector = $vector; ts = (Get-Date).ToString('o') } | ConvertTo-Json -Compress
  [Console]::Out.WriteLine($line)
  [Console]::Out.Flush()
}

# DNS server / IP changes and adapter availability (true push, <1s)
Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName 'NetworkAddressChanged' -SourceIdentifier 'dns' | Out-Null
Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName 'NetworkAvailabilityChanged' -SourceIdentifier 'adapter' | Out-Null

# Firewall rule add/remove/disable (WMI intrinsic event, 5s internal poll)
Register-CimIndicationEvent -Namespace 'root/standardcimv2' -Query "SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE TargetInstance ISA 'MSFT_NetFirewallRule'" -SourceIdentifier 'firewall' | Out-Null

# DoH / Dnscache registry drift (WMI registry event, 5s internal poll)
Register-WmiEvent -Query "SELECT * FROM RegistryKeyChangeEvent WITHIN 5 WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters'" -SourceIdentifier 'registry_doh' | Out-Null

# Heartbeat so the Node side knows the sensor is alive even when idle
Emit 'ready'

while ($true) {
  $evt = Wait-Event -Timeout 3600
  if ($null -eq $evt) { continue }
  Emit $evt.SourceIdentifier
  Remove-Event -EventIdentifier $evt.EventIdentifier
}
`;

/**
 * Pure NDJSON splitter for the sensor's stdout. Returns complete parsed events
 * and any trailing partial line to carry into the next chunk. Exported for tests.
 */
function parseSensorLines(buf) {
  const events = [];
  let rest = buf;
  let idx;
  while ((idx = rest.indexOf('\n')) >= 0) {
    const line = rest.slice(0, idx).trim();
    rest = rest.slice(idx + 1);
    if (!line) continue;
    try {
      const evt = JSON.parse(line);
      if (evt && evt.vector) events.push(evt);
    } catch {
      /* ignore non-JSON noise */
    }
  }
  return { events, rest };
}

function startTamperWatch({ onTamper }) {
  if (!isRealEnforcementAllowed('tamper-watch')) {
    logger.info('DEV_SAFE', 'Tamper sensor disabled — mock/safe mode active');
    return () => {};
  }

  let stopped = false;
  let child = null;
  let hostsWatcher = null;
  let backoff = INITIAL_BACKOFF_MS;
  let failures = 0;
  let stableTimer = null;

  // Coalesce bursts: a single change often emits several events. Once a vector
  // is pending it absorbs further hits until the debounce window fires.
  const pending = new Map();
  function emit(vector, detail) {
    if (stopped || pending.has(vector)) return;
    const t = setTimeout(() => {
      pending.delete(vector);
      try {
        onTamper({ vector, detail });
      } catch (e) {
        logger.error('TAMPER', 'onTamper handler failed', e.message);
      }
    }, DEBOUNCE_MS);
    if (typeof t.unref === 'function') t.unref();
    pending.set(vector, t);
  }

  function spawnSensor() {
    if (stopped) return;
    const b64 = Buffer.from(SENSOR_SCRIPT, 'utf16le').toString('base64');
    child = spawn(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', b64],
      { windowsHide: true },
    );

    let buf = '';
    child.stdout.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const { events, rest } = parseSensorLines(buf);
      buf = rest;
      for (const evt of events) {
        if (evt.vector === 'ready') {
          logger.info('TAMPER', 'Sensor subscriptions active');
          continue;
        }
        emit(evt.vector, evt);
      }
    });

    child.stderr.on('data', (d) => {
      logger.warn('TAMPER', 'sensor stderr', d.toString().slice(0, 200));
    });

    child.on('error', (e) => logger.warn('TAMPER', 'sensor spawn error', e.message));

    child.on('exit', (code) => {
      child = null;
      if (stableTimer) {
        clearTimeout(stableTimer);
        stableTimer = null;
      }
      if (stopped) return;
      failures += 1;
      logger.warn('TAMPER', `sensor exited (code ${code}); restart in ${backoff}ms (failures=${failures})`);
      if (failures >= SENSOR_DOWN_AFTER) {
        emit('sensor_down', { failures });
      }
      const retry = setTimeout(spawnSensor, backoff);
      if (typeof retry.unref === 'function') retry.unref();
      backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
    });

    // If it stays up a while, treat it as healthy: reset backoff/failures.
    stableTimer = setTimeout(() => {
      backoff = INITIAL_BACKOFF_MS;
      failures = 0;
    }, STABLE_RESET_MS);
    if (typeof stableTimer.unref === 'function') stableTimer.unref();

    logger.info('TAMPER', 'Event sensor process started');
  }

  // Hosts file — native Node push event, instant, zero PowerShell.
  try {
    const hostsPath = getHostsPath();
    if (hostsPath && fs.existsSync(hostsPath)) {
      hostsWatcher = fs.watch(hostsPath, { persistent: false }, () => emit('hosts'));
      hostsWatcher.on('error', (e) => logger.warn('TAMPER', 'hosts watcher error', e.message));
    }
  } catch (e) {
    logger.warn('TAMPER', 'hosts watch failed', e.message);
  }

  spawnSensor();

  return () => {
    stopped = true;
    for (const t of pending.values()) clearTimeout(t);
    pending.clear();
    if (stableTimer) clearTimeout(stableTimer);
    if (hostsWatcher) {
      try {
        hostsWatcher.close();
      } catch {
        /* ignore */
      }
    }
    if (child) {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    }
  };
}

module.exports = { startTamperWatch, parseSensorLines };
