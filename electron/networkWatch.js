const { execSync } = require('child_process');
const logger = require('./logger');
const { applyDNS } = require('./dns');
const { syncHostsBlocklist, flushDnsCache } = require('./hosts');
const { disableChromiumDoHPolicies } = require('./browserPolicy');
const { resetHostsBaseline } = require('./watchdog');

function getNetworkFingerprint() {
  try {
    const script = [
      '$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |',
      '  Sort-Object RouteMetric | Select-Object -First 1).NextHop',
      '$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |',
      '  Where-Object { $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -notlike "127.*" } |',
      '  Select-Object -First 1).IPAddress',
      '$dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |',
      '  Select-Object -ExpandProperty ServerAddresses -First 2) -join ","',
      '[PSCustomObject]@{ gw = $gw; ip = $ip; dns = $dns } | ConvertTo-Json -Compress',
    ].join(' ');
    const out = execSync(`powershell -NoProfile -Command "${script}"`, { encoding: 'utf8' }).trim();
    const data = JSON.parse(out);
    return {
      gateway: data.gw || '',
      ip: data.ip || '',
      dns: data.dns || '',
      key: `${data.gw}|${data.ip}`,
    };
  } catch (e) {
    logger.warn('NETWORK', 'Could not read network fingerprint', e.message);
    return { gateway: '', ip: '', dns: '', key: '' };
  }
}

function runLockdown(reason) {
  logger.info('NETWORK', `Re-applying lockdown (${reason})`);
  disableChromiumDoHPolicies();
  const dns = applyDNS();
  const hosts = syncHostsBlocklist();
  if (hosts.ok) resetHostsBaseline();
  flushDnsCache();
  return { dns, hosts };
}

function startNetworkWatch(intervalMs = 45000) {
  let last = getNetworkFingerprint();
  logger.info('NETWORK', 'Watching for network changes', last);

  const timer = setInterval(() => {
    const current = getNetworkFingerprint();
    if (!current.key || current.key === last.key) return;

    logger.warn('NETWORK', 'Network changed — lockdown will re-apply', {
      from: last,
      to: current,
    });
    try {
      runLockdown('network-changed');
    } catch (e) {
      logger.error('NETWORK', 'Lockdown on network change failed', e.message);
    }
    last = current;
  }, intervalMs);

  return () => clearInterval(timer);
}

module.exports = { getNetworkFingerprint, runLockdown, startNetworkWatch };
