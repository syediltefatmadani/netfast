const logger = require('./logger');
const { wasRealEnforcementApplied, assertRealEnforcementAllowed } = require('./enforcementGuard');
const { removeDnsFirewall } = require('./firewall');
const { removeMongoNrptRules } = require('./mongoDns');
const { flushDnsCache } = require('./hosts');
const { removeChromiumCleanBrowsingPolicies } = require('./browserPolicy');
const {
  loadSnapshot,
  restoreAdapterDnsFromSnapshot,
  restoreWindowsDohFromSnapshot,
  restoreTunnelsFromSnapshot,
  removeCleanBrowsingDohOnly,
} = require('./preLockdownSnapshot');
const { restoreEnforcementBackup } = require('./networkEnforcement');

function removeFocuslockHostsSections() {
  const { isHostsFileEnforcementEnabled } = require('./hosts');
  if (!isHostsFileEnforcementEnabled()) {
    return { ok: true, skipped: true, reason: 'hosts_file_enforcement_disabled' };
  }
  const fs = require('fs');
  const { getHostsPath, MARKER_BEGIN, MARKER_END, MONGO_MARKER_BEGIN, MONGO_MARKER_END } = require('./hosts');
  const hostsPath = getHostsPath();
  if (!fs.existsSync(hostsPath)) return { ok: true, skipped: true };

  let content = fs.readFileSync(hostsPath, 'utf8');
  let changed = false;

  for (const [beginMark, endMark] of [
    [MARKER_BEGIN, MARKER_END],
    [MONGO_MARKER_BEGIN, MONGO_MARKER_END],
  ]) {
    const begin = content.indexOf(beginMark);
    const end = content.indexOf(endMark);
    if (begin !== -1 && end !== -1) {
      content =
        content.slice(0, begin).trimEnd() +
        '\r\n' +
        content.slice(end + endMark.length).trimStart();
      changed = true;
    }
  }

  if (changed) {
    fs.writeFileSync(hostsPath, content, 'utf8');
    flushDnsCache();
    logger.info('RESTORE', 'NetFast hosts sections removed');
  }
  return { ok: true, changed };
}

/**
 * Remove NetFast enforcement and restore pre-lockdown settings when possible.
 */
function restorePreNetfastSystemState(reason) {
  if (!wasRealEnforcementApplied() && !assertRealEnforcementAllowed('system-restore')) {
    logger.info('DEV_SAFE', 'Skipped system restore — enforcement was not applied');
    return { ok: true, skipped: true, mock: true, reason };
  }
  logger.warn('RESTORE', `Restoring system state (${reason})`);
  const warnings = [];
  const snapshot = loadSnapshot();

  try {
    getDnsHealthMonitor().stop();
  } catch {
    /* monitor may not be started */
  }

  try {
    removeDnsFirewall();
  } catch (e) {
    warnings.push(`Firewall removal: ${e.message}`);
  }

  try {
    removeMongoNrptRules();
  } catch (e) {
    warnings.push(`NRPT removal: ${e.message}`);
  }

  try {
    removeChromiumCleanBrowsingPolicies();
  } catch (e) {
    warnings.push(`Browser policy removal: ${e.message}`);
  }

  try {
    removeFocuslockHostsSections();
  } catch (e) {
    warnings.push(`Hosts cleanup: ${e.message}`);
  }

  if (snapshot?.hasSnapshot) {
    const dns = restoreAdapterDnsFromSnapshot(snapshot);
    if (!dns.ok) warnings.push('Adapter DNS could not be fully restored from snapshot');
    const doh = restoreWindowsDohFromSnapshot(snapshot);
    if (!doh.ok) warnings.push('Windows DoH could not be fully restored from snapshot');
    restoreTunnelsFromSnapshot(snapshot);
  } else {
    removeCleanBrowsingDohOnly();
    warnings.push(
      'Pre-lockdown snapshot missing — removed NetFast items only; verify DNS and DoH manually.',
    );
  }

  try {
    const enforceRestore = restoreEnforcementBackup(reason);
    if (!enforceRestore.ok && enforceRestore.reason !== 'no_backup') {
      warnings.push('IPv6 binding / enforcement backup could not be fully restored');
    }
  } catch (e) {
    warnings.push(`Enforcement backup restore: ${e.message}`);
  }

  flushDnsCache();

  const result = {
    ok: warnings.length === 0,
    systemRestored: true,
    enforcementRemoved: true,
    warnings,
    reason,
  };
  logger.info('RESTORE', 'System restoration complete', result);
  return result;
}

function getDnsHealthMonitor() {
  return require('./services/dns').getDnsHealthMonitor();
}

module.exports = { restorePreNetfastSystemState, removeFocuslockHostsSections };
