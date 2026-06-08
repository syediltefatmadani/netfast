const logger = require('../../logger');

const {

  DnsStatus,

  isProtectionActive,

  isProtectionWithWarnings,

  protectionLabelFromStatus,

} = require('./DnsStatus');

const { DnsValidator } = require('./DnsValidator');

const { DnsAuditLogger } = require('./DnsAuditLogger');

const { runEncoded } = require('../../powershell');



const CHECK_INTERVAL_MS = 5 * 60 * 1000;



function getActiveNetworkName() {

  try {

    const out = runEncoded(`

$if = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } | Select-Object -First 1

if ($if) { $if.Name } else { 'unknown' }

`);

    return out.trim() || 'unknown';

  } catch {

    return 'unknown';

  }

}



class DnsHealthMonitor {

  /**

   * @param {{ validator?: DnsValidator, auditLogger?: DnsAuditLogger, onStatusChange?: (report: object) => void }} [deps]

   */

  constructor(deps = {}) {

    this.validator = deps.validator || new DnsValidator();

    this.audit = deps.auditLogger || new DnsAuditLogger();

    this.onStatusChange = deps.onStatusChange || null;

    this.lastReport = null;

    this.timer = null;

    this.running = false;

  }



  async runHealthCheck(reason = 'scheduled') {

    if (this.running) return this.lastReport;

    this.running = true;

    const networkName = getActiveNetworkName();

    try {

      const validation = await this.validator.runFullValidation();

      const summary = validation.summary || {};

      const warnings = [];

      if (summary.providerMisses?.length) {

        warnings.push(

          `CleanBrowsing provider miss on: ${summary.providerMisses.join(', ')} (fallback active)`,

        );

      }



      const report = {

        timestamp: Date.now(),

        reason,

        networkName,

        status: validation.status,

        details: validation.details,

        healthy: isProtectionActive(validation.status),

        hasWarnings: isProtectionWithWarnings(validation.status),

        protectionLabel: protectionLabelFromStatus(validation.status, warnings),

        validation,

        dohReachable: summary.dohReachable ?? validation.connectivity?.reachable ?? false,

        cleanBrowsingPrimaryWorking: summary.cleanBrowsingPrimaryWorking ?? false,

        safeDomainAllowed: summary.safeDomainAllowed ?? false,

        knownAdultBlockedByDoh: summary.knownAdultBlockedByDoh ?? false,

        providerMisses: summary.providerMisses ?? [],

        fallbackBlockedMisses: summary.fallbackBlockedMisses ?? [],

        criticalUnblockedRestrictedDomains: summary.criticalUnblockedRestrictedDomains ?? [],

        finalStatus: summary.finalStatus ?? 'failed',

      };



      this.lastReport = report;

      this.audit.append({

        networkName,

        status: validation.status,

        details: `${reason}: ${validation.details}`,

        meta: {

          finalStatus: report.finalStatus,

          providerMisses: report.providerMisses,

          criticalUnblocked: report.criticalUnblockedRestrictedDomains,

          policyFailures: validation.policy?.failures?.map((f) => f.domain) || [],

        },

      });

      logger.info('DNS_HEALTH', `Check (${reason}): ${validation.status}`, {

        details: validation.details,

        finalStatus: report.finalStatus,

        providerMisses: report.providerMisses,

        networkName,

      });

      if (this.onStatusChange) this.onStatusChange(report);

      return report;

    } catch (e) {

      const report = {

        timestamp: Date.now(),

        reason,

        networkName,

        status: DnsStatus.NETWORK_ERROR,

        details: e.message,

        healthy: false,

        hasWarnings: false,

        protectionLabel: 'Not protected',

        validation: null,

        finalStatus: 'failed',

        dohReachable: false,

        providerMisses: [],

        criticalUnblockedRestrictedDomains: [],

      };

      this.lastReport = report;

      this.audit.append({

        networkName,

        status: DnsStatus.NETWORK_ERROR,

        details: e.message,

      });

      logger.execError('DNS_HEALTH', 'Health check failed', e);

      if (this.onStatusChange) this.onStatusChange(report);

      return report;

    } finally {

      this.running = false;

    }

  }



  runImmediateDnsHealthCheck(reason = 'network-change') {

    return this.runHealthCheck(reason);

  }



  start(intervalMs = CHECK_INTERVAL_MS) {

    this.stop();

    this.runHealthCheck('startup');

    this.timer = setInterval(() => this.runHealthCheck('scheduled'), intervalMs);

    logger.info('DNS_HEALTH', `Monitor started (every ${intervalMs / 1000}s)`);

  }



  stop() {

    if (this.timer) clearInterval(this.timer);

    this.timer = null;

  }



  getLastReport() {

    return this.lastReport;

  }

}



let singleton = null;



function getDnsHealthMonitor(deps) {

  if (!singleton) singleton = new DnsHealthMonitor(deps);

  return singleton;

}



module.exports = { DnsHealthMonitor, getDnsHealthMonitor, CHECK_INTERVAL_MS };

