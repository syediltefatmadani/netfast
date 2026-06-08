#!/usr/bin/env node
/**
 * NetFast DNS debug CLI (no Electron required).
 * Usage:
 *   node electron/cli.js health-doh
 *   node electron/cli.js diagnose-domain pornhat.com --restricted adult
 */

const {
  runDohHealthSummary,
  evaluateDomainProtection,
  formatDomainStatusMessage,
} = require('./services/dns');

function parseArgs(argv) {
  const args = argv.slice(2);
  const cmd = args[0];
  const flags = {};
  let domain = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--restricted' && args[i + 1]) {
      flags.restricted = args[++i];
      continue;
    }
    if (args[i] === '--category' && args[i + 1]) {
      flags.category = args[++i];
      continue;
    }
    if (!args[i].startsWith('--') && !domain) domain = args[i];
  }
  return { cmd, domain, flags };
}

function printDiagnose(result) {
  console.log(`Domain: ${result.domain}`);
  console.log(`Expected restricted: ${result.expectedRestricted}`);
  console.log(`CleanBrowsing DoH reachable: ${result.dohReachable}`);
  console.log(`DoH resolved: ${result.dohResolved}`);
  console.log(`DoH blocked: ${result.dohBlocked}`);
  console.log(`Provider miss: ${result.providerMiss}`);
  const { domainListedInHosts } = require('./services/dns/domainProtection');
  console.log(`Hosts fallback present: ${domainListedInHosts(result.domain)}`);
  if (result.httpsChecked) {
    console.log(`HTTPS reachable: ${result.httpsReachable}`);
  }
  console.log(`Final blocked: ${result.finalBlocked}`);
  console.log(`Blocked by: ${result.blockedBy?.join(', ') || 'none'}`);
  console.log(`Status: ${result.status}`);
  console.log(`Message: ${formatDomainStatusMessage(result)}`);
  if (result.warning) console.log(`Warning: ${result.warning}`);
  if (result.error) console.log(`Error: ${result.error}`);
}

async function main() {
  const { cmd, domain, flags } = parseArgs(process.argv);

  if (cmd === 'health-doh') {
    const summary = await runDohHealthSummary();
    console.log(JSON.stringify(summary, null, 2));
    console.log('\n--- Summary ---');
    console.log(`DoH endpoint reachable: ${summary.dohReachable}`);
    console.log(`Safe domain allowed: ${summary.safeDomainAllowed}`);
    console.log(`Known adult blocked by DoH: ${summary.knownAdultBlockedByDoh}`);
    console.log(`Provider misses: ${summary.providerMisses.join(', ') || 'none'}`);
    console.log(`Fallback blocked misses: ${summary.fallbackBlockedMisses.join(', ') || 'none'}`);
    console.log(`Critical unblocked: ${summary.criticalUnblockedRestrictedDomains.join(', ') || 'none'}`);
    console.log(`Final status: ${summary.finalStatus}`);
    process.exit(summary.finalStatus === 'failed' ? 1 : 0);
  }

  if (cmd === 'diagnose-domain') {
    if (!domain) {
      console.error('Usage: node electron/cli.js diagnose-domain <domain> [--restricted adult]');
      process.exit(1);
    }
    const category = flags.category || flags.restricted || 'unknown';
    const expectedRestricted = Boolean(flags.restricted) || ['adult', 'proxy', 'vpn'].includes(category);
    const evaluation = await evaluateDomainProtection(domain, {
      expectedRestricted,
      category: expectedRestricted ? category : 'unknown',
      checkHttps: true,
      applyFallbackOnMiss: true,
    });
    printDiagnose(evaluation);
    process.exit(evaluation.finalBlocked || !expectedRestricted ? 0 : 1);
  }

  console.error('Commands: health-doh | diagnose-domain <domain> [--restricted adult]');
  process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
