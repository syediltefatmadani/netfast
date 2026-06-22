const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const logger = require('./logger');
const { resolveStatePath } = require('./dataPaths');
const { assertRealEnforcementAllowed, wasRealEnforcementApplied } = require('./enforcementGuard');
const { getMockFirewallResult } = require('./mockEnforcement');
const {
  applyProcessExemptionFirewall,
  removeProcessExemptionFirewall,
} = require('./processExclusions');
const {
  applyDeveloperFirewallRules,
  removeDeveloperFirewallRules,
} = require('./developerFirewall');
const {
  applyRawDnsBlockRules,
  removeRawDnsBlockRules,
  verifyRawDnsBlockRules,
  verifyRawDnsBlockRulesAsync,
} = require('./dnsBypassFirewall');
const { execAsync } = require('./asyncExec');
const { isDeveloperLikeMode } = require('./policyMode');

const RULE_PREFIX = 'NetFast-DNS-';
const FIREWALL_SCHEMA_VERSION = 2;
const FIREWALL_SCHEMA_PATH = resolveStatePath('firewall-schema.json');

const ADMIN_PRIVILEGE_MESSAGE =
  'DNS firewall lock requires Administrator privileges. Please restart NetFast as Administrator.';

/** Stale rules from prior strategies — removed on every apply. */
const STALE_RULE_NAMES = [
  `${RULE_PREFIX}Block-UDP-53-Other`,
  `${RULE_PREFIX}Block-TCP-53-Other`,
  `${RULE_PREFIX}Allow-UDP-53-1-1-1-1`,
  `${RULE_PREFIX}Allow-TCP-53-1-1-1-1`,
  `${RULE_PREFIX}Allow-TCP-443-1-1-1-1`,
  `${RULE_PREFIX}Allow-UDP-53-1-0-0-1`,
  `${RULE_PREFIX}Allow-TCP-53-1-0-0-1`,
  `${RULE_PREFIX}Allow-TCP-443-1-0-0-1`,
];

const BYPASS_RESOLVERS = [
  { ip: '1.1.1.1', dohHttps: true },
  { ip: '1.0.0.1', dohHttps: true },
  { ip: '8.8.8.8', dohHttps: true },
  { ip: '8.8.4.4', dohHttps: true },
  { ip: '9.9.9.9', dohHttps: true },
  { ip: '149.112.112.112', dohHttps: true },
  { ip: '94.140.14.14', dohHttps: true },
  { ip: '94.140.15.15', dohHttps: true },
  { ip: '76.76.2.0', dohHttps: false },
  { ip: '76.76.10.0', dohHttps: false },
  { ip: '45.90.28.0', dohHttps: false },
  { ip: '45.90.30.0', dohHttps: false },
  { ip: '2606:4700:4700::1111', dohHttps: false },
  { ip: '2606:4700:4700::1001', dohHttps: false },
  { ip: '2001:4860:4860::8888', dohHttps: false },
  { ip: '2001:4860:4860::8844', dohHttps: false },
  { ip: '2620:fe::fe', dohHttps: false },
  { ip: '2620:fe::9', dohHttps: false },
  { ip: '2a10:50c0::ad1:ff', dohHttps: false },
  { ip: '2a10:50c0::ad2:ff', dohHttps: false },
];

let ALLOWED_RESOLVERS = null;
let EXPECTED_CORE_RULES = null;
let EXPECTED_BYPASS_RULES = null;

function ipToRuleSlug(ip) {
  return ip.replace(/:/g, '-');
}

function initResolversAndRules() {
  if (ALLOWED_RESOLVERS) return;
  const { DNS } = require('./dns');
  ALLOWED_RESOLVERS = [
    DNS.ipv4.primary,
    DNS.ipv4.secondary,
    DNS.ipv6.primary,
    DNS.ipv6.secondary,
  ];

  EXPECTED_CORE_RULES = [];
  for (const ip of ALLOWED_RESOLVERS) {
    const slug = ipToRuleSlug(ip);
    EXPECTED_CORE_RULES.push(`${RULE_PREFIX}Allow-TCP-443-${slug}`);
    EXPECTED_CORE_RULES.push(`${RULE_PREFIX}Allow-UDP-53-${slug}`);
    EXPECTED_CORE_RULES.push(`${RULE_PREFIX}Allow-TCP-53-${slug}`);
  }

  EXPECTED_BYPASS_RULES = [];
  for (const { ip, dohHttps } of BYPASS_RESOLVERS) {
    const slug = ipToRuleSlug(ip);
    for (const proto of ['UDP', 'TCP']) {
      EXPECTED_BYPASS_RULES.push(`${RULE_PREFIX}Block-Bypass-${proto}-53-${slug}`);
      EXPECTED_BYPASS_RULES.push(`${RULE_PREFIX}Block-Bypass-${proto}-853-${slug}`);
    }
    if (dohHttps) {
      EXPECTED_BYPASS_RULES.push(`${RULE_PREFIX}Block-Bypass-TCP-443-${slug}`);
    }
  }
}

function isAdminElevationError(msg) {
  const lower = (msg || '').toLowerCase();
  return (
    lower.includes('elevation') ||
    lower.includes('run as administrator') ||
    lower.includes('access is denied')
  );
}

function runNetsh(args) {
  if (!assertRealEnforcementAllowed(`netsh:${args.split(' ')[0] || 'firewall'}`)) return;
  execSync(`netsh advfirewall firewall ${args}`, { stdio: 'pipe' });
}

function createFirewallRule({ name, dir, action, protocol, remoteip, remoteport, program, enable = 'yes', category }) {
  if (!assertRealEnforcementAllowed(`New-NetFirewallRule:${name}`)) {
    return {
      ruleName: name,
      ok: true,
      mock: true,
      category,
      reason: 'Mock firewall rule applied',
      adminRequired: false,
    };
  }
  const sanitizedName = name.replace(/["]/g, '');
  let cmd = `add rule name="${sanitizedName}" dir=${dir} action=${action} enable=${enable}`;
  if (protocol) cmd += ` protocol=${protocol}`;
  if (remoteip) cmd += ` remoteip=${remoteip}`;
  if (remoteport) cmd += ` remoteport=${remoteport}`;
  if (program) cmd += ` program="${program}"`;

  const fullCmd = `netsh advfirewall firewall ${cmd}`;
  let stdout = '';
  let stderr = '';
  let ok = false;
  let reason = '';
  let adminRequired = false;

  try {
    stdout = execSync(fullCmd, { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' });
    ok = true;
  } catch (e) {
    stdout = e.stdout ? e.stdout.toString() : '';
    stderr = e.stderr ? e.stderr.toString() : '';
    const msg = `${e.message || ''} ${stderr} ${stdout}`;
    if (isAdminElevationError(msg)) {
      adminRequired = true;
      reason = ADMIN_PRIVILEGE_MESSAGE;
    } else if (msg.toLowerCase().includes('not a valid') || msg.toLowerCase().includes('invalid argument')) {
      reason = `Invalid argument: ${stderr || e.message}`;
    } else {
      reason = stderr || e.message;
    }
  }

  const res = {
    ruleName: sanitizedName,
    command: fullCmd,
    ok,
    stdout: stdout.trim(),
    stderr: stderr.trim(),
    category,
    reason: ok ? 'Rule applied successfully' : reason,
    adminRequired,
  };

  if (ok) {
    logger.info('FIREWALL', `Rule OK [${category}]: ${sanitizedName}`);
  } else {
    logger.warn('FIREWALL', `Rule FAILED [${category}]: ${sanitizedName}`, {
      reason: res.reason,
      stderr: res.stderr,
      stdout: res.stdout,
    });
  }

  return res;
}

function parseOurRules(out) {
  return out
    .split('\n')
    .filter((line) => line.includes('Rule Name:') && line.includes('NetFast'))
    .map((line) => line.replace('Rule Name:', '').trim());
}

function listOurRules() {
  try {
    const out = execSync('netsh advfirewall firewall show rule name=all', { encoding: 'utf8' });
    return parseOurRules(out);
  } catch {
    return [];
  }
}

/** Non-blocking variant of listOurRules for the read/verify UI path. */
async function listOurRulesAsync() {
  try {
    const out = await execAsync('netsh advfirewall firewall show rule name=all');
    return parseOurRules(out);
  } catch {
    return [];
  }
}

function deleteRuleByName(name) {
  try {
    runNetsh(`delete rule name="${name}"`);
    logger.info('FIREWALL', `Removed stale rule ${name}`);
    return true;
  } catch {
    return false;
  }
}

function getRuleState(name) {
  try {
    const out = execSync(`netsh advfirewall firewall show rule name="${name.replace(/"/g, '')}"`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (/No rules match the specified criteria/i.test(out)) {
      return { exists: false, enabled: false };
    }
    const enabled = /Enabled:\s*Yes/i.test(out);
    return { exists: true, enabled };
  } catch {
    return { exists: false, enabled: false };
  }
}

function enableRuleByName(name) {
  try {
    runNetsh(`set rule name="${name.replace(/"/g, '')}" new enable=yes`);
    logger.info('FIREWALL', `Enabled existing rule ${name}`);
    return true;
  } catch (e) {
    logger.warn('FIREWALL', `Could not enable rule ${name}`, e.message);
    return false;
  }
}

function ensureFirewallRule(spec) {
  const state = getRuleState(spec.name);
  if (state.exists && state.enabled) {
    return {
      ruleName: spec.name,
      ok: true,
      created: false,
      enabled: true,
      skipped: true,
      category: spec.category,
      reason: 'Rule already present',
      adminRequired: false,
    };
  }
  if (state.exists && !state.enabled) {
    const enabled = enableRuleByName(spec.name);
    return {
      ruleName: spec.name,
      ok: enabled,
      created: false,
      enabled,
      category: spec.category,
      reason: enabled ? 'Rule re-enabled' : 'Rule exists but could not be enabled',
      adminRequired: false,
    };
  }
  return createFirewallRule(spec);
}

function loadFirewallSchemaState() {
  try {
    if (!fs.existsSync(FIREWALL_SCHEMA_PATH)) return null;
    return JSON.parse(fs.readFileSync(FIREWALL_SCHEMA_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function saveFirewallSchemaState(state) {
  const dir = path.dirname(FIREWALL_SCHEMA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(FIREWALL_SCHEMA_PATH, JSON.stringify(state, null, 2), 'utf8');
}

function shouldCleanStaleFirewallRules() {
  const now = Date.now();
  const stored = loadFirewallSchemaState();
  if (!stored || stored.version !== FIREWALL_SCHEMA_VERSION) {
    saveFirewallSchemaState({ version: FIREWALL_SCHEMA_VERSION, lastStaleCleanupAt: now });
    return true;
  }
  const dayMs = 24 * 60 * 60 * 1000;
  if (!stored.lastStaleCleanupAt || now - stored.lastStaleCleanupAt > dayMs) {
    saveFirewallSchemaState({ ...stored, lastStaleCleanupAt: now });
    return true;
  }
  return false;
}

function removeStaleFirewallRules() {
  const active = listOurRules();
  let removed = 0;
  for (const staleName of STALE_RULE_NAMES) {
    if (active.includes(staleName)) {
      if (deleteRuleByName(staleName)) removed++;
    }
  }
  for (const name of active) {
    if (name.includes('Block-UDP-53-Other') || name.includes('Block-TCP-53-Other')) {
      if (deleteRuleByName(name)) removed++;
    }
    if (/Allow-(UDP|TCP)-53-1-1-1-1/.test(name) || /Allow-(UDP|TCP)-53-1-0-0-1/.test(name)) {
      if (deleteRuleByName(name)) removed++;
    }
    if (/Allow-TCP-443-1-1-1-1/.test(name) || /Allow-TCP-443-1-0-0-1/.test(name)) {
      if (deleteRuleByName(name)) removed++;
    }
  }
  if (removed) {
    logger.info('FIREWALL', 'Global DNS block / Cloudflare allow rules removed', { count: removed });
  }
  return removed;
}

function removeDnsFirewall() {
  if (!wasRealEnforcementApplied() && !assertRealEnforcementAllowed('removeDnsFirewall')) {
    logger.info('DEV_SAFE', 'Skipped firewall removal — enforcement was not applied');
    return;
  }
  removeProcessExemptionFirewall();
  removeDeveloperFirewallRules();
  removeStaleFirewallRules();
  removeRawDnsBlockRules();
  for (const name of listOurRules()) {
    if (
      name.startsWith(RULE_PREFIX) ||
      name.startsWith('NetFast-Exempt-') ||
      name.startsWith('NetFast-Dev-')
    ) {
      deleteRuleByName(name);
    }
  }
}

function applyDnsFirewall() {
  if (!assertRealEnforcementAllowed('applyDnsFirewall')) {
    logger.info('DEV_SAFE', 'Mock firewall enforcement success');
    return getMockFirewallResult();
  }
  initResolversAndRules();
  logger.info('FIREWALL', 'Applying DNS firewall — CleanBrowsing allow + known bypass blocks');

  if (shouldCleanStaleFirewallRules()) {
    removeStaleFirewallRules();
    for (const name of listOurRules()) {
      if (name.startsWith(RULE_PREFIX) && /Allow-(UDP|TCP)-53-/.test(name)) {
        deleteRuleByName(name);
      }
    }
  }

  const succeeded = [];
  const failed = [];
  const failedCoreRules = [];
  const failedBypassRules = [];
  const failedOptionalRules = [];
  let adminRequired = false;
  let rulesCreated = 0;
  let rulesEnabled = 0;
  let rulesSkipped = 0;

  for (const ip of ALLOWED_RESOLVERS) {
    const slug = ipToRuleSlug(ip);
    const cidr = ip.includes(':') ? `${ip}/128` : `${ip}/32`;
    const coreRules = [
      { name: `${RULE_PREFIX}Allow-TCP-443-${slug}`, protocol: 'TCP', remoteport: '443' },
      { name: `${RULE_PREFIX}Allow-UDP-53-${slug}`, protocol: 'UDP', remoteport: '53' },
      { name: `${RULE_PREFIX}Allow-TCP-53-${slug}`, protocol: 'TCP', remoteport: '53' },
    ];
    for (const spec of coreRules) {
      const result = ensureFirewallRule({
        name: spec.name,
        dir: 'out',
        action: 'allow',
        protocol: spec.protocol,
        remoteip: cidr,
        remoteport: spec.remoteport,
        category: 'core',
      });
      if (result.ok) {
        succeeded.push(spec.name);
        if (result.skipped) rulesSkipped++;
        else if (result.created) rulesCreated++;
        else if (result.enabled) rulesEnabled++;
      } else {
        failed.push({ rule: spec.name, error: result.reason });
        failedCoreRules.push(result);
        if (result.adminRequired) adminRequired = true;
      }
    }
  }

  logger.info('FIREWALL', 'CleanBrowsing DoH allow rules ensured (TCP 443 only)', {
    resolvers: ALLOWED_RESOLVERS,
    created: rulesCreated,
    enabled: rulesEnabled,
    skipped: rulesSkipped,
  });

  for (const { ip, dohHttps } of BYPASS_RESOLVERS) {
    const slug = ipToRuleSlug(ip);
    const cidr = ip.includes(':') ? `${ip}/128` : `${ip}/32`;
    for (const proto of ['UDP', 'TCP']) {
      for (const port of ['53', '853']) {
        const ruleName = `${RULE_PREFIX}Block-Bypass-${proto}-${port}-${slug}`;
        const result = ensureFirewallRule({
          name: ruleName,
          dir: 'out',
          action: 'block',
          protocol: proto,
          remoteip: cidr,
          remoteport: port,
          category: 'bypass',
        });
        if (result.ok) succeeded.push(ruleName);
        else {
          failed.push({ rule: ruleName, error: result.reason });
          failedBypassRules.push(result);
          if (result.adminRequired) adminRequired = true;
        }
      }
    }
    if (dohHttps) {
      const ruleName = `${RULE_PREFIX}Block-Bypass-TCP-443-${slug}`;
      const result = ensureFirewallRule({
        name: ruleName,
        dir: 'out',
        action: 'block',
        protocol: 'TCP',
        remoteip: cidr,
        remoteport: '443',
        category: 'bypass',
      });
      if (result.ok) succeeded.push(ruleName);
      else {
        failed.push({ rule: ruleName, error: result.reason });
        failedBypassRules.push(result);
        if (result.adminRequired) adminRequired = true;
      }
    }
  }
  logger.info('FIREWALL', 'Known bypass DNS resolver block rules applied', {
    resolverCount: BYPASS_RESOLVERS.length,
  });

  const rawDns = applyRawDnsBlockRules();
  if (rawDns.applied?.length) {
    for (const r of rawDns.applied) succeeded.push(r.displayName);
  }
  if (rawDns.failed?.length) {
    for (const f of rawDns.failed) {
      failed.push({ rule: f.displayName, error: f.error || f.reason });
      failedBypassRules.push(f);
      if (f.adminRequired) adminRequired = true;
    }
  }
  if (rawDns.adminRequired) adminRequired = true;

  const exempt = applyProcessExemptionFirewall();
  if (exempt.failed?.length) {
    for (const f of exempt.failed) failedOptionalRules.push(f);
  }
  if (exempt.adminRequired && (failedCoreRules.length > 0 || failedBypassRules.length > 0)) {
    adminRequired = true;
  }
  if (exempt.succeeded?.length) {
    for (const s of exempt.succeeded) succeeded.push(s);
  }

  let developer = { skipped: true, developerExceptionsApplied: false, succeeded: [], failed: [] };
  if (isDeveloperLikeMode()) {
    developer = applyDeveloperFirewallRules();
    if (developer.failed?.length) {
      for (const f of developer.failed) failedOptionalRules.push(f);
    }
    if (developer.succeeded?.length) {
      for (const s of developer.succeeded) succeeded.push(s);
    }
  } else {
    removeDeveloperFirewallRules();
  }

  const activeRules = new Set(listOurRules());
  const hasGlobalBlock = [...activeRules].some(
    (n) => n.includes('Block-UDP-53-Other') || n.includes('Block-TCP-53-Other'),
  );
  if (hasGlobalBlock) {
    logger.error('FIREWALL', 'Global block-all DNS rules still present after cleanup');
  }

  const missingCore = EXPECTED_CORE_RULES.filter((r) => !activeRules.has(r));
  const missingBypass = EXPECTED_BYPASS_RULES.filter((r) => !activeRules.has(r));
  const rawDnsVerify = verifyRawDnsBlockRules();

  const firewallCoreLocked = missingCore.length === 0 && failedCoreRules.length === 0;
  const bypassResolversBlocked =
    missingBypass.length === 0 && failedBypassRules.length === 0 && !hasGlobalBlock;
  const rawDnsBypassBlocked = rawDnsVerify.allEnabled && rawDns.ok !== false;
  const firewallLocked = firewallCoreLocked && bypassResolversBlocked && rawDnsBypassBlocked;

  const error = adminRequired
    ? ADMIN_PRIVILEGE_MESSAGE
    : !firewallCoreLocked
      ? `CleanBrowsing allow rules incomplete (${failedCoreRules.length} failed, ${missingCore.length} missing)`
      : !rawDnsBypassBlocked
        ? `Raw DNS bypass block rules incomplete (${rawDnsVerify.missing.length} missing, ${rawDnsVerify.disabled.length} disabled)`
        : !bypassResolversBlocked
          ? `Bypass resolver block rules incomplete (${failedBypassRules.length} failed, ${missingBypass.length} missing)`
          : null;

  if (firewallLocked) {
    logger.info('FIREWALL', 'DNS firewall locked', {
      firewallCoreLocked,
      bypassResolversBlocked,
      rawDnsBypassBlocked,
      optionalFailures: failedOptionalRules.length,
      globalBlockRemoved: !hasGlobalBlock,
    });
  } else {
    logger.error('FIREWALL', error || 'DNS firewall incomplete', {
      failedCoreRules,
      failedBypassRules,
      failedOptionalRules,
      missingCore,
      missingBypass,
      rawDnsVerify,
    });
  }

  const status =
    firewallLocked && !error
      ? failedOptionalRules.length > 0 || hasGlobalBlock
        ? 'Protected with warnings'
        : 'Protected'
      : 'Not protected';

  return {
    ok: firewallLocked,
    firewallLocked,
    firewallCoreLocked,
    bypassResolversBlocked,
    rawDnsBypassBlocked,
    firewallExemptionsApplied: exempt.skipped || failedOptionalRules.length === 0,
    developerExceptionsApplied: Boolean(developer.developerExceptionsApplied),
    adminRequired,
    error,
    status,
    succeeded,
    failed,
    failedCoreRules,
    failedBypassRules,
    failedOptionalRules,
    missingCore,
    missingBypass,
    hasGlobalBlock,
    rawDns,
    rawDnsVerify,
    exempt,
    developer,
  };
}

function verifyFirewall() {
  try {
    initResolversAndRules();
    const activeRules = new Set(listOurRules());
    const hasGlobalBlock = [...activeRules].some(
      (n) => n.includes('Block-UDP-53-Other') || n.includes('Block-TCP-53-Other'),
    );
    const missingCore = EXPECTED_CORE_RULES.filter((r) => !activeRules.has(r));
    const missingBypass = EXPECTED_BYPASS_RULES.filter((r) => !activeRules.has(r));
    const rawDnsVerify = verifyRawDnsBlockRules();
    const firewallCoreLocked = missingCore.length === 0;
    const bypassResolversBlocked = missingBypass.length === 0 && !hasGlobalBlock;
    const rawDnsBypassBlocked = rawDnsVerify.allEnabled;
    const firewallLocked = firewallCoreLocked && bypassResolversBlocked && rawDnsBypassBlocked;
    if (!firewallLocked) {
      logger.warn('FIREWALL', 'Firewall verification failed', {
        missingCore,
        missingBypass,
        hasGlobalBlock,
        rawDnsVerify,
      });
    }
    return {
      firewallLocked,
      firewallCoreLocked,
      bypassResolversBlocked,
      rawDnsBypassBlocked,
      hasGlobalBlock,
      missingCore,
      missingBypass,
      rawDnsVerify,
    };
  } catch (e) {
    logger.execError('FIREWALL', 'Firewall verification failed', e);
    return {
      firewallLocked: false,
      firewallCoreLocked: false,
      bypassResolversBlocked: false,
      rawDnsBypassBlocked: false,
      hasGlobalBlock: false,
      missingCore: [],
      missingBypass: [],
      rawDnsVerify: { allEnabled: false, missing: [], disabled: [] },
    };
  }
}

/** Non-blocking variant of verifyFirewall — same logic, async netsh reads. */
async function verifyFirewallAsync() {
  try {
    initResolversAndRules();
    const [rules, rawDnsVerify] = await Promise.all([
      listOurRulesAsync(),
      verifyRawDnsBlockRulesAsync(),
    ]);
    const activeRules = new Set(rules);
    const hasGlobalBlock = [...activeRules].some(
      (n) => n.includes('Block-UDP-53-Other') || n.includes('Block-TCP-53-Other'),
    );
    const missingCore = EXPECTED_CORE_RULES.filter((r) => !activeRules.has(r));
    const missingBypass = EXPECTED_BYPASS_RULES.filter((r) => !activeRules.has(r));
    const firewallCoreLocked = missingCore.length === 0;
    const bypassResolversBlocked = missingBypass.length === 0 && !hasGlobalBlock;
    const rawDnsBypassBlocked = rawDnsVerify.allEnabled;
    const firewallLocked = firewallCoreLocked && bypassResolversBlocked && rawDnsBypassBlocked;
    if (!firewallLocked) {
      logger.warn('FIREWALL', 'Firewall verification failed', {
        missingCore,
        missingBypass,
        hasGlobalBlock,
        rawDnsVerify,
      });
    }
    return {
      firewallLocked,
      firewallCoreLocked,
      bypassResolversBlocked,
      rawDnsBypassBlocked,
      hasGlobalBlock,
      missingCore,
      missingBypass,
      rawDnsVerify,
    };
  } catch (e) {
    logger.execError('FIREWALL', 'Firewall verification failed', e);
    return {
      firewallLocked: false,
      firewallCoreLocked: false,
      bypassResolversBlocked: false,
      rawDnsBypassBlocked: false,
      hasGlobalBlock: false,
      missingCore: [],
      missingBypass: [],
      rawDnsVerify: { allEnabled: false, missing: [], disabled: [] },
    };
  }
}

module.exports = {
  applyDnsFirewall,
  removeDnsFirewall,
  verifyFirewall,
  verifyFirewallAsync,
  createFirewallRule,
  ensureFirewallRule,
  removeStaleFirewallRules,
  shouldCleanStaleFirewallRules,
  ADMIN_PRIVILEGE_MESSAGE,
  BYPASS_RESOLVERS,
  STALE_RULE_NAMES,
};
