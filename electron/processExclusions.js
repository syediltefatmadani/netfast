const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const { runEncoded } = require('./powershell');

const EXEMPT_RULE_PREFIX = 'NetFast-Exempt-';

const MONGODB_PROCESS_NAMES = ['mongod.exe', 'mongos.exe', 'mongo.exe'];
const MONGODB_CLIENT_PROCESS_NAMES = ['node.exe', 'bun.exe'];

const COMMON_MONGO_BIN_DIRS = [
  'C:\\Program Files\\MongoDB\\Server\\8.0\\bin',
  'C:\\Program Files\\MongoDB\\Server\\7.0\\bin',
  'C:\\Program Files\\MongoDB\\Server\\6.0\\bin',
  'C:\\Program Files\\MongoDB\\Server\\5.0\\bin',
  'C:\\Program Files\\MongoDB\\Server\\4.4\\bin',
];

function isExclusionEnabled() {
  return process.env.NETFAST_MONGO_EXEMPT !== '0';
}

function getExcludedProcessNames() {
  const names = [...MONGODB_PROCESS_NAMES];
  if (process.env.NETFAST_MONGO_EXEMPT_NODE !== '0') {
    names.push(...MONGODB_CLIENT_PROCESS_NAMES);
  }
  return [...new Set(names)];
}

function discoverExecutablePaths(exeName) {
  const found = new Set();
  const base = exeName.toLowerCase();

  for (const dir of COMMON_MONGO_BIN_DIRS) {
    const candidate = path.join(dir, base);
    if (fs.existsSync(candidate)) found.add(candidate);
  }

  try {
    const out = execSync(`where ${base}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    for (const line of out.split(/\r?\n/)) {
      const p = line.trim();
      if (p && fs.existsSync(p)) found.add(p);
    }
  } catch {
    /* not on PATH */
  }

  if (base === 'node.exe') {
    const nvmRoot = process.env.NVM_HOME || path.join(process.env.APPDATA || '', 'nvm');
    try {
      if (fs.existsSync(nvmRoot)) {
        for (const ver of fs.readdirSync(nvmRoot)) {
          const candidate = path.join(nvmRoot, ver, base);
          if (fs.existsSync(candidate)) found.add(candidate);
        }
      }
    } catch {
      /* optional */
    }
    for (const dir of [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'nodejs'),
      path.join(process.env['ProgramFiles(x86)'] || '', 'nodejs'),
      path.join(process.env.LOCALAPPDATA || '', 'fnm_multishells'),
    ]) {
      const candidate = path.join(dir, base);
      if (fs.existsSync(candidate)) found.add(candidate);
    }
  }

  const stem = base.replace(/\.exe$/i, '');
  try {
    const out = runEncoded(`
$procs = Get-Process -Name '${stem.replace(/'/g, "''")}' -ErrorAction SilentlyContinue
$procs | ForEach-Object { $_.Path } | Where-Object { $_ } | ConvertTo-Json -Compress
`);
    const trimmed = out.trim();
    if (trimmed) {
      const parsed = JSON.parse(trimmed);
      const list = Array.isArray(parsed) ? parsed : [parsed];
      for (const p of list) {
        if (p && fs.existsSync(p)) found.add(p);
      }
    }
  } catch {
    /* no running process */
  }

  return [...found];
}

function discoverAllExcludedPrograms() {
  const programs = new Map();
  for (const name of getExcludedProcessNames()) {
    for (const p of discoverExecutablePaths(name)) {
      programs.set(p.toLowerCase(), p);
    }
  }
  return [...programs.values()];
}

function ruleNameFor(programPath, tag) {
  const slug = path.basename(programPath, '.exe').replace(/[^a-zA-Z0-9-]/g, '-');
  const hash = require('crypto').createHash('md5').update(programPath).digest('hex').slice(0, 8);
  return `${EXEMPT_RULE_PREFIX}${slug}-${tag}-${hash}`;
}

function listExemptRules() {
  try {
    const out = execSync('netsh advfirewall firewall show rule name=all', { encoding: 'utf8' });
    return out
      .split('\n')
      .filter((line) => line.includes('Rule Name:') && line.includes(EXEMPT_RULE_PREFIX))
      .map((line) => line.replace('Rule Name:', '').trim());
  } catch {
    return [];
  }
}

function runNetsh(args) {
  execSync(`netsh advfirewall firewall ${args}`, { stdio: 'pipe' });
}

function removeProcessExemptionFirewall() {
  for (const name of listExemptRules()) {
    try {
      runNetsh(`delete rule name="${name}"`);
      logger.info('FIREWALL_EXEMPT', `Removed ${name}`);
    } catch (e) {
      logger.warn('FIREWALL_EXEMPT', `Could not remove ${name}`, e.message);
    }
  }
}

function applyMongoLocalRule(createFirewallRule, program, tag, remoteip) {
  const name = ruleNameFor(program, `Mongo-${tag}`);
  return createFirewallRule({
    name,
    dir: 'out',
    action: 'allow',
    protocol: 'TCP',
    remoteip,
    remoteport: '27017',
    program,
    category: 'optional',
  });
}

/**
 * Optional local MongoDB port rules only — no per-process DNS port 53 bypass
 * (global block-all removed; mongodb+srv uses Windows CleanBrowsing DNS).
 */
function applyProcessExemptionFirewall() {
  if (!isExclusionEnabled()) {
    logger.info('FIREWALL_EXEMPT', 'MongoDB optional exemptions disabled (NETFAST_MONGO_EXEMPT=0)');
    return { ok: true, skipped: true, programs: [], succeeded: [], failed: [], adminRequired: false };
  }

  const { createFirewallRule } = require('./firewall');

  removeProcessExemptionFirewall();
  const programs = discoverAllExcludedPrograms();
  const succeeded = [];
  const failed = [];
  let adminRequired = false;

  for (const program of programs) {
    const v4 = applyMongoLocalRule(createFirewallRule, program, 'local-v4', '127.0.0.0/8');
    if (v4.ok) succeeded.push(v4.ruleName);
    else {
      failed.push({ rule: v4.ruleName, error: v4.reason, optional: true });
      if (v4.adminRequired) adminRequired = true;
    }

    const v6 = applyMongoLocalRule(createFirewallRule, program, 'local-v6', '::1');
    if (v6.ok) {
      succeeded.push(v6.ruleName);
    } else if (/not valid|invalid argument|address keyword/i.test(v6.reason || '')) {
      logger.info('FIREWALL_EXEMPT', 'Mongo local IPv6 firewall exemption skipped; optional only.', {
        program,
        reason: v6.reason,
      });
    } else {
      failed.push({ rule: v6.ruleName, error: v6.reason, optional: true });
      if (v6.adminRequired) adminRequired = true;
    }

    const anyName = ruleNameFor(program, 'Mongo-any');
    const anyResult = createFirewallRule({
      name: anyName,
      dir: 'out',
      action: 'allow',
      protocol: 'TCP',
      remoteport: '27017',
      program,
      category: 'optional',
    });
    if (anyResult.ok) succeeded.push(anyName);
    else {
      failed.push({ rule: anyName, error: anyResult.reason, optional: true });
      if (anyResult.adminRequired) adminRequired = true;
    }
  }

  logger.info('FIREWALL_EXEMPT', 'Optional MongoDB port exemptions', {
    programs,
    succeeded: succeeded.length,
    failed: failed.length,
  });

  return {
    ok: true,
    skipped: false,
    programs,
    succeeded,
    failed,
    adminRequired,
  };
}

function refreshRuntimeExemptions() {
  if (!isExclusionEnabled()) return { refreshed: false };
  const programs = discoverAllExcludedPrograms();
  if (programs.length === 0) return { refreshed: false, programs };
  const active = new Set(listExemptRules());
  const missing = programs.some((program) => {
    const name = ruleNameFor(program, 'Mongo-local-v4');
    return !active.has(name);
  });
  if (!missing) return { refreshed: false, programs };
  logger.info('FIREWALL_EXEMPT', 'Refreshing optional Mongo exemptions', programs);
  return { ...applyProcessExemptionFirewall(), refreshed: true };
}

function verifyProcessExemptionFirewall() {
  return true;
}

function getWatchdogAllowedProcessNames() {
  return getExcludedProcessNames();
}

function getDeveloperWatchdogProcessNames() {
  if (process.env.NETFAST_POLICY_MODE !== 'developer' && process.env.NETFAST_POLICY_MODE !== 'testing') {
    return [];
  }
  const { DEV_ALLOWLIST } = require('./policyMode');
  return DEV_ALLOWLIST.processes;
}

function getWatchdogAllowedProcessNamesExtended() {
  return [...new Set([...getExcludedProcessNames(), ...getDeveloperWatchdogProcessNames()])];
}

module.exports = {
  MONGODB_PROCESS_NAMES,
  MONGODB_CLIENT_PROCESS_NAMES,
  EXEMPT_RULE_PREFIX,
  isExclusionEnabled,
  getExcludedProcessNames,
  discoverExecutablePaths,
  discoverAllExcludedPrograms,
  applyProcessExemptionFirewall,
  removeProcessExemptionFirewall,
  verifyProcessExemptionFirewall,
  refreshRuntimeExemptions,
  getWatchdogAllowedProcessNames: getWatchdogAllowedProcessNamesExtended,
};
