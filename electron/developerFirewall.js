const crypto = require('crypto');
const path = require('path');
const { execSync } = require('child_process');
const logger = require('./logger');
const { DEV_ALLOWLIST, isDeveloperLikeMode } = require('./policyMode');
const { discoverExecutablePaths } = require('./processExclusions');

const DEV_RULE_PREFIX = 'NetFast-Dev-';

const LOCALHOST_V4 = '127.0.0.0/8';

const PROCESS_HTTPS_ALLOW = new Set([
  'node.exe',
  'bun.exe',
  'git.exe',
  'docker.exe',
  'com.docker.backend.exe',
  'npm.cmd',
  'npx.cmd',
  'pnpm.exe',
  'yarn.cmd',
  'code.exe',
  'cursor.exe',
]);

const PROCESS_MONGO_OUTBOUND = new Set(['node.exe', 'bun.exe']);

const LOCAL_PORT_LABELS = {
  3000: 'Express',
  5173: 'Vite',
  6379: 'Redis',
  7000: 'API',
  27017: 'Mongo',
};

function ruleHash(programPath) {
  return crypto.createHash('md5').update(programPath).digest('hex').slice(0, 8);
}

function devRuleName(parts) {
  return `${DEV_RULE_PREFIX}${parts.join('-')}`;
}

function listDeveloperRules() {
  try {
    const out = execSync('netsh advfirewall firewall show rule name=all', { encoding: 'utf8' });
    return out
      .split('\n')
      .filter((line) => line.includes('Rule Name:') && line.includes(DEV_RULE_PREFIX))
      .map((line) => line.replace('Rule Name:', '').trim());
  } catch {
    return [];
  }
}

function deleteDeveloperRule(name) {
  try {
    execSync(`netsh advfirewall firewall delete rule name="${name}"`, { stdio: 'pipe' });
    logger.info('DEV_MODE', `Removed developer rule ${name}`);
    return true;
  } catch {
    return false;
  }
}

function removeDeveloperFirewallRules() {
  const active = listDeveloperRules();
  let removed = 0;
  for (const name of active) {
    if (deleteDeveloperRule(name)) removed++;
  }
  if (removed) {
    logger.info('DEV_MODE', 'Removed stale developer firewall rules', { count: removed });
  }
  return { removed, rules: active };
}

function discoverAllowlistedPrograms() {
  const programs = new Map();
  for (const exeName of DEV_ALLOWLIST.processes) {
    for (const p of discoverExecutablePaths(exeName)) {
      programs.set(p.toLowerCase(), { path: p, name: exeName.toLowerCase() });
    }
  }
  return [...programs.values()];
}

function applyProgramRule(createFirewallRule, program, tag, remoteport, remoteip) {
  const stem = path.basename(program, path.extname(program)).replace(/[^a-zA-Z0-9-]/g, '-');
  const hash = ruleHash(program);
  const name = devRuleName(['Allow', stem, tag, remoteport, hash]);
  return createFirewallRule({
    name,
    dir: 'out',
    action: 'allow',
    protocol: 'TCP',
    remoteip,
    remoteport: String(remoteport),
    program,
    category: 'developer',
  });
}

function applyLocalhostPortRule(createFirewallRule, port) {
  const label = LOCAL_PORT_LABELS[port] || `Port${port}`;
  const name = devRuleName(['Allow', 'localhost', label, String(port)]);
  return createFirewallRule({
    name,
    dir: 'out',
    action: 'allow',
    protocol: 'TCP',
    remoteip: LOCALHOST_V4,
    remoteport: String(port),
    category: 'developer',
  });
}

function applyDeveloperFirewallRules() {
  if (!isDeveloperLikeMode()) {
    removeDeveloperFirewallRules();
    return {
      ok: true,
      skipped: true,
      succeeded: [],
      failed: [],
      developerExceptionsApplied: false,
    };
  }

  const { createFirewallRule } = require('./firewall');
  removeDeveloperFirewallRules();

  const succeeded = [];
  const failed = [];
  const programs = discoverAllowlistedPrograms();

  logger.info('DEV_MODE', 'Applying developer firewall exceptions', {
    programs: programs.map((p) => p.path),
    localPorts: DEV_ALLOWLIST.localOnlyPorts,
  });

  for (const { path: program, name } of programs) {
    if (PROCESS_HTTPS_ALLOW.has(name)) {
      const https = applyProgramRule(createFirewallRule, program, 'HTTPS', 443);
      if (https.ok) {
        succeeded.push(https.ruleName);
        if (name === 'node.exe' || name === 'bun.exe') {
          logger.info('DEV_MODE', 'MongoDB Atlas allowed for Node', { program });
        }
      } else {
        failed.push({ rule: https.ruleName, error: https.reason, optional: true, category: 'developer' });
        logger.warn('DEV_MODE', `Developer exception failed: ${https.reason}`, { rule: https.ruleName });
      }
    }

    if (PROCESS_MONGO_OUTBOUND.has(name)) {
      const mongo = applyProgramRule(createFirewallRule, program, 'Mongo', 27017);
      if (mongo.ok) succeeded.push(mongo.ruleName);
      else {
        failed.push({ rule: mongo.ruleName, error: mongo.reason, optional: true, category: 'developer' });
        logger.warn('DEV_MODE', `Developer exception failed: ${mongo.reason}`, { rule: mongo.ruleName });
      }
    }
  }

  for (const port of DEV_ALLOWLIST.localOnlyPorts) {
    const local = applyLocalhostPortRule(createFirewallRule, port);
    if (local.ok) succeeded.push(local.ruleName);
    else if (/not valid|invalid argument|address keyword/i.test(local.reason || '')) {
      logger.warn('DEV_MODE', `Localhost firewall rule skipped for port ${port}`, { reason: local.reason });
    } else {
      failed.push({ rule: local.ruleName, error: local.reason, optional: true, category: 'developer' });
      logger.warn('DEV_MODE', `Developer exception failed: ${local.reason}`, { rule: local.ruleName });
    }
  }

  const v6Name = devRuleName(['Allow', 'localhost', 'IPv6', 'loopback']);
  const v6 = createFirewallRule({
    name: v6Name,
    dir: 'out',
    action: 'allow',
    protocol: 'TCP',
    remoteip: '::1',
    remoteport: DEV_ALLOWLIST.localOnlyPorts.join(','),
    category: 'developer',
  });
  if (v6.ok) {
    succeeded.push(v6.ruleName);
  } else if (/not valid|invalid argument|address keyword/i.test(v6.reason || '')) {
    logger.warn('DEV_MODE', 'IPv6 localhost firewall rule skipped; optional only.', { reason: v6.reason });
  } else {
    failed.push({ rule: v6.ruleName, error: v6.reason, optional: true, category: 'developer' });
  }

  logger.info('DEV_MODE', 'Localhost dev ports allowed', { ports: DEV_ALLOWLIST.localOnlyPorts });

  const developerExceptionsApplied = succeeded.length > 0;
  return {
    ok: true,
    skipped: false,
    succeeded,
    failed,
    programs: programs.map((p) => p.path),
    developerExceptionsApplied,
  };
}

function refreshDeveloperFirewallRules() {
  if (!isDeveloperLikeMode()) return { refreshed: false };
  const programs = discoverAllowlistedPrograms();
  if (programs.length === 0) return { refreshed: false, programs };
  const active = new Set(listDeveloperRules());
  const needsRefresh = programs.some(({ path: program, name }) => {
    if (!PROCESS_HTTPS_ALLOW.has(name)) return false;
    const stem = path.basename(program, path.extname(program)).replace(/[^a-zA-Z0-9-]/g, '-');
    const prefix = devRuleName(['Allow', stem, 'HTTPS', '443']);
    return ![...active].some((rule) => rule.startsWith(prefix));
  });
  if (!needsRefresh) return { refreshed: false, programs };
  logger.info('DEV_MODE', 'Refreshing developer firewall exceptions');
  return { ...applyDeveloperFirewallRules(), refreshed: true };
}

module.exports = {
  DEV_RULE_PREFIX,
  listDeveloperRules,
  removeDeveloperFirewallRules,
  applyDeveloperFirewallRules,
  refreshDeveloperFirewallRules,
  discoverAllowlistedPrograms,
};
