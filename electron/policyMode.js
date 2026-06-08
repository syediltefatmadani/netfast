const logger = require('./logger');

const VALID_MODES = ['strict', 'developer', 'testing', 'repair'];
const DEFAULT_MODE = 'strict';

const DEV_ALLOWLIST = {
  processes: [
    'node.exe',
    'npm.cmd',
    'npx.cmd',
    'pnpm.exe',
    'yarn.cmd',
    'bun.exe',
    'git.exe',
    'docker.exe',
    'com.docker.backend.exe',
    'wsl.exe',
    'wslhost.exe',
    'mongod.exe',
    'mongos.exe',
    'redis-server.exe',
    'redis-cli.exe',
    'code.exe',
    'cursor.exe',
  ],

  domains: [
    'github.com',
    '*.github.com',
    'githubusercontent.com',
    '*.githubusercontent.com',
    'registry.npmjs.org',
    '*.npmjs.org',
    'registry.yarnpkg.com',
    'pypi.org',
    '*.pypi.org',
    'files.pythonhosted.org',
    'docker.io',
    '*.docker.io',
    'registry-1.docker.io',
    'auth.docker.io',
    'production.cloudflare.docker.com',
    'mongodb.com',
    '*.mongodb.com',
    'mongodb.net',
    '*.mongodb.net',
  ],

  ports: [22, 80, 443, 3000, 5173, 6379, 7000, 27017],

  localOnlyPorts: [3000, 5173, 6379, 7000, 27017],
};

const MODE_LABELS = {
  strict: 'Strict',
  developer: 'Developer',
  testing: 'Testing',
  repair: 'Repair',
};

let cachedMode = null;

function normalizeMode(raw) {
  const mode = String(raw || DEFAULT_MODE)
    .trim()
    .toLowerCase();
  if (!VALID_MODES.includes(mode)) {
    logger.warn('POLICY', `Invalid NETFAST_POLICY_MODE "${raw}" — using strict`);
    return DEFAULT_MODE;
  }
  return mode;
}

function getPolicyMode() {
  if (cachedMode) return cachedMode;
  cachedMode = normalizeMode(process.env.NETFAST_POLICY_MODE);
  return cachedMode;
}

function resetPolicyModeCache() {
  cachedMode = null;
}

function isStrictMode() {
  return getPolicyMode() === 'strict';
}

function isDeveloperMode() {
  return getPolicyMode() === 'developer';
}

function isTestingMode() {
  return getPolicyMode() === 'testing';
}

function isRepairMode() {
  return getPolicyMode() === 'repair';
}

function isDeveloperLikeMode() {
  const mode = getPolicyMode();
  return mode === 'developer' || mode === 'testing';
}

function getModeLabel(mode = getPolicyMode()) {
  return MODE_LABELS[mode] || MODE_LABELS.strict;
}

function getProtectionStatusForMode(lockdownOk, hasWarnings) {
  const mode = getPolicyMode();
  if (mode === 'developer') {
    if (!lockdownOk) return 'Not protected';
    return 'Protected with developer exceptions';
  }
  if (mode === 'testing') {
    if (!lockdownOk) return 'Not protected';
    return hasWarnings ? 'Protected with warnings (testing)' : 'Protected (testing)';
  }
  if (mode === 'repair') {
    if (!lockdownOk) return 'Not protected';
    return hasWarnings ? 'Protected with warnings (repair)' : 'Protected (repair)';
  }
  if (!lockdownOk) return 'Not protected';
  return hasWarnings ? 'Protected with warnings' : 'Protected';
}

function logPolicyModeStartup() {
  const mode = getPolicyMode();
  logger.info('POLICY', `Mode: ${mode}`);
  if (isDeveloperMode()) {
    logger.warn('DEV_MODE', 'Developer exceptions enabled');
    logger.warn('DEV_MODE', 'Developer Mode reduces strictness for trusted tools only');
  }
}

function buildPolicyStatusSnapshot(extras = {}) {
  const mode = getPolicyMode();
  const warnings = [];
  const errors = [];

  if (isDeveloperMode()) {
    warnings.push('Developer mode allows trusted dev tools.');
    if (extras.dockerProtected === 'unknown' || extras.wslProtected === 'unknown') {
      warnings.push('Docker/WSL protection not verified.');
    }
  }

  return {
    mode,
    modeLabel: getModeLabel(mode),
    protectionStatus: extras.protectionStatus || getProtectionStatusForMode(false, false),
    dnsApplied: Boolean(extras.dnsApplied),
    dohConfigured: Boolean(extras.dohConfigured),
    browserDohLocked: extras.browserDohLocked !== false,
    firewallCoreLocked: Boolean(extras.firewallCoreLocked),
    bypassResolversBlocked: Boolean(extras.bypassResolversBlocked),
    developerExceptionsApplied: Boolean(extras.developerExceptionsApplied),
    dockerProtected: extras.dockerProtected ?? 'unknown',
    wslProtected: extras.wslProtected ?? 'unknown',
    warnings,
    errors,
  };
}

module.exports = {
  VALID_MODES,
  DEFAULT_MODE,
  DEV_ALLOWLIST,
  getPolicyMode,
  resetPolicyModeCache,
  isStrictMode,
  isDeveloperMode,
  isTestingMode,
  isRepairMode,
  isDeveloperLikeMode,
  getModeLabel,
  getProtectionStatusForMode,
  logPolicyModeStartup,
  buildPolicyStatusSnapshot,
};
