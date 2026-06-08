const { execSync } = require('child_process');
const logger = require('./logger');
const { assertRealEnforcementAllowed, wasRealEnforcementApplied } = require('./enforcementGuard');

const CLEANBROWSING_DOH_TEMPLATE = 'https://doh.cleanbrowsing.org/doh/family-filter/';

const CHROMIUM_POLICY_KEYS = [
  ['HKCU\\Software\\Policies\\Google\\Chrome', 'Chrome (HKCU)'],
  ['HKCU\\Software\\Policies\\Microsoft\\Edge', 'Edge (HKCU)'],
  ['HKCU\\Software\\Policies\\BraveSoftware\\Brave', 'Brave (HKCU)'],
  ['HKLM\\Software\\Policies\\Google\\Chrome', 'Chrome (HKLM)'],
  ['HKLM\\Software\\Policies\\Microsoft\\Edge', 'Edge (HKLM)'],
];

function runReg(args, label) {
  if (!assertRealEnforcementAllowed(`reg-add:${label}`)) return true;
  try {
    execSync(`reg add ${args}`, { stdio: 'pipe' });
    logger.info('BROWSER', label);
    return true;
  } catch (e) {
    logger.warn('BROWSER', `${label} failed`, e.message);
    return false;
  }
}

/**
 * Force Chromium browsers to use CleanBrowsing Family DoH (not Google/Cloudflare Secure DNS).
 * "off" relied on Windows DoH, which many browsers ignore; explicit template is required.
 */
function applyChromiumCleanBrowsingDoH() {
  if (!assertRealEnforcementAllowed('browser-doh-policy')) {
    logger.info('DEV_SAFE', 'Mock browser DoH policy success');
    return { ok: true, template: CLEANBROWSING_DOH_TEMPLATE, applied: CHROMIUM_POLICY_KEYS.length, mock: true };
  }
  const templateEsc = CLEANBROWSING_DOH_TEMPLATE;
  let applied = 0;
  for (const [key, label] of CHROMIUM_POLICY_KEYS) {
    const modeOk = runReg(`"${key}" /v DnsOverHttpsMode /t REG_SZ /d secure /f`, `${label} DoH mode=secure`);
    const tplOk = runReg(
      `"${key}" /v DnsOverHttpsTemplates /t REG_SZ /d ${templateEsc} /f`,
      `${label} DoH template=CleanBrowsing Family`,
    );
    if (modeOk && tplOk) applied++;
  }
  logger.info('BROWSER', 'Chromium Secure DNS locked to CleanBrowsing Family DoH', {
    template: CLEANBROWSING_DOH_TEMPLATE,
    policyRootsApplied: applied,
  });
  return { ok: applied > 0, template: CLEANBROWSING_DOH_TEMPLATE, applied };
}

/** @deprecated alias — now enables CleanBrowsing DoH in browsers */
function disableChromiumDoHPolicies() {
  return applyChromiumCleanBrowsingDoH();
}

function isCleanBrowsingDohTemplate(value) {
  const t = String(value || '').toLowerCase();
  return t.includes('cleanbrowsing.org') && t.includes('family-filter');
}

/**
 * Human-readable Chromium Secure DNS policy state for logs/UI.
 * applyChromiumCleanBrowsingDoH sets DnsOverHttpsMode=secure + CleanBrowsing template (not "off").
 */
function getChromiumDoHPolicyStatus() {
  return {
    strategy: 'cleanbrowsing_template',
    statusMessage: 'Browser DoH forced to CleanBrowsing Family template (mode=secure)',
    template: CLEANBROWSING_DOH_TEMPLATE,
  };
}

/** Remove NetFast Chromium DoH policy keys only (does not touch unrelated registry values). */
function removeChromiumCleanBrowsingPolicies() {
  if (!wasRealEnforcementApplied() && !assertRealEnforcementAllowed('remove-browser-doh-policy')) {
    logger.info('DEV_SAFE', 'Skipped browser policy removal — enforcement was not applied');
    return { ok: true, removed: 0, skipped: true };
  }
  let removed = 0;
  for (const [key, label] of CHROMIUM_POLICY_KEYS) {
    for (const valueName of ['DnsOverHttpsMode', 'DnsOverHttpsTemplates']) {
      try {
        execSync(`reg delete "${key}" /v ${valueName} /f`, { stdio: 'pipe' });
        logger.info('BROWSER', `${label} removed ${valueName}`);
        removed++;
      } catch {
        /* key or value may not exist */
      }
    }
  }
  return { ok: true, removed };
}

module.exports = {
  CLEANBROWSING_DOH_TEMPLATE,
  applyChromiumCleanBrowsingDoH,
  disableChromiumDoHPolicies,
  removeChromiumCleanBrowsingPolicies,
  isCleanBrowsingDohTemplate,
  getChromiumDoHPolicyStatus,
};
