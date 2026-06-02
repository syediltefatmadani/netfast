const { execSync } = require('child_process');
const logger = require('./logger');

function runReg(args, label) {
  try {
    execSync(`reg add ${args}`, { stdio: 'pipe' });
    logger.info('BROWSER', label);
    return true;
  } catch (e) {
    logger.warn('BROWSER', `${label} failed`, e.message);
    return false;
  }
}

/** Force Chrome/Edge to use system DNS (no Secure DNS bypass). Requires admin for HKLM; HKCU works per-user. */
function disableChromiumDoHPolicies() {
  const policies = [
    ['HKCU\\Software\\Policies\\Google\\Chrome', 'DnsOverHttpsMode', 'off', 'Chrome DoH policy (HKCU)'],
    ['HKCU\\Software\\Policies\\Microsoft\\Edge', 'DnsOverHttpsMode', 'off', 'Edge DoH policy (HKCU)'],
  ];
  for (const [key, name, value, label] of policies) {
    runReg(`"${key}" /v ${name} /t REG_SZ /d ${value} /f`, label);
  }
}

module.exports = { disableChromiumDoHPolicies };
