const { execSync } = require('child_process');
const logger = require('./logger');
const { assertRealEnforcementAllowed } = require('./enforcementGuard');

function mockEncodedOutput(script) {
  if (/ConvertTo-Json/.test(script)) {
    if (/\$rows\s*=\s*@\(\)/.test(script) || /\$results\s*=\s*@\(\)/.test(script)) return '[]';
    return '{}';
  }
  return 'ok\r\n';
}

/** Run PowerShell without cmd.exe eating $variables (UTF-16LE for -EncodedCommand). */
function runEncoded(script, operationName = 'PowerShell') {
  if (!assertRealEnforcementAllowed(operationName)) {
    return mockEncodedOutput(script);
  }

  if (process.env.NODE_ENV === 'development') {
    logger.info('POWERSHELL', 'Executing encoded script', { script: script.trim() });
  }

  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return execSync(`powershell -NoProfile -EncodedCommand ${b64}`, {
    encoding: 'utf8',
    timeout: 15000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

module.exports = { runEncoded };
