const { execSync } = require('child_process');
const logger = require('./logger');
const { assertRealEnforcementAllowed } = require('./enforcementGuard');
const { execFileAsync } = require('./asyncExec');

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

/**
 * Non-blocking variant of runEncoded. Returns a Promise that rejects on
 * timeout/error without stalling the Electron main-process event loop. Use this
 * from read/verify paths that feed the UI; runEncoded (sync) stays for the
 * apply/write enforcement paths.
 */
function runEncodedAsync(script, operationName = 'PowerShell') {
  if (!assertRealEnforcementAllowed(operationName)) {
    return Promise.resolve(mockEncodedOutput(script));
  }

  if (process.env.NODE_ENV === 'development') {
    logger.info('POWERSHELL', 'Executing encoded script (async)', { script: script.trim() });
  }

  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return execFileAsync('powershell', ['-NoProfile', '-EncodedCommand', b64], {
    encoding: 'utf8',
    timeout: 15000,
  });
}

module.exports = { runEncoded, runEncodedAsync };
