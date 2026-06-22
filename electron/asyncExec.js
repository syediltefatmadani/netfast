const { exec, execFile } = require('child_process');

/**
 * Promise wrappers around child_process that DO NOT block the Electron main
 * thread (unlike execSync). Used by the read/verify paths that feed the UI so
 * that PowerShell / netsh / netstat / tasklist calls run off the event loop's
 * critical path. The apply/write enforcement paths intentionally keep using the
 * synchronous variants.
 */

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_BUFFER = 8 * 1024 * 1024;

function execAsync(cmd, { timeout = DEFAULT_TIMEOUT_MS, encoding = 'utf8' } = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { encoding, timeout, maxBuffer: DEFAULT_MAX_BUFFER }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        return reject(err);
      }
      resolve(stdout);
    });
  });
}

function execFileAsync(file, args = [], { timeout = DEFAULT_TIMEOUT_MS, encoding = 'utf8' } = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { encoding, timeout, maxBuffer: DEFAULT_MAX_BUFFER }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        return reject(err);
      }
      resolve(stdout);
    });
  });
}

module.exports = { execAsync, execFileAsync, DEFAULT_TIMEOUT_MS };
