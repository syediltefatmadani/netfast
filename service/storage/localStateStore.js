const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('../config/serviceConfig');

/**
 * Tiny JSON persistence helper with atomic writes. All local stores
 * (service-state, protection-status, queues) go through here so a crash or power
 * loss mid-write can never leave a half-written, unparseable file.
 *
 * Atomic strategy: write to a temp file in the same directory, fsync, then
 * rename over the target (rename is atomic on NTFS/most filesystems).
 */

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch {
    // Corrupt/partial file: fall back to the default rather than crashing.
    return fallback;
  }
}

function writeJson(filePath, data) {
  ensureDir();
  const dir = path.dirname(filePath);
  const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.tmp`);
  const payload = JSON.stringify(data, null, 2);
  let fd;
  try {
    fd = fs.openSync(tmp, 'w');
    fs.writeSync(fd, payload);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
  fs.renameSync(tmp, filePath);
}

module.exports = { readJson, writeJson, ensureDir };
