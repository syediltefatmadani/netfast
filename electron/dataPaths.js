const fs = require('fs');
const path = require('path');
const { app } = require('electron');

const LEGACY_DATA_DIR = path.join(__dirname, '..', 'data');

function getNetFastDataDir() {
  let base;
  try {
    base = path.join(app.getPath('userData'), 'netfast-state');
  } catch {
    base = LEGACY_DATA_DIR;
  }
  if (!fs.existsSync(base)) fs.mkdirSync(base, { recursive: true });
  return base;
}

function resolveStatePath(filename) {
  const target = path.join(getNetFastDataDir(), filename);
  const legacy = path.join(LEGACY_DATA_DIR, filename);
  if (!fs.existsSync(target) && fs.existsSync(legacy)) {
    try {
      fs.copyFileSync(legacy, target);
    } catch {
      return legacy;
    }
  }
  return target;
}

module.exports = { getNetFastDataDir, resolveStatePath, LEGACY_DATA_DIR };
