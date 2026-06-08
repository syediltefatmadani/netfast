const fs = require('fs');
const { resolveStatePath } = require('./dataPaths');

const CACHE_PATH = resolveStatePath('challenge-cache.json');

function ensureCacheDir() {
  const dir = require('path').dirname(CACHE_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function getSavedChallengeStateSync() {
  try {
    if (!fs.existsSync(CACHE_PATH)) return null;
    return JSON.parse(fs.readFileSync(CACHE_PATH, 'utf8'));
  } catch {
    return null;
  }
}

async function getSavedChallengeState() {
  return getSavedChallengeStateSync();
}

function saveChallengeState(challenge) {
  if (!challenge) {
    if (fs.existsSync(CACHE_PATH)) fs.unlinkSync(CACHE_PATH);
    return null;
  }

  ensureCacheDir();
  const data = {
    id: challenge._id || challenge.id || null,
    status: challenge.status || null,
    updatedAt: new Date().toISOString(),
  };
  fs.writeFileSync(CACHE_PATH, JSON.stringify(data, null, 2), 'utf8');
  return data;
}

module.exports = {
  CACHE_PATH,
  getSavedChallengeState,
  getSavedChallengeStateSync,
  saveChallengeState,
};
