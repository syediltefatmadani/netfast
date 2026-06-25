const fs = require('fs');
const path = require('path');
const logger = require('../logging/serviceLogger');

/**
 * DoH / encrypted-DNS risk monitor.
 *
 * DoH detection is inherently imperfect — we DO NOT overpromise. We gather
 * best-effort evidence from browser configuration where readable and report a
 * confidence level rather than a hard boolean claim:
 *   - Firefox  : prefs.js -> network.trr.mode (2 = DoH+fallback, 3 = DoH only)
 *   - Chrome/Edge: Preferences -> dns_over_https.mode ("secure" / "automatic")
 *
 * Limitation: a service running as LocalSystem may not always be able to read a
 * locked per-user browser profile; missing evidence means "unknown", not "safe".
 */

function userProfiles() {
  const base = process.env.SystemDrive ? `${process.env.SystemDrive}\\Users` : 'C:\\Users';
  try {
    return fs
      .readdirSync(base, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(base, d.name))
      .filter((p) => !/\\(Public|Default|Default User|All Users)$/i.test(p));
  } catch {
    return [];
  }
}

function safeRead(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function listDir(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function checkFirefox(profile, evidence) {
  const root = path.join(profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
  for (const entry of listDir(root)) {
    if (!entry.isDirectory()) continue;
    const prefs = safeRead(path.join(root, entry.name, 'prefs.js'));
    if (!prefs) continue;
    const m = prefs.match(/user_pref\("network\.trr\.mode",\s*(\d+)\)/);
    if (m && (m[1] === '2' || m[1] === '3')) {
      evidence.push(`Firefox TRR (DoH) mode ${m[1]} enabled`);
    }
  }
}

function checkChromium(profile, brand, relDir, evidence) {
  const userData = path.join(profile, ...relDir);
  for (const entry of listDir(userData)) {
    if (!entry.isDirectory()) continue;
    if (!/^(Default|Profile \d+)$/.test(entry.name)) continue;
    const raw = safeRead(path.join(userData, entry.name, 'Preferences'));
    if (!raw) continue;
    try {
      const json = JSON.parse(raw);
      const mode = json?.dns_over_https?.mode;
      if (mode === 'secure' || mode === 'automatic') {
        evidence.push(`${brand} secure DNS (DoH) mode "${mode}"`);
      }
    } catch {
      /* preferences locked or partial */
    }
  }
}

function check() {
  const lastCheckedAt = new Date().toISOString();
  const evidence = [];

  for (const profile of userProfiles()) {
    try {
      checkFirefox(profile, evidence);
      checkChromium(profile, 'Chrome', ['AppData', 'Local', 'Google', 'Chrome', 'User Data'], evidence);
      checkChromium(profile, 'Edge', ['AppData', 'Local', 'Microsoft', 'Edge', 'User Data'], evidence);
    } catch (e) {
      logger.warn('DOH', 'Profile scan failed', e.message);
    }
  }

  const unique = Array.from(new Set(evidence));
  let confidence = 'low';
  if (unique.length >= 2) confidence = 'high';
  else if (unique.length === 1) confidence = 'medium';

  return {
    dohRiskDetected: unique.length > 0,
    confidence,
    evidence: unique,
    lastCheckedAt,
  };
}

module.exports = { check, name: 'doh' };
