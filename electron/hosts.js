const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const logger = require('./logger');

const MARKER_BEGIN = '# focuslock-block-begin';
const MARKER_END = '# focuslock-block-end';
const NULL_IP = '0.0.0.0';

/** Domains CleanBrowsing often misses; blocked via hosts when running as admin. */
const BLOCKED_DOMAINS = [
  'pornhat.com',
  'www.pornhat.com',
  'xhamster.com',
  'www.xhamster.com',
  'xhamsters.com',
  'www.xhamsters.com',
  'xvideos.com',
  'www.xvideos.com',
  'xnxx.com',
  'www.xnxx.com',
  'redtube.com',
  'www.redtube.com',
  'youporn.com',
  'www.youporn.com',
];

/**
 * Real Windows hosts file path.
 * 32-bit Electron/Node on 64-bit Windows: System32 redirects to SysWOW64 (no hosts there).
 * Use Sysnative to reach the real System32\drivers\etc\hosts.
 */
function getHostsPath() {
  const windir = process.env.windir || 'C:\\Windows';
  if (process.env.PROCESSOR_ARCHITEW6432) {
    return path.join(windir, 'Sysnative', 'drivers', 'etc', 'hosts');
  }
  return path.join(windir, 'System32', 'drivers', 'etc', 'hosts');
}

function flushDnsCache() {
  try {
    execSync('ipconfig /flushdns', { stdio: 'pipe' });
    logger.info('HOSTS', 'DNS client cache flushed');
  } catch (e) {
    logger.warn('HOSTS', 'DNS flush failed', e.message);
  }
}

function buildBlockSection() {
  const lines = [MARKER_BEGIN, '# Managed by NetFast — do not edit this section'];
  for (const domain of BLOCKED_DOMAINS) {
    lines.push(`${NULL_IP} ${domain}`);
  }
  lines.push(MARKER_END);
  return lines.join('\r\n');
}

function syncHostsBlocklist() {
  const hostsPath = getHostsPath();
  logger.info('HOSTS', 'Resolving hosts file', {
    path: hostsPath,
    arch: process.arch,
    wow64: Boolean(process.env.PROCESSOR_ARCHITEW6432),
  });

  try {
    if (!fs.existsSync(hostsPath)) {
      logger.error('HOSTS', 'Hosts file not found — blocking supplement cannot apply', {
        path: hostsPath,
        hint: 'Run NetFast as Administrator on 64-bit Windows.',
      });
      return { ok: false, path: hostsPath };
    }

    let content = fs.readFileSync(hostsPath, 'utf8');
    const block = buildBlockSection();
    const begin = content.indexOf(MARKER_BEGIN);
    const end = content.indexOf(MARKER_END);
    if (begin !== -1 && end !== -1) {
      content = content.slice(0, begin) + block + content.slice(end + MARKER_END.length);
    } else {
      content = content.trimEnd() + '\r\n\r\n' + block + '\r\n';
    }
    fs.writeFileSync(hostsPath, content, 'utf8');
    flushDnsCache();
    logger.info('HOSTS', 'Supplemental blocklist applied', {
      path: hostsPath,
      domains: BLOCKED_DOMAINS.length,
    });
    return { ok: true, path: hostsPath };
  } catch (e) {
    logger.execError('HOSTS', 'Failed to update hosts blocklist', e);
    return { ok: false, path: hostsPath, error: e.message };
  }
}

module.exports = { getHostsPath, syncHostsBlocklist, flushDnsCache, BLOCKED_DOMAINS };
