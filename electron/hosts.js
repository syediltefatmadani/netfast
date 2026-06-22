const fs = require('fs');

const path = require('path');

const { execSync } = require('child_process');

const logger = require('./logger');

const { expandDomainVariants } = require('./services/dns/filterTests');
const { assertRealEnforcementAllowed } = require('./enforcementGuard');



const MARKER_BEGIN = '# focuslock-block-begin';

const MARKER_END = '# focuslock-block-end';

const MONGO_MARKER_BEGIN = '# focuslock-mongo-begin';

const MONGO_MARKER_END = '# focuslock-mongo-end';

const NULL_IP = '0.0.0.0';

const NULL_IP6 = '::';



/** Domains CleanBrowsing often misses; blocked via hosts when running as admin. */

const BLOCKED_DOMAINS = [

  'pornhat.com',

  'www.pornhat.com',

  'pornhat.one',

  'www.pornhat.one',

  'reddit.com',

  'www.reddit.com',

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



/** Master switch — when false, NetFast never reads, writes, or monitors the Windows hosts file. */
function isHostsFileEnforcementEnabled() {
  return false;
}

function useHostsBlocklist() {
  if (!isHostsFileEnforcementEnabled()) return false;
  const v = (process.env.NETFAST_HOSTS_BLOCK ?? '1').toLowerCase();
  return v !== '0' && v !== 'false' && v !== 'no';
}



function getAllBlockedDomains() {

  return [...new Set(BLOCKED_DOMAINS.map((d) => d.toLowerCase()))];

}



function addBlockedDomains(domains) {

  const added = [];

  for (const d of expandDomainVariants(domains)) {

    const lower = d.toLowerCase();

    if (!BLOCKED_DOMAINS.includes(lower)) {

      BLOCKED_DOMAINS.push(lower);

      added.push(lower);

    }

  }

  return added;

}



function readBlockSectionDomains(content) {

  const begin = content.indexOf(MARKER_BEGIN);

  const end = content.indexOf(MARKER_END);

  if (begin === -1 || end === -1) return new Set();

  const section = content.slice(begin, end);

  const found = new Set();

  for (const line of section.split(/\r?\n/)) {

    const m = line.match(/^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::)\s+(\S+)/i);

    if (m) found.add(m[1].toLowerCase());

  }

  return found;

}



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

  const unique = getAllBlockedDomains();

  for (const domain of unique) {

    lines.push(`${NULL_IP} ${domain}`);

    lines.push(`${NULL_IP6} ${domain}`);

  }

  lines.push(MARKER_END);

  return lines.join('\r\n');

}



/**

 * Idempotently add domains to the NetFast hosts supplement (not Mongo section).

 * @param {string[]} domains

 * @param {string} [reason]

 */

async function ensureHostsBlockedDomains(domains, reason = 'manual') {
  if (!isHostsFileEnforcementEnabled()) {
    return {
      ok: true,
      added: [],
      alreadyPresent: [],
      failed: [],
      path: getHostsPath(),
      reason: 'hosts_file_enforcement_disabled',
      skipped: true,
    };
  }

  const hostsPath = getHostsPath();

  const result = {

    ok: false,

    added: [],

    alreadyPresent: [],

    failed: [],

    path: hostsPath,

    reason,

    skipped: false,

  };



  if (!useHostsBlocklist()) {

    result.skipped = true;

    result.reason = 'NETFAST_HOSTS_BLOCK disabled';

    return result;

  }



  try {

    if (!fs.existsSync(hostsPath)) {

      result.failed = [...domains];

      return result;

    }



    const content = fs.readFileSync(hostsPath, 'utf8');

    const inSection = readBlockSectionDomains(content);

    const variants = [];

    for (const d of domains) variants.push(...expandDomainVariants(d));



    for (const v of variants) {

      const lower = v.toLowerCase();

      if (inSection.has(lower) || BLOCKED_DOMAINS.includes(lower)) {

        result.alreadyPresent.push(lower);

      } else {

        result.added.push(lower);

      }

    }



    if (result.added.length === 0) {

      result.ok = true;

      return result;

    }



    addBlockedDomains(result.added);

    const sync = syncHostsBlocklist();

    result.ok = sync.ok;

    if (!sync.ok) result.failed = result.added;

    logger.info('HOSTS', 'Provider-miss domains added to supplement', {

      reason,

      added: result.added,

      path: hostsPath,

    });

    return result;

  } catch (e) {

    logger.execError('HOSTS', 'ensureHostsBlockedDomains failed', e);

    result.failed = [...domains];

    result.error = e.message;

    return result;

  }

}



function syncHostsBlocklist() {
  const hostsPath = getHostsPath();
  if (!isHostsFileEnforcementEnabled()) {
    return { ok: true, path: hostsPath, skipped: true, reason: 'hosts_file_enforcement_disabled' };
  }
  if (!assertRealEnforcementAllowed('hosts-blocklist-write')) {
    logger.info('DEV_SAFE', 'Mock hosts blocklist sync success');
    return { ok: true, skipped: true, mock: true, reason: 'dev_safe_mode' };
  }

  logger.info('HOSTS', 'Resolving hosts file', {

    path: hostsPath,

    arch: process.arch,

    wow64: Boolean(process.env.PROCESSOR_ARCHITEW6432),

  });



  if (!useHostsBlocklist()) {

    return { ok: true, path: hostsPath, skipped: true, reason: 'hosts_block_disabled' };

  }



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



    let newContent;

    if (begin !== -1 && end !== -1) {

      const currentBlock = content.slice(begin, end + MARKER_END.length);

      if (currentBlock === block) {

        logger.info('HOSTS', 'Supplemental blocklist unchanged — skipping write');

        return { ok: true, path: hostsPath, skipped: true, reason: 'unchanged' };

      }

      newContent = content.slice(0, begin) + block + content.slice(end + MARKER_END.length);

    } else {

      newContent = content.trimEnd() + '\r\n\r\n' + block + '\r\n';

    }



    if (content.trim() === newContent.trim()) {

      return { ok: true, path: hostsPath, skipped: true, reason: 'unchanged_content' };

    }



    fs.writeFileSync(hostsPath, newContent, 'utf8');

    flushDnsCache();

    logger.info('HOSTS', 'Supplemental blocklist applied', {

      path: hostsPath,

      domains: getAllBlockedDomains().length,

    });

    return { ok: true, path: hostsPath };

  } catch (e) {

    logger.execError('HOSTS', 'Failed to update hosts blocklist', e);

    return { ok: false, path: hostsPath, error: e.message };

  }

}



/** Atlas hostnames resolved via DoH (port 53 UDP is locked; hosts gives system resolver fixed A records). */

function syncMongoHostsEntries(entries) {
  const hostsPath = getHostsPath();
  if (!isHostsFileEnforcementEnabled()) {
    return { ok: true, path: hostsPath, skipped: true, reason: 'hosts_file_enforcement_disabled' };
  }
  if (!assertRealEnforcementAllowed('hosts-mongo-write')) {
    logger.info('DEV_SAFE', 'Mock Mongo hosts sync success');
    return { ok: true, skipped: true, mock: true };
  }



  try {

    if (!fs.existsSync(hostsPath)) {

      return { ok: false, path: hostsPath, error: 'hosts_not_found' };

    }



    let content = fs.readFileSync(hostsPath, 'utf8');

    const begin = content.indexOf(MONGO_MARKER_BEGIN);

    const end = content.indexOf(MONGO_MARKER_END);



    let block = '';

    if (entries && entries.length > 0) {

      const now = Date.now();

      const expiry = now + 24 * 60 * 60 * 1000;

      const lines = [

        MONGO_MARKER_BEGIN,

        '# MongoDB Atlas — managed by NetFast (DoH lookup)',

        `# Generated: ${new Date(now).toISOString()}`,

        `# Expires: ${new Date(expiry).toISOString()}`,

      ];

      for (const { hostname, ip } of entries) {

        if (hostname && ip) lines.push(`${ip} ${hostname}`);

      }

      lines.push(MONGO_MARKER_END);

      block = lines.join('\r\n');

    }



    let newContent;

    const hasBlock = begin !== -1 && end !== -1;



    if (hasBlock) {

      const currentBlock = content.slice(begin, end + MONGO_MARKER_END.length);



      if (block === '') {

        newContent =

          content.slice(0, begin).trimEnd() +

          '\r\n' +

          content.slice(end + MONGO_MARKER_END.length).trimStart();

      } else {

        const cleanContent = (b) =>

          b

            .split(/\r?\n/)

            .filter((l) => l && !l.trim().startsWith('#'))

            .map((l) => l.trim())

            .join('\n');

        if (cleanContent(currentBlock) === cleanContent(block)) {

          logger.info('HOSTS', 'MongoDB Atlas hosts entries unchanged — skipping write');

          return { ok: true, path: hostsPath, skipped: true, reason: 'unchanged', entries };

        }

        newContent = content.slice(0, begin) + block + content.slice(end + MONGO_MARKER_END.length);

      }

    } else {

      if (block === '') {

        return { ok: true, path: hostsPath, skipped: true, reason: 'no_block_to_remove' };

      }

      newContent = content.trimEnd() + '\r\n\r\n' + block + '\r\n';

    }



    if (content.trim() === newContent.trim()) {

      return { ok: true, path: hostsPath, skipped: true, reason: 'unchanged_content', entries };

    }



    fs.writeFileSync(hostsPath, newContent, 'utf8');

    flushDnsCache();

    logger.info('HOSTS', block === '' ? 'MongoDB Atlas hosts entries removed' : 'MongoDB Atlas hosts entries applied', {

      path: hostsPath,

      hosts: entries ? entries.map((e) => e.hostname) : [],

    });

    return { ok: true, path: hostsPath, entries };

  } catch (e) {

    logger.execError('HOSTS', 'MongoDB hosts sync failed', e);

    return { ok: false, path: hostsPath, error: e.message };

  }

}



module.exports = {

  isHostsFileEnforcementEnabled,

  getHostsPath,

  syncHostsBlocklist,

  syncMongoHostsEntries,

  ensureHostsBlockedDomains,

  flushDnsCache,

  useHostsBlocklist,

  getAllBlockedDomains,

  addBlockedDomains,

  BLOCKED_DOMAINS,

  MARKER_BEGIN,

  MARKER_END,

  MONGO_MARKER_BEGIN,

  MONGO_MARKER_END,

};

