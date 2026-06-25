const fs = require('fs');
const path = require('path');
const { FILES, LOG } = require('../config/serviceConfig');

/**
 * Structured, size-rotated logger for NetFastService.
 *
 * Design goals (Phase 2): log status CHANGES and important events, not every
 * routine check. Callers decide what is noteworthy; this module only formats,
 * mirrors to stdout (captured by node-windows into its own log), and appends to
 * a rotated service.log so logs never grow without bound.
 */

const VALID_TAGS = new Set([
  'SERVICE',
  'DNS',
  'VPN',
  'DOH',
  'HOSTS',
  'VIRTUALIZATION',
  'CHALLENGE',
  'HEARTBEAT',
  'VIOLATION',
  'SYNC',
  'IPC',
  'API',
  'ERROR',
]);

let stream = null;
let writtenBytes = 0;

function ensureDir() {
  const dir = path.dirname(FILES.log);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function openStream() {
  ensureDir();
  try {
    writtenBytes = fs.existsSync(FILES.log) ? fs.statSync(FILES.log).size : 0;
  } catch {
    writtenBytes = 0;
  }
  stream = fs.createWriteStream(FILES.log, { flags: 'a' });
  stream.on('error', () => {
    // Never let a logging failure crash the service; fall back to stdout only.
    stream = null;
  });
}

/** Roll service.log -> service.log.1 -> ... keeping LOG.maxFiles archives. */
function rotateIfNeeded(nextChunkLength) {
  if (writtenBytes + nextChunkLength <= LOG.maxBytes) return;
  try {
    if (stream) stream.end();
  } catch {
    /* ignore */
  }
  stream = null;
  try {
    const oldest = `${FILES.log}.${LOG.maxFiles}`;
    if (fs.existsSync(oldest)) fs.unlinkSync(oldest);
    for (let i = LOG.maxFiles - 1; i >= 1; i--) {
      const src = `${FILES.log}.${i}`;
      if (fs.existsSync(src)) fs.renameSync(src, `${FILES.log}.${i + 1}`);
    }
    if (fs.existsSync(FILES.log)) fs.renameSync(FILES.log, `${FILES.log}.1`);
  } catch {
    /* if rotation fails, keep appending to the existing file */
  }
  openStream();
}

function safeDetail(detail) {
  if (detail === undefined) return undefined;
  if (detail === null || typeof detail !== 'object') return detail;
  try {
    return JSON.parse(JSON.stringify(detail));
  } catch {
    return String(detail);
  }
}

function write(level, tag, message, detail) {
  const safeTag = VALID_TAGS.has(tag) ? tag : 'SERVICE';
  const ts = new Date().toISOString();
  const cleanDetail = safeDetail(detail);
  const head = `[NetFastService] ${ts} [${safeTag}] ${message}`;

  if (cleanDetail !== undefined) {
    console[level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log'](head, cleanDetail);
  } else {
    console[level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log'](head);
  }

  try {
    if (!stream) openStream();
    if (!stream) return;
    const line =
      `${head}${cleanDetail !== undefined ? ` ${JSON.stringify(cleanDetail)}` : ''}\n`;
    const len = Buffer.byteLength(line);
    rotateIfNeeded(len);
    stream.write(line);
    writtenBytes += len;
  } catch {
    /* stdout already has the line */
  }
}

module.exports = {
  info: (tag, message, detail) => write('log', tag, message, detail),
  warn: (tag, message, detail) => write('warn', tag, message, detail),
  error: (tag, message, detail) => write('error', tag, message, detail),
  /** Tail recent log lines (used by the `service:logs` script / API). */
  tail(limit = 200) {
    try {
      if (!fs.existsSync(FILES.log)) return [];
      const content = fs.readFileSync(FILES.log, 'utf8');
      const lines = content.split('\n').filter(Boolean);
      return lines.slice(-Math.max(1, limit));
    } catch {
      return [];
    }
  },
  LOG_PATH: FILES.log,
};
