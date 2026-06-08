const fs = require('fs');
const path = require('path');
const os = require('os');

const MAX_EVENTS = 500;

function defaultAuditPath() {
  try {
    const { app } = require('electron');
    return path.join(app.getPath('userData'), 'dns-audit.jsonl');
  } catch {
    return path.join(os.tmpdir(), 'netfast-dns-audit.jsonl');
  }
}

class DnsAuditLogger {
  constructor(filePath) {
    this.filePath = filePath || defaultAuditPath();
  }

  /**
   * @param {{ timestamp?: string, networkName: string, status: string, details: string, meta?: object }} event
   */
  append(event) {
    const row = {
      timestamp: event.timestamp || new Date().toISOString(),
      networkName: event.networkName || 'unknown',
      status: event.status,
      details: event.details,
      ...(event.meta ? { meta: event.meta } : {}),
    };
    try {
      fs.appendFileSync(this.filePath, `${JSON.stringify(row)}\n`, 'utf8');
      this.trimIfNeeded();
    } catch {
      /* disk full / permissions */
    }
    return row;
  }

  trimIfNeeded() {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const lines = fs.readFileSync(this.filePath, 'utf8').trim().split('\n');
      if (lines.length <= MAX_EVENTS) return;
      const kept = lines.slice(-MAX_EVENTS);
      fs.writeFileSync(this.filePath, `${kept.join('\n')}\n`, 'utf8');
    } catch {}
  }

  readRecent(limit = 50) {
    try {
      if (!fs.existsSync(this.filePath)) return [];
      const lines = fs.readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean);
      return lines.slice(-limit).map((line) => JSON.parse(line));
    } catch {
      return [];
    }
  }
}

module.exports = { DnsAuditLogger };
