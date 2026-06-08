const DOH_URL = 'https://doh.cleanbrowsing.org/doh/family-filter/dns-query';

function writeName(buf, domain) {
  for (const label of domain.split('.')) {
    if (!label.length || label.length > 63) throw new Error(`Invalid label: ${domain}`);
    buf.push(label.length);
    for (let i = 0; i < label.length; i++) buf.push(label.charCodeAt(i));
  }
  buf.push(0);
}

/** Build a minimal DNS wire-format query (type A, class IN). */
function encodeQuery(domain, type = 1) {
  const buf = [];
  const id = Math.floor(Math.random() * 65535);
  buf.push((id >> 8) & 0xff, id & 0xff);
  buf.push(0x01, 0x00); // RD=1
  buf.push(0x00, 0x01); // QDCOUNT=1
  buf.push(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  writeName(buf, domain);
  buf.push((type >> 8) & 0xff, type & 0xff);
  buf.push(0x00, 0x01); // IN
  return Buffer.from(buf);
}

function readName(msg, offset) {
  const labels = [];
  let o = offset;
  let jumped = false;
  let end = offset;
  while (msg[o] !== 0) {
    if ((msg[o] & 0xc0) === 0xc0) {
      if (!jumped) end = o + 2;
      o = ((msg[o] & 0x3f) << 8) | msg[o + 1];
      jumped = true;
      continue;
    }
    const len = msg[o];
    o += 1;
    labels.push(msg.subarray(o, o + len).toString('utf8'));
    o += len;
  }
  if (!jumped) end = o + 1;
  return { name: labels.join('.'), offset: end };
}

function parseResponse(buffer) {
  if (!buffer || buffer.length < 12) return { rcode: -1, answers: [] };
  const rcode = buffer[3] & 0x0f;
  const qd = (buffer[4] << 8) | buffer[5];
  const an = (buffer[6] << 8) | buffer[7];
  let offset = 12;
  for (let i = 0; i < qd; i++) {
    const q = readName(buffer, offset);
    offset = q.offset + 4;
  }
  const answers = [];
  for (let i = 0; i < an; i++) {
    const n = readName(buffer, offset);
    offset = n.offset;
    const type = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    const cls = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    const ttl =
      (buffer[offset] << 24) |
      (buffer[offset + 1] << 16) |
      (buffer[offset + 2] << 8) |
      buffer[offset + 3];
    offset += 4;
    const rdlen = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    const rdata = buffer.subarray(offset, offset + rdlen);
    offset += rdlen;
    let value = null;
    if (type === 1 && rdlen === 4) {
      value = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
    } else if (type === 5) {
      const c = readName(buffer, offset - rdlen);
      value = c.name;
    } else if (type === 33 && rdlen >= 7) {
      const t = readName(rdata, 6);
      value = {
        priority: (rdata[0] << 8) | rdata[1],
        weight: (rdata[2] << 8) | rdata[3],
        port: (rdata[4] << 8) | rdata[5],
        target: t.name,
      };
    } else if (type === 28 && rdlen === 16) {
      const parts = [];
      for (let j = 0; j < 16; j += 2) {
        parts.push(rdata.readUInt16BE(j).toString(16));
      }
      value = parts.join(':');
    }
    answers.push({ type, value, ttl, class: cls });
  }
  return { rcode, answers };
}

class DohClient {
  constructor(url = DOH_URL) {
    this.url = url;
  }

  async query(domain, recordType = 'A') {
    const typeMap = { A: 1, AAAA: 28, CNAME: 5, TXT: 16, SRV: 33 };
    const type = typeMap[recordType] ?? 1;
    const wire = encodeQuery(domain, type);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          Accept: 'application/dns-message',
        },
        body: wire,
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      return parseResponse(buf);
    } finally {
      clearTimeout(timer);
    }
  }

  async ping() {
    const logger = require('../../logger');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const reachableStatuses = [200, 400, 405, 415];
    try {
      let res;
      try {
        res = await fetch(this.url, {
          method: 'HEAD',
          signal: controller.signal,
        });
      } catch (e) {
        // Fallback to GET if HEAD fails
        const subController = new AbortController();
        const subTimer = setTimeout(() => subController.abort(), 8000);
        try {
          res = await fetch(this.url, {
            method: 'GET',
            signal: subController.signal,
          });
        } finally {
          clearTimeout(subTimer);
        }
      }

      const isReachable = reachableStatuses.includes(res.status);
      logger.info('DOH_CLIENT', `Ping/connectivity test to ${this.url}`, {
        url: this.url,
        status: res.status,
        reachable: isReachable,
      });
      return {
        ok: isReachable,
        reachable: isReachable,
        status: res.status,
        message: isReachable
          ? 'CleanBrowsing DoH endpoint reachable'
          : `CleanBrowsing DoH endpoint unreachable (HTTP ${res.status})`,
      };
    } catch (e) {
      const isTimeout = e.name === 'AbortError';
      logger.warn('DOH_CLIENT', `Ping/connectivity test to ${this.url} failed`, {
        url: this.url,
        error: e.message,
        timeout: isTimeout,
        reachable: false,
      });
      return {
        ok: false,
        reachable: false,
        status: null,
        error: e.message,
        timeout: isTimeout,
        message: `CleanBrowsing DoH endpoint unreachable: ${e.message}`,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

module.exports = { DohClient, encodeQuery, parseResponse, DOH_URL };
