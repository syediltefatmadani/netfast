const { DohClient } = require('./DohClient');
const {
  DOH_FAMILY_BASE,
  DOH_WIRE_URL,
  DOH_REACHABLE_HTTP_STATUSES,
} = require('./filterTests');

const TYPE_MAP = { A: 1, AAAA: 28, TXT: 16, CNAME: 5, SRV: 33 };

function reachableFromHttpStatus(status) {
  return status != null && DOH_REACHABLE_HTTP_STATUSES.has(status);
}

function classifyResponseType({ rcode, answers, blocked, nxdomain, error, timeout }) {
  if (timeout) return 'timeout';
  if (error && !nxdomain) return 'error';
  if (nxdomain || rcode === 3) return 'nxdomain';
  if (blocked) return 'blocked';
  if (answers?.length) return 'resolved';
  return 'unknown';
}

function isBlockedDohResult({ rcode, answers, blocked }) {
  if (blocked) return true;
  if (rcode === 3) return true;
  if (!answers?.length && rcode !== 0) return true;
  return false;
}

function parseDnsJson(body, domain) {
  const status = body.Status;
  const answers = (body.Answer || [])
    .map((a) => {
      if (a.type === 1 && a.data) return a.data;
      if (a.type === 28 && a.data) return a.data;
      if (a.type === 5 && a.data) return a.data;
      return null;
    })
    .filter(Boolean);
  const nxdomain = status === 3;
  const blocked = isBlockedDohResult({
    rcode: status,
    answers,
    blocked: nxdomain || answers.every((a) => {
      const lower = String(a).toLowerCase();
      return (
        lower === '0.0.0.0' ||
        lower === '127.0.0.1' ||
        lower === '::' ||
        lower === '::1' ||
        lower.includes('restricted.') ||
        lower.includes('rpz.')
      );
    }),
  });
  return {
    ok: true,
    reachable: true,
    status,
    domain,
    type: body.Question?.[0]?.type ?? 1,
    answers,
    blocked,
    nxdomain,
    resolved: !blocked && answers.length > 0,
    error: null,
    responseType: classifyResponseType({
      rcode: status,
      answers,
      blocked,
      nxdomain,
    }),
    raw: body,
  };
}

function wireToStructured(parsed, domain, type) {
  const answers = [];
  for (const a of parsed.answers || []) {
    if (a.value) answers.push(String(a.value));
  }
  const nxdomain = parsed.rcode === 3;
  const blocked = isBlockedDohResult({
    rcode: parsed.rcode,
    answers,
    blocked: nxdomain,
  });
  return {
    ok: true,
    reachable: true,
    status: parsed.rcode,
    domain,
    type,
    answers,
    blocked,
    nxdomain,
    resolved: !blocked && answers.length > 0,
    error: null,
    responseType: classifyResponseType({
      rcode: parsed.rcode,
      answers,
      blocked,
      nxdomain,
    }),
    raw: parsed,
  };
}

/**
 * Query CleanBrowsing Family DoH (JSON first, RFC8484 wire fallback).
 * @param {string} domain
 * @param {'A'|'AAAA'} [type]
 * @param {{ dohClient?: DohClient, timeoutMs?: number }} [opts]
 */
async function queryCleanBrowsingDoH(domain, type = 'A', opts = {}) {
  const typeNum = TYPE_MAP[type] ?? 1;

  if (opts.dohClient?.query) {
    try {
      const parsed = await opts.dohClient.query(domain, type);
      return wireToStructured(parsed, domain, typeNum);
    } catch (e) {
      return {
        ok: false,
        reachable: false,
        status: null,
        domain,
        type: typeNum,
        answers: [],
        blocked: false,
        nxdomain: false,
        resolved: false,
        error: e.message,
        responseType: 'error',
        raw: null,
      };
    }
  }

  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? 12000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const fail = (error, extra = {}) => ({
    ok: false,
    reachable: false,
    status: null,
    domain,
    type: typeNum,
    answers: [],
    blocked: false,
    nxdomain: false,
    resolved: false,
    error: error || 'unknown',
    responseType: extra.timeout ? 'timeout' : 'error',
    raw: null,
    ...extra,
  });

  try {
    const jsonUrl = `${DOH_FAMILY_BASE}?name=${encodeURIComponent(domain)}&type=${type}`;
    let res;
    try {
      res = await fetch(jsonUrl, {
        method: 'GET',
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      });
    } catch (e) {
      const timeout = e.name === 'AbortError';
      return fail(e.message, { timeout });
    }

    if (reachableFromHttpStatus(res.status) && res.ok) {
      const body = await res.json();
      return parseDnsJson(body, domain);
    }

    if (reachableFromHttpStatus(res.status) && !res.ok) {
      const client = opts.dohClient || new DohClient(DOH_WIRE_URL);
      const parsed = await client.query(domain, type);
      return wireToStructured(parsed, domain, typeNum);
    }

    return fail(`DoH HTTP ${res.status}`, { reachable: reachableFromHttpStatus(res.status) });
  } catch (e) {
    try {
      const client = opts.dohClient || new DohClient(DOH_WIRE_URL);
      const parsed = await client.query(domain, type);
      return wireToStructured(parsed, domain, typeNum);
    } catch (e2) {
      const timeout = e.name === 'AbortError' || e2.name === 'AbortError';
      return fail(e2.message || e.message, { timeout });
    }
  } finally {
    clearTimeout(timer);
  }
}

async function pingCleanBrowsingDoH(opts = {}) {
  const client = opts.dohClient || new DohClient(DOH_WIRE_URL);
  return client.ping();
}

module.exports = {
  queryCleanBrowsingDoH,
  pingCleanBrowsingDoH,
  reachableFromHttpStatus,
  classifyResponseType,
  isBlockedDohResult,
  DOH_FAMILY_BASE,
  DOH_WIRE_URL,
};
