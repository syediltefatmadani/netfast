const { execSync } = require('child_process');
const logger = require('./logger');

/** CleanBrowsing Family Filter — blocks adult, VPN/proxy, mixed content; enforces SafeSearch. */
const DNS = {
  filter: 'family',
  ipv4: { primary: '185.228.168.168', secondary: '185.228.169.168' },
  ipv6: { primary: '2a0d:2a00:1::', secondary: '2a0d:2a00:2::' },
};

function run(cmd, tag) {
  logger.info(tag, `> ${cmd}`);
  return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

function getConnectedAdapters() {
  const out = execSync('netsh interface show interface', { encoding: 'utf8' });
  const adapters = out
    .split('\n')
    .filter((l) => l.includes('Connected'))
    .map((l) => l.trim().split(/\s{2,}/).pop())
    .filter(Boolean);
  logger.info('DNS', 'Connected adapters', adapters);
  return adapters;
}

function disableWindowsDoH() {
  logger.info('DNS', 'Disabling Windows automatic DNS-over-HTTPS');
  try {
    run(
      'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" /v EnableAutoDoh /t REG_DWORD /d 0 /f',
      'DNS',
    );
  } catch (e) {
    logger.execError('DNS', 'EnableAutoDoh registry failed', e);
  }
  try {
    execSync(
      'powershell -NoProfile -Command "Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object { Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -ErrorAction SilentlyContinue }"',
      { encoding: 'utf8', stdio: 'pipe' },
    );
    logger.info('DNS', 'Cleared per-server DoH templates');
  } catch (e) {
    logger.warn('DNS', 'Could not clear DoH templates (may need admin)', e.message);
  }
}

function applyDNS() {
  logger.info('DNS', 'Applying CleanBrowsing Family Filter to connected adapters', DNS);
  disableWindowsDoH();
  const adapters = getConnectedAdapters();
  if (adapters.length === 0) {
    logger.warn('DNS', 'No connected adapters found — skipping apply');
    return { applied: [], failed: [] };
  }

  const applied = [];
  const failed = [];

  for (const adapter of adapters) {
    try {
      run(
        `netsh interface ipv4 set dns name="${adapter}" static ${DNS.ipv4.primary} primary`,
        'DNS',
      );
      run(`netsh interface ipv4 add dns name="${adapter}" ${DNS.ipv4.secondary} index=2`, 'DNS');
      run(
        `netsh interface ipv6 set dns name="${adapter}" static ${DNS.ipv6.primary} primary`,
        'DNS',
      );
      run(`netsh interface ipv6 add dns name="${adapter}" ${DNS.ipv6.secondary} index=2`, 'DNS');
      logger.info('DNS', `DNS applied on "${adapter}"`, {
        ipv4: [DNS.ipv4.primary, DNS.ipv4.secondary],
        ipv6: [DNS.ipv6.primary, DNS.ipv6.secondary],
      });
      applied.push(adapter);
    } catch (e) {
      logger.execError('DNS', `DNS set failed on "${adapter}"`, e);
      failed.push({ adapter, error: e.message });
    }
  }

  return { applied, failed };
}

function isBlockedLookup(output) {
  const text = output.toLowerCase();
  return (
    text.includes('0.0.0.0') ||
    text.includes('restricted.') ||
    text.includes('blocked') ||
    text.includes('nxdomain') ||
    text.includes('rpz.')
  );
}

function verifyBlocking() {
  const probes = [
    { domain: 'pornhub.com', label: 'catalog (pornhub)' },
    { domain: 'pornhat.com', label: 'hosts supplement (pornhat)' },
  ];
  const results = [];
  for (const { domain, label } of probes) {
    try {
      const out = execSync(`nslookup ${domain}`, {
        encoding: 'utf8',
        timeout: 8000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const blocked = isBlockedLookup(out);
      results.push({ domain, label, blocked });
      if (!blocked) {
        logger.warn('DNS', `Block probe FAILED — site still resolves`, { domain, label });
      } else {
        logger.info('DNS', `Block probe ${domain}`, { blocked, label });
      }
    } catch (e) {
      const out = `${e.stdout || ''}${e.stderr || ''}${e.message}`;
      const blocked = isBlockedLookup(out);
      results.push({ domain, label, blocked });
      logger.info('DNS', `Block probe ${domain}`, { blocked, label, note: 'lookup error treated as blocked' });
    }
  }
  return results;
}

function verifyDNS() {
  try {
    const ipv4 = execSync(
      'powershell "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"',
      { encoding: 'utf8' },
    ).trim();
    const ipv6 = execSync(
      'powershell "(Get-DnsClientServerAddress -AddressFamily IPv6).ServerAddresses"',
      { encoding: 'utf8' },
    ).trim();
    const result = {
      ipv4: { intact: ipv4.includes(DNS.ipv4.primary), servers: ipv4 },
      ipv6: { intact: ipv6.includes(DNS.ipv6.primary), servers: ipv6 },
      expected: DNS,
      probes: verifyBlocking(),
    };
    logger.info('DNS', 'Verify DNS', {
      ipv4Intact: result.ipv4.intact,
      ipv6Intact: result.ipv6.intact,
      ipv4Servers: ipv4.slice(0, 200),
      ipv6Servers: ipv6.slice(0, 200),
      probes: result.probes,
    });
    return result;
  } catch (e) {
    logger.execError('DNS', 'Verify DNS failed', e);
    return { ipv4: { intact: false }, ipv6: { intact: false } };
  }
}

function disableIPv6Tunneling() {
  logger.info('TUNNEL', 'Disabling IPv6 tunnel interfaces (teredo, 6to4, isatap)');
  const results = [];
  for (const t of ['teredo', '6to4', 'isatap']) {
    try {
      const out = run(`netsh interface ${t} set state disabled`, 'TUNNEL');
      logger.info('TUNNEL', `${t} disabled`, out.trim().slice(0, 120) || 'ok');
      results.push({ tunnel: t, ok: true });
    } catch (e) {
      logger.execError('TUNNEL', `Failed to disable ${t}`, e);
      results.push({ tunnel: t, ok: false });
    }
  }
  return results;
}

function verifyTeredoDisabled() {
  try {
    const out = execSync('netsh interface teredo show state', { encoding: 'utf8' });
    const disabled = out.toLowerCase().includes('disabled');
    logger.info('TUNNEL', 'Teredo state', { disabled, snippet: out.trim().split('\n')[0] });
    return disabled;
  } catch (e) {
    logger.execError('TUNNEL', 'Teredo verify failed', e);
    return false;
  }
}

module.exports = {
  applyDNS,
  verifyDNS,
  verifyBlocking,
  disableIPv6Tunneling,
  verifyTeredoDisabled,
  disableWindowsDoH,
  DNS,
};
