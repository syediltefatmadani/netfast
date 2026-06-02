const { ipcMain } = require('electron');
const logger = require('./logger');
const { applyDNS, verifyDNS } = require('./dns');
const { syncHostsBlocklist } = require('./hosts');
const { runFullCheck, getBatteryState, resetHostsBaseline } = require('./watchdog');

let dnsGapStart = null;
const GAP_MS = 2 * 60 * 1000;

ipcMain.handle('get-dns-status', async () => {
  logger.info('IPC', 'get-dns-status');
  return verifyDNS();
});

ipcMain.handle('get-vector-status', async () => {
  logger.info('IPC', 'get-vector-status');
  const check = runFullCheck();
  const dnsViolated = check.vectors.dns_ipv4.violated || check.vectors.dns_ipv6.violated;

  if (dnsViolated && !dnsGapStart) {
    dnsGapStart = Date.now();
    logger.warn('IPC', 'DNS violation detected — attempting restore');
    applyDNS();
  } else if (!dnsViolated && dnsGapStart) {
    logger.info('IPC', 'DNS restored — clearing violation gap timer');
    dnsGapStart = null;
  } else if (dnsViolated && dnsGapStart && Date.now() - dnsGapStart > GAP_MS) {
    logger.warn('IPC', 'DNS violation exceeded gap — marking reportable');
    check.vectors.dns_ipv4.reportable = true;
    check.vectors.dns_ipv6.reportable = true;
  }

  return check.vectors;
});

ipcMain.handle('restore-dns', async () => {
  logger.info('IPC', 'restore-dns (manual)');
  const result = applyDNS();
  const hosts = syncHostsBlocklist();
  if (hosts.ok) resetHostsBaseline();
  return { success: result.failed.length === 0, hosts, ...result };
});

ipcMain.handle('get-battery-state', async () => getBatteryState());
