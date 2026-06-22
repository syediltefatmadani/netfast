const { app, BrowserWindow } = require('electron');

const path = require('path');

const logger = require('./logger');

const { removeDnsFirewall } = require('./firewall');

const { removeMongoNrptRules } = require('./mongoDns');

const { runLockdown, startNetworkWatch } = require('./networkWatch');

const { logPolicyModeStartup, getPolicyMode } = require('./policyMode');

const { getDnsHealthMonitor } = require('./services/dns');

const {

  checkDeadlineOnStartup,

  setNetworkWatchStop,

  isEnforcementDisabled,

} = require('./vpnViolationHandler');

const { setEnforcementInProgress, getEnforcementStatus } = require('./enforcementState');

const { createPhaseTimer } = require('./startupTiming');

const {

  shouldRunStartupLockdown,

  logStartupEnforcementPolicy,

  shouldRunQuitCleanup,

  isDevSafeMode,

} = require('./enforcementGuard');

const { getSavedChallengeState } = require('./challengeState');

const { buildMockLockdownResult } = require('./mockEnforcement');

require('./ipc');



let mainWindow;



function createWindow() {

  mainWindow = new BrowserWindow({

    width: 1200,

    height: 800,

    minWidth: 900,

    minHeight: 600,

    webPreferences: {

      preload: path.join(__dirname, 'preload.js'),

      contextIsolation: true,

      nodeIntegration: false,

    },

    titleBarStyle: 'hiddenInset',

    backgroundColor: '#0a0a0f',

  });



  const isDev = process.env.NODE_ENV === 'development';

  const devUrl = process.env.VITE_DEV_URL || 'http://localhost:5173';

  isDev

    ? mainWindow.loadURL(devUrl)

    : mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));

  if (isDev) mainWindow.webContents.openDevTools();

}



async function runMockStartupLockdown(reason) {

  setEnforcementInProgress(true);

  const lockdown = buildMockLockdownResult(reason);

  logger.info('DEV_SAFE', 'Mock lockdown complete', {

    protectionLabel: lockdown.protectionLabel,

    reason,

  });

  setEnforcementInProgress(false, lockdown);

  return lockdown;

}



async function runBackgroundLockdown() {

  const challenge = await getSavedChallengeState();

  logStartupEnforcementPolicy(challenge);



  if (!shouldRunStartupLockdown(challenge)) {

    const reason = isDevSafeMode() ? 'dev-safe-mode' : 'no-active-challenge';

    await runMockStartupLockdown(reason);

    return;

  }



  if (isEnforcementDisabled()) {
    logger.warn('STARTUP', 'Skipping lockdown — challenge failed or VPN enforcement disabled');
    await runMockStartupLockdown('enforcement-disabled');
    return;
  }

  if (!getEnforcementStatus().inProgress) {
    setEnforcementInProgress(true);
  }

  try {
    const startupDeadline = checkDeadlineOnStartup();

    if (startupDeadline.action === 'deadline_expired') {
      logger.error('STARTUP', 'VPN re-apply deadline expired while app was closed', startupDeadline);
    }

    const lockdown = await runLockdown('startup');

    logger.info('STARTUP', 'Lockdown summary', {
      mode: lockdown.mode,
      status: lockdown.status,
      protectionLabel: lockdown.protectionLabel,
      fastPath: lockdown.fastPath,
      mock: lockdown.mock,
      developerExceptionsApplied: lockdown.developerExceptionsApplied,
      dnsApplied: lockdown.dnsApplied,
      ipv4Locked: lockdown.ipv4Locked,
      ipv6Locked: lockdown.ipv6Locked,
      dnsIntegrity: lockdown.dnsIntegrity,
      dohConfigured: lockdown.dohConfigured,
      nrptApplied: lockdown.nrptApplied,
      nrptError: lockdown.nrptError,
      firewallLocked: lockdown.firewallLocked,
      firewallCoreLocked: lockdown.firewallCoreLocked,
      bypassResolversBlocked: lockdown.bypassResolversBlocked,
      hostsFallbackEnabled: lockdown.hostsFallbackEnabled,
      mongoDiagnostic: lockdown.mongoDiagnostic,
      rogueServers: lockdown.rogueServers,
      warnings: lockdown.warnings,
      error: lockdown.error,
      tunnel: lockdown.tunnel,
      worker: true,
    });



    setNetworkWatchStop(startNetworkWatch());

    getDnsHealthMonitor({

      onStatusChange: (report) => {

        if (!report.healthy) {

          logger.warn('DNS_HEALTH', 'Protection inactive', {

            status: report.status,

            details: report.details,

          });

        }

      },

    }).start();



    setEnforcementInProgress(false, lockdown);

  } catch (e) {

    logger.error('STARTUP', 'Startup lockdown failed', e.message);

    setEnforcementInProgress(false, {

      protectionLabel: 'Not protected',

      status: 'Not protected',

      error: e.message,

    });

  }

}



app.whenReady().then(async () => {
  logPolicyModeStartup();
  logger.info('STARTUP', 'NetFast Electron ready', { mode: getPolicyMode() });

  const windowTimer = createPhaseTimer('window-creation');
  createWindow();
  windowTimer.end();

  const challenge = await getSavedChallengeState();
  if (shouldRunStartupLockdown(challenge) && !isEnforcementDisabled()) {
    setEnforcementInProgress(true);
  }

  setTimeout(() => {
    runBackgroundLockdown();
  }, 250);
});



app.on('will-quit', () => {

  if (!shouldRunQuitCleanup()) {

    logger.info('STARTUP', 'Skipping quit cleanup — real enforcement was not applied');

    try {

      getDnsHealthMonitor().stop();

    } catch {}

    return;

  }



  try {

    getDnsHealthMonitor().stop();

    removeMongoNrptRules();

    removeDnsFirewall();

  } catch {}

});



app.on('window-all-closed', () => {

  if (process.platform !== 'darwin') app.quit();

});

