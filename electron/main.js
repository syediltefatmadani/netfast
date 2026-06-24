const { app, BrowserWindow } = require('electron');

const path = require('path');

const logger = require('./logger');

const { removeDnsFirewall } = require('./firewall');

const { removeMongoNrptRules } = require('./mongoDns');

const { runLockdown, startNetworkWatch, runWatchCheck, setWatchFastFallback } = require('./networkWatch');

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

const { startProdServer } = require('./prodServer');

const { startTamperWatch } = require('./tamperWatch');

const { invalidateDnsStatusCache } = require('./dnsStatusCache');

require('./ipc');



let mainWindow;

let prodServer = null;

let tamperStop = null;

let lastLoadedUrl = null;



/** Bring the existing window to the foreground (restore if minimized, focus). */

function restoreMainWindow() {

  if (!mainWindow || mainWindow.isDestroyed()) return;

  if (mainWindow.isMinimized()) mainWindow.restore();

  if (!mainWindow.isVisible()) mainWindow.show();

  mainWindow.focus();

}



const RELOAD_COOLDOWN_MS = 5000;

let lastReloadAt = 0;



function attemptRecoveryReload(reason) {

  if (!mainWindow || mainWindow.isDestroyed()) return;

  const now = Date.now();

  if (now - lastReloadAt < RELOAD_COOLDOWN_MS) {

    logger.warn('WINDOW', `Skipping reload (cooldown) after ${reason}`);

    return;

  }

  lastReloadAt = now;

  logger.warn('WINDOW', `Auto-reloading renderer after ${reason}`);

  try {

    if (lastLoadedUrl) mainWindow.loadURL(lastLoadedUrl);

    else mainWindow.reload();

  } catch (e) {

    logger.error('WINDOW', 'Auto-reload failed', e.message);

  }

}



function registerCrashHandlers(win) {

  win.webContents.on('render-process-gone', (_event, details) => {

    logger.error('WINDOW', 'Renderer process gone', details);

    attemptRecoveryReload('render-process-gone');

  });

  win.webContents.on('unresponsive', () => {

    logger.warn('WINDOW', 'Renderer unresponsive');

  });

  win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {

    if (!isMainFrame || errorCode === -3 /* ERR_ABORTED */) return;

    logger.error('WINDOW', 'Renderer failed to load', { errorCode, errorDescription, validatedURL });

    attemptRecoveryReload('did-fail-load');

  });

}



function loadErrorPage(win, message) {

  const html = `<!doctype html><html><head><meta charset="utf-8"/>

<style>body{background:#0a0a0f;color:#e4e4e7;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style>

</head><body><div><h2>NetFast couldn't start the app window</h2>

<p style="color:#a1a1aa">${message || 'Unexpected error'}</p></div></body></html>`;

  win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);

}



function handleTamperEvent({ vector }) {

  if (vector === 'sensor_down') {

    logger.warn('TAMPER', 'Event sensor unavailable — reverting to fast polling backstop');

    setWatchFastFallback(true);

    return;

  }

  logger.info('TAMPER', `Tamper event (${vector}) — re-verifying enforcement`);

  invalidateDnsStatusCache();

  runWatchCheck(`event:${vector}`).catch((e) =>

    logger.error('TAMPER', 'Event-triggered watch check failed', e.message),

  );

}



async function createWindow() {

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

    show: false,

  });



  // Show only once the renderer has painted so a half-initialized window can't
  // get stuck off-screen / unfocusable when the main process is briefly busy.

  mainWindow.once('ready-to-show', () => {

    restoreMainWindow();

  });



  registerCrashHandlers(mainWindow);



  const isDev = process.env.NODE_ENV === 'development';



  if (isDev) {

    lastLoadedUrl = process.env.VITE_DEV_URL || 'http://localhost:5173';

    mainWindow.loadURL(lastLoadedUrl);

    mainWindow.webContents.openDevTools();

    return;

  }



  // Production: this is a TanStack Start SSR app — serve it from a loopback

  // server and loadURL, instead of loadFile() on a static index.html that does

  // not exist (which is what produced the blank white screen).

  try {

    prodServer = await startProdServer();

    lastLoadedUrl = prodServer.url;

    mainWindow.loadURL(prodServer.url);

  } catch (e) {

    logger.error('STARTUP', 'Failed to start production renderer server', e.message);

    loadErrorPage(mainWindow, 'The app server failed to start. Please reinstall NetFast.');

  }

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

    // Event-driven tamper detection: react instantly to OS change notifications

    // instead of fast polling. The network watch above is now a slow backstop.

    tamperStop = startTamperWatch({ onTamper: handleTamperEvent });

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



// Single-instance: clicking the taskbar/exe again must focus the running window
// instead of spawning a second process that fights over enforcement and ports.
const gotSingleInstanceLock = app.requestSingleInstanceLock();

if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    logger.info('WINDOW', 'Second instance launched — focusing existing window');
    restoreMainWindow();
  });

  app.on('activate', () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      createWindow();
    } else {
      restoreMainWindow();
    }
  });

  app.whenReady().then(async () => {
    logPolicyModeStartup();
    logger.info('STARTUP', 'NetFast Electron ready', { mode: getPolicyMode() });

    const windowTimer = createPhaseTimer('window-creation');
    await createWindow();
    windowTimer.end();

    const challenge = await getSavedChallengeState();
    if (shouldRunStartupLockdown(challenge) && !isEnforcementDisabled()) {
      setEnforcementInProgress(true);
    }

    setTimeout(() => {
      runBackgroundLockdown();
    }, 250);
  });
}



app.on('will-quit', () => {

  if (tamperStop) {

    try {

      tamperStop();

    } catch {}

    tamperStop = null;

  }

  if (prodServer) {

    try {

      prodServer.close();

    } catch {}

    prodServer = null;

  }

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

