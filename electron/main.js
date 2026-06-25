const { app, BrowserWindow } = require('electron');

const path = require('path');

const logger = require('./logger');

const { removeDnsFirewall } = require('./firewall');

const { removeMongoNrptRules } = require('./mongoDns');

const { runLockdown } = require('./networkWatch');

const { logPolicyModeStartup, getPolicyMode } = require('./policyMode');

const {

  checkDeadlineOnStartup,

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

const monitorManager = require('./monitoring/monitorManager');

const { createTray, updateTray, destroyTray, showBackgroundMonitoringNotificationOnce } = require('./tray');

require('./ipc');



let mainWindow;

let prodServer = null;

let lastLoadedUrl = null;

// Tray-app lifecycle: closing the window only HIDES it; the app (and monitoring)
// keeps running in the tray. We only truly exit when the user picks Quit, which
// flips this flag so the window 'close' handler stops intercepting.
let isQuitting = false;



/** Bring the existing window to the foreground (restore if minimized, focus). */

function restoreMainWindow() {

  if (!mainWindow || mainWindow.isDestroyed()) {

    createWindow();

    return;

  }

  if (mainWindow.isMinimized()) mainWindow.restore();

  if (!mainWindow.isVisible()) mainWindow.show();

  mainWindow.focus();

}



/** Explicit, controlled quit (tray > Quit). Lets the window close + app cleanup run. */
function quitApp() {

  logger.info('TRAY', 'Quit requested from tray');

  isQuitting = true;

  app.quit();

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

  // Close button must NOT quit the app — hide the window and keep monitoring
  // running in the background. The app only exits via tray > Quit (isQuitting).
  mainWindow.on('close', (event) => {
    if (isQuitting) return;
    event.preventDefault();
    mainWindow.hide();
    showBackgroundMonitoringNotificationOnce();
    logger.info('TRAY', 'Window hidden — monitoring continues in background');
  });



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



    // Single owner for the background monitoring lifecycle (network watch +
    // event-driven tamper sensor + DNS health). Idempotent: safe to call again.
    monitorManager.start();



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

    createTray({
      onOpen: restoreMainWindow,
      onQuit: quitApp,
      getStatus: () => monitorManager.getStatus(),
    });

    // Keep the tray's protection-status line fresh as monitoring state changes.
    monitorManager.addStatusListener(() => updateTray());

    const challenge = await getSavedChallengeState();
    if (shouldRunStartupLockdown(challenge) && !isEnforcementDisabled()) {
      setEnforcementInProgress(true);
    }

    setTimeout(() => {
      runBackgroundLockdown();
    }, 250);
  });
}



// Any quit path (tray Quit, OS shutdown, dev exit) must release the window
// 'close' interceptor so the app can actually exit.
app.on('before-quit', () => {

  isQuitting = true;

});



app.on('will-quit', () => {

  // Stop the whole monitoring lifecycle through its single owner.

  try {

    monitorManager.stop();

  } catch {}

  destroyTray();

  if (prodServer) {

    try {

      prodServer.close();

    } catch {}

    prodServer = null;

  }

  if (!shouldRunQuitCleanup()) {

    logger.info('STARTUP', 'Skipping quit cleanup — real enforcement was not applied');

    return;

  }



  try {

    removeMongoNrptRules();

    removeDnsFirewall();

  } catch {}

});



app.on('window-all-closed', () => {

  // Intentionally do NOT quit here. NetFast is a tray app: the window hides on
  // close and monitoring keeps running. The app only exits via tray > Quit.

  logger.info('TRAY', 'All windows closed — staying alive in tray');

});

