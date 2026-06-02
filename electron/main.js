const { app, BrowserWindow } = require('electron');
const path = require('path');
const logger = require('./logger');
const { disableIPv6Tunneling } = require('./dns');
const { runLockdown, startNetworkWatch } = require('./networkWatch');
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

app.whenReady().then(async () => {
  logger.info('STARTUP', 'NetFast Electron ready — running lockdown');
  try {
    const lockdown = runLockdown('startup');
    const tunnelResult = disableIPv6Tunneling();
    logger.info('STARTUP', 'Lockdown summary', {
      dns: lockdown.dns,
      hosts: lockdown.hosts,
      tunnel: tunnelResult,
    });
    startNetworkWatch();
  } catch (e) {
    logger.error('STARTUP', 'Startup lockdown failed', e.message);
  }
  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
