const { BrowserWindow } = require('electron');

let inProgress = false;
let lastStatus = null;
let lastCompletedAt = null;

function setEnforcementInProgress(value, status = null) {
  inProgress = Boolean(value);
  if (!value && status) {
    lastStatus = status;
    lastCompletedAt = Date.now();
  }
  notifyRenderer();
}

function getEnforcementStatus() {
  return {
    inProgress,
    lastCompletedAt,
    protectionLabel: inProgress ? 'Applying protection...' : lastStatus?.protectionLabel || null,
    lockdown: lastStatus,
  };
}

function notifyRenderer() {
  const payload = getEnforcementStatus();
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) {
      win.webContents.send('enforcement-status-changed', payload);
    }
  }
}

module.exports = {
  setEnforcementInProgress,
  getEnforcementStatus,
};
