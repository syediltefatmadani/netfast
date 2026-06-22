const { BrowserWindow } = require('electron');

/** Send an IPC message to every live renderer window. */
function broadcast(channel, payload) {
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) {
      win.webContents.send(channel, payload);
    }
  }
}

module.exports = { broadcast };
