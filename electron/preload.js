const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
  invoke: (channel, data) => ipcRenderer.invoke(channel, data),
  onEnforcementStatusChanged: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('enforcement-status-changed', listener);
    return () => ipcRenderer.removeListener('enforcement-status-changed', listener);
  },
  onStatusRefreshed: (callback) => {
    const listener = () => callback();
    ipcRenderer.on('status-refreshed', listener);
    return () => ipcRenderer.removeListener('status-refreshed', listener);
  },
});
