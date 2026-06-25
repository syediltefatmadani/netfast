const { Tray, Menu, nativeImage, Notification, app } = require('electron');
const logger = require('./logger');

let tray = null;
let backgroundNoticeShown = false;
let trayCallbacks = { onOpen: () => {}, onQuit: () => {}, getStatus: () => ({}) };

const ICON_SIZE = 16;
// Brand purple (#6c47ff) drawn as a filled rounded square so the tray icon is
// recognisable without shipping a binary asset.
const ICON_RGB = { r: 0x6c, g: 0x47, b: 0xff };

/**
 * Build the tray icon in-process from a raw BGRA bitmap. Avoids committing a
 * binary .ico/.png and works on Windows where the tray expects a small icon.
 */
function buildTrayIcon() {
  const size = ICON_SIZE;
  const radius = 3;
  const buffer = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      const inCorner =
        (x < radius && y < radius && (radius - x) ** 2 + (radius - y) ** 2 > radius ** 2) ||
        (x >= size - radius &&
          y < radius &&
          (x - (size - 1 - radius)) ** 2 + (radius - y) ** 2 > radius ** 2) ||
        (x < radius &&
          y >= size - radius &&
          (radius - x) ** 2 + (y - (size - 1 - radius)) ** 2 > radius ** 2) ||
        (x >= size - radius &&
          y >= size - radius &&
          (x - (size - 1 - radius)) ** 2 + (y - (size - 1 - radius)) ** 2 > radius ** 2);
      // BGRA order (Windows nativeImage bitmap layout).
      buffer[i] = ICON_RGB.b;
      buffer[i + 1] = ICON_RGB.g;
      buffer[i + 2] = ICON_RGB.r;
      buffer[i + 3] = inCorner ? 0 : 255;
    }
  }
  return nativeImage.createFromBitmap(buffer, { width: size, height: size });
}

function statusLabel() {
  try {
    const status = trayCallbacks.getStatus() || {};
    if (status.enforcementInProgress) return 'Protection Status: Applying...';
    if (!status.running) return 'Protection Status: Not monitoring';
    return `Protection Status: ${status.protectionLabel || 'Monitoring'}`;
  } catch {
    return 'Protection Status: Unknown';
  }
}

function buildMenu() {
  return Menu.buildFromTemplate([
    { label: 'Open NetFast', click: () => trayCallbacks.onOpen() },
    { type: 'separator' },
    // Read-only status line; clicking it does nothing.
    { label: statusLabel(), enabled: false },
    { type: 'separator' },
    { label: 'Quit NetFast', click: () => trayCallbacks.onQuit() },
  ]);
}

/**
 * @param {{ onOpen: () => void, onQuit: () => void, getStatus: () => object }} callbacks
 */
function createTray(callbacks) {
  trayCallbacks = { ...trayCallbacks, ...callbacks };
  if (tray) return tray;

  try {
    tray = new Tray(buildTrayIcon());
  } catch (e) {
    logger.error('TRAY', 'Failed to create tray icon', e.message);
    return null;
  }

  tray.setToolTip('NetFast — monitoring in the background');
  tray.setContextMenu(buildMenu());
  // Single click (Windows) / click should reopen the control panel.
  tray.on('click', () => trayCallbacks.onOpen());

  logger.info('TRAY', 'System tray ready');
  return tray;
}

/** Refresh the tray menu so the protection status line stays current. */
function updateTray() {
  if (!tray) return;
  try {
    tray.setContextMenu(buildMenu());
  } catch (e) {
    logger.warn('TRAY', 'Failed to refresh tray menu', e.message);
  }
}

function destroyTray() {
  if (tray) {
    try {
      tray.destroy();
    } catch {
      /* already gone */
    }
    tray = null;
  }
}

/**
 * Tell the user once per app session that monitoring continues in the background
 * after the window is hidden. Never spams on every close.
 */
function showBackgroundMonitoringNotificationOnce() {
  if (backgroundNoticeShown) return;
  backgroundNoticeShown = true;
  try {
    if (Notification.isSupported()) {
      new Notification({
        title: app.getName?.() || 'NetFast',
        body: 'NetFast is still monitoring in the background.',
        silent: true,
      }).show();
    } else {
      logger.info('TRAY', 'Notifications unsupported — skipping background notice');
    }
  } catch (e) {
    logger.warn('TRAY', 'Failed to show background notification', e.message);
  }
}

module.exports = {
  createTray,
  updateTray,
  destroyTray,
  showBackgroundMonitoringNotificationOnce,
};
