/**
 * NetFastService entry point.
 *
 * Runs as a plain Node process (under node-windows in production, or directly via
 * `npm run service:run` in development). It is fully independent of Electron and
 * the React renderer — closing or never launching the desktop app has no effect
 * on monitoring. This process:
 *   1. loads persisted local state,
 *   2. starts the monitoring manager (single owner of all timers),
 *   3. starts the loopback control API for Electron, and
 *   4. shuts both down cleanly on stop signals.
 */

const logger = require('./logging/serviceLogger');
const serviceState = require('./storage/serviceState');
const manager = require('./serviceManager');
const { startApi, stopApi } = require('./api/httpServer');
const { SERVICE_VERSION } = require('./config/serviceConfig');

let shuttingDown = false;

async function main() {
  logger.info('SERVICE', `NetFastService v${SERVICE_VERSION} booting`, { pid: process.pid });

  serviceState.load();
  manager.start();

  try {
    await startApi(manager);
  } catch (e) {
    // If the port is already taken, another service instance is likely running.
    // Exit rather than running a second monitoring engine (no duplicates).
    logger.error('ERROR', 'Failed to start control API — exiting to avoid a duplicate instance', e.message);
    manager.stop();
    process.exit(1);
  }
}

function shutdown(reason) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('SERVICE', `Shutting down (${reason})`);
  try {
    stopApi();
    manager.stop();
  } finally {
    // Give logs a tick to flush.
    setTimeout(() => process.exit(0), 150);
  }
}

// Windows service stop / Ctrl+C / parent exit.
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('message', (msg) => {
  // node-windows sends a 'shutdown' message before stopping the wrapper.
  if (msg === 'shutdown') shutdown('node-windows shutdown');
});
process.on('uncaughtException', (err) => {
  logger.error('ERROR', 'Uncaught exception', { message: err.message, stack: err.stack });
});
process.on('unhandledRejection', (reason) => {
  logger.error('ERROR', 'Unhandled rejection', { reason: String(reason) });
});

main();
