/**
 * Uninstalls NetFastService. Must be run elevated:  npm run service:uninstall
 * The user is always free to remove the service — no anti-uninstall behavior.
 */
const { buildService, SERVICE_NAME } = require('./serviceDefinition');

const svc = buildService();

svc.on('uninstall', () => {
  console.log(`[${SERVICE_NAME}] uninstalled.`);
});

svc.on('doesnotexist', () => {
  console.log(`[${SERVICE_NAME}] is not installed — nothing to do.`);
});

svc.on('error', (err) => {
  console.error(`[${SERVICE_NAME}] uninstall error:`, err?.message || err);
  console.error('Make sure this terminal is running as Administrator.');
  process.exitCode = 1;
});

svc.uninstall();
