/**
 * Installs NetFastService as a Windows service (Automatic start) and starts it.
 * Must be run from an elevated (Administrator) terminal:  npm run service:install
 */
const { buildService, SERVICE_NAME } = require('./serviceDefinition');

const svc = buildService();

svc.on('install', () => {
  console.log(`[${SERVICE_NAME}] installed. Starting...`);
  svc.start();
});

svc.on('alreadyinstalled', () => {
  console.log(`[${SERVICE_NAME}] is already installed. Use "npm run service:start".`);
});

svc.on('invalidinstallation', () => {
  console.error(`[${SERVICE_NAME}] invalid installation detected.`);
  process.exitCode = 1;
});

svc.on('start', () => {
  console.log(`[${SERVICE_NAME}] started. It now runs in the background and on every boot.`);
});

svc.on('error', (err) => {
  console.error(`[${SERVICE_NAME}] install error:`, err?.message || err);
  console.error('Make sure this terminal is running as Administrator.');
  process.exitCode = 1;
});

svc.install();
