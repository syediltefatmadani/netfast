/**
 * Start/stop/status helper for the installed NetFastService.
 * Usage (elevated for start/stop):
 *   node service/control.js start
 *   node service/control.js stop
 *   node service/control.js status
 */
const { buildService, SERVICE_NAME } = require('./serviceDefinition');

const action = (process.argv[2] || '').toLowerCase();

if (action === 'status') {
  // Read the endpoint file the running service publishes (no elevation needed).
  const fs = require('fs');
  const { FILES } = require('./config/serviceConfig');
  try {
    const info = JSON.parse(fs.readFileSync(FILES.endpoint, 'utf8'));
    console.log(`[${SERVICE_NAME}] endpoint:`, info);
  } catch {
    console.log(`[${SERVICE_NAME}] not running (no endpoint file found).`);
  }
  return;
}

if (action !== 'start' && action !== 'stop') {
  console.error('Usage: node service/control.js <start|stop|status>');
  process.exitCode = 1;
  return;
}

const svc = buildService();

svc.on('start', () => console.log(`[${SERVICE_NAME}] started.`));
svc.on('stop', () => console.log(`[${SERVICE_NAME}] stopped.`));
svc.on('doesnotexist', () =>
  console.error(`[${SERVICE_NAME}] is not installed. Run "npm run service:install" first.`),
);
svc.on('error', (err) => {
  console.error(`[${SERVICE_NAME}] ${action} error:`, err?.message || err);
  console.error('Make sure this terminal is running as Administrator.');
  process.exitCode = 1;
});

if (action === 'start') svc.start();
else svc.stop();
