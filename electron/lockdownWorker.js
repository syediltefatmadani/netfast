const { parentPort, workerData } = require('worker_threads');

async function main() {
  const { executeLockdownCore } = require('./lockdownCore');
  const payload = await executeLockdownCore(workerData.reason);
  parentPort.postMessage({ type: 'result', payload });
}

main().catch((e) => {
  parentPort.postMessage({
    type: 'error',
    error: e.message || String(e),
    stack: e.stack,
  });
});
