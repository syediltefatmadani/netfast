const path = require('path');
const { Worker } = require('worker_threads');
const logger = require('./logger');

function runLockdownInWorker(reason) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const workerPath = path.join(__dirname, 'lockdownWorker.js');

    const worker = new Worker(workerPath, {
      workerData: { reason },
      env: process.env,
    });

    worker.on('message', (msg) => {
      if (msg.type === 'result') {
        settled = true;
        resolve(msg.payload);
      } else if (msg.type === 'error') {
        settled = true;
        reject(new Error(msg.error || 'Lockdown worker failed'));
      }
    });

    worker.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    worker.on('exit', (code) => {
      if (!settled && code !== 0) {
        settled = true;
        reject(new Error(`Lockdown worker exited with code ${code}`));
      }
    });
  }).catch((e) => {
    logger.error('LOCKDOWN_WORKER', 'Worker failed', e.message);
    throw e;
  });
}

module.exports = { runLockdownInWorker };
