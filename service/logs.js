/**
 * Prints recent NetFastService log lines.  Usage:  npm run service:logs
 * Optional line count:  node service/logs.js 500
 */
const logger = require('./logging/serviceLogger');

const limit = Number(process.argv[2]) || 200;
const lines = logger.tail(limit);

if (lines.length === 0) {
  console.log(`No log entries found at ${logger.LOG_PATH}.`);
} else {
  console.log(`--- Last ${lines.length} line(s) from ${logger.LOG_PATH} ---`);
  for (const line of lines) console.log(line);
}
