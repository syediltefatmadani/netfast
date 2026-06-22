const logger = require('./logger');

/** Let the Electron main process handle window/IPC events between heavy sync work. */
function yieldToEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}

function createPhaseTimer(phase, context = {}) {
  const startMs = Date.now();
  return {
    end(extra = {}) {
      const durationMs = Date.now() - startMs;
      logger.info('STARTUP_TIMING', phase, { durationMs, ...context, ...extra });
      return durationMs;
    },
  };
}

function timedPhase(phase, fn, context = {}) {
  const timer = createPhaseTimer(phase, context);
  try {
    const result = fn();
    timer.end({ ok: true });
    return result;
  } catch (e) {
    timer.end({ ok: false, error: e.message });
    throw e;
  }
}

async function timedPhaseAsync(phase, fn, context = {}) {
  const timer = createPhaseTimer(phase, context);
  try {
    const result = await fn();
    timer.end({ ok: true });
    return result;
  } catch (e) {
    timer.end({ ok: false, error: e.message });
    throw e;
  }
}

module.exports = { createPhaseTimer, timedPhase, timedPhaseAsync, yieldToEventLoop };
