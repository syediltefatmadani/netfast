const PREFIX = '[NetFast]';

function stamp() {
  return new Date().toISOString();
}

function log(level, tag, message, detail) {
  const head = `${PREFIX} ${stamp()} [${tag}] ${message}`;
  if (detail !== undefined) {
    console[level](head, detail);
  } else {
    console[level](head);
  }
}

module.exports = {
  info: (tag, message, detail) => log('log', tag, message, detail),
  warn: (tag, message, detail) => log('warn', tag, message, detail),
  error: (tag, message, detail) => log('error', tag, message, detail),
  execError: (tag, message, err) => {
    const detail = {
      message: err.message,
      stderr: err.stderr?.toString?.()?.trim() || undefined,
      stdout: err.stdout?.toString?.()?.trim() || undefined,
      status: err.status,
    };
    if (detail.stderr?.toLowerCase().includes('elevation')) {
      detail.hint = 'Run NetFast as Administrator to change system DNS and tunnel settings.';
    }
    log('error', tag, message, detail);
  },
};
