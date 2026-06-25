const path = require('path');
const { SERVICE_NAME } = require('./config/serviceConfig');

/**
 * Builds the node-windows Service descriptor shared by install/uninstall/control
 * scripts. Keeping it in one place guarantees every script targets the exact
 * same Windows service (same name + script path), which is how node-windows
 * locates an already-installed service.
 *
 * NOTE: node-windows install/uninstall require an elevated (Administrator)
 * terminal. The service is installed as a normal, fully visible Windows service
 * (start type Automatic) — no stealth, no anti-uninstall, no persistence tricks.
 */
function buildService() {
  // Lazy-require so non-Windows dev machines can at least load other modules.
  const { Service } = require('node-windows');

  return new Service({
    name: SERVICE_NAME,
    description:
      'NetFast background monitoring engine — transparent DNS/VPN/hosts protection monitoring and accountability heartbeats. Manageable like any normal Windows service.',
    script: path.join(__dirname, 'index.js'),
    // Start automatically on boot; restart with backoff on crash (NOT an
    // infinite aggressive respawn — node-windows caps retries).
    wait: 2,
    grow: 0.5,
    maxRestarts: 5,
    env: [
      { name: 'NODE_ENV', value: process.env.NODE_ENV || 'production' },
      ...(process.env.NETFAST_API_URL
        ? [{ name: 'NETFAST_API_URL', value: process.env.NETFAST_API_URL }]
        : []),
    ],
  });
}

module.exports = { buildService, SERVICE_NAME };
