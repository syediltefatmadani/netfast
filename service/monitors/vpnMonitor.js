const { runPowerShell, cached, parseJsonList } = require('../util/commandRunner');
const { INTERVALS } = require('../config/serviceConfig');

/**
 * VPN monitor — DETECT AND REPORT ONLY. Per the product boundary the service
 * never kills VPN processes or blocks VPN apps; it only enumerates active
 * tunnel-like network adapters and surfaces them as accountability signals.
 *
 * The keyword set mirrors electron/vpnDetect.js so detection stays consistent
 * across the desktop app and the service. (Duplicated rather than imported
 * because that module pulls in the enforcement-gated PowerShell helper, which
 * would return mock data in the service — see util/commandRunner.js.)
 */

const VPN_KEYWORDS =
  /vpn|tap|tun|wintun|wireguard|openvpn|nord|proton|express|surfshark|tailscale|zerotier|warp|cloudflare|private internet access|windscribe|mullvad|softether|ikev2|anyconnect|hotspot|outline|wg_/i;

const TUNNEL_DESCRIPTION =
  /TAP-Windows|\bTAP\b|Wintun|WireGuard|OpenVPN|NordLynx|IKEv2|SoftEther|Tunnel|ExpressVPN|Proton|Surfshark|Hotspot|Cisco AnyConnect|ZeroTier|Tailscale|Cloudflare WARP|Outline|wg_/i;

const LIST_ADAPTERS_SCRIPT = `
$rows = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    name = $_.Name
    description = $_.InterfaceDescription
    status = $_.Status
    connected = ($_.Status -eq 'Up')
  }
}
$rows | ConvertTo-Json -Compress
`;

function isVpnLikeAdapter(name, description) {
  const combined = `${name || ''} ${description || ''}`;
  return VPN_KEYWORDS.test(combined) || TUNNEL_DESCRIPTION.test(description || '');
}

async function listAdapters() {
  return cached('vpn:adapters', INTERVALS.vpnDetectionMs - 1000, async () => {
    const out = await runPowerShell(LIST_ADAPTERS_SCRIPT, { timeoutMs: 10000 });
    return parseJsonList(out);
  });
}

async function check() {
  const lastCheckedAt = new Date().toISOString();
  let adapters = [];
  try {
    adapters = await listAdapters();
  } catch {
    adapters = [];
  }

  const connected = adapters.filter((a) => a && a.connected);
  const tunnels = connected.filter((a) => isVpnLikeAdapter(a.name, a.description));

  return {
    vpnDetected: tunnels.length > 0,
    detectedVpnNames: tunnels.map((a) => a.description || a.name).filter(Boolean),
    networkInterfaces: connected.map((a) => a.name).filter(Boolean),
    lastCheckedAt,
  };
}

module.exports = { check, isVpnLikeAdapter, name: 'vpn' };
