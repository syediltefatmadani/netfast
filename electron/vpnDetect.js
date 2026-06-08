const logger = require('./logger');
const { runEncoded } = require('./powershell');

/** VPN/tunnel keywords — match name or description (case-insensitive). */
const VPN_KEYWORDS =
  /vpn|tap|tun|wintun|wireguard|openvpn|nord|proton|express|surfshark|tailscale|zerotier|warp|cloudflare|private internet access|windscribe|mullvad|turbo|softether|ikev2|anyconnect|hotspot|pangolin|outline|wg_/i;

const TUNNEL_DESCRIPTION =
  /TAP-Windows|\bTAP\b|Wintun|WireGuard|OpenVPN|NordLynx|IKEv2|SoftEther|Tunnel|ExpressVPN|Proton|Surfshark|Hotspot|Cisco AnyConnect|ZeroTier|Tailscale|Cloudflare WARP|Pangolin|Outline|wg_/i;

function isVpnLikeAdapter(name, description) {
  const combined = `${name || ''} ${description || ''}`;
  return VPN_KEYWORDS.test(combined) || TUNNEL_DESCRIPTION.test(description || '');
}

function isTunnelDescription(description) {
  return TUNNEL_DESCRIPTION.test(description || '') || VPN_KEYWORDS.test(description || '');
}

function listAdapters() {
  try {
    const out = runEncoded(`
$rows = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    name = $_.Name
    description = $_.InterfaceDescription
    status = $_.Status
    connected = ($_.Status -eq 'Up')
  }
}
$rows | ConvertTo-Json -Compress
`);
    const parsed = JSON.parse(out.trim() || '[]');
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    logger.warn('VPN', 'Adapter enumeration failed', e.message);
    return [];
  }
}

/** Adapters that look like VPN/tunnel endpoints and are currently up. */
function getActiveTunnelAdapters() {
  return listAdapters()
    .filter((a) => a.connected && isVpnLikeAdapter(a.name, a.description))
    .map((a) => ({
      name: a.name,
      description: a.description,
      kind: 'tunnel',
    }));
}

/**
 * unknown_vpn vector: active VPN/tunnel interface present.
 * Exemption windows (challenge.vpnExemption) are not wired in the desktop app yet.
 */
function checkUnknownVpn() {
  const adapters = getActiveTunnelAdapters();
  const violated = adapters.length > 0;
  return { violated, adapters };
}

module.exports = {
  VPN_KEYWORDS,
  isVpnLikeAdapter,
  isTunnelDescription,
  listAdapters,
  getActiveTunnelAdapters,
  checkUnknownVpn,
};
