const logger = require('./logger');
const { runEncoded, runEncodedAsync } = require('./powershell');

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

function parseAdapters(out) {
  const parsed = JSON.parse(out.trim() || '[]');
  return Array.isArray(parsed) ? parsed : [parsed];
}

function tunnelAdaptersFrom(adapters) {
  return adapters
    .filter((a) => a.connected && isVpnLikeAdapter(a.name, a.description))
    .map((a) => ({ name: a.name, description: a.description, kind: 'tunnel' }));
}

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
    return parseAdapters(runEncoded(LIST_ADAPTERS_SCRIPT));
  } catch (e) {
    logger.warn('VPN', 'Adapter enumeration failed', e.message);
    return [];
  }
}

async function listAdaptersAsync() {
  try {
    return parseAdapters(await runEncodedAsync(LIST_ADAPTERS_SCRIPT));
  } catch (e) {
    logger.warn('VPN', 'Adapter enumeration failed', e.message);
    return [];
  }
}

/** Adapters that look like VPN/tunnel endpoints and are currently up. */
function getActiveTunnelAdapters() {
  return tunnelAdaptersFrom(listAdapters());
}

async function getActiveTunnelAdaptersAsync() {
  return tunnelAdaptersFrom(await listAdaptersAsync());
}

/**
 * unknown_vpn vector: active VPN/tunnel interface present.
 * Exemption windows (challenge.vpnExemption) are not wired in the desktop app yet.
 */
function checkUnknownVpn() {
  const adapters = getActiveTunnelAdapters();
  return { violated: adapters.length > 0, adapters };
}

async function checkUnknownVpnAsync() {
  const adapters = await getActiveTunnelAdaptersAsync();
  return { violated: adapters.length > 0, adapters };
}

module.exports = {
  VPN_KEYWORDS,
  isVpnLikeAdapter,
  isTunnelDescription,
  listAdapters,
  listAdaptersAsync,
  getActiveTunnelAdapters,
  getActiveTunnelAdaptersAsync,
  checkUnknownVpn,
  checkUnknownVpnAsync,
};
