You are working on my Windows desktop enforcement app for DNS-based challenge/block mode.

Goal:
Make DNS enforcement reliable across all networks including Airtel home Wi-Fi, Jio hotspot, office Wi-Fi, Ethernet, and VPN/TAP adapters.

Important background:
The enforcement works fine on some networks, but on Airtel/home network the system has active IPv6, and DNS behavior becomes inconsistent. We tested with:

Resolve-DnsName reddit.com
Resolve-DnsName pornhat.one
Get-DnsClientServerAddress
curl.exe -I https://reddit.com

Windows effective resolver returned:
A     0.0.0.0
AAAA  ::

So Resolve-DnsName/curl are the real validation tools. Do not rely only on nslookup because nslookup can directly query a DNS server and give misleading results.

Main requirement:
Use both IPv4 and IPv6 DNS enforcement as the primary method.
If IPv6 DNS enforcement fails, times out, leaks, or returns real IPs for blocked domains, then fallback to strict mode by temporarily disabling IPv6 on active adapters.

Do not build IPv4-only enforcement. IPv4-only is not reliable on Airtel-style IPv6 networks.

CleanBrowsing DNS values:

IPv4:
185.228.168.168
185.228.169.168

IPv6:
2a0d:2a00:1::
2a0d:2a00:2::

Core implementation requirements:

1. Apply DNS enforcement to all active adapters.

Find all active adapters using PowerShell or Windows networking APIs.

Include:
- Wi-Fi
- Ethernet
- TAP-Windows Adapter
- Wintun
- WireGuard
- OpenVPN
- Tailscale
- ZeroTier
- Cloudflare WARP
- VPN virtual adapters
- Any adapter with Status = Up

Exclude:
- Loopback
- Disconnected adapters
- Bluetooth PAN unless it is active and has internet

Do not hardcode only "Wi-Fi".

2. Save original settings before enforcement.

Before making changes, store per adapter:
- InterfaceAlias
- InterfaceDescription
- IPv4 DNS servers
- IPv6 DNS servers
- IPv6 binding enabled/disabled state
- InterfaceMetric if modified
- Timestamp

Save this in a local state file so settings can be restored later.

Example state file:
enforcement-network-backup.json

3. Apply IPv4 DNS to every active adapter.

PowerShell equivalent:

Set-DnsClientServerAddress `
  -InterfaceAlias "<adapter>" `
  -AddressFamily IPv4 `
  -ServerAddresses ("185.228.168.168","185.228.169.168")

4. Apply IPv6 DNS to every active adapter.

PowerShell equivalent:

Set-DnsClientServerAddress `
  -InterfaceAlias "<adapter>" `
  -AddressFamily IPv6 `
  -ServerAddresses ("2a0d:2a00:1::","2a0d:2a00:2::")

5. Remove public DNS from all adapters.

During enforcement, no active adapter should keep:

8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
208.67.222.222
208.67.220.220

Overwrite them with CleanBrowsing DNS.

6. Flush DNS after every enforcement action.

Run:

ipconfig /flushdns

Also clear Windows DNS cache using available Windows APIs if possible.

7. Verify enforcement using Windows resolver.

After applying DNS, run checks equivalent to:

Resolve-DnsName reddit.com
Resolve-DnsName pornhat.one
curl.exe -I https://reddit.com
curl.exe -I https://pornhat.one

Expected blocked result:
- A record returns 0.0.0.0 or fails to resolve
- AAAA record returns :: or fails to resolve
- curl fails to resolve or fails to connect

Do not treat nslookup as final proof.

8. IPv6 fallback logic.

Primary mode:
- Apply IPv4 CleanBrowsing DNS
- Apply IPv6 CleanBrowsing DNS
- Flush DNS
- Verify with Resolve-DnsName and curl

If IPv6 check fails because:
- IPv6 DNS times out
- blocked domain returns real AAAA records
- curl/Chrome behavior differs from Resolve-DnsName
- adapter ignores IPv6 DNS
- VPN adapter adds its own IPv6 DNS
- enforcement cannot verify cleanly

Then switch to strict fallback mode:
- Disable IPv6 binding temporarily on all active adapters
- Keep IPv4 CleanBrowsing DNS enforced
- Flush DNS
- Verify again

PowerShell equivalent:

Disable-NetAdapterBinding `
  -Name "<adapter>" `
  -ComponentID ms_tcpip6 `
  -Confirm:$false

Important:
Only disable IPv6 during active challenge/enforcement mode.
Restore IPv6 exactly to its previous state after challenge ends.

9. Restore logic.

When challenge ends, enforcement is removed, or app exits cleanly:
- Restore original IPv4 DNS
- Restore original IPv6 DNS
- Re-enable IPv6 only on adapters where it was enabled before enforcement
- Do not enable IPv6 on adapters where it was originally disabled
- Flush DNS again
- Log restore success/failure

10. Monitor network changes continuously.

Reapply enforcement when:
- Wi-Fi network changes
- Adapter becomes active
- Adapter is added
- VPN adapter appears
- DNS server changes
- System wakes from sleep
- Internet reconnects
- IP address changes
- User manually changes DNS

On every such event:
- Detect active adapters again
- Save new adapter original settings if not already saved
- Reapply IPv4 + IPv6 DNS
- Run verification
- If IPv6 fails, use strict fallback mode

11. VPN detection.

Detect VPN-like adapters using name/description keywords:

vpn
tap
tun
wintun
wireguard
openvpn
nord
proton
express
surfshark
tailscale
zerotier
warp
cloudflare
private internet access
windscribe
mullvad
turbo

If VPN adapter appears:
- Mark it as a VPN attempt
- Apply DNS enforcement to the VPN adapter too
- Do not ignore it just because blocking still works
- Show warning to user according to existing app logic
- If this is second VPN attempt, fail the challenge according to existing challenge rules

12. Browser Secure DNS / DoH handling.

Check and log whether system/browser may be using DNS-over-HTTPS.

The app should detect common DoH bypass risks:
- Chrome Secure DNS enabled
- Edge Secure DNS enabled
- Firefox DNS over HTTPS enabled if detectable
- Windows encrypted DNS templates if present

Do not break unrelated browser settings unless this is already part of enforcement policy, but log it clearly and warn/restrict if needed.

13. Logging.

Add detailed enforcement logs:

Before enforcement:
- Active adapters
- IPv4 DNS per adapter
- IPv6 DNS per adapter
- IPv6 enabled/disabled state
- VPN adapters detected

After enforcement:
- DNS per adapter
- IPv6 status
- DNS flush result
- Resolve-DnsName result
- curl result
- Enforcement success/failure reason

Logs should make it obvious why Airtel, Jio, office Wi-Fi, VPN, or hotspot behaves differently.

14. Validation commands.

After implementation, these commands should show clean enforcement:

Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses

Resolve-DnsName reddit.com
Resolve-DnsName pornhat.one

curl.exe -I https://reddit.com
curl.exe -I https://pornhat.one

Expected for blocked domains:
A = 0.0.0.0 or resolution failure
AAAA = :: or resolution failure
curl = could not resolve host or blocked connection

15. Do not make unrelated changes.

Do not change:
- UI except required warning/error messages
- Payment logic
- Challenge subscription rules
- Database schema
- Auth
- Existing backend APIs
- Unrelated Electron app structure

Only modify network enforcement, restore, verification, VPN detection, and logging.

16. Safety requirement.

Never leave the user's network broken.

If enforcement fails halfway:
- Attempt rollback using saved backup
- Show clear error
- Log failed adapter and failed command
- Do not silently leave DNS half-changed

Final expected behavior:
The app should enforce CleanBrowsing on IPv4 and IPv6 across all active adapters. On networks where IPv6 behaves badly, like Airtel home network, it should automatically fallback to disabling IPv6 during challenge mode and restore it later. Enforcement should survive VPN adapters, network changes, sleep/resume, and manual DNS changes.