You are working on my Windows desktop enforcement app for DNS-based challenge/block mode.

Goal:
Harden DNS enforcement so users cannot bypass blocking using direct raw DNS tools like nslookup, Resolve-DnsName -Server, custom DNS clients, or DNS-over-TLS.

Current finding:
Normal Windows resolver blocking works:

Resolve-DnsName reddit.com
Resolve-DnsName pornhat.one

returns:
A     0.0.0.0
AAAA  ::

curl also fails:
curl.exe -I https://reddit.com
curl: (6) Could not resolve host

But direct DNS queries still bypass:

Resolve-DnsName reddit.com -Server 2a0d:2a00:1::

returns real IPs.

This means Windows resolver enforcement is working, but raw DNS bypass is still possible.

Main task:
Implement firewall hardening during active challenge/enforcement mode.

Requirements:

1. Keep existing DNS enforcement.

Continue enforcing CleanBrowsing DNS on all active adapters:

IPv4:
185.228.168.168
185.228.169.168

IPv6:
2a0d:2a00:1::
2a0d:2a00:2::

Apply to all active adapters:
- Wi-Fi
- Ethernet
- VPN/TAP
- Wintun
- WireGuard
- OpenVPN
- Tailscale
- ZeroTier
- WARP
- any adapter with Status = Up

2. Add Windows Firewall rules to block raw DNS bypass.

During challenge mode, create outbound firewall rules:

Block UDP 53
Block TCP 53
Block TCP 853
Block UDP 853

Rule names must be unique and easy to remove:

NetFast Block Direct DNS UDP 53
NetFast Block Direct DNS TCP 53
NetFast Block DNS-over-TLS TCP 853
NetFast Block DNS-over-QUIC UDP 853

PowerShell equivalent:

New-NetFirewallRule `
  -DisplayName "NetFast Block Direct DNS UDP 53" `
  -Direction Outbound `
  -Action Block `
  -Protocol UDP `
  -RemotePort 53

New-NetFirewallRule `
  -DisplayName "NetFast Block Direct DNS TCP 53" `
  -Direction Outbound `
  -Action Block `
  -Protocol TCP `
  -RemotePort 53

New-NetFirewallRule `
  -DisplayName "NetFast Block DNS-over-TLS TCP 853" `
  -Direction Outbound `
  -Action Block `
  -Protocol TCP `
  -RemotePort 853

New-NetFirewallRule `
  -DisplayName "NetFast Block DNS-over-QUIC UDP 853" `
  -Direction Outbound `
  -Action Block `
  -Protocol UDP `
  -RemotePort 853

3. Make firewall rules idempotent.

Before creating a rule, check whether it already exists.

Do not create duplicate rules every time enforcement re-runs.

Example logic:
- If rule exists, leave it enabled.
- If rule exists but disabled, enable it.
- If rule does not exist, create it.

4. Do not block HTTPS/443 globally.

Important:
Do not block TCP 443 globally because CleanBrowsing DoH uses:

https://doh.cleanbrowsing.org/doh/family-filter/

Blocking all 443 would break normal internet.

Only block:
- raw DNS port 53
- DNS-over-TLS/QUIC port 853

5. Keep CleanBrowsing DoH working.

Windows currently has CleanBrowsing DoH templates:

185.228.168.168
185.228.169.168
2a0d:2a00:1::
2a0d:2a00:2::

Do not remove these DoH settings unless intentionally restoring network settings after challenge ends.

6. Verification after applying firewall rules.

After enabling DNS + firewall enforcement, run checks equivalent to:

ipconfig /flushdns

Resolve-DnsName reddit.com
Resolve-DnsName pornhat.one

curl.exe -I https://reddit.com
curl.exe -I https://pornhat.one

nslookup reddit.com
Resolve-DnsName reddit.com -Server 2a0d:2a00:1::
Resolve-DnsName reddit.com -Server 8.8.8.8

Expected:
- Resolve-DnsName should return 0.0.0.0 / ::
- curl should fail to resolve blocked domains
- nslookup/direct server queries should timeout or fail
- normal safe sites like google.com should still work

Also test:

Resolve-DnsName google.com
curl.exe -I https://google.com

Expected:
google.com resolves and curl returns an HTTP response.

7. Remove firewall rules when challenge ends.

When enforcement is removed, challenge ends, challenge fails, or restore is triggered, remove only our own rules:

Remove-NetFirewallRule -DisplayName "NetFast Block Direct DNS UDP 53"
Remove-NetFirewallRule -DisplayName "NetFast Block Direct DNS TCP 53"
Remove-NetFirewallRule -DisplayName "NetFast Block DNS-over-TLS TCP 853"
Remove-NetFirewallRule -DisplayName "NetFast Block DNS-over-QUIC UDP 853"

Do not remove unrelated firewall rules.

8. Add rollback safety.

If firewall rule creation fails midway:
- Log the error
- Attempt to remove any partially created NetFast rules
- Do not silently leave the system half-configured
- Show clear error to user/admin

9. Admin privilege handling.

Firewall and DNS changes require administrator privileges.

If the app is not running as admin:
- Show a clear message
- Request elevation
- Do not pretend enforcement is active

10. VPN handling.

If VPN adapter appears:
- Count it as VPN attempt
- Reapply DNS enforcement
- Ensure firewall rules remain active
- Do not ignore VPN just because the blocked sites still fail
- Keep existing business rule: first VPN attempt warning, second VPN attempt fails challenge

11. Network-change handling.

Whenever any of these occur:
- adapter added
- adapter removed
- adapter status changed
- VPN connected
- Wi-Fi changed
- DNS changed manually
- system wakes from sleep

Re-run:
- adapter DNS enforcement
- firewall rule verification
- DNS flush
- enforcement verification

12. Logging.

Add logs for:

Before enforcement:
- active adapters
- DNS per adapter
- IPv6 status
- existing firewall rules

After enforcement:
- DNS per adapter
- firewall rules enabled
- Resolve-DnsName result
- curl result
- nslookup/direct DNS result
- success/failure

13. Do not make unrelated changes.

Do not change:
- UI except required status/error messages
- payment logic
- database schema
- challenge subscription rules
- auth
- unrelated Electron app structure

Only modify:
- DNS enforcement
- firewall hardening
- VPN detection integration
- verification
- restore/rollback
- logging

Final expected behavior:
During challenge mode, normal browser/app DNS should be blocked for restricted domains, and direct DNS bypass using nslookup or Resolve-DnsName -Server should fail because outbound raw DNS and DoT/DoQ ports are blocked. Safe sites should continue working normally through the approved CleanBrowsing/Windows resolver path.