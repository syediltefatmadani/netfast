Fix the remaining NetFast lockdown issues from my latest logs.

Context:
The app is mostly working now:
- MongoDB connects.
- FocusLock server starts on port 7000.
- Vite starts.
- Electron starts.
- CleanBrowsing IPv4 DNS applies successfully.
- CleanBrowsing IPv6 DNS applies successfully.
- DNS lock reports successful.
- Hosts fallback is disabled, which is correct.
- Firewall strategy has changed to CleanBrowsing allow + known bypass DNS resolver blocking, which is correct.

Remaining problems to fix:

====================================================
ISSUE 1: NRPT MongoDB PowerShell cleanup is still broken
====================================================

Current log error:
[MONGO_DNS] NRPT apply failed — PowerShell parameter or syntax error.

Exact PowerShell error:
ForEach-Object : A parameter cannot be found that matches parameter name 'Namespace'.

Cause:
The current script is still using a pipeline with ForEach-Object to remove old NRPT rules. PowerShell is parsing `-Namespace` wrongly and treating it like a parameter of ForEach-Object instead of Remove-DnsClientNrptRule.

Bad pattern:
Get-DnsClientNrptRule ... | Where-Object { ... } | ForEach-Object {
  Remove-DnsClientNrptRule -Namespace $_.Namespace -Force
}

Fix:
Do not use pipeline ForEach-Object for NRPT cleanup.
Store old rules in a variable and use a normal foreach loop.

Replace the NRPT cleanup/apply script with this safer version:

$ErrorActionPreference = 'Stop'
$prefix = 'NetFast-Mongo-'

$oldRules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
  ($_.DisplayName -like "$prefix*") -or ($_.Comment -like "$prefix*")
}

foreach ($rule in $oldRules) {
  if ($rule.Namespace) {
    Remove-DnsClientNrptRule -Namespace $rule.Namespace -Force
  }
}

$namespaces = @('.mongodb.net', '.mongodb.com')
$servers = @('185.228.168.168', '185.228.169.168')
$i = 0
$added = @()

foreach ($ns in $namespaces) {
  $i++
  $label = "$prefix$i"

  Add-DnsClientNrptRule `
    -Namespace $ns `
    -NameServers $servers `
    -Comment $label

  $added += @{
    namespace = $ns
    comment = $label
    servers = $servers
  }
}

@{
  ok = $true
  rules = $added
} | ConvertTo-Json -Compress

Requirements:
1. Do not use `-Name` with Add-DnsClientNrptRule.
2. Do not use pipeline ForEach-Object for Remove-DnsClientNrptRule.
3. Use UTF-16LE encoding when passing script to `powershell -EncodedCommand`.
4. In development mode, log the decoded PowerShell script before executing it.
5. If NRPT fails, classify it correctly:
   - PowerShell syntax/parameter error
   - elevation/admin error
   - cmdlet unavailable
   - unknown error
6. Do not falsely log this as “run as Administrator” unless the error actually says elevation/admin is required.
7. NRPT failure should be a warning, not fatal, if MongoDB is already connecting.

====================================================
ISSUE 2: Optional IPv6 Mongo local firewall rule fails
====================================================

Current failing command:
netsh advfirewall firewall add rule name="NetFast-Exempt-node-Mongo-local-v6-..." dir=out action=allow enable=yes protocol=TCP remoteip=::1/128 remoteport=27017 program="..."

Error:
A specified IP address or address keyword is not valid.

Cause:
Windows netsh is rejecting `remoteip=::1/128`.

Fix:
When creating optional Mongo local IPv6 loopback exemption, try this first:

remoteip=::1

Instead of:

remoteip=::1/128

If `remoteip=::1` also fails:
- Skip this optional rule.
- Log:
  "Mongo local IPv6 firewall exemption skipped; optional only."
- Do not mark firewallCoreLocked false.
- Do not mark firewallLocked false.
- Add it only to failedOptionalRules or warnings.

Important:
The IPv4 local Mongo rule using `remoteip=127.0.0.0/8` already works. Keep it.

====================================================
ISSUE 3: Final status should not fail because of optional rules
====================================================

Make sure final lockdown status uses this logic:

firewallCoreLocked = CleanBrowsing allow rules applied successfully
bypassResolversBlocked = known bypass resolver block rules applied successfully
firewallLocked = firewallCoreLocked && bypassResolversBlocked

Optional Mongo/Node exemptions must not make firewallLocked false.

If only optional rules fail:
Status should be:
"Protected with warnings"

Not:
"Not protected"

Final result object should include:

{
  dnsApplied: boolean,
  ipv4Locked: boolean,
  ipv6Locked: boolean,
  dnsIntegrity: boolean,
  dohConfigured: boolean,

  firewallCoreLocked: boolean,
  bypassResolversBlocked: boolean,
  firewallLocked: boolean,

  nrptApplied: boolean,
  nrptError: string | null,

  failedCoreRules: [],
  failedBypassRules: [],
  failedOptionalRules: [],
  warnings: [],
  errors: [],

  status: "Protected" | "Protected with warnings" | "Not protected"
}

====================================================
ISSUE 4: Keep the current correct behavior
====================================================

Do not reintroduce old problems.

Keep these behaviors:
1. CleanBrowsing IPv4 DNS:
   - 185.228.168.168
   - 185.228.169.168

2. CleanBrowsing IPv6 DNS:
   - 2a0d:2a00:1::
   - 2a0d:2a00:2::

3. Do not revert IPv6 to DHCP.

4. Do not recreate global block-all DNS rules:
   - NetFast-DNS-Block-UDP-53-Other
   - NetFast-DNS-Block-TCP-53-Other

5. Keep known bypass DNS resolver blocking.

6. Do not globally allow Cloudflare DNS.

7. Keep MongoDB Atlas hosts fallback disabled by default:
   MONGO_HOSTS_FALLBACK=false

8. Do not write MongoDB Atlas shard IPs into hosts by default.

9. Let MongoDB driver resolve mongodb+srv normally through Windows DNS/CleanBrowsing.

====================================================
Validation expected after fix
====================================================

After running `npm run dev`, I should see:

1. MongoDB connected.
2. FocusLock server running on port 7000.
3. NRPT rules applied OR clean warning without crash.
4. DNS lock applied successfully.
5. ipv4Locked: true.
6. ipv6Locked: true.
7. firewallCoreLocked: true.
8. bypassResolversBlocked: true.
9. firewallLocked: true.
10. No global block-all DNS rules.
11. No fatal failure from optional IPv6 Mongo local firewall rule.
12. Final status:
   Protected
   or
   Protected with warnings

Do not modify unrelated UI, architecture, package versions, database models, authentication, or business logic.

Give me the full updated files, not snippets.