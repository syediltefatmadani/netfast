Implement a proper “DoH-primary, fallback-secondary” enforcement model in NetFast.

Context:
NetFast is a Windows Electron app that enforces restricted-content blocking using these layers:

Primary:
- CleanBrowsing Family DNS-over-HTTPS / DNS
- DoH endpoint:
  https://doh.cleanbrowsing.org/doh/family-filter/
- CleanBrowsing IPv4:
  185.228.168.168
  185.228.169.168
- CleanBrowsing IPv6:
  2a0d:2a00:1::
  2a0d:2a00:2::

Fallback:
- hosts.js local denylist supplement
- firewall.js known bypass resolver blocking
- browserPolicy.js browser DoH/system DNS enforcement
- IPv6 tunnel disabling
- watchdog/network re-lockdown

Problem:
Some adult domains resolve through CleanBrowsing DNS/DoH but still get blocked by fallback layers. Example:
- nslookup pornhat.com using CleanBrowsing returned real IPs.
- curl to https://pornhat.com failed.
- google.com and microsoft.com worked.

This means:
- CleanBrowsing/DoH is technically reachable and active.
- But CleanBrowsing provider missed the specific domain.
- Fallback blocked access.
- NetFast must not falsely report “DoH blocked” when DoH did not block.
- NetFast should treat DoH as primary, but detect provider misses and fall back locally.

Goal:
Implement a clear layered result model:

{
  domain: string,
  category: "adult" | "proxy" | "vpn" | "safe" | "unknown",

  dohChecked: boolean,
  dohReachable: boolean,
  dohResolved: boolean,
  dohBlocked: boolean,
  dohStatus: number | null,
  dohResponseType: "blocked" | "resolved" | "nxdomain" | "error" | "timeout" | "unknown",

  providerMiss: boolean,

  fallbackChecked: boolean,
  fallbackBlocked: boolean,
  fallbackLayers: string[],

  httpsChecked: boolean,
  httpsReachable: boolean,

  finalBlocked: boolean,
  blockedBy: string[],
  status: "blocked_by_doh" | "blocked_by_fallback" | "allowed" | "error",
  warning: string | null,
  error: string | null
}

Core rule:
- DoH/CleanBrowsing is primary.
- If DoH blocks a restricted domain, final status is blocked_by_doh.
- If DoH resolves a restricted domain but fallback blocks it, final status is blocked_by_fallback and providerMiss = true.
- If DoH resolves a restricted domain and fallback does not block it, final status is allowed but this is a critical failure.
- Do not mark “DoH working” as false just because CleanBrowsing missed a domain.
- Do not mark “domain unblocked” only because DNS resolved.

====================================================
1. Add CleanBrowsing DoH query helper
====================================================

Create or update a helper, for example:

src/electron/dohHealth.js
or
src/electron/dns/dohClient.js

Implement a function:

async function queryCleanBrowsingDoH(domain, type = "A")

It should query:
https://doh.cleanbrowsing.org/doh/family-filter/

Use DNS-over-HTTPS JSON format if supported:

GET https://doh.cleanbrowsing.org/doh/family-filter/?name=<domain>&type=<type>
Accept: application/dns-json

If CleanBrowsing endpoint does not support JSON reliably, use RFC8484 wireformat with application/dns-message.

Return structured result:

{
  ok: boolean,
  reachable: boolean,
  status: number | null,
  domain,
  type,
  answers: [],
  blocked: boolean,
  nxdomain: boolean,
  resolved: boolean,
  error: string | null,
  raw: optional
}

Blocked detection should support:
- NXDOMAIN
- CleanBrowsing block page IPs if known/configured
- empty answer for a known blocked test domain
- provider-specific block response if present

Do not assume every non-200 means unreachable.
Treat HTTP statuses 200, 400, 405, 415 as endpoint reachable.
Only timeout/network failure means unreachable.

====================================================
2. Add known validation domains
====================================================

Add config:

const FILTER_TESTS = {
  safeAllowed: [
    "google.com",
    "microsoft.com"
  ],
  knownAdultBlocked: [
    "pornhub.com",
    "xvideos.com"
  ],
  providerMissCandidates: [
    "pornhat.com",
    "pornhat.one"
  ]
}

Do not rely on only one adult domain.
Do not use facebook.com as an adult-filter test.

Health check should test:
1. CleanBrowsing DoH reachable.
2. Safe domain resolves.
3. Known adult domain is blocked.
4. Provider-miss candidates are checked separately and reported as providerMiss if they resolve.

====================================================
3. Implement domain enforcement evaluator
====================================================

Create function:

async function evaluateDomainProtection(domain, options = {})

Inputs:
{
  domain,
  expectedRestricted: boolean,
  category?: string,
  checkHttps?: boolean,
  applyFallbackOnMiss?: boolean
}

Flow:

1. Query CleanBrowsing DoH for A and AAAA.
2. Determine dohBlocked:
   - blocked if NXDOMAIN/block response/no usable answer for known restricted domain.
   - not blocked if real public IPs are returned.
3. If expectedRestricted && dohBlocked:
   return finalBlocked true, blockedBy ["cleanbrowsing_doh"].
4. If expectedRestricted && !dohBlocked:
   providerMiss = true.
   Then check fallback:
   - hosts supplement has domain?
   - local denylist has domain?
   - firewall/app-level domain rule exists?
   - optional HTTPS reachability test fails?
5. If fallback blocks:
   return finalBlocked true, blockedBy ["hosts" or "firewall" or "https_unreachable"], status "blocked_by_fallback".
6. If fallback does not block:
   if applyFallbackOnMiss is true, add domain to local supplement blocklist and re-test.
   If still not blocked, return critical error.

Important:
Do not auto-add safe/unknown domains to fallback.
Only auto-add domains if:
- expectedRestricted = true
- category is adult/proxy/vpn
- providerMiss = true

====================================================
4. Add provider-miss fallback workflow
====================================================

When CleanBrowsing misses a restricted domain:

Example:
domain = pornhat.com
expectedRestricted = true
DoH returns Cloudflare IPs.

Then:

1. Mark providerMiss = true.
2. Add to local fallback denylist if not already present:
   - pornhat.com
   - www.pornhat.com
   - optionally wildcard support if your hosts/local blocker supports it
3. If hosts file is used, write between existing markers:
   # focuslock-block-begin
   0.0.0.0 pornhat.com
   :: pornhat.com
   0.0.0.0 www.pornhat.com
   :: www.pornhat.com
   # focuslock-block-end

Important:
Windows hosts does not support wildcard domains.
If wildcard is needed, implement local DNS proxy or explicit subdomain list.
Do not pretend hosts supports wildcards.

4. Flush DNS cache once after batch update:
   ipconfig /flushdns

5. Re-test access if checkHttps = true.

Return:

{
  finalBlocked: true,
  blockedBy: ["hosts_supplement"],
  providerMiss: true,
  warning: "CleanBrowsing did not block this restricted domain; local fallback applied."
}

====================================================
5. Update hosts supplement behavior
====================================================

hosts.js should support:

- read existing NetFast block section
- add domains idempotently
- remove stale entries if needed
- batch writes
- no duplicate entries
- flush DNS once after write
- disabled/enabled by config:
  NETFAST_HOSTS_BLOCK=true

Add function:

async function ensureHostsBlockedDomains(domains, reason)

Return:

{
  ok: true/false,
  added: [],
  alreadyPresent: [],
  failed: [],
  path: "C:\\Windows\\System32\\drivers\\etc\\hosts"
}

Do not use hosts fallback for MongoDB Atlas by default.
Keep Mongo hosts fallback separate and disabled:
MONGO_HOSTS_FALLBACK=false

====================================================
6. Fix NetFast status wording
====================================================

Current bad logic:
- DNS resolved = unblocked
- Curl failed = maybe blocked but not attributed
- DoH reachable = filtering fully working

Replace with layered wording:

Examples:

Case A:
DoH blocks:
"Blocked by CleanBrowsing DoH"

Case B:
DoH resolves but fallback blocks:
"Blocked by local fallback — CleanBrowsing provider miss detected"

Case C:
DoH resolves and fallback does not block:
"Not blocked — provider miss and fallback failed"

Case D:
DoH unreachable but system DNS/hosts blocks:
"Protected with warning — DoH health unreachable, fallback active"

Case E:
safe domain works:
"Allowed"

====================================================
7. Update DnsHealthMonitor
====================================================

DnsHealthMonitor should return:

{
  dohReachable: boolean,
  cleanBrowsingPrimaryWorking: boolean,
  safeDomainAllowed: boolean,
  knownAdultBlockedByDoh: boolean,
  providerMisses: [],
  fallbackBlockedMisses: [],
  criticalUnblockedRestrictedDomains: [],
  finalStatus: "healthy" | "healthy_with_provider_misses" | "degraded" | "failed"
}

Rules:
- If DoH endpoint reachable + known adult test blocked + safe domain allowed:
  healthy.
- If DoH endpoint reachable + known adult test blocked + provider miss blocked by fallback:
  healthy_with_provider_misses.
- If DoH endpoint unreachable but fallback still blocks:
  degraded.
- If restricted domain is reachable:
  failed.

Do not trigger full re-lockdown just because CleanBrowsing missed one domain and fallback blocked it.
Do trigger warning/telemetry:
- vector: dns_filtering_provider_miss
- severity: warning
- no challenge termination unless restricted content is actually reachable.

====================================================
8. Update watchdog vectors
====================================================

Add or update vectors:

dns_filtering:
- fails only if primary known adult test is not blocked by DoH AND fallback does not block.

dns_provider_miss:
- warning vector when DoH misses a restricted domain but fallback blocks it.

fallback_blocking:
- confirms local supplement is active.

Do not mark integrity FAILED if finalBlocked = true and only providerMiss = true.
Instead mark:
Protected with warnings.

====================================================
9. Add CLI/debug commands
====================================================

Add a developer/debug IPC or CLI function:

netfast diagnose-domain pornhat.com --restricted adult

Should output:

Domain: pornhat.com
Expected restricted: true
CleanBrowsing DoH reachable: true
DoH resolved: true
DoH blocked: false
Provider miss: true
Hosts fallback present: true/false
HTTPS reachable: true/false
Final blocked: true/false
Blocked by: cleanbrowsing_doh | hosts_supplement | firewall | none
Status: blocked_by_fallback / blocked_by_doh / allowed

Also add:

netfast health-doh

to test:
- DoH endpoint reachable
- safe domain allowed
- known adult domain blocked
- provider misses

====================================================
10. Browser policy correction
====================================================

Clarify browser DoH strategy in code comments and status.

If the app sets Chrome/Edge/Brave Secure DNS mode to "off":
Status should say:
"Browser DoH disabled; browser follows system CleanBrowsing DNS."

If the app sets browser Secure DNS to CleanBrowsing template:
Status should say:
"Browser DoH forced to CleanBrowsing template."

Do not claim browser DoH is forced to CleanBrowsing if the registry actually sets DoH mode to off.

Either strategy is acceptable, but logs/UI must be honest.

====================================================
11. Firewall rules should stay practical
====================================================

Keep current strategy:
- Allow CleanBrowsing resolvers on 53 and 443.
- Block known bypass resolvers on 53, 853, and 443 where applicable.
- Do not restore blanket block-all port 53 rules.
- Do not globally block TCP 443.
- Do not globally allow Cloudflare DNS.

This is important because MongoDB Atlas mongodb+srv requires SRV/TXT DNS and normal internet must continue working.

====================================================
12. MongoDB behavior must remain stable
====================================================

Do not break MongoDB.

Keep:
- MONGO_HOSTS_FALLBACK=false by default.
- Do not write MongoDB Atlas shard IPs to hosts by default.
- Let MongoDB Node driver resolve mongodb+srv normally through Windows DNS/CleanBrowsing.
- NRPT can be attempted, but failure should be warning if MongoDB is connected.

Also fix the existing NRPT cleanup bug if present:
Do not use pipeline ForEach-Object for Remove-DnsClientNrptRule.
Use normal foreach loop.

====================================================
13. Final expected behavior
====================================================

After implementation:

Test 1:
nslookup pornhat.com may still return IPs because nslookup is DNS-only.
This should not be treated as final unblocked.

Test 2:
curl -I https://pornhat.com fails.
NetFast should report:
finalBlocked: true
dohBlocked: false
providerMiss: true
blockedBy: ["hosts_supplement" or "connection_layer"]
status: "blocked_by_fallback"

Test 3:
curl -I https://google.com works.
NetFast should report:
finalBlocked: false
status: "allowed"

Test 4:
Known CleanBrowsing-blocked adult test domain:
DoH should block.
NetFast should report:
finalBlocked: true
blockedBy: ["cleanbrowsing_doh"]
status: "blocked_by_doh"

Test 5:
If DoH endpoint is unreachable:
NetFast should not instantly claim unprotected if fallback blocks still work.
It should report:
Protected with warning / degraded.

Final UI status:
- Protected = DoH primary works and no misses.
- Protected with warnings = DoH works but provider misses were caught by fallback, or optional NRPT/IPv6 local Mongo rule failed.
- Not protected = restricted domain reachable, DNS rogue detected, browser DoH bypass active, or firewall bypass resolver block failed.

Do not modify unrelated UI, auth, database models, package versions, or business logic.
Give me full updated files, not snippets.