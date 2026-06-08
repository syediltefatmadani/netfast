Implement a controlled Developer Mode in NetFast.

Goal:
Allow trusted developer tools and services to work without breaking the main restricted-content enforcement system.

Important:
Do not simply disable NetFast protection.
Do not allow unrestricted internet access.
Do not disable CleanBrowsing DoH.
Do not disable browser DoH policies.
Do not remove bypass DNS resolver blocking globally.

Instead, add a controlled Developer Mode that allows specific developer tools, local services, and required ports/domains while keeping restricted-content blocking active.

====================================================
1. Add policy modes
====================================================

Add a policy mode setting:

NETFAST_POLICY_MODE=strict | developer | testing | repair

Default:
strict

Developer mode:
NETFAST_POLICY_MODE=developer

Strict mode:
- Normal production lockdown.
- No broad developer exceptions.

Developer mode:
- Keep CleanBrowsing DoH/DNS active.
- Keep browser DoH locked to CleanBrowsing.
- Keep known bypass DNS resolvers blocked.
- Allow trusted developer tools and services.

====================================================
2. Developer allowlist
====================================================

Create a developer allowlist config.

Example:

const DEV_ALLOWLIST = {
  processes: [
    "node.exe",
    "npm.cmd",
    "npx.cmd",
    "pnpm.exe",
    "yarn.cmd",
    "bun.exe",
    "git.exe",
    "docker.exe",
    "com.docker.backend.exe",
    "wsl.exe",
    "wslhost.exe",
    "mongod.exe",
    "mongos.exe",
    "redis-server.exe",
    "redis-cli.exe",
    "code.exe",
    "cursor.exe"
  ],

  domains: [
    "github.com",
    "*.github.com",
    "githubusercontent.com",
    "*.githubusercontent.com",
    "registry.npmjs.org",
    "*.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "*.pypi.org",
    "files.pythonhosted.org",
    "docker.io",
    "*.docker.io",
    "registry-1.docker.io",
    "auth.docker.io",
    "production.cloudflare.docker.com",
    "mongodb.com",
    "*.mongodb.com",
    "mongodb.net",
    "*.mongodb.net"
  ],

  ports: [
    22,
    80,
    443,
    3000,
    5173,
    6379,
    7000,
    27017
  ],

  localOnlyPorts: [
    3000,
    5173,
    6379,
    7000,
    27017
  ]
}

Important:
- These are developer-service exceptions only.
- Do not allow these processes to use blocked DNS resolvers directly unless absolutely necessary.
- DNS should still go through CleanBrowsing/local NetFast DNS logic where possible.

====================================================
3. MongoDB Atlas developer exception
====================================================

In developer mode, allow MongoDB Atlas connectivity.

Requirements:
1. Allow outbound TCP 27017 for trusted Node processes only.
2. Allow outbound TCP 443 for trusted Node processes.
3. Keep SRV/TXT DNS resolution working.
4. Do not write MongoDB Atlas shard IPs to hosts by default.
5. Keep MONGO_HOSTS_FALLBACK=false by default.
6. NRPT can be applied, but if NRPT fails and MongoDB connects, treat it as warning only.

Add Mongo diagnostic:

{
  srvLookupOk: boolean,
  txtLookupOk: boolean,
  shardLookupOk: boolean,
  tcp27017Reachable: boolean,
  atlasConnectionLikely: boolean,
  error: string | null
}

If Mongo fails, classify clearly:
- DNS SRV failed
- TXT failed
- TCP 27017 failed
- Atlas IP whitelist likely issue
- firewall blocked
- unknown

====================================================
4. Docker / WSL developer handling
====================================================

In developer mode, detect Docker and WSL.

Detect:
- Docker Desktop running
- WSL installed/running
- Docker virtual adapters
- WSL resolv.conf DNS

Add diagnostics:

dockerDnsOk
dockerInternetOk
dockerRestrictedBlocked
wslDnsOk
wslInternetOk
wslRestrictedBlocked

Run optional tests:
docker run --rm alpine nslookup google.com
docker run --rm alpine nslookup pornhub.com
docker run --rm curlimages/curl -I https://google.com

WSL:
wsl cat /etc/resolv.conf
wsl nslookup google.com
wsl nslookup pornhub.com

Developer mode should allow Docker to work, but report if Docker/WSL is not protected.

Status examples:
- Windows protected: true
- Browser protected: true
- Docker protected: unknown / false / true
- WSL protected: unknown / false / true

Do not silently claim Docker is protected unless validated.

====================================================
5. Localhost handling
====================================================

In developer mode, allow localhost development.

Allow:
- 127.0.0.1
- localhost
- ::1 only if Windows firewall supports it cleanly

For local dev services, prefer IPv4 localhost:

127.0.0.1

If netsh rejects ::1 firewall rule:
- skip it
- log warning only
- do not mark lockdown failed

Local ports to allow:
- 3000
- 5173
- 6379
- 7000
- 27017

But only for localhost/local subnet where possible.

====================================================
6. Firewall behavior in developer mode
====================================================

Keep these protections:
- Allow CleanBrowsing DoH TCP 443.
- Block known bypass DNS resolvers on 53, 853, and 443.
- Do not globally block TCP 443.
- Do not globally block all DNS port 53.
- Do not globally allow Cloudflare/Google DNS.

Add developer firewall allow rules only for trusted processes and ports.

Example rule names:
NetFast-Dev-Allow-node-Mongo-27017-HASH
NetFast-Dev-Allow-node-HTTPS-443-HASH
NetFast-Dev-Allow-docker-HTTPS-443-HASH
NetFast-Dev-Allow-git-HTTPS-443-HASH
NetFast-Dev-Allow-localhost-Redis-6379
NetFast-Dev-Allow-localhost-Vite-5173

All developer allow rules must be:
category: "developer"
optional: true
non-fatal if failed unless the user is in Developer Mode and the specific service is required.

====================================================
7. Restricted content must still be blocked
====================================================

Developer Mode must not allow restricted sites.

Even in Developer Mode:
- CleanBrowsing DoH remains primary.
- Hosts fallback remains active if NETFAST_HOSTS_BLOCK=true.
- Known bypass DNS resolvers remain blocked.
- Adult/proxy/VPN test domains must remain blocked.
- Browser DoH must stay locked.

Developer Mode is not Disable Mode.

Add validation:
- google.com allowed
- microsoft.com allowed
- known adult test domain blocked
- known bypass resolvers blocked
- developer services reachable

====================================================
8. UI/status model
====================================================

Add visible mode status:

Current Mode:
- Strict
- Developer
- Testing
- Repair

Developer Mode status should show:

Protected with developer exceptions

Example result:

{
  mode: "developer",
  protectionStatus: "Protected with developer exceptions",
  dnsApplied: true,
  dohConfigured: true,
  browserDohLocked: true,
  firewallCoreLocked: true,
  bypassResolversBlocked: true,
  developerExceptionsApplied: true,
  dockerProtected: "unknown",
  wslProtected: "unknown",
  warnings: [
    "Developer mode allows trusted dev tools.",
    "Docker/WSL protection not verified."
  ],
  errors: []
}

====================================================
9. Safety requirements
====================================================

Add clear warnings in logs/UI:

Developer Mode reduces strictness for trusted tools only.
Do not ship Developer Mode enabled by default.
Do not enable Developer Mode for normal users.
Do not allow arbitrary process bypass.
Do not allow arbitrary domain bypass.
Do not bypass restricted-content enforcement.

Require one of:
- env flag NETFAST_POLICY_MODE=developer
- signed local dev config
- admin-only toggle

Do not let normal users toggle Developer Mode casually.

====================================================
10. Cleanup behavior
====================================================

On switching from developer to strict:
- Remove all NetFast-Dev-* firewall rules.
- Remove developer-only exceptions.
- Re-run strict lockdown.
- Revalidate restricted content blocking.

On startup:
- If strict mode, remove stale developer rules.
- If developer mode, refresh developer rules.

====================================================
11. Logging
====================================================

Log clearly:

[POLICY] Mode: developer
[DEV_MODE] Developer exceptions enabled
[DEV_MODE] MongoDB Atlas allowed for Node
[DEV_MODE] Docker detected
[DEV_MODE] WSL detected
[DEV_MODE] Localhost dev ports allowed
[DEV_MODE] Restricted content validation passed
[DEV_MODE] Developer exception failed: <reason>

Do not hide developer exceptions under normal firewall logs.

====================================================
12. Expected result
====================================================

In Developer Mode:

Should work:
- npm install
- git pull/push
- Vite localhost:5173
- Express localhost:3000
- Redis 127.0.0.1:6379
- MongoDB Atlas mongodb+srv
- Docker pull/run, if Docker DNS is compatible
- Cursor/VS Code dev servers

Should still be blocked:
- adult sites
- proxy/VPN bypass domains
- direct use of 1.1.1.1 / 8.8.8.8 as DNS
- browser switching to Google/Cloudflare DoH

Final expected status:
Protected with developer exceptions

Do not change unrelated UI, auth, database models, package versions, or business logic.
Give me full updated files, not snippets.