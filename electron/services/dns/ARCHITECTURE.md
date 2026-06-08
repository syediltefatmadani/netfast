# DNS Hardening Architecture



## Source of truth



**CleanBrowsing Family DoH** is authoritative for whether a domain is blocked **by the provider** — not `ipconfig`, `nslookup`, or `Get-DnsClientServerAddress`.



- Wire: `https://doh.cleanbrowsing.org/doh/family-filter/dns-query`

- JSON: `https://doh.cleanbrowsing.org/doh/family-filter?name=<domain>&type=A`

- Policy probes: see `filterTests.js` (`knownAdultBlocked`, `providerMissCandidates`, `safeAllowed`)



## Layered result model



`evaluateDomainProtection()` in `domainProtection.js` returns per-domain:



- **Primary:** `dohBlocked` / `blocked_by_doh` when CleanBrowsing blocks.

- **Provider miss:** DoH resolves a restricted domain → `providerMiss: true`.

- **Fallback:** hosts supplement, system resolver sinkholes, optional HTTPS probe → `blocked_by_fallback`.

- **Failure:** restricted domain still reachable → `criticalUnblockedRestrictedDomains` / `FAILED`.



`nslookup` may show IPs while the site is still blocked via hosts/HTTPS — that is not “unblocked.”



## Components



| Module | Role |

|--------|------|

| `dohHealth.js` | `queryCleanBrowsingDoH()` — JSON + wire RFC8484 |

| `domainProtection.js` | `evaluateDomainProtection()`, `runDohHealthSummary()` |

| `filterTests.js` | Validation domain lists |

| `DnsValidator.js` | Health validation using layered model |

| `DnsHealthMonitor.js` | 5-minute checks; `finalStatus` healthy / healthy_with_provider_misses / degraded / failed |

| `hosts.js` | `ensureHostsBlockedDomains()` — idempotent supplement (not Mongo) |

| `dns.js` + `firewall.js` | Adapter DNS + allow CB 443; block bypass resolvers |

| `mongoDns.js` | Atlas NRPT; `MONGO_HOSTS_FALLBACK=false` by default |



## Watchdog vectors



- `dns_filtering` — fails only if known adult not blocked by DoH **and** fallback does not cover gaps.

- `dns_provider_miss` — warning when DoH misses but fallback blocks (no integrity FAIL).

- `fallback_blocking` — confirms local supplement active.



## Debug



```bash

npm run health-doh

npm run diagnose-domain -- pornhat.com --restricted adult

```



## Tests



```bash

npm run test:dns

```

