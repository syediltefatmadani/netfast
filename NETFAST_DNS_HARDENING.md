# NetFast DNS Hardening Upgrade

## Objective

Upgrade NetFast so that DNS filtering cannot be bypassed by:

* ISP DNS hijacking
* Port 53 interception
* Router-enforced DNS
* Public Wi-Fi DNS redirection
* Hotel/campus DNS overrides
* Windows DNS setting manipulation

The solution must use **DNS-over-HTTPS (DoH)** instead of traditional DNS.

---

## Current Behavior

NetFast currently:

1. Sets system DNS to CleanBrowsing.
2. Detects DNS changes.
3. Detects tampering attempts.
4. Issues one warning.
5. Terminates subscription on subsequent violations.

### Problem

Many networks intercept DNS traffic on port 53, causing DNS requests to bypass CleanBrowsing even when Windows DNS settings appear correct.

---

# New Requirements

## 1. Use DNS-over-HTTPS (DoH)

Implement encrypted DNS using CleanBrowsing's DoH endpoint.

### Requirements

* All DNS validation checks must use DoH.
* Never rely solely on Windows DNS settings.
* Assume Windows DNS settings can be spoofed or ignored by the network.

### Validation Must Verify

* DNS response actually originates from CleanBrowsing.
* Filtering behavior is active.
* Blocked domains are truly blocked.

---

## 2. Create DNS Health Service

Build a background service:

```typescript
class DnsHealthMonitor
```

### Responsibilities

* Run every 5 minutes.
* Validate filtering.
* Detect hijacking.
* Detect filtering inactivity.
* Report status to app.

### Possible States

```typescript
enum DnsStatus {
  HEALTHY,
  FILTERING_INACTIVE,
  CLEANBROWSING_UNREACHABLE,
  NETWORK_ERROR,
  TAMPERING_SUSPECTED
}
```

---

## 3. Filtering Verification

Do not merely check:

```bash
ipconfig /all
```

or

```powershell
Get-DnsClientServerAddress
```

These only show configuration.

Instead, verify actual behavior.

### Example Workflow

```text
Request blocked domain
      ↓
Resolve via DoH
      ↓
Check returned result
      ↓
Confirm CleanBrowsing policy applied
```

If a domain that should be blocked resolves normally:

```typescript
FILTERING_INACTIVE
```

---

## 4. Detect DNS Hijacking

Implement multiple checks.

### Check A: DoH Connectivity

Verify:

* HTTPS reachable
* TLS valid
* DoH endpoint responding

Failure:

```typescript
CLEANBROWSING_UNREACHABLE
```

---

### Check B: Blocked Domain Test

Maintain an internal test list:

```typescript
[
  "pornhat.com",
  "pornhat.one",
  "reddit.com",
  "reddit"
]
```

For each domain:

```typescript
verifyDomainBlocked(domain)
```

If policy unexpectedly allows access:

```typescript
FILTERING_INACTIVE
```

---

### Check C: Consistency Test

Compare:

```text
System DNS result
vs
DoH result
```

Large discrepancies indicate:

```typescript
TAMPERING_SUSPECTED
```

---

## 5. Warning Logic

Existing business rule remains unchanged.

### First Violation

```typescript
warningIssued = true
```

Display:

> NetFast protection is inactive. Please restore filtering to continue your commitment.

### Second Violation

```typescript
terminateSubscription()
```

---

## 6. Network Change Handling

Detect:

* Wi-Fi change
* Ethernet change
* VPN connection
* DNS configuration change

When network changes:

```typescript
runImmediateDnsHealthCheck()
```

Do not wait for the scheduled check.

---

## 7. Evidence Logging

Create an audit log.

```typescript
interface DnsAuditEvent {
  timestamp: string;
  networkName: string;
  status: DnsStatus;
  details: string;
}
```

Store locally.

### Purpose

* Diagnostics
* Support investigations
* Tampering analysis
* Reliability monitoring

---

## 8. False Positive Protection

Do **not** assume malicious intent.

Possible causes:

* ISP DNS interception
* Hotel Wi-Fi
* Campus network
* Corporate firewall
* Temporary internet outage

Mark as:

```typescript
FILTERING_INACTIVE
```

not

```typescript
USER_TAMPERED
```

unless multiple indicators exist.

---

## 9. Architecture Requirements

### Technology Requirements

* TypeScript
* Electron-compatible APIs
* Modular service architecture
* Dependency injection
* Strong typing
* Unit tests

### Folder Structure

```text
src/services/dns/
├── DnsHealthMonitor.ts
├── DnsValidator.ts
├── DohClient.ts
├── DnsAuditLogger.ts
├── DnsStatus.ts
└── tests/
```

---

## 10. Deliverables

Provide:

1. Full implementation.
2. File-by-file code.
3. Unit tests.
4. Integration tests.
5. Architecture explanation.
6. Security review.
7. Potential bypass vectors still remaining after DoH implementation.
8. Recommendations for future hardening.

---

# Important Design Principle

Focus on reliability and accurate detection.

The goal is **not** to block every bypass attempt.

The goal is to ensure that:

* DNS filtering remains active.
* Any loss of filtering is detected quickly.
* Violations are handled consistently.
* False positives are minimized.

---

# Architectural Recommendation

Do **not** trust the operating system's configured DNS settings as the source of truth.

Instead:

* Treat CleanBrowsing DoH as the authoritative DNS source.
* Verify filtering through actual DNS resolution behavior.
* Confirm that blocked domains are truly blocked.
* Use behavioral validation rather than configuration validation.

This approach is significantly more resilient against:

* ISP DNS interception
* Public Wi-Fi DNS overrides
* Router-enforced DNS
* Misconfigured network environments
* Port 53 hijacking
