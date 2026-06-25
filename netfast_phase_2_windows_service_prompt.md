# NetFast Phase 2 Architecture Upgrade — Dedicated Windows Background Service

## Context

NetFast is an accountability and habit-building desktop application.

Phase 1 should already have fixed the immediate Electron issue:

- Closing the Electron window hides the UI instead of quitting the app.
- Monitoring logic was moved out of React renderer components.
- Electron Main Process owns lightweight monitoring.
- A system tray controls the UI.
- Duplicate timers and aggressive PowerShell polling were reduced.

Now implement **Phase 2 only**.

The goal of Phase 2 is to introduce a dedicated Windows background service so core monitoring can continue even when the Electron UI is fully closed or not currently running.

---

# Primary Objective

Create a dedicated Windows service named:

```text
NetFastService
```

The service should be responsible for background monitoring, heartbeat reporting, and protection integrity checks.

Electron should become the user-facing control panel.

The service should become the background monitoring engine.

Do not implement production installer signing, auto-update, full tamper protection, billing enforcement, or mobile expansion in this phase.

---

# Important Product Boundary

NetFast is an accountability app, not malware.

Do not implement stealth behavior.

Do not hide processes.

Do not prevent uninstall.

Do not bypass Windows security.

Do not attempt persistence tricks.

Do not create self-restarting malware-like behavior.

Do not kill other apps.

Do not modify system settings without explicit user consent.

The service should be visible and manageable as a normal Windows service.

The product promise is:

```text
Transparent protection monitoring + accountability logging
```

Not:

```text
Unbreakable device control
```

---

# Phase 2 Scope

Implement only the dedicated background service architecture.

Do not redesign the React UI except for small service-status indicators.

Do not create duplicate monitoring systems.

Refactor existing monitoring code so that the service owns the core checks, while Electron reads service status and displays it.

---

# Target Architecture

Use a structure similar to this, adjusting to the actual project layout:

```text
netfast/
  electron/
    main.ts
    tray.ts
    ipc/
      serviceIpc.ts

  src/
    renderer/
      pages/
      components/

  service/
    index.ts
    serviceManager.ts
    monitors/
      dnsMonitor.ts
      vpnMonitor.ts
      hostsMonitor.ts
      dohMonitor.ts
      virtualizationMonitor.ts
      challengeMonitor.ts
    sync/
      heartbeatClient.ts
      offlineQueue.ts
    logging/
      serviceLogger.ts
    config/
      serviceConfig.ts
    storage/
      localStateStore.ts

  shared/
    types/
      monitoring.ts
      heartbeat.ts
      violation.ts
      serviceStatus.ts
```

The exact folder structure can differ, but the separation must remain clear:

```text
React Renderer = UI only
Electron Main Process = desktop shell + tray + IPC bridge
NetFastService = background monitoring engine
Shared Types = common contracts
Backend = challenge state, heartbeat, violations, audit logs
```

---

# Service Responsibilities

`NetFastService` must handle:

## 1. DNS Monitoring

Detect whether the required protection DNS is still active.

Monitor:

- CleanBrowsing DNS present
- DNS changed away from expected resolver
- DNS resolution does not match expected filtering behavior
- Possible DNS leak
- Local DNS override risk

Expected result:

```ts
{
  dnsProtected: boolean;
  activeResolvers: string[];
  expectedResolvers: string[];
  lastCheckedAt: string;
  issue?: string;
}
```

Avoid relying only on reading system settings.

Use both:

- system configuration checks
- real DNS verification checks

Do not claim 100% bypass detection.

Log uncertainty clearly.

---

## 2. VPN Detection

Detect active or newly installed VPN-related adapters/processes/services.

Monitor for common VPN indicators, including:

- TAP adapters
- WireGuard
- OpenVPN
- Tailscale
- ProtonVPN
- NordVPN
- Surfshark
- ExpressVPN
- Mullvad
- Cloudflare WARP
- ZeroTier
- SoftEther

Detection methods may include:

- network adapter inspection
- service/process name checks
- routing table changes
- DNS resolver changes
- known interface names

Do not kill VPN processes.

Do not block VPN apps.

Only detect and report.

Expected result:

```ts
{
  vpnDetected: boolean;
  detectedVpnNames: string[];
  networkInterfaces: string[];
  lastCheckedAt: string;
}
```

---

## 3. DoH / Encrypted DNS Monitoring

Monitor signs that DNS-over-HTTPS or encrypted DNS may bypass the intended DNS protection.

Detect:

- known DoH browser settings where feasible
- known DoH resolver domains/IPs where feasible
- browser policies/config files where appropriate
- DNS verification failures that suggest encrypted DNS bypass

Do not overpromise.

DoH detection is not perfect.

Represent results as:

```ts
{
  dohRiskDetected: boolean;
  confidence: "low" | "medium" | "high";
  evidence: string[];
  lastCheckedAt: string;
}
```

---

## 4. Hosts File Monitoring

Monitor Windows hosts file integrity.

Target file:

```text
C:\Windows\System32\drivers\etc\hosts
```

Detect:

- protection entries removed
- suspicious entries added
- unauthorized edits
- file timestamp changes
- file hash changes

Use efficient file watching when possible.

Do not poll aggressively.

Expected result:

```ts
{
  hostsFileHealthy: boolean;
  hash: string;
  lastModifiedAt: string;
  suspiciousEntries: string[];
  lastCheckedAt: string;
}
```

---

## 5. Virtualization / Alternate Environment Detection

Detect whether the user may be attempting to bypass protection through alternate local environments.

Monitor for:

- WSL
- Hyper-V
- VirtualBox
- VMware
- Docker Desktop
- Sandbox-like environments where relevant

Do not block these tools.

Only report their presence as risk signals.

Expected result:

```ts
{
  virtualizationRiskDetected: boolean;
  detectedSystems: string[];
  confidence: "low" | "medium" | "high";
  lastCheckedAt: string;
}
```

---

## 6. Challenge State Monitoring

The service must know whether there is an active challenge.

If no challenge is active:

- run in lightweight idle mode
- avoid expensive checks
- keep service alive
- report service status only when needed

If challenge is active:

- run full monitoring schedule
- send heartbeats
- report violations
- cache status locally
- recover after network loss

The service should maintain local state:

```ts
{
  activeChallengeId: string | null;
  userId: string | null;
  challengeStatus: "none" | "active" | "paused" | "completed" | "terminated";
  lastHeartbeatAt: string | null;
  serviceStartedAt: string;
}
```

---

# Monitoring Intervals

Use these intervals as the default Phase 2 schedule:

```text
Service health check:             every 60 seconds
DNS verification:                 every 60 seconds when challenge active
VPN detection:                    every 60 seconds when challenge active
Hosts file verification:          event-driven + fallback every 5 minutes
DoH risk check:                   every 5 minutes when challenge active
Virtualization check:             every 10 minutes when challenge active
Challenge state sync:             every 5 minutes
Heartbeat sync:                   every 5 minutes
Offline queue flush:              every 2 minutes when network is available
```

Do not use aggressive polling.

Do not spawn PowerShell continuously.

Prefer:

- native Node.js APIs
- Windows command calls only when necessary
- cached results
- debounced file watchers
- status-change-based logging
- shared reusable utilities

Avoid:

- infinite loops
- duplicate intervals
- duplicate service instances
- noisy logs
- repeated expensive system calls
- repeated PowerShell calls every few seconds

---

# Service Lifecycle Requirements

The service must:

```text
Start automatically on Windows boot.
Continue running when Electron UI is closed.
Continue running when no Electron window exists.
Expose current status to Electron.
Stop cleanly when the service is intentionally stopped.
Recover gracefully after crash/restart.
```

The service must not depend on React or the browser window lifecycle.

---

# Electron Integration

Electron should communicate with the service through a clean local interface.

Choose the safest and simplest practical approach for the current stack:

- local HTTP server bound to `127.0.0.1`
- named pipe
- local IPC
- file-based status store with locking
- another appropriate local mechanism

The chosen mechanism must be documented in code comments.

Electron should be able to:

```text
Read service status
Read latest protection status
Read recent violation logs
Start challenge monitoring
Stop challenge monitoring if allowed
Trigger manual verification
Show service health in UI
```

Example IPC channels between Electron and renderer:

```text
service:getStatus
service:getProtectionStatus
service:getViolations
service:manualCheck
service:startChallenge
service:stopChallenge
```

Renderer must not talk directly to the Windows service if Electron Main can act as a safer bridge.

---

# Service API Contract

Create a small internal service API.

Example endpoints or equivalent methods:

```text
GET  /health
GET  /status
GET  /protection-status
GET  /violations/recent
POST /challenge/start
POST /challenge/stop
POST /monitoring/check-now
POST /sync/heartbeat
```

Use equivalent named pipe or IPC methods if not using HTTP.

Example `/status` response:

```json
{
  "serviceRunning": true,
  "serviceVersion": "0.2.0",
  "challengeId": "challenge_123",
  "challengeStatus": "active",
  "monitoringActive": true,
  "lastHeartbeatAt": "2026-06-25T10:30:00.000Z",
  "lastCheckAt": "2026-06-25T10:31:00.000Z"
}
```

Example `/protection-status` response:

```json
{
  "dnsProtected": true,
  "vpnDetected": false,
  "dohRiskDetected": false,
  "hostsFileHealthy": true,
  "virtualizationRiskDetected": false,
  "overallStatus": "healthy",
  "lastCheckedAt": "2026-06-25T10:31:00.000Z"
}
```

---

# Heartbeat Payload

Send a heartbeat to the backend every 5 minutes when a challenge is active.

Payload:

```json
{
  "userId": "",
  "challengeId": "",
  "deviceId": "",
  "serviceVersion": "",
  "status": "active",
  "dnsProtected": true,
  "vpnDetected": false,
  "dohRiskDetected": false,
  "hostsFileHealthy": true,
  "virtualizationRiskDetected": false,
  "tamperingDetected": false,
  "lastViolationAt": null,
  "timestamp": ""
}
```

If the backend is unreachable:

- store heartbeat locally
- retry later
- do not lose events
- avoid duplicate uploads

---

# Violation Model

Create a clear violation type.

```ts
type ViolationSeverity = "low" | "medium" | "high" | "critical";

type ViolationType =
  | "dns_changed"
  | "cleanbrowsing_removed"
  | "vpn_detected"
  | "doh_risk_detected"
  | "hosts_modified"
  | "virtualization_detected"
  | "service_interrupted"
  | "monitoring_offline"
  | "permission_or_config_changed";
```

Each violation should include:

```ts
{
  id: string;
  userId: string;
  challengeId: string;
  deviceId: string;
  type: ViolationType;
  severity: ViolationSeverity;
  evidence: string[];
  detectedAt: string;
  syncedAt: string | null;
}
```

Do not terminate challenges locally based on one raw signal unless existing business rules already require it.

The service should record and sync violations.

The backend should decide final enforcement if possible.

---

# Logging Requirements

Use structured logs.

Categories:

```text
[SERVICE]
[DNS]
[VPN]
[DOH]
[HOSTS]
[VIRTUALIZATION]
[CHALLENGE]
[HEARTBEAT]
[VIOLATION]
[SYNC]
[IPC]
[ERROR]
```

Avoid duplicate logs.

Log status changes, not every routine check.

Bad:

```text
[DNS] checking
[DNS] checking
[DNS] checking
```

Good:

```text
[DNS] CleanBrowsing verified
[DNS] Status changed: CleanBrowsing not detected
[VIOLATION] vpn_detected: WireGuard adapter found
```

Logs should be stored locally with rotation.

Do not let logs grow forever.

---

# Local Storage Requirements

Store local service state safely.

Required local stores:

```text
service-state.json
protection-status.json
violations-queue.json
heartbeat-queue.json
service.log
```

Requirements:

- avoid corrupted writes
- use atomic writes where possible
- handle missing/corrupt files gracefully
- do not store unnecessary sensitive browsing data
- store only what is needed for accountability integrity

---

# Backend Sync Requirements

Implement or prepare clean backend client methods:

```ts
sendHeartbeat(payload)
sendViolation(violation)
fetchChallengeState(challengeId)
flushOfflineQueue()
```

If backend endpoints are not ready, create a clean adapter with TODO comments and mockable methods.

Do not scatter fetch calls throughout monitor modules.

All backend communication should go through one sync/client layer.

---

# Security and Privacy Requirements

Collect only what is required for protection integrity.

Do not collect:

- browsing history
- private messages
- screenshots
- keystrokes
- full traffic contents
- personal files

Allowed accountability signals:

- DNS protection status
- VPN presence
- DoH risk state
- hosts file integrity
- service health
- heartbeat status
- challenge state
- violation evidence summaries

Make evidence specific but not invasive.

Example good evidence:

```text
WireGuard network adapter detected.
```

Example bad evidence:

```text
Full list of websites the user visited.
```

---

# UI Updates for Phase 2

Keep UI changes minimal.

Add a simple service health/status area:

```text
Background Service: Running
Monitoring: Active
Last heartbeat: 2 minutes ago
DNS protection: Healthy
VPN: Not detected
Hosts file: Healthy
```

If the service is not running:

```text
Background Service is not running.
Monitoring may stop when the app is closed.

[Repair Service]
```

Only add “Repair Service” if there is a safe implementation.

Do not redesign the dashboard in Phase 2.

---

# Installation / Development Setup

For development, provide scripts to install/uninstall/start/stop the service locally.

Example scripts:

```text
npm run service:build
npm run service:install
npm run service:uninstall
npm run service:start
npm run service:stop
npm run service:logs
```

Use the current project package manager and conventions.

If the project uses TypeScript, compile the service properly.

If permissions are required, document that the command must run as Administrator.

---

# Service Stop / Tamper Signals

In Phase 2, do not implement aggressive tamper protection.

But the system should detect and report service interruption where possible.

Examples:

- Electron notices service is unreachable
- Backend heartbeat missing
- Service restart count changes
- Service last seen timestamp is stale

Represent this as:

```text
service_interrupted
```

Do not try to secretly restart forever.

Do not prevent the user from stopping the service in this phase.

---

# Acceptance Criteria

Phase 2 is complete only when all of these are true:

1. A dedicated `NetFastService` exists.

2. The service can be installed, started, stopped, and uninstalled in development.

3. The service starts on Windows boot after installation.

4. Core monitoring runs inside the service, not React.

5. Electron can be fully closed and the service still runs.

6. Electron can reopen and display the latest service status.

7. DNS monitoring works from the service.

8. VPN detection works from the service.

9. Hosts file monitoring works from the service.

10. Heartbeat payload is generated every 5 minutes during an active challenge.

11. Offline heartbeat/violation queue exists.

12. Duplicate intervals are prevented.

13. PowerShell or command-line calls are not aggressively repeated.

14. Logs are structured and rotated.

15. The service does not use stealth, malware-like persistence, or uninstall prevention.

16. Existing Phase 1 tray behavior is not broken.

---

# Required Tests

After implementation, run or describe these tests:

```text
Test 1:
Install service → start service → verify service appears in Windows Services.

Test 2:
Open NetFast UI → verify UI shows Background Service: Running.

Test 3:
Start active challenge → close Electron completely from tray quit → verify service continues running.

Test 4:
Wait 6 minutes → verify heartbeat was generated or queued.

Test 5:
Change DNS away from CleanBrowsing → verify service detects DNS issue.

Test 6:
Restore CleanBrowsing DNS → verify service detects recovery.

Test 7:
Enable a VPN or simulate VPN adapter → verify VPN detection creates a violation.

Test 8:
Modify hosts file → verify hosts monitor detects change.

Test 9:
Disconnect internet → verify heartbeat/violation is queued locally.

Test 10:
Reconnect internet → verify offline queue flushes safely.

Test 11:
Open and close Electron multiple times → verify no duplicate service monitors are created.

Test 12:
Check CPU/memory while service is idle → verify lightweight behavior.

Test 13:
Stop service manually → verify Electron/backend can detect service interruption.
```

---

# Development Instructions

Before coding:

1. Inspect the current Phase 1 architecture.
2. Find existing monitor modules.
3. Identify which logic must move from Electron Main Process into `NetFastService`.
4. Identify existing backend challenge/heartbeat APIs.
5. Create a short implementation plan.

While coding:

- Move logic instead of duplicating it.
- Keep Phase 1 tray behavior working.
- Keep React as UI only.
- Use shared types between Electron and service.
- Use one monitor manager inside the service.
- Prevent duplicate timers.
- Keep service checks lightweight.
- Add clear logs.

After coding, summarize:

- Files added
- Files modified
- How the service is installed and run
- How Electron communicates with the service
- Which monitors now run in the service
- How heartbeats and offline queue work
- Known limitations
- What remains for Phase 3

---

# Deliverable

Implement Phase 2 only.

Do not implement Phase 3 production hardening yet.

Do not build signed installer yet.

Do not implement anti-uninstall or stealth persistence.

The result should be a clean, testable Windows background service that owns monitoring independently from the Electron UI.
