# NetFast Phase 1 Architecture Fix — Background Monitoring + System Tray

## Context

NetFast is an Electron + React desktop accountability app for habit-building and web protection monitoring.

The current issue is:

When the user closes the Electron window, the app stops monitoring because some monitoring logic is tied to the React renderer/window lifecycle.

This is wrong.

The monitoring system must continue running even when the UI window is closed.

The immediate goal is to refactor the app so the UI is only a control panel, while monitoring runs independently in the Electron Main Process.

---

## Primary Objective

Implement Phase 1 only.

Do not build the Windows Service yet.

Do not redesign the whole app.

Do not create duplicate monitoring systems.

Refactor the current implementation so NetFast becomes a proper system-tray desktop app where monitoring continues after the main window is closed.

---

## Core Requirements

### 1. Convert NetFast into a System Tray App

Add a system tray icon.

The tray menu should include:

- Open NetFast
- Protection Status
- Pause Monitoring, only if already supported by existing challenge rules
- Quit NetFast

Expected behavior:

When the user clicks the window close button:

```text
Do not quit the app.
Hide the main window.
Keep monitoring running in the background.
```

When the user clicks the tray icon or “Open NetFast”:

```text
Show the existing main window again.
```

Only quit the app when:

```text
The user explicitly chooses Quit from the tray menu.
```

or when the app intentionally exits during development.

---

### 2. Show Background Monitoring Notification

When the user closes the window for the first time, show a native desktop notification:

```text
NetFast is still monitoring in the background.
```

Do not spam this notification every time.

Show it once per app session unless there is already a better notification preference system.

---

### 3. Move Monitoring Out of React Renderer

React components must not own core monitoring timers.

React should only:

- Display monitoring status
- Trigger start/stop actions through IPC
- Receive updates from the main process
- Render logs/status/history

Monitoring must run in:

```text
Electron Main Process
```

Not in:

```text
React Renderer Process
```

If existing monitoring logic is inside React hooks, components, or renderer-side intervals, refactor it into a dedicated main-process monitoring module.

Create or improve a structure similar to:

```text
electron/
  main.ts
  tray.ts
  monitoring/
    monitorManager.ts
    dnsMonitor.ts
    vpnMonitor.ts
    hostsMonitor.ts
    browserMonitor.ts
    challengeSync.ts
    logger.ts
```

Use the actual project structure if different, but keep the architecture clean.

---

## Monitoring Manager

Create a central `MonitorManager`.

It should be responsible for:

- Starting all monitors
- Stopping all monitors
- Preventing duplicate timers
- Exposing current protection status
- Sending status updates to renderer via IPC
- Writing structured logs
- Cleaning up properly on explicit app quit

The manager should have clear methods:

```ts
start()
stop()
restart()
getStatus()
isRunning()
```

The app must not create multiple monitor intervals when the user opens/closes the window multiple times.

---

## Required Monitoring Intervals

Use these intervals for Phase 1:

```text
DNS Verification:              every 60 seconds
VPN Detection:                 every 60 seconds
Hosts File Verification:       every 30 seconds
Challenge State Sync:          every 5 minutes
Browser / Bypass Detection:    every 60 seconds
```

Do not run checks faster than this unless there is already a proven event-driven reason.

---

## Performance Requirements

The current implementation launches PowerShell too frequently and causes performance issues.

Fix this.

Performance goals:

- CPU usage should stay near idle when no violation is happening
- No visible UI lag
- No repeated PowerShell spawning every few seconds
- No infinite loops
- No duplicate intervals
- No repeated logs for the same unchanged status
- Expensive checks should be cached where reasonable

Prefer:

- Node.js native APIs
- Windows registry reads only when necessary
- Event-driven watchers where possible
- Debounced checks
- Reused child processes only if necessary

Avoid:

- aggressive polling
- repeated PowerShell calls
- renderer-owned timers
- duplicate monitoring loops
- noisy logs

---

## Logging Requirements

Create structured logs with clear categories:

```text
[MONITOR]
[DNS]
[VPN]
[HOSTS]
[CHALLENGE]
[BYPASS]
[TRAY]
[IPC]
```

Logs should be useful but not spammy.

Only log status changes or important events.

Bad example:

```text
[DNS] Checking DNS...
[DNS] Checking DNS...
[DNS] Checking DNS...
```

Good example:

```text
[DNS] Protection verified: CleanBrowsing active
[DNS] Protection changed: CleanBrowsing not detected
```

---

## IPC Requirements

React should communicate with the main process through IPC.

Add or clean up IPC channels such as:

```text
monitoring:getStatus
monitoring:start
monitoring:stop
monitoring:statusChanged
monitoring:getLogs
```

The renderer should not directly run DNS/VPN/hosts monitoring logic.

The renderer should request status from the main process and subscribe to updates.

---

## Window Close Behavior

Implement this exact behavior:

```ts
mainWindow.on("close", (event) => {
  if (!isQuitting) {
    event.preventDefault();
    mainWindow.hide();
    showBackgroundMonitoringNotificationOnce();
  }
});
```

Use the project’s existing TypeScript/JavaScript style.

The app should continue running in the tray.

The monitoring manager should remain active.

---

## Explicit Quit Behavior

Add a controlled quit flow.

When user selects Quit from tray:

```text
Set isQuitting = true
Stop monitoring cleanly only if required
Flush logs/status
Quit app
```

During normal close button click:

```text
Do not stop monitoring.
Do not quit app.
Only hide window.
```

---

## Challenge State

If there is an active challenge:

- Monitoring must continue when window is hidden
- Challenge status must continue syncing every 5 minutes
- Violations must still be detected
- Heartbeats/status updates must still be sent

If there is no active challenge:

- Monitoring can run in lightweight idle mode
- Do not perform expensive checks unnecessarily

---

## Important Security / Product Constraints

NetFast is an accountability app, not malware.

Do not implement stealth behavior.

Do not hide from Task Manager.

Do not prevent uninstall.

Do not bypass Windows security.

Do not create self-restarting malware-like behavior.

Do not implement Phase 2 service persistence in this task.

The app should be transparent:

```text
If the user closes the window, the app remains visible in the system tray.
```

---

## Acceptance Criteria

The task is complete only if all of these are true:

1. Closing the main window hides the app instead of quitting it.
2. The app appears in the system tray.
3. The tray menu can reopen the app.
4. Monitoring continues after the window is closed.
5. Monitoring logic is not owned by React components.
6. React only displays status and communicates through IPC.
7. No duplicate monitoring intervals are created after repeated close/open cycles.
8. PowerShell is not spawned aggressively.
9. Logs are structured and not duplicated.
10. Explicit Quit from tray properly exits the app.
11. Existing app functionality is not broken.

---

## Development Instructions

Before coding:

1. Inspect the current Electron entry files.
2. Identify where monitoring currently starts.
3. Identify any renderer-side timers, intervals, hooks, or PowerShell calls.
4. Create a short implementation plan.
5. Then refactor.

While coding:

- Reuse existing monitoring functions where possible.
- Move logic instead of duplicating it.
- Keep changes minimal and focused.
- Preserve existing UI unless a small status display update is necessary.
- Add comments only where they explain architecture decisions.

After coding:

Run or describe these tests:

```text
Test 1:
Open app → start challenge/monitoring → close window → verify app stays in tray.

Test 2:
Close window → wait 2 minutes → verify DNS/VPN/hosts checks still run.

Test 3:
Reopen app from tray → verify latest monitoring status is displayed.

Test 4:
Close and reopen app 5 times → verify no duplicate intervals/log spam.

Test 5:
Click Quit from tray → verify app exits cleanly.

Test 6:
Check CPU/memory usage while app is hidden → verify no aggressive polling.
```

---

## Deliverable

Implement Phase 1 only.

At the end, summarize:

- Files changed
- What monitoring was moved out of React
- How tray behavior works
- How duplicate timers are prevented
- Any remaining technical debt
- What should be done later in Phase 2

---

## Critical Focus

For the current bug, solve only this:

```text
Close window ≠ quit app
React UI ≠ monitoring engine
Main process = monitoring owner
Tray = background control
```

Once this works cleanly, then move to the Windows Service phase.
