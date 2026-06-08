You are working on my Electron + Node + React Windows app called NetFast / FocusLock.

Problem:
Every time I run:

npm run dev

my internet connection breaks because the Electron app starts in strict mode and runs real DNS/firewall/browser lockdown during development.

From my logs, dev startup runs:
- NODE_ENV=development electron .
- [POLICY] Mode: strict
- [NETWORK] Re-applying lockdown (startup)
- Browser DoH policy changes
- Windows DoH changes
- Adapter DNS changes
- Firewall DNS bypass rules
- DNS verification

This must not happen automatically in development.

Goal:
Make development mode safe by default. Running npm run dev should NOT modify system DNS, firewall, browser policies, hosts file, NRPT, DoH, or adapter settings.

Required behavior:

1. Add safe dev mode by default.

Update package.json scripts:

"dev": should run server + React + Electron in safe mode.

Example:

"dev": "concurrently \"npm run dev:server\" \"npm run dev:react\" \"npm run dev:electron:safe\"",
"dev:electron:safe": "wait-on http://localhost:5173 && cross-env NODE_ENV=development NETFAST_DISABLE_ENFORCEMENT=true electron .",
"dev:electron:enforce": "wait-on http://localhost:5173 && cross-env NODE_ENV=development NETFAST_DISABLE_ENFORCEMENT=false NETFAST_ALLOW_REAL_ENFORCEMENT=true electron ."

Meaning:
- npm run dev = safe, no system changes
- npm run dev:electron:enforce = explicit dangerous enforcement test

2. Add a hard guard before any real enforcement.

In Electron main process startup, before running lockdown/enforcement:

const isDev = process.env.NODE_ENV === "development";
const enforcementDisabled = process.env.NETFAST_DISABLE_ENFORCEMENT === "true";
const allowRealEnforcement = process.env.NETFAST_ALLOW_REAL_ENFORCEMENT === "true";

if (isDev && (enforcementDisabled || !allowRealEnforcement)) {
  log("[DEV_SAFE] Real enforcement disabled. Skipping DNS/firewall/browser lockdown.");
  // Do not run lockdown.
  // Do not apply DNS.
  // Do not apply firewall.
  // Do not apply browser policies.
  // Do not change hosts file.
  // Do not change NRPT.
  // Do not change Windows DoH.
} else {
  await runLockdown("startup");
}

Important:
In development, enforcement should only run when NETFAST_ALLOW_REAL_ENFORCEMENT=true.

3. Do not enforce just because mode is strict.

Current bad behavior:
mode=strict triggers lockdown on startup.

Correct behavior:
Only enforce if a real active challenge exists.

Use logic like:

const challenge = await getSavedChallengeState();

if (challenge?.status === "active") {
  await runLockdown("startup");
} else {
  log("[STARTUP] No active challenge. Skipping lockdown.");
}

In dev safe mode, even active challenge enforcement should be mocked/skipped unless NETFAST_ALLOW_REAL_ENFORCEMENT=true.

4. Add mock enforcement for development.

When dev safe mode is active:
- UI should still show protection screens for testing.
- But all system-level operations should be no-op.
- Return fake/simulated success for:
  - DNS apply
  - firewall apply
  - browser DoH apply
  - verification
- Clearly log that it is simulated.

Example:
[DEV_SAFE] Mock DNS enforcement success
[DEV_SAFE] Mock firewall enforcement success

5. Wrap all dangerous functions with a single guard.

Dangerous functions include:
- Set-DnsClientServerAddress
- netsh DNS commands
- Add-DnsClientDohServerAddress
- Remove-DnsClientDohServerAddress
- New-NetFirewallRule
- Remove-NetFirewallRule
- Enable/Disable-NetAdapterBinding
- hosts file changes
- browser policy registry changes
- NRPT changes
- scheduled task creation/removal

Before each dangerous operation, call:

assertRealEnforcementAllowed(operationName)

If not allowed:
- log skipped operation
- return safe mock result
- do not execute PowerShell

6. Add emergency reset command.

Add package script:

"reset:network": "powershell -ExecutionPolicy Bypass -File scripts/reset-netfast-network.ps1"

Create:
scripts/reset-netfast-network.ps1

It should:
- Remove NetFast/FocusLock firewall rules
- Reset adapter DNS to DHCP/automatic
- Re-enable IPv6 if disabled
- Remove NetFast NRPT rules
- Remove NetFast scheduled task
- Remove NetFast browser Secure DNS policies if created by app
- Flush DNS

Do not remove unrelated firewall/browser/system settings.

7. Add clear startup logs.

At app startup, log:

- NODE_ENV
- NETFAST_DISABLE_ENFORCEMENT
- NETFAST_ALLOW_REAL_ENFORCEMENT
- challenge status
- whether real enforcement is enabled or skipped

Example:

[STARTUP] env=development
[STARTUP] devSafeMode=true
[STARTUP] realEnforcementAllowed=false
[STARTUP] skipping lockdown because dev safe mode is active

8. Fix package workflow.

Expected behavior:

npm run dev
- opens app
- starts server
- starts Vite
- starts Electron
- does NOT touch DNS/firewall/browser settings

npm run dev:electron:enforce
- runs real enforcement only when explicitly requested
- should show warning in logs

Production packaged app:
- real enforcement allowed only when challenge.status === active
- app should reapply enforcement after reboot only for active challenge

9. Do not make unrelated changes.

Do not change:
- payment logic
- challenge business rules
- database schema
- auth
- frontend design
- unrelated server logic

Only change:
- startup enforcement gating
- package scripts
- dangerous operation guards
- dev mock enforcement
- reset script
- logging

Final expected result:
Running npm run dev should never break internet again. Real DNS/firewall enforcement should only run in production with active challenge, or in development when I explicitly run the enforcement test command with NETFAST_ALLOW_REAL_ENFORCEMENT=true.