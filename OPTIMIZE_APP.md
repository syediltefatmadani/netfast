 Analyze and optimize my Electron NetFast startup performance.

Problem:
The Electron app takes too long to open because startup runs full DNS/firewall/browser enforcement synchronously.

Important log findings:
1. App runs dev mode with concurrently: server + Vite + Electron.
2. Electron waits for Vite localhost before opening.
3. Startup immediately runs lockdown.
4. Many PowerShell scripts are executed repeatedly.
5. Set-DnsClientServerAddress is called with -AddressFamily, but logs show:
   "A parameter cannot be found that matches parameter name 'AddressFamily'."
   This causes failed DNS apply and slow netsh fallback.
6. Firewall rules are removed and recreated/rechecked repeatedly.
7. nodemon restarts during enforcement, likely because logs/state files are written inside watched project folders.

Tasks:
1. Make Electron window open immediately.
2. Run lockdown/enforcement in the background after window is visible.
3. Show UI status: "Applying protection..." until enforcement passes.
4. Do not block BrowserWindow creation on DNS/firewall enforcement.
5. Fix Set-DnsClientServerAddress usage. Remove unsupported -AddressFamily parameter.
6. Reduce repeated PowerShell calls by batching adapter scan, DNS apply, DNS flush, and verification into fewer scripts.
7. Make firewall enforcement idempotent:
   - If rule exists and is correct, do nothing.
   - If rule exists but disabled, enable it.
   - If missing, create it.
   - Do not remove/recreate all rules every launch.
8. Only clean stale firewall rules occasionally or when rule schema changes, not every startup.
9. Move enforcement logs/state files outside nodemon watched folders, or update nodemon ignore.
10. Add timing logs around each startup phase:
   - window creation
   - browser DoH policy
   - Windows DoH
   - adapter scan
   - DNS apply
   - firewall apply
   - verification
11. Add a fast path:
   If DNS, DoH, firewall, and adapter state already match required enforcement, skip reapplying and only verify.
12. Do not change business logic, payment logic, challenge rules, or UI except adding enforcement progress state.

Expected result:
Electron window should appear within 1–3 seconds. Enforcement can continue in background, but the app should not feel stuck.