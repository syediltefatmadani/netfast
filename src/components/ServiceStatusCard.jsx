import { useEffect, useState, useCallback } from 'react';
import { Server, ShieldCheck, ShieldAlert, RefreshCw } from 'lucide-react';
import { electronBridge } from '../electron/bridge';

/**
 * Minimal Phase 2 service-health panel. Reads the NetFastService status + latest
 * protection snapshot through the Electron bridge and shows whether the
 * background monitoring engine is running independently of this window.
 */
function relativeTime(iso) {
  if (!iso) return 'never';
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return 'unknown';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins === 1) return '1 minute ago';
  if (mins < 60) return `${mins} minutes ago`;
  const hrs = Math.floor(mins / 60);
  return hrs === 1 ? '1 hour ago' : `${hrs} hours ago`;
}

function Row({ label, value, ok }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-zinc-500">{label}</span>
      <span className={ok === false ? 'text-[#fca5a5]' : ok === true ? 'text-[#86efac]' : 'text-zinc-300'}>
        {value}
      </span>
    </div>
  );
}

export default function ServiceStatusCard() {
  const [status, setStatus] = useState(null);
  const [protection, setProtection] = useState(null);
  const [checking, setChecking] = useState(false);

  const refresh = useCallback(async () => {
    const [s, p] = await Promise.all([
      electronBridge.getServiceStatus(),
      electronBridge.getServiceProtectionStatus(),
    ]);
    setStatus(s);
    setProtection(p);
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, [refresh]);

  const runManualCheck = async () => {
    setChecking(true);
    try {
      await electronBridge.serviceManualCheck();
      await refresh();
    } finally {
      setChecking(false);
    }
  };

  const running = status?.serviceRunning && status?.serviceReachable;

  if (!running) {
    return (
      <div className="rounded-2xl border border-[#ef4444]/40 bg-[#ef4444]/10 px-5 py-4">
        <div className="flex items-center gap-2 text-[#fca5a5] font-medium">
          <ShieldAlert className="w-4 h-4" /> Background Service is not running
        </div>
        <p className="mt-1 text-xs text-zinc-400">
          Monitoring may stop when the app is closed. Install/start NetFastService
          (run <code className="text-zinc-300">npm run service:install</code> as Administrator).
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[#1e1e2e] bg-[#12121a] px-5 py-4 space-y-2.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-zinc-200 font-medium">
          <Server className="w-4 h-4 text-[#6c47ff]" /> Background Service
        </div>
        <span className="inline-flex items-center gap-1.5 text-xs text-[#86efac]">
          <ShieldCheck className="w-3.5 h-3.5" /> Running
        </span>
      </div>

      <Row label="Monitoring" value={status.monitoringActive ? 'Active' : 'Idle'} ok={status.monitoringActive} />
      <Row label="Last heartbeat" value={relativeTime(status.lastHeartbeatAt)} />
      {protection && (
        <>
          <Row label="DNS protection" value={protection.dnsProtected ? 'Healthy' : 'Issue'} ok={protection.dnsProtected} />
          <Row label="VPN" value={protection.vpnDetected ? 'Detected' : 'Not detected'} ok={!protection.vpnDetected} />
          <Row label="Hosts file" value={protection.hostsFileHealthy ? 'Healthy' : 'Modified'} ok={protection.hostsFileHealthy} />
        </>
      )}
      {(status.queuedHeartbeats > 0 || status.queuedViolations > 0) && (
        <Row
          label="Pending sync"
          value={`${status.queuedHeartbeats} hb / ${status.queuedViolations} viol`}
        />
      )}

      <button
        onClick={runManualCheck}
        disabled={checking}
        className="mt-1 w-full flex items-center justify-center gap-2 py-2 rounded-xl bg-[#1e1e2e] hover:bg-[#26263a] text-zinc-300 text-sm transition disabled:opacity-50"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${checking ? 'animate-spin' : ''}`} />
        {checking ? 'Checking...' : 'Run verification now'}
      </button>
    </div>
  );
}
