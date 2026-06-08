import { Shield, Globe, Wifi, FileCode, Activity, Plug } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';

const VECTOR_META = {
  dns_filtering:   { label: 'Filtering Effectiveness', icon: Shield },
  dns_ipv4:        { label: 'DNS Integrity',           icon: Shield },
  dns_ipv6:        { label: 'IPv6 DNS Integrity',      icon: Shield },
  windows_doh:     { label: 'DoH Configuration',       icon: Globe },
  firefox_doh:     { label: 'Firefox Secure DNS',      icon: Globe },
  chrome_doh:      { label: 'Chrome Secure DNS',       icon: Globe },
  ipv6_tunnel:     { label: 'IPv6 Tunnel Adapters',     icon: Wifi },
  hosts_modified:  { label: 'Hosts File Integrity',     icon: FileCode },
  rogue_dns:       { label: 'DNS Port Monitor',         icon: Wifi },
  unknown_vpn:     { label: 'VPN/Proxy Detection',      icon: Plug },
  watchdog_killed: { label: 'Watchdog Process',         icon: Activity },
  app_tampered:    { label: 'App Integrity',            icon: Shield },
};

export default function VectorStatusGrid() {
  const vectorStatus = useChallengeStore((s) => s.vectorStatus);

  if (!vectorStatus) {
    return (
      <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6">
        <p className="text-zinc-500 text-sm">Loading vector status…</p>
      </div>
    );
  }

  return (
    <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6">
      <h3 className="text-sm uppercase tracking-wider text-zinc-500 mb-4">Vector Status</h3>
      <div className="space-y-2">
        {Object.entries(VECTOR_META).map(([key, meta]) => {
          const entry = vectorStatus[key] || {};
          const Icon = meta.icon;
          const isWarn = entry.violated === true || (entry.warnings ?? 0) >= 1;
          return (
            <div
              key={key}
              className="flex items-center justify-between p-3 rounded-xl bg-[#0a0a0f] border border-[#1e1e2e]"
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isWarn ? 'text-[#f59e0b]' : 'text-zinc-500'}`} />
                <span className="text-sm text-zinc-200">{meta.label}</span>
              </div>
              {isWarn ? (
                <span className="text-xs px-2.5 py-1 rounded-full bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30">
                  Warning
                </span>
              ) : (
                <span className="text-xs px-2.5 py-1 rounded-full bg-[#22c55e]/20 text-[#22c55e] border border-[#22c55e]/30">
                  Clear
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
