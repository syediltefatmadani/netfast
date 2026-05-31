import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { ArrowLeft, Check, ChevronDown, ChevronUp, Battery, Plug, AlertTriangle } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';

const LABELS = {
  dns_ipv4: 'IPv4 DNS Integrity', dns_ipv6: 'IPv6 DNS Integrity',
  firefox_doh: 'Firefox Secure DNS', chrome_doh: 'Chrome Secure DNS',
  windows_doh: 'System DNS Encryption', ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity', rogue_dns: 'DNS Port Monitor',
  unknown_vpn: 'VPN/Proxy Detection', watchdog_killed: 'Watchdog Process',
  app_tampered: 'App Integrity',
};

function formatTs(ts) {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true,
  });
}

export default function ViolationLog() {
  const navigate = useNavigate();
  const { violationLog, loadAll } = useChallengeStore();
  const [open, setOpen] = useState({});

  useEffect(() => { if (!violationLog?.length) loadAll(); }, [loadAll, violationLog]);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <div className="max-w-3xl mx-auto px-8 py-12">
        <button
          onClick={() => navigate({ to: '/dashboard' })}
          className="flex items-center gap-2 text-zinc-500 hover:text-zinc-300 mb-8"
        >
          <ArrowLeft className="w-4 h-4" /> Back to dashboard
        </button>

        <h1 className="text-3xl font-light text-white mb-2">Integrity Event Log</h1>
        <p className="text-zinc-500 mb-10">Every detected vector event, recorded immutably.</p>

        {!violationLog?.length ? (
          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-12 text-center">
            <div className="w-16 h-16 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/40 flex items-center justify-center mx-auto mb-4">
              <Check className="w-8 h-8 text-[#22c55e]" />
            </div>
            <p className="text-xl text-white">No integrity events recorded.</p>
            <p className="text-zinc-500 mt-2">Keep going.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {violationLog.map((v) => {
              const isOpen = open[v.id];
              const terminated = v.action === 'terminated';
              return (
                <div key={v.id} className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl overflow-hidden">
                  <div className="p-5">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-white font-medium">{LABELS[v.vector] || v.vectorLabel}</p>
                        <p className="text-sm text-zinc-500 mt-1">{formatTs(v.timestamp)}</p>
                      </div>
                      {terminated ? (
                        <span className="text-xs px-2.5 py-1 rounded-full bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
                          Terminated
                        </span>
                      ) : (
                        <span className="text-xs px-2.5 py-1 rounded-full bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30">
                          Warning
                        </span>
                      )}
                    </div>

                    {!terminated && (
                      <div className="mt-4 flex items-start gap-2 p-3 rounded-xl bg-[#f59e0b]/10 border border-[#f59e0b]/30">
                        <AlertTriangle className="w-4 h-4 text-[#f59e0b] mt-0.5 shrink-0" />
                        <p className="text-sm text-[#f59e0b]">
                          One more event on this check terminates your challenge.
                        </p>
                      </div>
                    )}

                    <button
                      onClick={() => setOpen((o) => ({ ...o, [v.id]: !o[v.id] }))}
                      className="mt-4 flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200"
                    >
                      {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      {isOpen ? 'Hide' : 'Show'} evidence
                    </button>

                    {isOpen && (
                      <div className="mt-4 p-4 rounded-xl bg-[#0a0a0f] border border-[#1e1e2e] space-y-2 text-sm">
                        <div className="flex items-center gap-2 text-zinc-400">
                          <Battery className="w-4 h-4" /> Battery: <span className="text-white">{v.evidence.batteryPercent}%</span>
                        </div>
                        <div className="flex items-center gap-2 text-zinc-400">
                          <Plug className="w-4 h-4" /> AC Power: <span className="text-white">{v.evidence.onAC ? 'Connected' : 'Disconnected'}</span>
                        </div>
                        <p className="text-zinc-400 pt-2 border-t border-[#1e1e2e]">
                          <span className="text-zinc-500">Note: </span>{v.evidence.note}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
