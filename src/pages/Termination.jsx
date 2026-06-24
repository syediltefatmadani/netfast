import { useEffect, useState } from 'react';
import { Download, RefreshCw } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';

const LABELS = {
  dns_filtering: 'Filtering Effectiveness',
  dns_ipv4: 'DNS Integrity', dns_ipv6: 'IPv6 DNS Integrity',
  firefox_doh: 'Firefox Secure DNS', chrome_doh: 'Chrome Secure DNS',
  windows_doh: 'DoH Configuration', ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity', rogue_dns: 'DNS Port Monitor',
  unknown_vpn: 'VPN/Proxy Detection', watchdog_killed: 'Watchdog Process',
  app_tampered: 'App Integrity',
};

function fmt(ts) {
  return new Date(ts).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });
}

export default function Termination() {
  const { violationLog, loadAll, challenge } = useChallengeStore();
  const [appealOpen, setAppealOpen] = useState(false);
  const [appealText, setAppealText] = useState('');
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => { loadAll(); }, [loadAll]);

  const terminationVector = violationLog?.[violationLog.length - 1]?.vector || 'firefox_doh';

  const download = () => {
    const blob = new Blob([JSON.stringify({ challenge, violationLog }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'netfast-evidence-log.json'; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="min-h-screen text-zinc-200"
      style={{ background: 'radial-gradient(circle at top, rgba(239,68,68,0.10), #0a0a0f 60%)' }}
    >
      <div className="max-w-4xl mx-auto px-8 py-16">
        <div className="text-center mb-12">
          <p className="text-xs uppercase tracking-[0.3em] text-[#ef4444] mb-3">Challenge terminated</p>
          <h1 className="text-5xl font-light text-white">Challenge Ended</h1>
          <p className="text-zinc-400 mt-3">
            Reason: <span className="text-[#ef4444]">{LABELS[terminationVector]}</span>
          </p>
        </div>

        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-[#1e1e2e]">
            <h2 className="text-sm uppercase tracking-wider text-zinc-500">Full evidence log</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 text-xs uppercase">
                <th className="px-6 py-3">Date</th>
                <th className="px-6 py-3">Vector</th>
                <th className="px-6 py-3">Action</th>
                <th className="px-6 py-3">Battery</th>
                <th className="px-6 py-3">Power</th>
              </tr>
            </thead>
            <tbody>
              {(violationLog || []).map((v) => (
                <tr key={v.id} className="border-t border-[#1e1e2e]">
                  <td className="px-6 py-4 text-zinc-300">{fmt(v.timestamp)}</td>
                  <td className="px-6 py-4 text-white">{LABELS[v.vector]}</td>
                  <td className="px-6 py-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${
                      v.action === 'terminated'
                        ? 'bg-[#ef4444]/20 text-[#ef4444] border-[#ef4444]/30'
                        : 'bg-[#f59e0b]/20 text-[#f59e0b] border-[#f59e0b]/30'
                    }`}>
                      {v.action}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-zinc-400">{v.evidence.batteryPercent}%</td>
                  <td className="px-6 py-4 text-zinc-400">{v.evidence.onAC ? 'AC' : 'Battery'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6 mb-8">
          <p className="text-xs uppercase tracking-wider text-zinc-500 mb-2">Pattern detected</p>
          <p className="text-zinc-300">
            Repeated Firefox DoH activation while on AC power suggests intentional circumvention.
            Each event was recorded within a window where automatic restoration was disabled.
          </p>
        </div>

        <div className="flex gap-3 mb-12">
          <button
            onClick={download}
            className="flex items-center gap-2 px-5 py-3 rounded-xl bg-[#12121a] border border-[#1e1e2e] hover:border-[#6c47ff]/40 transition"
          >
            <Download className="w-4 h-4" /> Download evidence log
          </button>
          <button
            onClick={() => setAppealOpen((o) => !o)}
            className="flex items-center gap-2 px-5 py-3 rounded-xl bg-[#6c47ff] hover:bg-[#7c5aff] text-white transition"
          >
            Appeal this decision
          </button>
        </div>

        {appealOpen && (
          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6 mb-12">
            {submitted ? (
              <p className="text-[#22c55e]">Appeal submitted. We'll review within 72 hours.</p>
            ) : (
              <>
                <p className="text-zinc-300 mb-3">Explain why this termination should be reviewed:</p>
                <textarea
                  value={appealText}
                  onChange={(e) => setAppealText(e.target.value)}
                  rows={5}
                  className="w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-xl p-4 text-zinc-200 focus:outline-none focus:border-[#6c47ff]/60 resize-none"
                  placeholder="Provide context, evidence, or extenuating circumstances..."
                />
                <button
                  onClick={() => setSubmitted(true)}
                  disabled={!appealText.trim()}
                  className="mt-3 px-5 py-2.5 rounded-xl bg-[#6c47ff] hover:bg-[#7c5aff] text-white disabled:opacity-30 transition"
                >
                  Submit appeal
                </button>
              </>
            )}
          </div>
        )}

        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-8">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#6c47ff]/10 border border-[#6c47ff]/30 flex items-center justify-center shrink-0">
              <RefreshCw className="w-5 h-5 text-[#6c47ff]" />
            </div>
            <div>
              <h3 className="text-xl text-white font-light mb-2">Start a new challenge</h3>
              <p className="text-zinc-400 leading-relaxed mb-4">
                Relapse recovery protocol — three steps:
              </p>
              <ol className="space-y-2 text-zinc-300 text-sm">
                <li><span className="text-[#6c47ff]">1.</span> Acknowledge what happened, honestly.</li>
                <li><span className="text-[#6c47ff]">2.</span> Reflect for 24 hours before committing again.</li>
                <li><span className="text-[#6c47ff]">3.</span> Restart stronger with a tier that matches your reality.</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
