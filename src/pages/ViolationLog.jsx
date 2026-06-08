import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  ArrowLeft, Check, ChevronDown, ChevronUp, Battery, Plug, AlertTriangle,
  Search, Filter, FileText, Cpu, Globe, GitCommitVertical,
} from 'lucide-react';
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

function formatTime(ts) {
  return new Date(ts).toLocaleString('en-US', {
    hour: 'numeric', minute: '2-digit', hour12: true,
  });
}

function formatDayHeader(ts) {
  const d = new Date(ts);
  const today = new Date();
  const diffDays = Math.floor((today.setHours(0,0,0,0) - new Date(d).setHours(0,0,0,0)) / 86400000);
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return d.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });
}

function dayKey(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

const FILTERS = [
  { key: 'all',      label: 'All events' },
  { key: 'critical', label: 'Critical' },
  { key: 'warning',  label: 'Warning' },
];

export default function ViolationLog() {
  const navigate = useNavigate();
  const { violationLog, loadAll } = useChallengeStore();
  const [open, setOpen] = useState({});
  const [filter, setFilter] = useState('all');
  const [vectorFilter, setVectorFilter] = useState('all');
  const [query, setQuery] = useState('');

  useEffect(() => { if (!violationLog?.length) loadAll(); }, [loadAll, violationLog]);

  const counts = useMemo(() => {
    const c = { total: 0, critical: 0, warning: 0 };
    (violationLog || []).forEach((v) => {
      c.total++;
      if (v.severity === 'critical') c.critical++;
      else c.warning++;
    });
    return c;
  }, [violationLog]);

  const vectorOptions = useMemo(() => {
    const set = new Set((violationLog || []).map((v) => v.vector));
    return ['all', ...Array.from(set)];
  }, [violationLog]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (violationLog || []).filter((v) => {
      if (filter !== 'all' && v.severity !== filter) return false;
      if (vectorFilter !== 'all' && v.vector !== vectorFilter) return false;
      if (!q) return true;
      const hay = `${LABELS[v.vector] || ''} ${v.evidence?.note || ''} ${(v.evidence?.processSnapshot || []).join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [violationLog, filter, vectorFilter, query]);

  const grouped = useMemo(() => {
    const map = new Map();
    filtered.forEach((v) => {
      const k = dayKey(v.timestamp);
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(v);
    });
    return Array.from(map.entries()).map(([k, items]) => ({
      key: k,
      label: formatDayHeader(items[0].timestamp),
      items: items.sort((a, b) => b.timestamp - a.timestamp),
    }));
  }, [filtered]);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <div className="max-w-4xl mx-auto px-8 py-12">
        <button
          onClick={() => navigate({ to: '/dashboard' })}
          className="flex items-center gap-2 text-zinc-500 hover:text-zinc-300 mb-8 text-sm transition"
        >
          <ArrowLeft className="w-4 h-4" /> Back to dashboard
        </button>

        <h1 className="text-3xl font-light text-white mb-2">Integrity Event Log</h1>
        <p className="text-zinc-500 mb-8">Every detected vector event, recorded immutably.</p>

        {/* Summary stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <StatCard label="Total events" value={counts.total} accent="#6c47ff" />
          <StatCard label="Critical" value={counts.critical} accent="#ef4444" />
          <StatCard label="Warnings" value={counts.warning} accent="#f59e0b" />
        </div>

        {/* Filters */}
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-4 mb-6 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search events, processes, notes…"
              className="w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-xl pl-10 pr-3 py-2.5 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-[#6c47ff]/40 transition"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-zinc-600" />
            {FILTERS.map((f) => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={`text-xs px-3 py-1.5 rounded-full border transition ${
                  filter === f.key
                    ? 'bg-[#6c47ff]/20 text-[#6c47ff] border-[#6c47ff]/40'
                    : 'bg-[#0a0a0f] text-zinc-500 border-[#1e1e2e] hover:text-zinc-300'
                }`}
              >
                {f.label}
              </button>
            ))}
            <div className="w-px h-5 bg-[#1e1e2e] mx-1" />
            <select
              value={vectorFilter}
              onChange={(e) => setVectorFilter(e.target.value)}
              className="text-xs bg-[#0a0a0f] border border-[#1e1e2e] rounded-full px-3 py-1.5 text-zinc-400 focus:outline-none focus:border-[#6c47ff]/40"
            >
              {vectorOptions.map((v) => (
                <option key={v} value={v}>{v === 'all' ? 'All vectors' : LABELS[v] || v}</option>
              ))}
            </select>
          </div>
        </div>

        {!violationLog?.length ? (
          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-12 text-center">
            <div className="w-16 h-16 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/40 flex items-center justify-center mx-auto mb-4">
              <Check className="w-8 h-8 text-[#22c55e]" />
            </div>
            <p className="text-xl text-white">No integrity events recorded.</p>
            <p className="text-zinc-500 mt-2">Keep going.</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-10 text-center">
            <p className="text-zinc-400">No events match these filters.</p>
          </div>
        ) : (
          <div className="relative">
            {/* Timeline rail */}
            <div className="absolute left-[11px] top-2 bottom-2 w-px bg-[#1e1e2e]" />
            <div className="space-y-8">
              {grouped.map((group) => (
                <div key={group.key}>
                  <div className="flex items-center gap-3 mb-3 pl-7">
                    <p className="text-xs uppercase tracking-[0.2em] text-zinc-600">{group.label}</p>
                    <div className="flex-1 h-px bg-[#1e1e2e]" />
                  </div>
                  <div className="space-y-3">
                    {group.items.map((v) => {
                      const isOpen = open[v.id];
                      const critical = v.severity === 'critical';
                      return (
                        <div key={v.id} className="relative pl-7">
                          <span
                            className={`absolute left-[7px] top-6 w-[10px] h-[10px] rounded-full border-2 border-[#0a0a0f] ${
                              critical ? 'bg-[#ef4444]' : 'bg-[#f59e0b]'
                            }`}
                          />
                          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl overflow-hidden hover:border-[#6c47ff]/30 transition">
                            <div className="p-5">
                              <div className="flex items-start justify-between gap-4">
                                <div className="min-w-0">
                                  <p className="text-white font-medium">{LABELS[v.vector] || v.vectorLabel}</p>
                                  <p className="text-sm text-zinc-500 mt-1">{formatTime(v.timestamp)}</p>
                                  <p className="text-sm text-zinc-400 mt-2 leading-relaxed">{v.evidence?.note}</p>
                                </div>
                                <SeverityBadge severity={v.severity} />
                              </div>

                              {critical && (
                                <div className="mt-4 flex items-start gap-2 p-3 rounded-xl bg-[#ef4444]/10 border border-[#ef4444]/30">
                                  <AlertTriangle className="w-4 h-4 text-[#ef4444] mt-0.5 shrink-0" />
                                  <p className="text-sm text-[#ef4444]">
                                    One more event on this check terminates your challenge.
                                  </p>
                                </div>
                              )}

                              <button
                                onClick={() => setOpen((o) => ({ ...o, [v.id]: !o[v.id] }))}
                                className="mt-4 flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 transition"
                              >
                                {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                                {isOpen ? 'Hide evidence' : 'Show evidence'}
                              </button>

                              {isOpen && <EvidencePanel evidence={v.evidence} />}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-5">
      <p className="text-xs uppercase tracking-wider text-zinc-500">{label}</p>
      <p className="text-3xl font-light mt-2 tabular-nums" style={{ color: accent }}>{value}</p>
    </div>
  );
}

function SeverityBadge({ severity }) {
  if (severity === 'critical') {
    return (
      <span className="shrink-0 text-xs px-2.5 py-1 rounded-full bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
        Critical
      </span>
    );
  }
  return (
    <span className="shrink-0 text-xs px-2.5 py-1 rounded-full bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30">
      Warning
    </span>
  );
}

function EvidencePanel({ evidence }) {
  if (!evidence) return null;
  return (
    <div className="mt-4 rounded-xl bg-[#0a0a0f] border border-[#1e1e2e] divide-y divide-[#1e1e2e]">
      <div className="grid grid-cols-2 gap-px bg-[#1e1e2e]">
        <Cell icon={Battery} label="Battery" value={`${evidence.batteryPercent}%`} />
        <Cell icon={Plug} label="AC Power" value={evidence.onAC ? 'Connected' : 'Disconnected'} />
      </div>

      {evidence.dnsResolver && (
        <Row icon={Globe} label="DNS Resolver" value={evidence.dnsResolver} mono />
      )}

      {evidence.filePath && (
        <Row icon={FileText} label="Target" value={evidence.filePath} mono />
      )}

      {evidence.processSnapshot?.length > 0 && (
        <div className="p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-zinc-500 mb-2">
            <Cpu className="w-3.5 h-3.5" /> Process snapshot
          </div>
          <ul className="space-y-1">
            {evidence.processSnapshot.map((p, i) => (
              <li key={i} className="text-sm text-zinc-300 font-mono">{p}</li>
            ))}
          </ul>
        </div>
      )}

      {evidence.diff && (
        <div className="p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-zinc-500 mb-2">
            <GitCommitVertical className="w-3.5 h-3.5" /> Diff
          </div>
          <pre className="text-xs font-mono leading-relaxed whitespace-pre-wrap">
            {evidence.diff.split('\n').map((line, i) => {
              const color = line.startsWith('+') ? 'text-[#22c55e]' : line.startsWith('-') ? 'text-[#ef4444]' : 'text-zinc-400';
              return <div key={i} className={color}>{line}</div>;
            })}
          </pre>
        </div>
      )}
    </div>
  );
}

function Cell({ icon: Icon, label, value }) {
  return (
    <div className="p-4 bg-[#0a0a0f]">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-zinc-500 mb-1.5">
        <Icon className="w-3.5 h-3.5" /> {label}
      </div>
      <p className="text-sm text-white">{value}</p>
    </div>
  );
}

function Row({ icon: Icon, label, value, mono }) {
  return (
    <div className="p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-zinc-500 mb-1.5">
        <Icon className="w-3.5 h-3.5" /> {label}
      </div>
      <p className={`text-sm text-zinc-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  );
}
