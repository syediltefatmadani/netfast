import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { AlertTriangle, FileText, Activity, Shield, ShieldAlert } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';
import StreakRing from '../components/StreakRing';
import VectorStatusGrid from '../components/VectorStatusGrid';
import IdentityBanner from '../components/IdentityBanner';

function useTicker() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, []);
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { challenge, dnsStatus, lastCheckedAt, loadAll, refreshVectors } = useChallengeStore();
  useTicker();

  useEffect(() => {
    loadAll();
    const id = setInterval(() => refreshVectors(), 30000);
    return () => clearInterval(id);
  }, [loadAll, refreshVectors]);

  const day = challenge?.day ?? 0;
  const total = challenge?.totalDays ?? 30;
  const deposit = challenge?.deposit ?? 500;
  const dnsProtected = dnsStatus?.ipv4?.intact && dnsStatus?.ipv6?.intact;
  const secondsAgo = lastCheckedAt ? Math.max(0, Math.floor((Date.now() - lastCheckedAt) / 1000)) : 0;

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <div className="max-w-7xl mx-auto px-8 py-10">
        <IdentityBanner />

        <div className="flex flex-col items-center my-10">
          <StreakRing current={day} total={total} />
          <div className="mt-8 flex items-center gap-8">
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Progress</p>
              <p className="text-xl text-white mt-1">Day {day} of {total}</p>
            </div>
            <div className="w-px h-10 bg-[#1e1e2e]" />
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Escrow</p>
              <p className="text-xl text-[#6c47ff] mt-1">₹{deposit} secured</p>
            </div>
            <div className="w-px h-10 bg-[#1e1e2e]" />
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">DNS</p>
              {dnsProtected ? (
                <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#22c55e]/20 text-[#22c55e] border border-[#22c55e]/30">
                  <Shield className="w-3.5 h-3.5" /> Protected
                </span>
              ) : (
                <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
                  <ShieldAlert className="w-3.5 h-3.5" /> Compromised
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6 mt-12">
          <VectorStatusGrid />

          <div className="space-y-4">
            <button
              onClick={() => navigate({ to: '/struggling' })}
              className="w-full flex items-center justify-center gap-3 py-6 rounded-2xl bg-[#ef4444] hover:bg-[#dc2626] text-white text-lg font-medium transition"
            >
              <AlertTriangle className="w-5 h-5" />
              I'm struggling right now
            </button>

            <button
              onClick={() => navigate({ to: '/violations' })}
              className="w-full flex items-center justify-between px-5 py-4 rounded-2xl bg-[#12121a] border border-[#1e1e2e] hover:border-[#6c47ff]/40 transition text-left"
            >
              <span className="flex items-center gap-3 text-zinc-200">
                <FileText className="w-4 h-4 text-zinc-500" />
                View violation log
              </span>
              <span className="text-zinc-600">→</span>
            </button>

            <button className="w-full flex items-center justify-between px-5 py-4 rounded-2xl bg-[#12121a] border border-[#1e1e2e] hover:border-[#6c47ff]/40 transition text-left">
              <span className="flex items-center gap-3 text-zinc-200">
                <Activity className="w-4 h-4 text-zinc-500" />
                View evidence log
              </span>
              <span className="text-zinc-600">→</span>
            </button>

            <div className="mt-8 flex items-center gap-2.5 text-sm text-zinc-500">
              <span className="relative flex w-2 h-2">
                <span className="absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-60 animate-ping" />
                <span className="relative inline-flex w-2 h-2 rounded-full bg-[#22c55e]" />
              </span>
              Monitoring active — last check {secondsAgo}s ago
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
