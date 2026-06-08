import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { AlertTriangle, FileText, Activity, Shield, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';
import StreakRing from '../components/StreakRing';
import VectorStatusGrid from '../components/VectorStatusGrid';
import IdentityBanner from '../components/IdentityBanner';
import VpnWarningModal from '../components/VpnWarningModal';

function useTicker() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, []);
}

function DnsProtectionBadge({ dnsStatus }) {
  const state = dnsStatus?.protectionState ?? (dnsStatus?.protectionActive ? 'protected' : 'inactive');
  const label = dnsStatus?.protectionLabel ?? '';
  const isDeveloperProtected = label.includes('developer exceptions');

  if (isDeveloperProtected) {
    return (
      <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#6c47ff]/20 text-[#a78bfa] border border-[#6c47ff]/40">
        <ShieldCheck className="w-3.5 h-3.5" /> Protected with developer exceptions
      </span>
    );
  }

  if (state === 'vpn_warning') {
    return (
      <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/40">
        <ShieldAlert className="w-3.5 h-3.5" /> VPN warning
      </span>
    );
  }

  if (state === 'applying') {
    return (
      <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#3b82f6]/20 text-[#60a5fa] border border-[#3b82f6]/40">
        <Shield className="w-3.5 h-3.5 animate-pulse" /> Applying protection...
      </span>
    );
  }

  if (state === 'protected') {
    return (
      <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#22c55e]/20 text-[#22c55e] border border-[#22c55e]/30">
        <Shield className="w-3.5 h-3.5" /> Protected
      </span>
    );
  }

  if (state === 'warnings') {
    return (
      <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#f59e0b]/20 text-[#fbbf24] border border-[#f59e0b]/40">
        <ShieldCheck className="w-3.5 h-3.5" /> Protected with warnings
      </span>
    );
  }

  return (
    <span className="mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30">
      <ShieldAlert className="w-3.5 h-3.5" /> Inactive
    </span>
  );
}

function PolicyModeBadge({ dnsStatus }) {
  const modeLabel = dnsStatus?.modeLabel ?? 'Strict';
  const isDeveloper = dnsStatus?.mode === 'developer';
  return (
    <span
      className={`mt-1 inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm border ${
        isDeveloper
          ? 'bg-[#6c47ff]/15 text-[#c4b5fd] border-[#6c47ff]/35'
          : 'bg-[#1e1e2e] text-zinc-400 border-[#2a2a3a]'
      }`}
    >
      Mode: {modeLabel}
    </span>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const {
    challenge,
    dnsStatus,
    vpnRuntime,
    lastCheckedAt,
    loadAll,
    refreshVectors,
    reapplyLoading,
    reapplyError,
    reapplyVpnProtection,
  } = useChallengeStore();
  useTicker();

  useEffect(() => {
    loadAll();
    const id = setInterval(() => refreshVectors(), 30000);
    const unsubscribe =
      window.electron?.onEnforcementStatusChanged?.((status) => {
        if (!status.inProgress) refreshVectors();
      }) ?? (() => {});
    return () => {
      clearInterval(id);
      unsubscribe();
    };
  }, [loadAll, refreshVectors]);

  useEffect(() => {
    if (vpnRuntime?.status === 'Challenge failed' || challenge?.status === 'terminated') {
      navigate({ to: '/termination' });
    }
  }, [vpnRuntime?.status, challenge?.status, navigate]);

  const day = challenge?.day ?? 0;
  const total = challenge?.totalDays ?? 30;
  const deposit = challenge?.deposit ?? 500;
  const vpnPaused = vpnRuntime?.challengePaused === true;
  const protectionState = vpnPaused
    ? 'vpn_warning'
    : dnsStatus?.protectionState ?? (dnsStatus?.protectionActive ? 'protected' : 'inactive');
  const showVpnModal =
    vpnPaused && (vpnRuntime?.showModal !== false || !vpnRuntime?.warningAcknowledged);
  const warnings = dnsStatus?.warnings ?? [];
  const errors = dnsStatus?.errors ?? [];
  const secondsAgo = lastCheckedAt ? Math.max(0, Math.floor((Date.now() - lastCheckedAt) / 1000)) : 0;

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <VpnWarningModal
        open={showVpnModal}
        msRemaining={vpnRuntime?.msRemaining ?? 0}
        reapplyLoading={reapplyLoading}
        reapplyError={reapplyError}
        onAcknowledgeAndReapply={() => reapplyVpnProtection()}
      />

      <div className="max-w-7xl mx-auto px-8 py-10">
        <IdentityBanner />

        {vpnPaused && (
          <div className="mb-6 rounded-2xl border border-[#ef4444]/40 bg-[#ef4444]/10 px-5 py-4 text-sm text-[#fca5a5]">
            {vpnRuntime?.status || 'VPN warning — protection re-apply required'}. Disable your VPN
            and re-apply protection before the deadline to continue.
          </div>
        )}

        <div className="flex flex-col items-center my-10">
          <StreakRing current={day} total={total} />
          <div className="mt-8 flex items-center gap-8">
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Progress</p>
              <p className="text-xl text-white mt-1">
                Day {day} of {total}
              </p>
            </div>
            <div className="w-px h-10 bg-[#1e1e2e]" />
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Escrow</p>
              <p className="text-xl text-[#6c47ff] mt-1">₹{deposit} secured</p>
            </div>
            <div className="w-px h-10 bg-[#1e1e2e]" />
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">DNS</p>
              <DnsProtectionBadge dnsStatus={dnsStatus} />
            </div>
            <div className="w-px h-10 bg-[#1e1e2e]" />
            <div className="text-center">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Policy</p>
              <PolicyModeBadge dnsStatus={dnsStatus} />
            </div>
          </div>
        </div>

        {protectionState === 'applying' && (
          <div className="mt-6 rounded-2xl border border-[#3b82f6]/40 bg-[#3b82f6]/10 px-5 py-4 text-sm text-[#93c5fd]">
            Applying protection... DNS, firewall, and browser policies are being enforced in the background.
          </div>
        )}

        {protectionState === 'inactive' && (
          <div className="mt-6 rounded-2xl border border-[#ef4444]/40 bg-[#ef4444]/10 px-5 py-4 text-sm text-[#fca5a5]">
            NetFast protection is inactive. Please restore filtering to continue your commitment.
            {dnsStatus?.error && (
              <span className="block mt-1 text-zinc-400 text-xs">{dnsStatus.error}</span>
            )}
            {dnsStatus?.health?.details && (
              <span className="block mt-1 text-zinc-400 text-xs">{dnsStatus.health.details}</span>
            )}
            {errors.length > 0 && (
              <ul className="mt-2 list-disc list-inside text-xs text-zinc-400">
                {errors.map((msg) => (
                  <li key={msg}>{msg}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {protectionState === 'warnings' && (warnings.length > 0 || errors.length > 0) && (
          <div className="mt-6 rounded-2xl border border-[#f59e0b]/40 bg-[#f59e0b]/10 px-5 py-4 text-sm text-[#fbbf24]">
            NetFast is active but some lockdown checks need attention.
            {warnings.length > 0 && (
              <ul className="mt-2 list-disc list-inside text-xs text-zinc-400">
                {warnings.map((msg) => (
                  <li key={msg}>{msg}</li>
                ))}
              </ul>
            )}
            {errors.length > 0 && (
              <ul className="mt-2 list-disc list-inside text-xs text-[#fca5a5]">
                {errors.map((msg) => (
                  <li key={msg}>{msg}</li>
                ))}
              </ul>
            )}
          </div>
        )}

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
                <span
                  className={`absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping ${
                    protectionState === 'inactive'
                      ? 'bg-[#ef4444]'
                      : protectionState === 'applying'
                        ? 'bg-[#3b82f6]'
                        : 'bg-[#22c55e]'
                  }`}
                />
                <span
                  className={`relative inline-flex w-2 h-2 rounded-full ${
                    protectionState === 'inactive'
                      ? 'bg-[#ef4444]'
                      : protectionState === 'applying'
                        ? 'bg-[#3b82f6]'
                        : protectionState === 'warnings'
                          ? 'bg-[#f59e0b]'
                          : 'bg-[#22c55e]'
                  }`}
                />
              </span>
              Monitoring active — last check {secondsAgo}s ago
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
