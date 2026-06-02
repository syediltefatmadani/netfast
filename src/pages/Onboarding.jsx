import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Lock, Check } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';
import { createChallenge } from '../api/challenge';

const TIERS = [
  { id: 'spark',  name: 'Spark',  days: 7,   deposit: 99,   note: 'First-timers', locked: false },
  { id: 'commit', name: 'Commit', days: 30,  deposit: 500,  note: 'Core users',   locked: false },
  { id: 'forge',  name: 'Forge',  days: 60,  deposit: 1200, note: 'Serious',      locked: false },
  { id: 'legend', name: 'Legend', days: 120, deposit: 2000, note: 'Unlocks after 1 success', locked: true },
];

export default function Onboarding() {
  const navigate = useNavigate();
  const setChallenge = useChallengeStore((s) => s.setChallenge);
  const [step, setStep] = useState(1);
  const [identity, setIdentity] = useState('');
  const [tier, setTier] = useState(null);
  const [partner, setPartner] = useState('');
  const [usesVpn, setUsesVpn] = useState(false);
  const [vpnAdapter, setVpnAdapter] = useState('');
  const [vpnStart, setVpnStart] = useState('09:00');
  const [vpnEnd, setVpnEnd] = useState('18:00');
  const [agree, setAgree] = useState(false);

  const submit = async () => {
    if (!agree || !identity || !tier) return;
    try {
      const payload = {
        tier: tier.name,
        identityStatement: identity,
        accountabilityPartner: partner || null,
        vpnExemption: usesVpn ? { adapter: vpnAdapter, start: vpnStart, end: vpnEnd } : null,
      };
      const ch = await createChallenge(payload);
      setChallenge({
        id: ch._id || ch.id,
        status: ch.status,
        day: 1,
        totalDays: ch.totalDays,
        deposit: ch.deposit,
        tier: ch.tier,
        identityStatement: ch.identityStatement,
        accountabilityPartner: ch.accountabilityPartner,
        vpnExemption: ch.vpnExemption,
        createdAt: ch.createdAt,
      });
      navigate({ to: '/payment' });
    } catch (err) {
      console.error(err);
      alert(
        err.message?.includes('fetch')
          ? 'Cannot reach the API server. Run: npm run dev:server (from the netfast folder) and ensure VITE_API_URL in .env matches PORT.'
          : err.message || 'Failed to create challenge',
      );
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <div className="max-w-3xl mx-auto px-8 py-12">
        <div className="flex items-center gap-3 mb-12">
          {[1, 2, 3].map((n) => (
            <div key={n} className="flex items-center gap-3 flex-1">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium ${
                  n <= step ? 'bg-[#6c47ff] text-white' : 'bg-[#12121a] text-zinc-600 border border-[#1e1e2e]'
                }`}
              >
                {n < step ? <Check className="w-4 h-4" /> : n}
              </div>
              {n < 3 && <div className={`h-px flex-1 ${n < step ? 'bg-[#6c47ff]' : 'bg-[#1e1e2e]'}`} />}
            </div>
          ))}
        </div>

        {step === 1 && (
          <div className="space-y-8">
            <h1 className="text-5xl font-light text-white">Who are you becoming?</h1>
            <input
              autoFocus
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              placeholder="I am a focused person who controls their mind"
              className="w-full bg-[#12121a] border border-[#1e1e2e] rounded-2xl px-6 py-5 text-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#6c47ff]/60"
            />
            {identity && (
              <p className="text-3xl italic text-[#6c47ff] font-light text-center py-6">
                "{identity}"
              </p>
            )}
            <p className="text-sm text-zinc-500">This will appear on your dashboard every day.</p>
            <div className="flex justify-end">
              <button
                disabled={!identity.trim()}
                onClick={() => setStep(2)}
                className="px-6 py-3 rounded-xl bg-[#6c47ff] text-white hover:bg-[#7c5aff] disabled:opacity-30 disabled:cursor-not-allowed transition"
              >
                Continue →
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-8">
            <h1 className="text-4xl font-light text-white">Choose your challenge</h1>
            <div className="grid grid-cols-2 gap-4">
              {TIERS.map((t) => {
                const active = tier?.id === t.id;
                return (
                  <button
                    key={t.id}
                    disabled={t.locked}
                    onClick={() => setTier(t)}
                    className={`text-left p-6 rounded-2xl border transition relative ${
                      t.locked
                        ? 'bg-[#0d0d14] border-[#1e1e2e] opacity-50 cursor-not-allowed'
                        : active
                        ? 'bg-[#12121a] border-[#6c47ff]'
                        : 'bg-[#12121a] border-[#1e1e2e] hover:border-[#6c47ff]/40'
                    }`}
                  >
                    {t.locked && (
                      <Lock className="w-4 h-4 text-zinc-500 absolute top-4 right-4" />
                    )}
                    <p className="text-xs uppercase tracking-wider text-zinc-500">{t.note}</p>
                    <p className="text-2xl text-white mt-2">{t.name}</p>
                    <p className="text-sm text-zinc-400 mt-1">{t.days} days</p>
                    <p className="text-3xl text-[#6c47ff] mt-4 font-light">₹{t.deposit}</p>
                  </button>
                );
              })}
            </div>
            <div className="flex justify-between">
              <button onClick={() => setStep(1)} className="text-zinc-500 hover:text-zinc-300">← Back</button>
              <button
                disabled={!tier}
                onClick={() => setStep(3)}
                className="px-6 py-3 rounded-xl bg-[#6c47ff] text-white hover:bg-[#7c5aff] disabled:opacity-30 transition"
              >
                Continue →
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-8">
            <h1 className="text-4xl font-light text-white">Accountability</h1>

            <div className="space-y-2">
              <label className="text-sm text-zinc-400">Accountability partner email (optional)</label>
              <input
                type="email"
                value={partner}
                onChange={(e) => setPartner(e.target.value)}
                placeholder="mentor@example.com"
                className="w-full bg-[#12121a] border border-[#1e1e2e] rounded-xl px-4 py-3 text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#6c47ff]/60"
              />
            </div>

            <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <label className="text-zinc-300">Do you use a work or school VPN?</label>
                <button
                  onClick={() => setUsesVpn(!usesVpn)}
                  className={`relative w-12 h-6 rounded-full transition ${usesVpn ? 'bg-[#6c47ff]' : 'bg-[#1e1e2e]'}`}
                >
                  <span
                    className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition ${usesVpn ? 'left-6' : 'left-0.5'}`}
                  />
                </button>
              </div>
              {usesVpn && (
                <div className="mt-5 space-y-4">
                  <div>
                    <label className="text-xs text-zinc-500">VPN adapter name</label>
                    <input
                      value={vpnAdapter}
                      onChange={(e) => setVpnAdapter(e.target.value)}
                      placeholder="e.g. Cisco AnyConnect"
                      className="mt-1 w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#6c47ff]/60"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-zinc-500">Allowed from</label>
                      <input
                        type="time"
                        value={vpnStart}
                        onChange={(e) => setVpnStart(e.target.value)}
                        className="mt-1 w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-3 py-2 text-sm text-white"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-500">Until</label>
                      <input
                        type="time"
                        value={vpnEnd}
                        onChange={(e) => setVpnEnd(e.target.value)}
                        className="mt-1 w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-3 py-2 text-sm text-white"
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            <label className="flex items-start gap-3 cursor-pointer p-5 bg-[#12121a] border border-[#1e1e2e] rounded-2xl">
              <input
                type="checkbox"
                checked={agree}
                onChange={(e) => setAgree(e.target.checked)}
                className="mt-1 accent-[#6c47ff] w-4 h-4"
              />
              <span className="text-sm text-zinc-400 leading-relaxed">
                <span className="text-zinc-200 font-medium">I understand the terms.</span> Any integrity gap exceeding the system restoration window will result in a warning. A second such event on the same check terminates my challenge and forfeits my deposit. There are no exceptions.
              </span>
            </label>

            <div className="flex justify-between">
              <button onClick={() => setStep(2)} className="text-zinc-500 hover:text-zinc-300">← Back</button>
              <button
                disabled={!agree}
                onClick={submit}
                className="px-6 py-3 rounded-xl bg-[#6c47ff] text-white hover:bg-[#7c5aff] disabled:opacity-30 transition"
              >
                Lock In My Commitment →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
