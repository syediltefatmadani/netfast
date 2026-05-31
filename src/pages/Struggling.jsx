import { useNavigate } from '@tanstack/react-router';
import { ArrowLeft } from 'lucide-react';
import UrgePauseTimer from '../components/UrgePauseTimer';
import { useChallengeStore } from '../store/challengeStore';

const ACTIVITIES = [
  { emoji: '🧘', label: '10-minute meditation', sub: 'Sit. Breathe. Observe.' },
  { emoji: '🚿', label: 'Cold shower timer', sub: '3 minutes. Resets your state.' },
  { emoji: '📝', label: 'Journal prompt', sub: '"Write one thing you\'re grateful for right now."' },
];

export default function Struggling() {
  const navigate = useNavigate();
  const identity = useChallengeStore((s) => s.challenge?.identityStatement);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200">
      <button
        onClick={() => navigate({ to: '/dashboard' })}
        className="absolute top-6 left-6 flex items-center gap-2 text-zinc-500 hover:text-zinc-300 transition"
      >
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <div className="max-w-3xl mx-auto px-8 py-20 flex flex-col items-center">
        <h1 className="text-4xl md:text-5xl font-light text-white text-center mb-12">
          You've got this. Wait 5 minutes.
        </h1>

        <UrgePauseTimer />

        <p className="text-zinc-500 mt-10 text-lg">The urge will pass. It always does.</p>

        <div className="grid grid-cols-3 gap-4 mt-14 w-full">
          {ACTIVITIES.map((a) => (
            <button
              key={a.label}
              className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6 text-left hover:border-[#6c47ff]/40 transition"
            >
              <div className="text-3xl mb-3">{a.emoji}</div>
              <p className="text-zinc-200 font-medium">{a.label}</p>
              <p className="text-sm text-zinc-500 mt-1">{a.sub}</p>
            </button>
          ))}
        </div>

        {identity && (
          <p className="text-sm italic text-[#6c47ff] mt-16 text-center">"{identity}"</p>
        )}
      </div>
    </div>
  );
}
