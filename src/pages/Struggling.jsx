import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { ArrowLeft, Check, Eye, Ear, Hand, Wind, Coffee, ChevronRight } from 'lucide-react';
import UrgePauseTimer from '../components/UrgePauseTimer';
import { useChallengeStore } from '../store/challengeStore';

const SENSES = [
  { n: 5, label: 'things you can see', icon: Eye, placeholder: 'e.g. lamp, mug, my hands…' },
  { n: 4, label: 'things you can touch', icon: Hand, placeholder: 'e.g. desk surface, fabric…' },
  { n: 3, label: 'things you can hear', icon: Ear, placeholder: 'e.g. fan hum, traffic…' },
  { n: 2, label: 'things you can smell', icon: Wind, placeholder: 'e.g. coffee, fresh air…' },
  { n: 1, label: 'thing you can taste', icon: Coffee, placeholder: 'e.g. mint, water…' },
];

function Grounding() {
  const [step, setStep] = useState(0);
  const [answers, setAnswers] = useState({});
  const [input, setInput] = useState('');
  const current = SENSES[step];

  if (step >= SENSES.length) {
    return (
      <div className="text-center py-8">
        <div className="w-14 h-14 rounded-full bg-[#22c55e]/15 border border-[#22c55e]/40 flex items-center justify-center mx-auto mb-4">
          <Check className="w-7 h-7 text-[#22c55e]" />
        </div>
        <p className="text-zinc-200 font-medium">Grounded. You're here, in your body.</p>
        <button
          onClick={() => { setStep(0); setAnswers({}); setInput(''); }}
          className="mt-4 text-sm text-zinc-500 hover:text-zinc-300 transition"
        >
          Run again
        </button>
      </div>
    );
  }

  const Icon = current.icon;
  const items = answers[step] || [];
  const remaining = current.n - items.length;

  const add = () => {
    const v = input.trim();
    if (!v) return;
    const next = [...items, v];
    setAnswers({ ...answers, [step]: next });
    setInput('');
    if (next.length >= current.n) {
      setTimeout(() => setStep(step + 1), 400);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-3 mb-5">
        <div className="w-10 h-10 rounded-lg bg-[#6c47ff]/10 border border-[#6c47ff]/30 flex items-center justify-center">
          <Icon className="w-5 h-5 text-[#6c47ff]" />
        </div>
        <div>
          <p className="text-xs uppercase tracking-widest text-zinc-500">
            Step {step + 1} of {SENSES.length}
          </p>
          <p className="text-zinc-200 font-medium">
            Name <span className="text-[#6c47ff]">{remaining}</span> {current.label}
          </p>
        </div>
      </div>

      <div className="flex gap-2 mb-4">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          placeholder={current.placeholder}
          className="flex-1 bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-4 py-2.5 text-zinc-200 placeholder-zinc-600 focus:border-[#6c47ff]/50 focus:outline-none transition text-sm"
        />
        <button
          onClick={add}
          className="px-4 py-2.5 rounded-lg bg-[#6c47ff] hover:bg-[#7c5aff] text-white text-sm font-medium transition"
        >
          Add
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {Array.from({ length: current.n }).map((_, i) => (
          <div
            key={i}
            className={`px-3 py-1.5 rounded-md text-xs border ${
              items[i]
                ? 'bg-[#6c47ff]/10 border-[#6c47ff]/40 text-zinc-200'
                : 'border-dashed border-[#1e1e2e] text-zinc-600'
            }`}
          >
            {items[i] || `#${i + 1}`}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Struggling() {
  const navigate = useNavigate();
  const identity = useChallengeStore((s) => s.challenge?.identityStatement);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200 relative">
      <button
        onClick={() => navigate({ to: '/dashboard' })}
        className="absolute top-6 left-6 flex items-center gap-2 text-zinc-500 hover:text-zinc-300 transition text-sm z-10"
      >
        <ArrowLeft className="w-4 h-4" /> Back to dashboard
      </button>

      <div className="max-w-6xl mx-auto px-8 py-16">
        <div className="text-center mb-12">
          <p className="text-xs uppercase tracking-[0.3em] text-[#6c47ff] mb-3">
            Urge intervention · 5 minutes
          </p>
          <h1 className="text-4xl md:text-5xl font-light text-white">
            You've got this. Wait it out.
          </h1>
          <p className="text-zinc-500 mt-4 text-lg">
            The urge will pass — neurologically, it always does in under 5 minutes.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1px_1fr] gap-10 items-start">
          {/* Left: Box breathing timer */}
          <div className="flex flex-col items-center">
            <p className="text-xs uppercase tracking-widest text-zinc-500 mb-6">
              Box breathing · 4·4·4·4
            </p>
            <UrgePauseTimer />
          </div>

          {/* Divider */}
          <div className="hidden lg:block w-px h-full bg-[#1e1e2e]" />

          {/* Right: 5-4-3-2-1 grounding */}
          <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-6">
            <p className="text-xs uppercase tracking-widest text-zinc-500 mb-1">
              5·4·3·2·1 grounding
            </p>
            <h2 className="text-xl text-white font-light mb-6">Bring yourself back to the room</h2>
            <Grounding />
          </div>
        </div>

        {/* Identity reminder */}
        {identity && (
          <div className="mt-14 border-t border-[#1e1e2e] pt-8 text-center">
            <p className="text-xs uppercase tracking-widest text-zinc-600 mb-3">
              Remember why
            </p>
            <p className="text-lg italic text-[#6c47ff]">"{identity}"</p>
          </div>
        )}

        {/* Escape routes */}
        <div className="mt-12 flex flex-col items-center gap-3">
          <p className="text-xs uppercase tracking-widest text-zinc-600">Still struggling?</p>
          <div className="flex gap-3 flex-wrap justify-center">
            <button
              onClick={() => navigate({ to: '/violations' })}
              className="text-sm text-zinc-500 hover:text-zinc-300 transition flex items-center gap-1"
            >
              Review your integrity log <ChevronRight className="w-3.5 h-3.5" />
            </button>
            <span className="text-zinc-700">·</span>
            <a
              href="https://www.crisistextline.org"
              target="_blank"
              rel="noreferrer"
              className="text-sm text-zinc-500 hover:text-zinc-300 transition flex items-center gap-1"
            >
              Contact a real human <ChevronRight className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
