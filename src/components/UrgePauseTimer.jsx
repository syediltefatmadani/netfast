import { useEffect, useRef, useState } from 'react';
import { Check, RotateCcw, Pause, Play } from 'lucide-react';

const TOTAL = 5 * 60;
// Box breathing: 4s inhale, 4s hold, 4s exhale, 4s hold
const PHASES = [
  { label: 'Breathe in', dur: 4, scale: 1 },
  { label: 'Hold', dur: 4, scale: 1 },
  { label: 'Breathe out', dur: 4, scale: 0.55 },
  { label: 'Hold', dur: 4, scale: 0.55 },
];

export default function UrgePauseTimer() {
  const [remaining, setRemaining] = useState(TOTAL);
  const [running, setRunning] = useState(true);
  const [done, setDone] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (done || !running) return;
    ref.current = setInterval(() => {
      setRemaining((r) => {
        if (r <= 1) {
          clearInterval(ref.current);
          setDone(true);
          return 0;
        }
        return r - 1;
      });
    }, 1000);
    return () => clearInterval(ref.current);
  }, [done, running]);

  const reset = () => {
    clearInterval(ref.current);
    setRemaining(TOTAL);
    setDone(false);
    setRunning(true);
  };

  const elapsed = TOTAL - remaining;
  // Determine current breathing phase
  const cycleLen = PHASES.reduce((s, p) => s + p.dur, 0);
  const inCycle = elapsed % cycleLen;
  let acc = 0;
  let phaseIdx = 0;
  let phaseElapsed = 0;
  for (let i = 0; i < PHASES.length; i++) {
    if (inCycle < acc + PHASES[i].dur) {
      phaseIdx = i;
      phaseElapsed = inCycle - acc;
      break;
    }
    acc += PHASES[i].dur;
  }
  const phase = PHASES[phaseIdx];
  const nextPhase = PHASES[(phaseIdx + 1) % PHASES.length];
  const phaseProgress = phaseElapsed / phase.dur;
  // Interpolate scale toward next phase target
  const scale = phase.scale + (nextPhase.scale - phase.scale) * phaseProgress;

  const mm = String(Math.floor(remaining / 60)).padStart(2, '0');
  const ss = String(remaining % 60).padStart(2, '0');
  const pct = (remaining / TOTAL) * 100;

  if (done) {
    return (
      <div className="flex flex-col items-center gap-6 py-10">
        <div
          className="w-28 h-28 rounded-full bg-[#22c55e]/15 border border-[#22c55e]/40 flex items-center justify-center"
          style={{ animation: 'pop 0.5s ease-out both' }}
        >
          <Check className="w-14 h-14 text-[#22c55e]" />
        </div>
        <p className="text-2xl text-white font-light">You made it. The urge has passed.</p>
        <p className="text-zinc-500 text-sm max-w-sm text-center">
          Notice the difference in your body right now versus 5 minutes ago. Log this win.
        </p>
        <button
          onClick={reset}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#12121a] border border-[#1e1e2e] text-zinc-300 hover:border-[#6c47ff]/40 transition"
        >
          <RotateCcw className="w-4 h-4" /> Run again
        </button>
        <style>{`@keyframes pop { from { transform: scale(0.6); opacity:0 } to { transform: scale(1); opacity:1 } }`}</style>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-8 w-full max-w-md">
      {/* Breathing visualizer */}
      <div className="relative w-64 h-64 flex items-center justify-center">
        <div
          className="absolute inset-0 rounded-full bg-[#6c47ff]/5 border border-[#6c47ff]/10"
        />
        <div
          className="absolute rounded-full bg-gradient-to-br from-[#6c47ff]/30 to-[#6c47ff]/5 border border-[#6c47ff]/30 transition-transform ease-linear"
          style={{
            width: '100%',
            height: '100%',
            transform: `scale(${scale})`,
            transitionDuration: '1000ms',
            boxShadow: '0 0 60px rgba(108,71,255,0.25)',
          }}
        />
        <div className="relative z-10 flex flex-col items-center">
          <div className="text-5xl font-light text-white tabular-nums tracking-tight">
            {mm}:{ss}
          </div>
          <div className="text-sm uppercase tracking-[0.2em] text-[#6c47ff] mt-2">
            {running ? phase.label : 'Paused'}
          </div>
        </div>
      </div>

      <div className="w-full h-1 rounded-full bg-[#1e1e2e] overflow-hidden">
        <div
          className="h-full bg-[#6c47ff] transition-all duration-1000 ease-linear"
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={() => setRunning((r) => !r)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#12121a] border border-[#1e1e2e] text-zinc-300 text-sm hover:border-[#6c47ff]/40 transition"
        >
          {running ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          {running ? 'Pause' : 'Resume'}
        </button>
        <button
          onClick={reset}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-300 transition"
        >
          <RotateCcw className="w-3.5 h-3.5" /> Reset
        </button>
      </div>
    </div>
  );
}
