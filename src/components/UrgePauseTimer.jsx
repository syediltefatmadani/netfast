import { useEffect, useRef, useState } from 'react';
import { Check, RotateCcw } from 'lucide-react';

const TOTAL = 5 * 60;

export default function UrgePauseTimer() {
  const [remaining, setRemaining] = useState(TOTAL);
  const [done, setDone] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (done) return;
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
  }, [done]);

  const reset = () => {
    clearInterval(ref.current);
    setRemaining(TOTAL);
    setDone(false);
  };

  const mm = String(Math.floor(remaining / 60)).padStart(2, '0');
  const ss = String(remaining % 60).padStart(2, '0');
  const pct = (remaining / TOTAL) * 100;

  if (done) {
    return (
      <div className="flex flex-col items-center gap-6 py-10">
        <div
          className="w-24 h-24 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/40 flex items-center justify-center"
          style={{ animation: 'pop 0.5s ease-out both' }}
        >
          <Check className="w-12 h-12 text-[#22c55e]" />
        </div>
        <p className="text-2xl text-white font-light">You made it. That urge has passed.</p>
        <button
          onClick={reset}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#12121a] border border-[#1e1e2e] text-zinc-300 hover:border-[#6c47ff]/40 transition"
        >
          <RotateCcw className="w-4 h-4" /> Reset timer
        </button>
        <style>{`@keyframes pop { from { transform: scale(0.6); opacity:0 } to { transform: scale(1); opacity:1 } }`}</style>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-6 w-full max-w-md">
      <div className="text-8xl font-light text-[#6c47ff] tabular-nums tracking-tight">
        {mm}:{ss}
      </div>
      <div className="w-full h-2 rounded-full bg-[#1e1e2e] overflow-hidden">
        <div
          className="h-full bg-[#6c47ff] transition-all duration-1000 ease-linear"
          style={{ width: `${pct}%` }}
        />
      </div>
      <button
        onClick={reset}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-300 transition"
      >
        <RotateCcw className="w-3.5 h-3.5" /> Reset timer
      </button>
    </div>
  );
}
