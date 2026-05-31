import { useEffect, useState } from 'react';

export default function StreakRing({ current = 0, total = 30, size = 240 }) {
  const stroke = 14;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const targetOffset = circumference - (current / total) * circumference;
  const [offset, setOffset] = useState(circumference);

  useEffect(() => {
    const t = setTimeout(() => setOffset(targetOffset), 80);
    return () => clearTimeout(t);
  }, [targetOffset]);

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1e1e2e"
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#6c47ff"
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.4, 0, 0.2, 1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-6xl font-semibold text-white tabular-nums">{current}</span>
        <span className="text-sm text-zinc-500 mt-1">of {total} days</span>
      </div>
    </div>
  );
}
