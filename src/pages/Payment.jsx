import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Lock, Shield } from 'lucide-react';
import { useChallengeStore } from '../store/challengeStore';

export default function Payment() {
  const challenge = useChallengeStore((s) => s.challenge);
  const navigate = useNavigate();
  const [toast, setToast] = useState(false);

  const deposit = challenge?.deposit ?? 500;
  const tier = challenge?.tier ?? 'Commit';
  const days = challenge?.totalDays ?? 30;

  const handlePay = () => {
    setToast(true);
    setTimeout(() => {
      setToast(false);
      navigate({ to: '/dashboard' });
    }, 1800);
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-200 flex items-center justify-center px-6">
      <div className="max-w-md w-full">
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-2xl p-10 text-center">
          <p className="text-xs uppercase tracking-[0.3em] text-zinc-500">Your Tier</p>
          <p className="text-4xl text-white mt-2 font-light">{tier}</p>
          <p className="text-sm text-zinc-500 mt-1">{days} day challenge</p>

          <div className="my-10 flex flex-col items-center gap-4">
            <div className="w-20 h-20 rounded-full bg-[#6c47ff]/10 border border-[#6c47ff]/30 flex items-center justify-center">
              <Lock className="w-9 h-9 text-[#6c47ff]" />
            </div>
            <p className="text-xl text-white">
              Your <span className="text-[#6c47ff] font-medium">₹{deposit}</span> is held in escrow
            </p>
          </div>

          <button
            onClick={handlePay}
            className="w-full py-4 rounded-xl bg-[#6c47ff] text-white hover:bg-[#7c5aff] transition font-medium"
          >
            Pay ₹{deposit} via Razorpay
          </button>

          <p className="text-xs text-zinc-500 mt-6 flex items-center justify-center gap-2">
            <Shield className="w-3.5 h-3.5" />
            Refunded automatically on day {days} with zero violations
          </p>
        </div>
      </div>

      {toast && (
        <div className="fixed bottom-8 left-1/2 -translate-x-1/2 bg-[#12121a] border border-[#6c47ff]/40 text-zinc-200 px-5 py-3 rounded-xl text-sm shadow-2xl">
          Payment integration coming soon — backend required
        </div>
      )}
    </div>
  );
}
