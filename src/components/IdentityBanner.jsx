import { useChallengeStore } from '../store/challengeStore';

export default function IdentityBanner() {
  const challenge = useChallengeStore((s) => s.challenge);
  const text = challenge?.identityStatement || 'I am becoming who I choose to be.';

  return (
    <div
      className="text-center py-6"
      style={{ animation: 'identity-fade 1s ease-out both' }}
    >
      <p className="text-xs uppercase tracking-[0.3em] text-zinc-600 mb-3">Your Identity</p>
      <p className="text-2xl italic text-[#6c47ff] font-light">"{text}"</p>
      <style>{`
        @keyframes identity-fade {
          from { opacity: 0; transform: translateY(-6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
