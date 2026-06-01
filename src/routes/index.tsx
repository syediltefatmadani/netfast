import { createFileRoute, redirect } from "@tanstack/react-router";
import { useChallengeStore } from "@/store/challengeStore";

export const Route = createFileRoute("/")({
  beforeLoad: () => {
    const hasChallenge = !!(useChallengeStore as any).getState().challenge;
    throw redirect({ to: hasChallenge ? "/dashboard" : "/onboarding" });
  },
  component: () => null,
});
