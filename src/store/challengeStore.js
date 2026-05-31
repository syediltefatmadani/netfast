import { create } from 'zustand';
import { electronBridge } from '../electron/bridge';
import { getChallenge } from '../api/challenge';
import { getViolationLog } from '../api/violations';

export const useChallengeStore = create((set, get) => ({
  challenge: null,
  vectorStatus: null,
  dnsStatus: null,
  violationLog: [],
  isLoading: false,
  lastCheckedAt: null,

  loadAll: async (challengeId) => {
    set({ isLoading: true });
    const [challenge, vectorStatus, dnsStatus, violationLog] = await Promise.all([
      getChallenge(challengeId),
      electronBridge.getVectorStatus(),
      electronBridge.getDNSStatus(),
      getViolationLog(challengeId),
    ]);
    set({ challenge, vectorStatus, dnsStatus, violationLog, isLoading: false, lastCheckedAt: Date.now() });
  },

  refreshVectors: async () => {
    const vectorStatus = await electronBridge.getVectorStatus();
    set({ vectorStatus, lastCheckedAt: Date.now() });
  },

  setChallenge: (challenge) => set({ challenge }),
}));
