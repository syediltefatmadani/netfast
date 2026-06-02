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
    const id = challengeId || localStorage.getItem('fl_challenge_id');
    if (!id) {
      set({ isLoading: false });
      return;
    }
    set({ isLoading: true });
    const [challenge, vectorStatus, dnsStatus, violationLog] = await Promise.all([
      getChallenge(id),
      electronBridge.getVectorStatus(),
      electronBridge.getDNSStatus(),
      getViolationLog(id),
    ]);
    set({ challenge, vectorStatus, dnsStatus, violationLog, isLoading: false, lastCheckedAt: Date.now() });
  },

  refreshVectors: async () => {
    const vectorStatus = await electronBridge.getVectorStatus();
    set({ vectorStatus, lastCheckedAt: Date.now() });
  },

  setChallenge: (challenge) => set({ challenge }),

  startHeartbeat: (challengeId) => {
    const loop = setInterval(async () => {
      const { electronBridge } = await import('../electron/bridge');
      const { sendHeartbeat } = await import('../api/challenge');
      const vectorStatus = await electronBridge.getVectorStatus();
      const battery = await electronBridge.getBatteryState();
      const anyViolated = Object.values(vectorStatus).some((v) => v.violated);
      await sendHeartbeat({
        challengeId,
        vectors: vectorStatus,
        integrityOk: !anyViolated,
        batteryPercent: battery.percent,
        onACPower: battery.onAC,
      });
      set({ vectorStatus });
    }, 30000);
    return () => clearInterval(loop);
  },
}));
