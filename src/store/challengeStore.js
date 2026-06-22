import { create } from 'zustand';
import { electronBridge } from '../electron/bridge';
import { getChallenge } from '../api/challenge';
import { getViolationLog, reportVpnViolation } from '../api/violations';

export const useChallengeStore = create((set, get) => ({
  challenge: null,
  vectorStatus: null,
  dnsStatus: null,
  violationLog: [],
  vpnRuntime: null,
  isLoading: false,
  lastCheckedAt: null,
  reapplyLoading: false,
  reapplyError: null,
  _vectorsInFlight: false,

  loadAll: async (challengeId) => {
    const id = challengeId || localStorage.getItem('fl_challenge_id');
    if (!id) {
      set({ isLoading: false });
      return;
    }
    set({ isLoading: true });
    const context = buildVpnContext(id);
    const [challenge, vectorStatus, dnsStatus, violationLog, vpnRuntime] = await Promise.all([
      getChallenge(id),
      electronBridge.getVectorStatus(context),
      electronBridge.getDNSStatus(),
      getViolationLog(id),
      electronBridge.getVpnChallengeState(context),
    ]);
    await get().syncVpnBackendReport(id, vpnRuntime);
    await electronBridge.syncChallengeState(challenge).catch(() => {});
    set({
      challenge,
      vectorStatus,
      dnsStatus,
      violationLog,
      vpnRuntime,
      isLoading: false,
      lastCheckedAt: Date.now(),
    });
  },

  refreshVectors: async () => {
    // Guard against overlapping refreshes: the 30s interval, the enforcement
    // listener, and the status-refreshed push can all fire close together.
    if (get()._vectorsInFlight) return;
    set({ _vectorsInFlight: true });
    try {
      const id = get().challenge?._id || localStorage.getItem('fl_challenge_id');
      const context = buildVpnContext(id);
      const [vectorStatus, dnsStatus, vpnRuntime] = await Promise.all([
        electronBridge.getVectorStatus(context),
        electronBridge.getDNSStatus(),
        electronBridge.getVpnChallengeState(context),
      ]);
      if (id) await get().syncVpnBackendReport(id, vpnRuntime);
      set({ vectorStatus, dnsStatus, vpnRuntime, lastCheckedAt: Date.now() });
    } finally {
      set({ _vectorsInFlight: false });
    }
  },

  syncVpnBackendReport: async (challengeId, vpnRuntime) => {
    const report = vpnRuntime?.pendingBackendReport;
    if (!report || !challengeId) return;
    try {
      await reportVpnViolation(challengeId, report);
      if (report.challengeFailed) {
        const challenge = await getChallenge(challengeId);
        set({ challenge });
      }
    } catch (e) {
      console.error('VPN violation report failed', e);
    }
  },

  reapplyVpnProtection: async () => {
    const id = get().challenge?._id || localStorage.getItem('fl_challenge_id');
    if (!id) return;
    set({ reapplyLoading: true, reapplyError: null });
    try {
      await electronBridge.vpnAcknowledgeWarning();
      const context = buildVpnContext(id);
      const result = await electronBridge.vpnReapplyProtection(context);
      if (!result.ok) {
        set({
          reapplyLoading: false,
          reapplyError: result.message || 'Re-apply failed.',
        });
        const vpnRuntime = await electronBridge.getVpnChallengeState(context);
        set({ vpnRuntime });
        return result;
      }
      const [vpnRuntime, dnsStatus, vectorStatus] = await Promise.all([
        electronBridge.getVpnChallengeState(context),
        electronBridge.getDNSStatus(),
        electronBridge.getVectorStatus(context),
      ]);
      set({
        reapplyLoading: false,
        reapplyError: null,
        vpnRuntime,
        dnsStatus,
        vectorStatus,
        lastCheckedAt: Date.now(),
      });
      return result;
    } catch (e) {
      set({
        reapplyLoading: false,
        reapplyError: e.message || 'Re-apply failed.',
      });
      throw e;
    }
  },

  setChallenge: (challenge) => set({ challenge }),

  startHeartbeat: (challengeId) => {
    const loop = setInterval(async () => {
      const { electronBridge } = await import('../electron/bridge');
      const { sendHeartbeat } = await import('../api/challenge');
      const context = buildVpnContext(challengeId);
      const vectorStatus = await electronBridge.getVectorStatus(context);
      const vpnRuntime = await electronBridge.getVpnChallengeState(context);
      await get().syncVpnBackendReport(challengeId, vpnRuntime);

      const challengePaused = vpnRuntime?.challengePaused === true;
      const anyViolated = Object.entries(vectorStatus).some(
        ([k, v]) => v.violated && k !== 'unknown_vpn',
      );
      const battery = await electronBridge.getBatteryState();

      await sendHeartbeat({
        challengeId,
        vectors: vectorStatus,
        integrityOk: challengePaused ? false : !anyViolated,
        challengePaused,
        vpnRuntime,
        vpnViolation: vpnRuntime?.pendingBackendReport || undefined,
        batteryPercent: battery.percent,
        onACPower: battery.onAC,
      });

      set({ vectorStatus, vpnRuntime });
    }, 30000);
    return () => clearInterval(loop);
  },
}));

function buildVpnContext(challengeId) {
  return {
    challengeId,
    userId: localStorage.getItem('fl_user_id') || undefined,
    deviceId: localStorage.getItem('fl_device_id') || undefined,
  };
}
