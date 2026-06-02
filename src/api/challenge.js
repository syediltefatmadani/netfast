import { API_BASE } from '../lib/apiBase';
import { ensureAuth } from './auth';

const getToken = () => localStorage.getItem('fl_token');

function toApiPayload(payload) {
  let vpnExemption;
  if (payload.vpnExemption) {
    const v = payload.vpnExemption;
    vpnExemption = {
      adapterName: v.adapterName ?? v.adapter,
      allowedHours: {
        start: v.allowedHours?.start ?? parseInt(String(v.start ?? '9').split(':')[0], 10),
        end: v.allowedHours?.end ?? parseInt(String(v.end ?? '18').split(':')[0], 10),
      },
    };
  }
  return {
    tier: payload.tier,
    identityStatement: payload.identityStatement,
    accountabilityPartner: payload.accountabilityPartner || undefined,
    vpnExemption,
  };
}

export async function getChallenge(challengeId) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/challenge/${challengeId}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!res.ok) throw new Error((await res.json()).message || 'Failed to load challenge');
  return res.json();
}

export async function createChallenge(payload) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(toApiPayload(payload)),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Failed to create challenge');
  const id = data._id || data.id;
  if (id) localStorage.setItem('fl_challenge_id', id);
  return data;
}

export async function sendHeartbeat(payload) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/heartbeat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(payload),
  });
  return res.json();
}
