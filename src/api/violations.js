import { API_BASE } from '../lib/apiBase';
import { ensureAuth } from './auth';

const getToken = () => localStorage.getItem('fl_token');

export async function reportVpnViolation(challengeId, payload) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/violations/${challengeId}/vpn`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).message || 'Failed to report VPN violation');
  return res.json();
}

export async function getViolationLog(challengeId) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/violations/${challengeId}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return res.json();
}

export async function reportViolation(challengeId, vector, evidence) {
  return { recorded: true };
}
