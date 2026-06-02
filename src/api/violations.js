import { API_BASE } from '../lib/apiBase';
import { ensureAuth } from './auth';

const getToken = () => localStorage.getItem('fl_token');

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
