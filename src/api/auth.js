import { API_BASE } from '../lib/apiBase';

export async function login(email, password) {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (data.token) localStorage.setItem('fl_token', data.token);
  if (data.userId) localStorage.setItem('fl_user_id', data.userId);
  return data;
}

export async function register(payload) {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (data.token) localStorage.setItem('fl_token', data.token);
  if (data.userId) localStorage.setItem('fl_user_id', data.userId);
  return data;
}

/** Ensures a JWT exists (dev/onboarding flow before a dedicated login UI). */
export async function ensureAuth() {
  if (localStorage.getItem('fl_token')) return;

  let email = localStorage.getItem('fl_email');
  let password = localStorage.getItem('fl_password');
  if (!email) {
    email = `user_${Date.now()}@focuslock.local`;
    password = crypto.randomUUID();
    localStorage.setItem('fl_email', email);
    localStorage.setItem('fl_password', password);
  }

  const loginRes = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const loginData = await loginRes.json();
  if (loginData.token) {
    localStorage.setItem('fl_token', loginData.token);
    if (loginData.userId) localStorage.setItem('fl_user_id', loginData.userId);
    return;
  }

  await register({ email, password });
}
