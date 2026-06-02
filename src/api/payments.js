import { API_BASE } from '../lib/apiBase';
import { ensureAuth } from './auth';

const getToken = () => localStorage.getItem('fl_token');

export async function initiateDeposit(challengeId) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/payments/create-order`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify({ challengeId }),
  });
  return res.json();
}

export async function verifyPayment(challengeId, razorpayPaymentId, razorpaySignature) {
  await ensureAuth();
  const res = await fetch(`${API_BASE}/api/payments/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify({ challengeId, razorpayPaymentId, razorpaySignature }),
  });
  return res.json();
}

export async function getPaymentStatus(challengeId) {
  const challenge = await import('./challenge').then((m) => m.getChallenge(challengeId));
  return {
    status: challenge.depositStatus,
    amount: challenge.deposit,
    currency: 'INR',
  };
}
