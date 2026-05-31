export async function getPaymentStatus(challengeId) {
  return { status: 'locked', amount: 500, currency: 'INR', depositedAt: Date.now() - 14 * 86400000 };
}

export async function initiateDeposit(challengeId, amount) {
  return { orderId: 'mock_order_001', amount, currency: 'INR' };
}
