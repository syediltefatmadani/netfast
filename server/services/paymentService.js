const Razorpay = require('razorpay');
const { sendRefundEmail } = require('./emailService');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

async function triggerRefund(challenge) {
  if (!challenge.razorpayPaymentId) return;
  if (challenge.deposit > 1000) {
    challenge.depositStatus = 'refund_pending_review';
    await challenge.save();
    return;
  }
  await razorpay.payments.refund(challenge.razorpayPaymentId, { amount: challenge.deposit * 100 });
  challenge.depositStatus = 'refunded';
  await challenge.save();
  await sendRefundEmail(challenge);
}

async function triggerRefundForfeiture(challenge) {
  challenge.depositStatus = 'forfeited';
  await challenge.save();
}

module.exports = { triggerRefund, triggerRefundForfeiture };
