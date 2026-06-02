const router = require('express').Router();
const Razorpay = require('razorpay');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const Challenge = require('../models/Challenge');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

router.post('/create-order', auth, async (req, res, next) => {
  try {
    const { challengeId } = req.body;
    const challenge = await Challenge.findById(challengeId);
    if (!challenge) return res.status(404).json({ message: 'Challenge not found' });
    const order = await razorpay.orders.create({
      amount: challenge.deposit * 100,
      currency: 'INR',
      receipt: `focuslock_${challengeId}`,
    });
    challenge.razorpayOrderId = order.id;
    await challenge.save();
    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/verify', auth, async (req, res, next) => {
  try {
    const { challengeId, razorpayPaymentId, razorpaySignature } = req.body;
    const challenge = await Challenge.findById(challengeId);
    const body = challenge.razorpayOrderId + '|' + razorpayPaymentId;
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');
    if (expected !== razorpaySignature) return res.status(400).json({ message: 'Invalid signature' });
    challenge.razorpayPaymentId = razorpayPaymentId;
    challenge.depositStatus = 'locked';
    await challenge.save();
    res.json({ verified: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
