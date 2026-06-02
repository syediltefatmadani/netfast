const cron = require('node-cron');
const Challenge = require('../models/Challenge');
const { triggerRefund } = require('../services/paymentService');

cron.schedule('0 0 * * *', async () => {
  const challenges = await Challenge.find({ status: 'active' });
  for (const challenge of challenges) {
    const daysPassed = Math.floor((Date.now() - challenge.createdAt) / 86400000);
    if (daysPassed >= challenge.totalDays) {
      challenge.status = 'completed';
      challenge.completedAt = Date.now();
      await challenge.save();
      await triggerRefund(challenge);
    }
  }
});
