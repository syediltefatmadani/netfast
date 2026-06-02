const router = require('express').Router();
const auth = require('../middleware/auth');
const Challenge = require('../models/Challenge');

const TIER_CONFIG = {
  Spark: { days: 7, deposit: 99 },
  Commit: { days: 30, deposit: 500 },
  Forge: { days: 60, deposit: 1200 },
  Legend: { days: 120, deposit: 2000 },
};

router.post('/', auth, async (req, res, next) => {
  try {
    const { tier, identityStatement, accountabilityPartner, vpnExemption } = req.body;
    const config = TIER_CONFIG[tier];
    if (!config) return res.status(400).json({ message: 'Invalid tier' });
    const challenge = await Challenge.create({
      userId: req.user.id,
      tier,
      totalDays: config.days,
      deposit: config.deposit,
      identityStatement,
      accountabilityPartner,
      vpnExemption,
    });
    res.status(201).json(challenge);
  } catch (err) {
    next(err);
  }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const challenge = await Challenge.findById(req.params.id);
    if (!challenge) return res.status(404).json({ message: 'Not found' });
    const day = Math.floor((Date.now() - challenge.createdAt) / 86400000) + 1;
    res.json({ ...challenge.toObject(), day });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
