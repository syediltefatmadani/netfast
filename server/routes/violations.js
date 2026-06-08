const router = require('express').Router();
const auth = require('../middleware/auth');
const ViolationLog = require('../models/ViolationLog');
const { processVpnViolation } = require('../services/violationEngine');

router.post('/:challengeId/vpn', auth, async (req, res, next) => {
  try {
    const result = await processVpnViolation(req.params.challengeId, req.body);
    res.json({ ...result, timestamp: Date.now() });
  } catch (err) {
    next(err);
  }
});

router.get('/:challengeId', auth, async (req, res, next) => {
  try {
    const logs = await ViolationLog.find({ challengeId: req.params.challengeId }).sort({
      timestamp: -1,
    });
    res.json(logs);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
