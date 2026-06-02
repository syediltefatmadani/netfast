const router = require('express').Router();
const auth = require('../middleware/auth');
const ViolationLog = require('../models/ViolationLog');

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
