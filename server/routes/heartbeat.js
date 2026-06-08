const router = require('express').Router();
const auth = require('../middleware/auth');
const HeartbeatLog = require('../models/HeartbeatLog');
const { processViolation } = require('../services/violationEngine');

router.post('/', auth, async (req, res, next) => {
  try {
    const { challengeId, vectors, integrityOk, batteryPercent, onACPower } = req.body;
    await HeartbeatLog.create({
      challengeId,
      userId: req.user.id,
      integrityOk,
      vectors,
      batteryPercent,
      onACPower,
    });

    if (vectors) {
      for (const [vectorName, vectorData] of Object.entries(vectors)) {
        if (vectorName === 'unknown_vpn' && vectorData.vpnHandlerManaged) continue;
        if (vectorData.violated) {
          await processViolation(challengeId, vectorName, {
            batteryPercent,
            onACPower,
            ...vectorData,
          });
        }
      }
    }

    if (req.body.vpnViolation) {
      const { processVpnViolation } = require('../services/violationEngine');
      await processVpnViolation(challengeId, req.body.vpnViolation);
    }
    res.json({ received: true, timestamp: Date.now() });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
