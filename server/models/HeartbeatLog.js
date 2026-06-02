const mongoose = require('mongoose');

const HeartbeatSchema = new mongoose.Schema({
  challengeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Challenge', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  integrityOk: Boolean,
  vectors: Object,
  batteryPercent: Number,
  onACPower: Boolean,
  timestamp: { type: Date, default: Date.now },
});

HeartbeatSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });
module.exports = mongoose.model('HeartbeatLog', HeartbeatSchema);
