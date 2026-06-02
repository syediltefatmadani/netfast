const mongoose = require('mongoose');

const ViolationSchema = new mongoose.Schema({
  challengeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Challenge', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  vector: { type: String, required: true },
  action: { type: String, enum: ['warning', 'termination'], required: true },
  evidence: Object,
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('ViolationLog', ViolationSchema);
