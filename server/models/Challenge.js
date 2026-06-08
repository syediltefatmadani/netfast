const mongoose = require('mongoose');

const vectorSchema = new mongoose.Schema(
  {
    warnings: { type: Number, default: 0 },
    terminated: { type: Boolean, default: false },
    log: { type: Array, default: [] },
  },
  { _id: false },
);

const ChallengeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['active', 'completed', 'terminated'], default: 'active' },
  tier: { type: String, enum: ['Spark', 'Commit', 'Forge', 'Legend'], required: true },
  totalDays: { type: Number, required: true },
  deposit: { type: Number, required: true },
  identityStatement: { type: String, required: true },
  accountabilityPartner: String,
  vpnExemption: { adapterName: String, allowedHours: { start: Number, end: Number } },
  depositStatus: {
    type: String,
    enum: ['pending', 'locked', 'refunded', 'forfeited', 'refund_pending_review'],
    default: 'pending',
  },
  razorpayPaymentId: String,
  razorpayOrderId: String,
  vectors: {
    dns_filtering: { type: vectorSchema, default: () => ({}) },
    dns_ipv4: { type: vectorSchema, default: () => ({}) },
    dns_ipv6: { type: vectorSchema, default: () => ({}) },
    firefox_doh: { type: vectorSchema, default: () => ({}) },
    chrome_doh: { type: vectorSchema, default: () => ({}) },
    windows_doh: { type: vectorSchema, default: () => ({}) },
    ipv6_tunnel: { type: vectorSchema, default: () => ({}) },
    hosts_modified: { type: vectorSchema, default: () => ({}) },
    rogue_dns: { type: vectorSchema, default: () => ({}) },
    unknown_vpn: { type: vectorSchema, default: () => ({}) },
    watchdog_killed: { type: vectorSchema, default: () => ({}) },
    app_tampered: { type: vectorSchema, default: () => ({}) },
  },
  terminatedAt: Date,
  terminationVector: String,
  completedAt: Date,
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Challenge', ChallengeSchema);
