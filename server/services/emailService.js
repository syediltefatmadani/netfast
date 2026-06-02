const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const LABELS = {
  dns_ipv4: 'IPv4 DNS Integrity',
  dns_ipv6: 'IPv6 DNS Integrity',
  dns_reset: 'DNS Configuration',
  firefox_doh: 'Firefox Secure DNS',
  chrome_doh: 'Chrome Secure DNS',
  doh_browser: 'Browser DNS Encryption',
  windows_doh: 'System DNS Encryption',
  ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity',
  rogue_dns: 'DNS Port Monitor',
  unknown_vpn: 'VPN/Proxy Detection',
  watchdog_killed: 'Watchdog Process',
  app_tampered: 'App Integrity',
};

async function sendViolationEmail(challenge, vector, evidence) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  const label = LABELS[vector] || vector;

  await resend.emails.send({
    from: process.env.FROM_EMAIL,
    to: user.email,
    subject: `FocusLock Warning — ${label} check triggered`,
    html: `<h2>⚠️ Integrity Warning</h2>
           <p>A violation was detected on your <strong>${label}</strong> check.</p>
           <p>This is your <strong>first and only warning</strong> for this check.
              A second detection will terminate your challenge.</p>
           <p>Battery: ${evidence.batteryPercent}% ${evidence.onACPower ? '(plugged in)' : '(on battery)'}<br/>
              Time: ${new Date().toLocaleString()}</p>`,
  });

  if (challenge.accountabilityPartner) {
    await resend.emails.send({
      from: process.env.FROM_EMAIL,
      to: challenge.accountabilityPartner,
      subject: `FocusLock — Your friend received a warning`,
      html: `<p>Your accountability partner received a warning on their FocusLock challenge. They may need your support.</p>`,
    });
  }
}

async function sendTerminationEmail(challenge, vector, evidence) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  await resend.emails.send({
    from: process.env.FROM_EMAIL,
    to: user.email,
    subject: `FocusLock — Challenge Terminated`,
    html: `<h2>Challenge Ended</h2>
           <p>Your challenge was terminated due to a second violation on <strong>${LABELS[vector] || vector}</strong>.</p>
           <p>Your deposit of ₹${challenge.deposit} has been forfeited.</p>
           <p>You can appeal in the app or start a new challenge after 24 hours.</p>`,
  });
}

async function sendRefundEmail(challenge) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  await resend.emails.send({
    from: process.env.FROM_EMAIL,
    to: user.email,
    subject: `🎉 FocusLock — Challenge Complete! Refund Initiated`,
    html: `<h2>You did it.</h2>
           <p>You completed your ${challenge.totalDays}-day challenge with zero violations.</p>
           <p>Your deposit of <strong>₹${challenge.deposit}</strong> has been refunded.</p>`,
  });
}

module.exports = { sendViolationEmail, sendTerminationEmail, sendRefundEmail };
