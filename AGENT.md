# FocusLock — Cursor Implementation Prompt

> You are working on **FocusLock** — a desktop accountability app built with Electron + MERN stack.
> The React frontend has already been built in Lovable and exists in this repository.
> Your job is to complete the app by building:
> 1. The Express + MongoDB backend
> 2. The Electron main process
> 3. Wire the frontend mocks to real implementations
>
> **Do not modify any existing React component files unless explicitly told to.**
> Only touch `src/api/*.js`, `src/electron/bridge.js`, and `src/store/challengeStore.js` when replacing mocks with real calls.

---

## Current Repo Structure

The Lovable frontend already exists at the root. You will add to it:

```
focuslock/
├── src/                        ← Lovable frontend (DO NOT TOUCH components/pages)
│   ├── electron/bridge.js      ← Replace mocks with real IPC calls
│   ├── api/                    ← Replace mocks with real fetch() calls
│   └── store/challengeStore.js ← Wire to real api/ calls
│
├── electron/                   ← CREATE THIS — Electron main process
│   ├── main.js
│   ├── preload.js
│   ├── watchdog.js
│   ├── dns.js
│   ├── ipc.js
│   └── autolaunch.js
│
├── server/                     ← CREATE THIS — Express backend
│   ├── index.js
│   ├── config/
│   │   ├── db.js
│   │   └── env.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Challenge.js
│   │   ├── ViolationLog.js
│   │   └── HeartbeatLog.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── challenge.js
│   │   ├── violations.js
│   │   ├── heartbeat.js
│   │   └── payments.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── errorHandler.js
│   ├── services/
│   │   ├── violationEngine.js
│   │   ├── emailService.js
│   │   └── paymentService.js
│   └── jobs/
│       ├── heartbeatMonitor.js
│       └── refundProcessor.js
│
├── .env.example
├── package.json                ← Update with all dependencies
└── electron-builder.config.js
```

---

## Step 1 — Root package.json

Update the root `package.json`:

```json
{
  "name": "focuslock",
  "version": "1.0.0",
  "main": "electron/main.js",
  "scripts": {
    "dev": "concurrently \"npm run dev:react\" \"npm run dev:electron\"",
    "dev:react": "vite",
    "dev:electron": "wait-on http://localhost:5173 && electron .",
    "dev:server": "nodemon server/index.js",
    "build": "vite build && electron-builder",
    "server": "node server/index.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "bcryptjs": "^2.4.3",
    "concurrently": "^8.2.0",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "electron-updater": "^6.1.7",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "ioredis": "^5.3.2",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.0.3",
    "node-cron": "^3.0.3",
    "node-windows": "^1.0.0-beta.8",
    "razorpay": "^2.9.2",
    "resend": "^2.0.0",
    "wait-on": "^7.2.0"
  },
  "devDependencies": {
    "electron": "^29.0.0",
    "electron-builder": "^24.9.1",
    "nodemon": "^3.0.2"
  }
}
```

---

## Step 2 — Environment

Create `.env.example`:

```env
PORT=7000
NODE_ENV=development
MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/focuslock
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRES_IN=30d
RAZORPAY_KEY_ID=rzp_test_xxxx
RAZORPAY_KEY_SECRET=your_razorpay_secret
RESEND_API_KEY=re_xxxx
FROM_EMAIL=noreply@focuslock.app
REDIS_URL=redis://localhost:6379
CLIENT_URL=http://localhost:5173
```

---

## Step 3 — server/index.js

```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const connectDB = require('./config/db');
const errorHandler = require('./middleware/errorHandler');

const app = express();
connectDB();

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

app.use('/api/auth',       require('./routes/auth'));
app.use('/api/challenge',  require('./routes/challenge'));
app.use('/api/violations', require('./routes/violations'));
app.use('/api/heartbeat',  require('./routes/heartbeat'));
app.use('/api/payments',   require('./routes/payments'));

app.use(errorHandler);

const PORT = process.env.PORT || 7000;
app.listen(PORT, () => console.log(`FocusLock server running on port ${PORT}`));
```

---

## Step 4 — MongoDB Models

### server/models/User.js

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  email:             { type: String, required: true, unique: true, lowercase: true },
  passwordHash:      { type: String, required: true },
  deviceFingerprint: String,
  createdAt:         { type: Date, default: Date.now }
});

UserSchema.pre('save', async function () {
  if (this.isModified('passwordHash'))
    this.passwordHash = await bcrypt.hash(this.passwordHash, 12);
});

UserSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

module.exports = mongoose.model('User', UserSchema);
```

### server/models/Challenge.js

```javascript
const mongoose = require('mongoose');

const vectorSchema = new mongoose.Schema({
  warnings:   { type: Number, default: 0 },
  terminated: { type: Boolean, default: false },
  log:        { type: Array, default: [] }
}, { _id: false });

const ChallengeSchema = new mongoose.Schema({
  userId:               { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status:               { type: String, enum: ['active','completed','terminated'], default: 'active' },
  tier:                 { type: String, enum: ['Spark','Commit','Forge','Legend'], required: true },
  totalDays:            { type: Number, required: true },
  deposit:              { type: Number, required: true },
  identityStatement:    { type: String, required: true },
  accountabilityPartner: String,
  vpnExemption:         { adapterName: String, allowedHours: { start: Number, end: Number } },
  depositStatus:        { type: String, enum: ['pending','locked','refunded','forfeited','refund_pending_review'], default: 'pending' },
  razorpayPaymentId:    String,
  razorpayOrderId:      String,
  vectors: {
    dns_ipv4:        { type: vectorSchema, default: () => ({}) },
    dns_ipv6:        { type: vectorSchema, default: () => ({}) },
    firefox_doh:     { type: vectorSchema, default: () => ({}) },
    chrome_doh:      { type: vectorSchema, default: () => ({}) },
    windows_doh:     { type: vectorSchema, default: () => ({}) },
    ipv6_tunnel:     { type: vectorSchema, default: () => ({}) },
    hosts_modified:  { type: vectorSchema, default: () => ({}) },
    rogue_dns:       { type: vectorSchema, default: () => ({}) },
    unknown_vpn:     { type: vectorSchema, default: () => ({}) },
    watchdog_killed: { type: vectorSchema, default: () => ({}) },
    app_tampered:    { type: vectorSchema, default: () => ({}) },
  },
  terminatedAt:      Date,
  terminationVector: String,
  completedAt:       Date,
  createdAt:         { type: Date, default: Date.now }
});

module.exports = mongoose.model('Challenge', ChallengeSchema);
```

### server/models/HeartbeatLog.js

```javascript
const mongoose = require('mongoose');

const HeartbeatSchema = new mongoose.Schema({
  challengeId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Challenge', required: true },
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  integrityOk:    Boolean,
  vectors:        Object,
  batteryPercent: Number,
  onACPower:      Boolean,
  timestamp:      { type: Date, default: Date.now }
});

HeartbeatSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });
module.exports = mongoose.model('HeartbeatLog', HeartbeatSchema);
```

### server/models/ViolationLog.js

```javascript
const mongoose = require('mongoose');

const ViolationSchema = new mongoose.Schema({
  challengeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Challenge', required: true },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  vector:      { type: String, required: true },
  action:      { type: String, enum: ['warning','termination'], required: true },
  evidence:    Object,
  timestamp:   { type: Date, default: Date.now }
});

module.exports = mongoose.model('ViolationLog', ViolationSchema);
```

---

## Step 5 — Routes

### server/routes/auth.js

```javascript
const router = require('express').Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

router.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.create({ email, passwordHash: password });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    res.status(201).json({ token, userId: user._id });
  } catch (err) { next(err); }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password)))
      return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    res.json({ token, userId: user._id });
  } catch (err) { next(err); }
});

module.exports = router;
```

### server/routes/challenge.js

```javascript
const router = require('express').Router();
const auth = require('../middleware/auth');
const Challenge = require('../models/Challenge');

const TIER_CONFIG = {
  Spark:  { days: 7,   deposit: 99 },
  Commit: { days: 30,  deposit: 500 },
  Forge:  { days: 60,  deposit: 1200 },
  Legend: { days: 120, deposit: 2000 }
};

router.post('/', auth, async (req, res, next) => {
  try {
    const { tier, identityStatement, accountabilityPartner, vpnExemption } = req.body;
    const config = TIER_CONFIG[tier];
    if (!config) return res.status(400).json({ message: 'Invalid tier' });
    const challenge = await Challenge.create({
      userId: req.user.id, tier,
      totalDays: config.days, deposit: config.deposit,
      identityStatement, accountabilityPartner, vpnExemption
    });
    res.status(201).json(challenge);
  } catch (err) { next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const challenge = await Challenge.findById(req.params.id);
    if (!challenge) return res.status(404).json({ message: 'Not found' });
    const day = Math.floor((Date.now() - challenge.createdAt) / 86400000) + 1;
    res.json({ ...challenge.toObject(), day });
  } catch (err) { next(err); }
});

module.exports = router;
```

### server/routes/heartbeat.js

```javascript
const router = require('express').Router();
const auth = require('../middleware/auth');
const HeartbeatLog = require('../models/HeartbeatLog');
const { processViolation } = require('../services/violationEngine');

router.post('/', auth, async (req, res, next) => {
  try {
    const { challengeId, vectors, integrityOk, batteryPercent, onACPower } = req.body;
    await HeartbeatLog.create({ challengeId, userId: req.user.id, integrityOk, vectors, batteryPercent, onACPower });

    if (!integrityOk && vectors) {
      for (const [vectorName, vectorData] of Object.entries(vectors)) {
        if (vectorData.violated) {
          await processViolation(challengeId, vectorName, { batteryPercent, onACPower, ...vectorData });
        }
      }
    }
    res.json({ received: true, timestamp: Date.now() });
  } catch (err) { next(err); }
});

module.exports = router;
```

### server/routes/violations.js

```javascript
const router = require('express').Router();
const auth = require('../middleware/auth');
const ViolationLog = require('../models/ViolationLog');

router.get('/:challengeId', auth, async (req, res, next) => {
  try {
    const logs = await ViolationLog.find({ challengeId: req.params.challengeId }).sort({ timestamp: -1 });
    res.json(logs);
  } catch (err) { next(err); }
});

module.exports = router;
```

### server/routes/payments.js

```javascript
const router = require('express').Router();
const Razorpay = require('razorpay');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const Challenge = require('../models/Challenge');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

router.post('/create-order', auth, async (req, res, next) => {
  try {
    const { challengeId } = req.body;
    const challenge = await Challenge.findById(challengeId);
    if (!challenge) return res.status(404).json({ message: 'Challenge not found' });
    const order = await razorpay.orders.create({
      amount: challenge.deposit * 100,
      currency: 'INR',
      receipt: `focuslock_${challengeId}`
    });
    challenge.razorpayOrderId = order.id;
    await challenge.save();
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) { next(err); }
});

router.post('/verify', auth, async (req, res, next) => {
  try {
    const { challengeId, razorpayPaymentId, razorpaySignature } = req.body;
    const challenge = await Challenge.findById(challengeId);
    const body = challenge.razorpayOrderId + '|' + razorpayPaymentId;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');
    if (expected !== razorpaySignature) return res.status(400).json({ message: 'Invalid signature' });
    challenge.razorpayPaymentId = razorpayPaymentId;
    challenge.depositStatus = 'locked';
    await challenge.save();
    res.json({ verified: true });
  } catch (err) { next(err); }
});

module.exports = router;
```

---

## Step 6 — Services

### server/services/violationEngine.js

```javascript
const Challenge = require('../models/Challenge');
const ViolationLog = require('../models/ViolationLog');
const { sendViolationEmail, sendTerminationEmail } = require('./emailService');
const { triggerRefundForfeiture } = require('./paymentService');

const VECTOR_GROUPS = {
  dns_reset:   ['dns_ipv4', 'dns_ipv6'],
  doh_browser: ['firefox_doh', 'chrome_doh']
};

function resolveGroup(vector) {
  for (const [group, members] of Object.entries(VECTOR_GROUPS)) {
    if (members.includes(vector)) return group;
  }
  return vector;
}

async function processViolation(challengeId, vector, evidence) {
  const challenge = await Challenge.findById(challengeId);
  if (!challenge || challenge.status !== 'active') return;

  const key = resolveGroup(vector);
  const state = challenge.vectors[key] || challenge.vectors[vector];
  if (!state) return;

  const entry = { timestamp: Date.now(), evidence, vector };

  if (state.warnings === 0) {
    state.warnings = 1;
    state.log.push({ ...entry, action: 'warning' });
    challenge.markModified('vectors');
    await challenge.save();
    await ViolationLog.create({ challengeId, userId: challenge.userId, vector, action: 'warning', evidence });
    await sendViolationEmail(challenge, vector, evidence);
  } else {
    state.warnings = 2;
    state.terminated = true;
    state.log.push({ ...entry, action: 'termination' });
    challenge.status = 'terminated';
    challenge.terminatedAt = Date.now();
    challenge.terminationVector = vector;
    challenge.depositStatus = 'forfeited';
    challenge.markModified('vectors');
    await challenge.save();
    await ViolationLog.create({ challengeId, userId: challenge.userId, vector, action: 'termination', evidence });
    await sendTerminationEmail(challenge, vector, evidence);
    await triggerRefundForfeiture(challenge);
  }
}

module.exports = { processViolation };
```

### server/services/emailService.js

```javascript
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const LABELS = {
  dns_ipv4: 'IPv4 DNS Integrity', dns_ipv6: 'IPv6 DNS Integrity',
  dns_reset: 'DNS Configuration', firefox_doh: 'Firefox Secure DNS',
  chrome_doh: 'Chrome Secure DNS', doh_browser: 'Browser DNS Encryption',
  windows_doh: 'System DNS Encryption', ipv6_tunnel: 'IPv6 Tunnel Adapters',
  hosts_modified: 'Hosts File Integrity', rogue_dns: 'DNS Port Monitor',
  unknown_vpn: 'VPN/Proxy Detection', watchdog_killed: 'Watchdog Process',
  app_tampered: 'App Integrity'
};

async function sendViolationEmail(challenge, vector, evidence) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  const label = LABELS[vector] || vector;

  await resend.emails.send({
    from: process.env.FROM_EMAIL, to: user.email,
    subject: `FocusLock Warning — ${label} check triggered`,
    html: `<h2>⚠️ Integrity Warning</h2>
           <p>A violation was detected on your <strong>${label}</strong> check.</p>
           <p>This is your <strong>first and only warning</strong> for this check.
              A second detection will terminate your challenge.</p>
           <p>Battery: ${evidence.batteryPercent}% ${evidence.onACPower ? '(plugged in)' : '(on battery)'}<br/>
              Time: ${new Date().toLocaleString()}</p>`
  });

  if (challenge.accountabilityPartner) {
    await resend.emails.send({
      from: process.env.FROM_EMAIL, to: challenge.accountabilityPartner,
      subject: `FocusLock — Your friend received a warning`,
      html: `<p>Your accountability partner received a warning on their FocusLock challenge. They may need your support.</p>`
    });
  }
}

async function sendTerminationEmail(challenge, vector, evidence) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  await resend.emails.send({
    from: process.env.FROM_EMAIL, to: user.email,
    subject: `FocusLock — Challenge Terminated`,
    html: `<h2>Challenge Ended</h2>
           <p>Your challenge was terminated due to a second violation on <strong>${LABELS[vector] || vector}</strong>.</p>
           <p>Your deposit of ₹${challenge.deposit} has been forfeited.</p>
           <p>You can appeal in the app or start a new challenge after 24 hours.</p>`
  });
}

async function sendRefundEmail(challenge) {
  const User = require('../models/User');
  const user = await User.findById(challenge.userId);
  await resend.emails.send({
    from: process.env.FROM_EMAIL, to: user.email,
    subject: `🎉 FocusLock — Challenge Complete! Refund Initiated`,
    html: `<h2>You did it.</h2>
           <p>You completed your ${challenge.totalDays}-day challenge with zero violations.</p>
           <p>Your deposit of <strong>₹${challenge.deposit}</strong> has been refunded.</p>`
  });
}

module.exports = { sendViolationEmail, sendTerminationEmail, sendRefundEmail };
```

### server/services/paymentService.js

```javascript
const Razorpay = require('razorpay');
const { sendRefundEmail } = require('./emailService');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

async function triggerRefund(challenge) {
  if (!challenge.razorpayPaymentId) return;
  if (challenge.deposit > 1000) {
    challenge.depositStatus = 'refund_pending_review';
    await challenge.save();
    return;
  }
  await razorpay.payments.refund(challenge.razorpayPaymentId, { amount: challenge.deposit * 100 });
  challenge.depositStatus = 'refunded';
  await challenge.save();
  await sendRefundEmail(challenge);
}

async function triggerRefundForfeiture(challenge) {
  challenge.depositStatus = 'forfeited';
  await challenge.save();
}

module.exports = { triggerRefund, triggerRefundForfeiture };
```

---

## Step 7 — Middleware

### server/middleware/auth.js

```javascript
const jwt = require('jsonwebtoken');
module.exports = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};
```

### server/middleware/errorHandler.js

```javascript
module.exports = (err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    message: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};
```

---

## Step 8 — Cron Jobs

### server/jobs/refundProcessor.js

```javascript
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
```

---

## Step 9 — Electron

### electron/preload.js

```javascript
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('electron', {
  invoke: (channel, data) => ipcRenderer.invoke(channel, data)
});
```

### electron/dns.js

```javascript
const { execSync } = require('child_process');

const DNS = {
  ipv4: { primary: '185.228.168.10', secondary: '185.228.169.11' },
  ipv6: { primary: '2a0d:2a00:1::', secondary: '2a0d:2a00:2::' }
};

function getConnectedAdapters() {
  return execSync('netsh interface show interface', { encoding: 'utf8' })
    .split('\n').filter(l => l.includes('Connected'))
    .map(l => l.trim().split(/\s{2,}/).pop()).filter(Boolean);
}

function applyDNS() {
  for (const adapter of getConnectedAdapters()) {
    try {
      execSync(`netsh interface ipv4 set dns name="${adapter}" static ${DNS.ipv4.primary} primary`);
      execSync(`netsh interface ipv4 add dns name="${adapter}" ${DNS.ipv4.secondary} index=2`);
      execSync(`netsh interface ipv6 set dns name="${adapter}" static ${DNS.ipv6.primary} primary`);
      execSync(`netsh interface ipv6 add dns name="${adapter}" ${DNS.ipv6.secondary} index=2`);
    } catch (e) { console.error(`DNS set failed on ${adapter}:`, e.message); }
  }
}

function verifyDNS() {
  try {
    const ipv4 = execSync('powershell "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"', { encoding: 'utf8' });
    const ipv6 = execSync('powershell "(Get-DnsClientServerAddress -AddressFamily IPv6).ServerAddresses"', { encoding: 'utf8' });
    return {
      ipv4: { intact: ipv4.includes(DNS.ipv4.primary) },
      ipv6: { intact: ipv6.includes(DNS.ipv6.primary) }
    };
  } catch { return { ipv4: { intact: false }, ipv6: { intact: false } }; }
}

function disableIPv6Tunneling() {
  ['teredo', '6to4', 'isatap'].forEach(t => {
    try { execSync(`netsh interface ${t} set state disabled`); } catch {}
  });
}

function verifyTeredoDisabled() {
  try {
    const out = execSync('netsh interface teredo show state', { encoding: 'utf8' });
    return out.toLowerCase().includes('disabled');
  } catch { return false; }
}

module.exports = { applyDNS, verifyDNS, disableIPv6Tunneling, verifyTeredoDisabled };
```

### electron/watchdog.js

```javascript
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { verifyDNS, verifyTeredoDisabled } = require('./dns');

const HOSTS = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
let hostsHash = null;

const hash = f => crypto.createHash('md5').update(fs.readFileSync(f)).digest('hex');

function checkFirefoxDoH() {
  try {
    const p = path.join(process.env.APPDATA, 'Mozilla', 'Firefox', 'Profiles');
    if (!fs.existsSync(p)) return { violated: false };
    for (const profile of fs.readdirSync(p)) {
      const prefs = path.join(p, profile, 'prefs.js');
      if (!fs.existsSync(prefs)) continue;
      const content = fs.readFileSync(prefs, 'utf8');
      if (content.includes('"network.trr.mode", 2') || content.includes('"network.trr.mode", 3'))
        return { violated: true };
    }
  } catch {}
  return { violated: false };
}

function checkChromiumDoH() {
  const files = [
    path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\User Data\\Default\\Preferences'),
    path.join(process.env.LOCALAPPDATA, 'Microsoft\\Edge\\User Data\\Default\\Preferences'),
  ];
  for (const f of files) {
    try {
      if (!fs.existsSync(f)) continue;
      const data = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (data?.dns_over_https?.mode && data.dns_over_https.mode !== 'off') return { violated: true };
    } catch {}
  }
  return { violated: false };
}

function checkRogueDNS() {
  try {
    const out = execSync('netstat -ano | findstr ":53 "', { encoding: 'utf8' });
    for (const line of out.trim().split('\n').filter(Boolean)) {
      const pid = line.trim().split(/\s+/).pop();
      const name = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { encoding: 'utf8' }).split(',')[0].replace(/"/g, '');
      if (!name.includes('svchost') && !name.includes('System')) return { violated: true, process: name };
    }
  } catch {}
  return { violated: false };
}

function checkHostsFile() {
  try {
    const current = hash(HOSTS);
    if (!hostsHash) { hostsHash = current; return { violated: false }; }
    return { violated: current !== hostsHash };
  } catch { return { violated: false }; }
}

function getBatteryState() {
  try {
    const out = execSync('powershell "(Get-WmiObject Win32_Battery | Select-Object EstimatedChargeRemaining, BatteryStatus) | ConvertTo-Json"', { encoding: 'utf8' });
    const b = JSON.parse(out);
    return { percent: b.EstimatedChargeRemaining, onAC: b.BatteryStatus === 2 };
  } catch { return { percent: null, onAC: null }; }
}

function runFullCheck() {
  const dns = verifyDNS();
  const battery = getBatteryState();
  const vectors = {
    dns_ipv4:       { violated: !dns.ipv4.intact },
    dns_ipv6:       { violated: !dns.ipv6.intact },
    firefox_doh:    checkFirefoxDoH(),
    chrome_doh:     checkChromiumDoH(),
    ipv6_tunnel:    { violated: !verifyTeredoDisabled() },
    hosts_modified: checkHostsFile(),
    rogue_dns:      checkRogueDNS(),
  };
  return { integrityOk: !Object.values(vectors).some(v => v.violated), vectors, ...battery, timestamp: Date.now() };
}

module.exports = { runFullCheck, getBatteryState };
```

### electron/ipc.js

```javascript
const { ipcMain } = require('electron');
const { applyDNS, verifyDNS } = require('./dns');
const { runFullCheck, getBatteryState } = require('./watchdog');

let dnsGapStart = null;
const GAP_MS = 2 * 60 * 1000;

ipcMain.handle('get-dns-status', async () => verifyDNS());

ipcMain.handle('get-vector-status', async () => {
  const check = runFullCheck();
  const dnsViolated = check.vectors.dns_ipv4.violated || check.vectors.dns_ipv6.violated;

  if (dnsViolated && !dnsGapStart) {
    dnsGapStart = Date.now();
    applyDNS();
  } else if (!dnsViolated && dnsGapStart) {
    dnsGapStart = null;
  } else if (dnsViolated && dnsGapStart && (Date.now() - dnsGapStart > GAP_MS)) {
    check.vectors.dns_ipv4.reportable = true;
    check.vectors.dns_ipv6.reportable = true;
  }

  return check.vectors;
});

ipcMain.handle('restore-dns', async () => { applyDNS(); return { success: true }; });
ipcMain.handle('get-battery-state', async () => getBatteryState());
```

### electron/main.js

```javascript
const { app, BrowserWindow } = require('electron');
const path = require('path');
const { applyDNS, disableIPv6Tunneling } = require('./dns');
require('./ipc');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200, height: 800, minWidth: 900, minHeight: 600,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0a0a0f'
  });

  const isDev = process.env.NODE_ENV === 'development';
  isDev ? mainWindow.loadURL('http://localhost:5173') : mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  if (isDev) mainWindow.webContents.openDevTools();
}

app.whenReady().then(async () => {
  try { applyDNS(); disableIPv6Tunneling(); } catch (e) { console.error('Startup lockdown failed:', e.message); }
  createWindow();
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
```

---

## Step 10 — Wire Frontend to Real Calls

### src/api/auth.js

```javascript
const BASE = import.meta.env.VITE_API_URL || 'http://localhost:7000';

export async function login(email, password) {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (data.token) localStorage.setItem('fl_token', data.token);
  return data;
}

export async function register(payload) {
  const res = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (data.token) localStorage.setItem('fl_token', data.token);
  return data;
}
```

### src/api/challenge.js

```javascript
const BASE = import.meta.env.VITE_API_URL || 'http://localhost:7000';
const getToken = () => localStorage.getItem('fl_token');

export async function getChallenge(challengeId) {
  const res = await fetch(`${BASE}/api/challenge/${challengeId}`, { headers: { Authorization: `Bearer ${getToken()}` } });
  return res.json();
}

export async function createChallenge(payload) {
  const res = await fetch(`${BASE}/api/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(payload)
  });
  return res.json();
}

export async function sendHeartbeat(payload) {
  const res = await fetch(`${BASE}/api/heartbeat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(payload)
  });
  return res.json();
}
```

### src/electron/bridge.js

```javascript
export const electronBridge = {
  getDNSStatus: async () => {
    if (window.electron) return await window.electron.invoke('get-dns-status');
    return { ipv4: { intact: true }, ipv6: { intact: true }, timestamp: Date.now() };
  },
  getVectorStatus: async () => {
    if (window.electron) return await window.electron.invoke('get-vector-status');
    return {
      dns_ipv4: { warnings: 0 }, dns_ipv6: { warnings: 0 }, firefox_doh: { warnings: 1 },
      chrome_doh: { warnings: 0 }, windows_doh: { warnings: 0 }, ipv6_tunnel: { warnings: 0 },
      hosts_modified: { warnings: 0 }, rogue_dns: { warnings: 0 }, unknown_vpn: { warnings: 0 },
      watchdog_killed: { warnings: 0 }, app_tampered: { warnings: 0 }
    };
  },
  triggerDNSRestore: async () => {
    if (window.electron) return await window.electron.invoke('restore-dns');
    return { success: true };
  },
  getBatteryState: async () => {
    if (window.electron) return await window.electron.invoke('get-battery-state');
    return { percent: 87, onAC: true };
  }
};
```

### src/store/challengeStore.js — add heartbeat loop

```javascript
// Add this action to your existing Zustand store
startHeartbeat: (challengeId) => {
  const loop = setInterval(async () => {
    const { electronBridge } = await import('../electron/bridge');
    const { sendHeartbeat } = await import('../api/challenge');
    const vectorStatus = await electronBridge.getVectorStatus();
    const battery = await electronBridge.getBatteryState();
    const anyViolated = Object.values(vectorStatus).some(v => v.violated);
    await sendHeartbeat({ challengeId, vectors: vectorStatus, integrityOk: !anyViolated, batteryPercent: battery.percent, onACPower: battery.onAC });
    set({ vectorStatus });
  }, 30000);
  return () => clearInterval(loop);
}
```

---

## Step 11 — Build Config

### electron-builder.config.js

```javascript
module.exports = {
  appId: 'app.focuslock.desktop',
  productName: 'FocusLock',
  directories: { output: 'dist-electron' },
  files: ['dist/**/*', 'electron/**/*', 'node_modules/**/*'],
  win: { target: 'nsis', requestedExecutionLevel: 'requireAdministrator' },
  nsis: { oneClick: false, allowToChangeInstallationDirectory: true, runAfterFinish: true }
};
```

### server/ecosystem.config.js (PM2 for VPS)

```javascript
module.exports = {
  apps: [{
    name: 'focuslock-server',
    script: 'server/index.js',
    instances: 1,
    autorestart: true,
    watch: false,
    env_production: { NODE_ENV: 'production', PORT: 7000 }
  }]
};
```

---

## Step 12 — Completion Checklist

Work through these in order:

- [ ] Create all folders and files above
- [ ] `npm install` — verify no errors
- [ ] Copy `.env.example` to `.env` and fill in all values
- [ ] `npm run dev:server` — confirm MongoDB connects
- [ ] Test auth via Postman: `POST /api/auth/register` → `POST /api/auth/login`
- [ ] Test `POST /api/challenge` with JWT token
- [ ] Test `POST /api/heartbeat` with mock vector payload
- [ ] `npm run dev` — confirm Electron loads React at localhost:5173
- [ ] Verify DNS applied on launch via `ipconfig /all` in terminal
- [ ] Trigger test violation by calling `processViolation()` in a scratch script
- [ ] Confirm violation email sends via Resend dashboard
- [ ] `npm run build` — confirm electron-builder packages successfully
- [ ] Deploy server to VPS: `pm2 start ecosystem.config.js --env production`
