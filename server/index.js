const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const connectDB = require('./config/db');
const errorHandler = require('./middleware/errorHandler');

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

app.use('/api/auth', require('./routes/auth'));
app.use('/api/challenge', require('./routes/challenge'));
app.use('/api/violations', require('./routes/violations'));
app.use('/api/heartbeat', require('./routes/heartbeat'));
app.use('/api/payments', require('./routes/payments'));

app.use(errorHandler);

require('./jobs/refundProcessor');

const PORT = process.env.PORT || 7000;

async function start() {
  await connectDB();
  app.listen(PORT, () => console.log(`FocusLock server running on port ${PORT}`));
}

start().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
});
