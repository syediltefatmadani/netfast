const required = ['MONGO_URI', 'JWT_SECRET'];

function validateEnv() {
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    console.warn(`Warning: missing env vars: ${missing.join(', ')}`);
  }
}

module.exports = { validateEnv };
