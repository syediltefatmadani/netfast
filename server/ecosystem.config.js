module.exports = {
  apps: [
    {
      name: 'focuslock-server',
      script: 'server/index.js',
      instances: 1,
      autorestart: true,
      watch: false,
      env_production: { NODE_ENV: 'production', PORT: 7000 },
    },
  ],
};
