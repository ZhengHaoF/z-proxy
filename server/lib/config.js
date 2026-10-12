'use strict';

require('./env').load();

function integer(env, name, fallback, min, max) {
  const raw = env[name] === undefined ? String(fallback) : env[name];
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return value;
}

function readConfig(env = process.env) {
  const development = env.ALLOW_INSECURE_DEV === '1';
  const adminEnabled = env.ADMIN_ENABLED !== '0';
  const secret = env.PROXY_TOKEN || (development ? 'z-proxy-dev' : '');
  const adminPassword = env.ADMIN_PASSWORD || (development ? 'admin' : '');
  const weak = new Set(['admin', 'change-me', 'z-proxy-dev']);
  if (!development && (secret.trim().length < 24 || weak.has(secret))) {
    throw new Error('PROXY_TOKEN must contain at least 24 characters; generate a random secret');
  }
  if (!development && adminEnabled && (adminPassword.trim().length < 12 || weak.has(adminPassword))) {
    throw new Error('ADMIN_PASSWORD must contain at least 12 characters, or set ADMIN_ENABLED=0');
  }
  const host = env.HOST || (development ? '127.0.0.1' : '0.0.0.0');
  const adminHost = env.ADMIN_HOST || '127.0.0.1';
  if (development && (![host, adminHost].every(h => ['127.0.0.1', '::1', 'localhost'].includes(h)))) {
    throw new Error('ALLOW_INSECURE_DEV requires loopback-only HOST and ADMIN_HOST');
  }
  return Object.freeze({
    secret, adminPassword, development, adminEnabled, host, adminHost,
    port: integer(env, 'PORT', 8443, 1, 65535),
    adminPort: integer(env, 'ADMIN_PORT', 9090, 1, 65535),
    idleTimeoutMs: integer(env, 'IDLE_TIMEOUT', 300, 0, 86400) * 1000,
    handshakeTimeoutMs: integer(env, 'HANDSHAKE_TIMEOUT_MS', 10000, 50, 120000),
    dnsTimeoutMs: integer(env, 'DNS_TIMEOUT_MS', 5000, 50, 120000),
    connectTimeoutMs: integer(env, 'CONNECT_TIMEOUT_MS', 10000, 50, 120000),
    setupTimeoutMs: integer(env, 'SETUP_TIMEOUT_MS', 30000, 50, 300000),
    httpTimeoutMs: integer(env, 'HTTP_TIMEOUT_MS', 60000, 50, 300000),
    maxConnections: integer(env, 'MAX_CONNECTIONS', 1024, 1, 100000),
  });
}

module.exports = { readConfig };
