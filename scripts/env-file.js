'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

/**
 * Each service owns its own .env, next to its package.json.
 *
 * That separation is the point: service A's process cannot read service B's
 * secret, nor the auth service's token pepper and admin key.
 */
const SERVICES = {
  auth: path.join(ROOT, 'packages', 'auth-service'),
  a: path.join(ROOT, 'packages', 'service-a'),
  b: path.join(ROOT, 'packages', 'service-b'),
};

function envPath(service) {
  const dir = SERVICES[service];
  if (!dir) throw new Error(`unknown service "${service}"`);
  return path.join(dir, '.env');
}

function examplePath(service) {
  return path.join(SERVICES[service], '.env.example');
}

/** Reads one service's .env into a plain object. Missing file is empty. */
function read(service) {
  const file = envPath(service);
  if (!fs.existsSync(file)) return {};
  const values = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    values[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return values;
}

/**
 * Writes keys back, preserving comments and the order of lines already there.
 * Keys that are not present yet are appended.
 */
function merge(service, updates) {
  const file = envPath(service);
  const existing = fs.existsSync(file)
    ? fs.readFileSync(file, 'utf8').split('\n')
    : [];
  const remaining = {...updates};

  const lines = existing.map(line => {
    const eq = line.indexOf('=');
    if (eq < 0 || line.trim().startsWith('#')) return line;
    const key = line.slice(0, eq).trim();
    if (key in remaining) {
      const value = remaining[key];
      delete remaining[key];
      return `${key}=${value}`;
    }
    return line;
  });

  for (const [key, value] of Object.entries(remaining)) {
    lines.push(`${key}=${value}`);
  }

  fs.writeFileSync(file, lines.join('\n').replace(/\n+$/, '\n'), {mode: 0o600});
}

/** Creates a service's .env from its .env.example if it does not exist yet. */
function ensure(service) {
  const file = envPath(service);
  if (fs.existsSync(file)) return false;
  fs.copyFileSync(examplePath(service), file);
  fs.chmodSync(file, 0o600);
  return true;
}

/** Base URL of the auth service, derived from its own configuration. */
function authBaseUrl() {
  return (
    process.env.AUTH_BASE_URL ??
    read('a').AUTH_BASE_URL ??
    `http://localhost:${read('auth').AUTH_PORT || 3000}`
  ).replace(/\/+$/, '');
}

module.exports = {ROOT, SERVICES, envPath, read, merge, ensure, authBaseUrl};
