#!/usr/bin/env node
'use strict';
/**
 * Writes a Postman environment filled in from each service's .env.
 *
 * The generated file contains live credentials, so it is gitignored. The
 * committed template next to it has the same keys with the secrets blank.
 */
const fs = require('fs');
const path = require('path');
const env = require('./env-file');

const DIR = path.join(__dirname, '..', 'postman');
const TEMPLATE = path.join(DIR, 'tra-auth.postman_environment.template.json');
const OUT = path.join(DIR, 'tra-auth.postman_environment.json');

/** `secret` values are masked in the Postman UI and excluded from exports. */
function variable(key, value, type = 'default') {
  return {key, value, type, enabled: true};
}

function build({filled}) {
  const auth = filled ? env.read('auth') : {};
  const a = filled ? env.read('a') : {};
  const b = filled ? env.read('b') : {};

  return {
    id: filled
      ? 'd41f8a90-3c72-4b6e-8a15-9e0c4b2f7d63'
      : 'a20c5e74-19bf-4d3a-b6c8-5f7e1a9d4c02',
    name: filled ? 'TRA — local' : 'TRA — local (template)',
    values: [
      variable('authUrl', `http://localhost:${auth.AUTH_PORT || 3000}`),
      variable('serviceAUrl', `http://localhost:${a.A_PORT || 3001}`),
      variable('serviceBUrl', `http://localhost:${b.B_PORT || 3002}`),

      // From packages/auth-service/.env — the management API key.
      variable('adminKey', auth.ADMIN_API_KEY || '', 'secret'),

      // From packages/service-a/.env — service A's own credentials.
      variable('clientId', a.CLIENT_ID || 'service-a'),
      variable('clientSecret', a.CLIENT_SECRET || '', 'secret'),

      // Filled in by the OAuth requests' test scripts.
      variable('accessToken', '', 'secret'),
      variable('introspectToken', '', 'secret'),
      variable('disposableToken', '', 'secret'),

      // Which application the admin requests act on.
      variable('appId', 'service-a'),
      variable('secretId', ''),
      variable('newAppId', ''),
      variable('newSecretId', ''),
    ],
    _postman_variable_scope: 'environment',
    _postman_exported_at: new Date().toISOString(),
    _postman_exported_using: 'scripts/postman-env.js',
  };
}

fs.mkdirSync(DIR, {recursive: true});

// The template is committed; regenerate it whenever the keys change.
fs.writeFileSync(TEMPLATE, JSON.stringify(build({filled: false}), null, 2) + '\n');

const filled = build({filled: true});
fs.writeFileSync(OUT, JSON.stringify(filled, null, 2) + '\n', {mode: 0o600});

// Tokens are filled in at run time by the collection's test scripts; only
// the credentials that must come from a .env count as missing.
const RUNTIME_FILLED = ['accessToken', 'introspectToken', 'disposableToken'];
const missing = filled.values
  .filter(v => v.type === 'secret' && !v.value && !RUNTIME_FILLED.includes(v.key))
  .map(v => v.key);

console.log(`wrote ${OUT}`);
if (missing.length) {
  console.log(
    `\nstill blank: ${missing.join(', ')}\n` +
      'Run `npm run bootstrap` and `npm run seed`, then run this again.',
  );
} else {
  console.log('adminKey and clientSecret filled in from the service .env files');
}
console.log('\nIn Postman: Import → both files in postman/, then pick the "TRA — local" environment.');
