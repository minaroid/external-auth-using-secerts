#!/usr/bin/env node
'use strict';
/**
 * Creates each service's .env from its template and generates the two secrets
 * the auth service needs to start. Run once, before starting anything.
 */
const crypto = require('crypto');
const env = require('./env-file');

function main() {
  for (const service of ['auth', 'a', 'b']) {
    if (env.ensure(service)) {
      console.log(`created ${env.envPath(service)}`);
    } else {
      console.log(`${env.envPath(service)} already exists; leaving it alone`);
    }
  }

  const auth = env.read('auth');
  const isPlaceholder = value => !value || value.startsWith('change-me');
  const updates = {};

  if (isPlaceholder(auth.TOKEN_PEPPER)) {
    updates.TOKEN_PEPPER = crypto.randomBytes(48).toString('base64');
  }
  if (isPlaceholder(auth.ADMIN_API_KEY)) {
    updates.ADMIN_API_KEY = crypto.randomBytes(32).toString('hex');
  }

  if (Object.keys(updates).length) {
    env.merge('auth', updates);
    console.log(`\ngenerated in auth-service/.env: ${Object.keys(updates).join(', ')}`);
  } else {
    console.log('\nTOKEN_PEPPER and ADMIN_API_KEY are already set');
  }

  console.log('\nnext:');
  console.log('  npm run build');
  console.log('  npm run start:auth      # terminal 1');
  console.log('  npm run seed            # terminal 2, registers the demo apps');
  console.log('  npm run start:b         # terminal 3');
  console.log('  npm run start:a         # terminal 4');
  console.log('  npm run smoke           # end-to-end check');
}

main();
