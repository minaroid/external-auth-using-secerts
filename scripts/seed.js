#!/usr/bin/env node
'use strict';
/**
 * Registers the two demo applications and writes their secrets into .env.
 *
 * Re-running is safe: existing applications are updated in place and a fresh
 * secret is issued, which is also a decent illustration of the management API.
 */
const env = require('./env-file');

// The admin key lives in the auth service's own .env and nowhere else.
const AUTH = env.authBaseUrl();
const ADMIN_KEY = process.env.ADMIN_API_KEY || env.read('auth').ADMIN_API_KEY;

if (!ADMIN_KEY || ADMIN_KEY.startsWith('change-me')) {
  console.error(
    'ADMIN_API_KEY is not set in packages/auth-service/.env. ' +
      'Run `npm run bootstrap` first.',
  );
  process.exit(1);
}

/** Which .env each application's credentials belong in. */
const ENV_TARGET = {'service-a': 'a', 'service-b': 'b'};

/**
 * Service A calls service B, and both call the auth service to verify tokens —
 * which is why both list `tra-auth` in allowedAudiences with the `introspect`
 * scope.
 */
const APPLICATIONS = [
  {
    id: 'service-a',
    name: 'Service A',
    description: 'Front-office service that reads licensing orders from service B.',
    team: 'licensing-platform',
    owner: 'Platform Engineering',
    contactEmail: 'platform@example.ae',
    environment: 'dev',
    tags: ['internal', 'caller'],
    metadata: {
      tenantId: 'tdra',
      rateLimitTier: 'gold',
      dataResidency: 'ae',
      costCentre: 'CC-4410',
    },
    audience: 'service-a',
    allowedAudiences: ['service-b', 'tra-auth'],
    // Read only on purpose: the smoke test uses the missing orders:write scope
    // to show a 403 from an otherwise valid token.
    allowedScopes: ['orders:read', 'introspect'],
  },
  {
    id: 'service-b',
    name: 'Service B',
    description: 'Orders service. Verifies inbound tokens with the auth service.',
    team: 'orders-platform',
    owner: 'Orders Engineering',
    contactEmail: 'orders@example.ae',
    environment: 'dev',
    tags: ['internal', 'resource-server'],
    metadata: {tenantId: 'tdra', rateLimitTier: 'silver', dataResidency: 'ae'},
    audience: 'service-b',
    allowedAudiences: ['tra-auth'],
    allowedScopes: ['introspect'],
  },
];

async function api(method, path, body) {
  const response = await fetch(`${AUTH}${path}`, {
    method,
    headers: {
      'x-admin-key': ADMIN_KEY,
      ...(body ? {'content-type': 'application/json'} : {}),
      accept: 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const payload = await response.json().catch(() => undefined);
  if (!response.ok) {
    throw new Error(
      `${method} ${path} -> ${response.status} ${JSON.stringify(payload)}`,
    );
  }
  return payload;
}

async function waitForAuthService() {
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const response = await fetch(`${AUTH}/health`);
      if (response.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(
    `auth service is not answering at ${AUTH}. Start it with \`npm run start:auth\`.`,
  );
}

async function upsert(spec) {
  const {id, ...fields} = spec;
  const existing = await api('GET', '/admin/applications').then(apps =>
    apps.find(app => app.id === id),
  );

  if (existing) {
    await api('PATCH', `/admin/applications/${id}`, fields);
    console.log(`updated application ${id}`);
  } else {
    await api('POST', '/admin/applications', {id, ...fields});
    console.log(`created application ${id}`);
  }

  const issued = await api('POST', `/admin/applications/${id}/secrets`, {
    label: `seed-${new Date().toISOString().slice(0, 10)}`,
    ttlDays: 90,
  });
  console.log(
    `issued secret ${issued.id} for ${id} (expires ${new Date(issued.expiresAt).toDateString()})`,
  );
  return issued;
}

async function main() {
  await waitForAuthService();

  for (const spec of APPLICATIONS) {
    const issued = await upsert(spec);
    const target = ENV_TARGET[spec.id];
    // Each secret is written only to the service that owns it.
    env.merge(target, {CLIENT_ID: spec.id, CLIENT_SECRET: issued.secret});
    console.log(`wrote credentials to ${env.envPath(target)}`);
  }

  console.log('\nstart the services:  npm run start:b   and   npm run start:a');
}

main().catch(err => {
  console.error('seed failed:', err.message);
  process.exit(1);
});
