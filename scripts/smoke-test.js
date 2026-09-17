#!/usr/bin/env node
'use strict';
/**
 * End-to-end check of the whole flow. Requires all three services to be
 * running and `npm run seed` to have been executed.
 *
 * The credential lifecycle parts (rotate, revoke) run against a throwaway
 * application so the running services are never disturbed.
 */
const env = require('./env-file');

// Each service's settings come from its own .env.
const AUTH = env.authBaseUrl();
const SERVICE_A = `http://localhost:${process.env.A_PORT || env.read('a').A_PORT || 3001}`;
const SERVICE_B = (
  process.env.SERVICE_B_BASE_URL ||
  env.read('a').SERVICE_B_BASE_URL ||
  `http://localhost:${env.read('b').B_PORT || 3002}`
).replace(/\/+$/, '');
const ADMIN_KEY = process.env.ADMIN_API_KEY || env.read('auth').ADMIN_API_KEY;

const PROBE_ID = 'smoke-probe';
let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}`);
    if (detail !== undefined) {
      console.log(`      ${JSON.stringify(detail)}`);
    }
  }
}

function section(title) {
  console.log(`\n${title}`);
}

async function admin(method, path, body) {
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
    throw new Error(`${method} ${path} -> ${response.status} ${JSON.stringify(payload)}`);
  }
  return payload;
}

/** The client credentials grant, done by hand so the wire format is visible. */
async function requestToken(clientId, clientSecret, audience, scope) {
  const basic = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
  ).toString('base64');

  const body = new URLSearchParams({grant_type: 'client_credentials', audience});
  if (scope) body.set('scope', scope);

  const response = await fetch(`${AUTH}/oauth/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basic}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  return {status: response.status, body: await response.json().catch(() => undefined)};
}

async function callServiceB(path, token, init = {}) {
  const response = await fetch(`${SERVICE_B}${path}`, {
    ...init,
    headers: {
      ...(token ? {authorization: `Bearer ${token}`} : {}),
      accept: 'application/json',
      ...(init.body ? {'content-type': 'application/json'} : {}),
    },
  });
  return {status: response.status, body: await response.json().catch(() => undefined)};
}

async function introspect(token, callerToken) {
  const response = await fetch(`${AUTH}/oauth/introspect`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${callerToken}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({token}),
  });
  return response.json();
}

async function main() {
  if (!ADMIN_KEY) throw new Error('ADMIN_API_KEY missing; run `npm run bootstrap`');

  section('1. Services are up');
  for (const [name, url] of [
    ['auth-service', AUTH],
    ['service-a', SERVICE_A],
    ['service-b', SERVICE_B],
  ]) {
    const response = await fetch(`${url}/health`).catch(() => undefined);
    check(`${name} responds at ${url}`, response?.ok === true);
  }
  if (failed) {
    console.log('\nStart the services first. Aborting.');
    process.exit(1);
  }

  section('2. Service A can reach service B through the whole chain');
  const demo = await fetch(`${SERVICE_A}/demo/orders/1001`);
  const demoBody = await demo.json().catch(() => undefined);
  check('GET /demo/orders/1001 on service A returns 200', demo.status === 200, demoBody);
  check('the order came back from service B', demoBody?.order?.id === '1001', demoBody);

  section('3. Service B knows who is calling it');
  const who = await fetch(`${SERVICE_A}/demo/whoami`);
  const whoBody = await who.json().catch(() => undefined);
  check('service B identified the caller as service-a', whoBody?.appId === 'service-a', whoBody);
  check('the registry profile arrived', whoBody?.profile?.team === 'licensing-platform', whoBody?.profile);
  check('custom metadata arrived', whoBody?.profile?.metadata?.tenantId === 'tdra', whoBody?.profile?.metadata);
  check('granted scopes are visible', Array.isArray(whoBody?.scopes) && whoBody.scopes.includes('orders:read'), whoBody?.scopes);

  section('4. A valid token is still refused outside its scope');
  const write = await fetch(`${SERVICE_A}/demo/orders`, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({reference: 'SMOKE-1', amount: 100}),
  });
  check('POST /demo/orders is refused with 403 (no orders:write)', write.status === 403);

  section('5. Credential lifecycle on a throwaway application');
  await admin('DELETE', `/admin/applications/${PROBE_ID}`).catch(() => undefined);
  const created = await admin('POST', '/admin/applications?issueSecret=true&secretLabel=smoke', {
    id: PROBE_ID,
    name: 'Smoke Probe',
    description: 'Temporary application used by the smoke test.',
    team: 'platform-qa',
    environment: 'dev',
    tags: ['ephemeral'],
    metadata: {tenantId: 'tdra'},
    allowedAudiences: ['service-b', 'tra-auth'],
    allowedScopes: ['orders:read', 'introspect'],
  });
  const firstSecret = created.secret;
  check('application created with a secret returned once', Boolean(firstSecret?.secret), created.application?.id);
  check('the secret has an expiry', Boolean(firstSecret?.expiresAt), firstSecret?.expiresAt);

  const firstToken = await requestToken(PROBE_ID, firstSecret.secret, 'service-b', 'orders:read');
  check('client_credentials grant returns a token', firstToken.status === 200, firstToken.body);
  check('the token is opaque, not a JWT', /^tra_at_[0-9a-f]{16}\./.test(firstToken.body?.access_token ?? ''), firstToken.body?.access_token?.slice(0, 24));
  check('the token expires in minutes, not hours', firstToken.body?.expires_in <= 3600, firstToken.body?.expires_in);

  const probeRead = await callServiceB('/orders/1001', firstToken.body.access_token);
  check('service B accepts it', probeRead.status === 200, probeRead.body);

  section('6. A token is bound to one audience');
  const introspectToken = await requestToken(PROBE_ID, firstSecret.secret, 'tra-auth', 'introspect');
  const wrongAudience = await callServiceB('/orders/1001', introspectToken.body.access_token);
  check('a token minted for tra-auth is refused by service B', wrongAudience.status === 401, wrongAudience.body);

  section('7. Wrong credentials are refused and reveal nothing');
  const badSecret = await requestToken(PROBE_ID, 'tra_sk_0000000000000000.' + 'A'.repeat(43), 'service-b');
  check('a forged secret returns 401 invalid_client', badSecret.status === 401 && badSecret.body?.error === 'invalid_client', badSecret.body);
  const unknownApp = await requestToken('no-such-app', firstSecret.secret, 'service-b');
  check('an unknown application returns the same error', unknownApp.status === 401 && unknownApp.body?.error === 'invalid_client', unknownApp.body);
  const forbiddenAudience = await requestToken(PROBE_ID, firstSecret.secret, 'some-other-service');
  check('an audience the app may not call is refused', forbiddenAudience.status === 403, forbiddenAudience.body);
  const forbiddenScope = await requestToken(PROBE_ID, firstSecret.secret, 'service-b', 'orders:write');
  check('a scope the app was never granted is refused', forbiddenScope.status === 400 && forbiddenScope.body?.error === 'invalid_scope', forbiddenScope.body);

  section('8. Rotation keeps the old secret working during the grace window');
  const rotated = await admin('POST', `/admin/applications/${PROBE_ID}/secrets/${firstSecret.id}/rotate`, {
    label: 'rotated-by-smoke-test',
    graceMinutes: 10,
    ttlDays: 30,
  });
  const secondSecret = rotated.secret;
  check('a replacement secret was issued', Boolean(secondSecret?.secret), secondSecret?.id);
  check('the old secret has a stop date', Boolean(rotated.previous?.stopsWorkingAt), rotated.previous);

  const oldStillWorks = await requestToken(PROBE_ID, firstSecret.secret, 'service-b');
  check('the old secret still issues tokens during the grace window', oldStillWorks.status === 200, oldStillWorks.body);
  const newWorks = await requestToken(PROBE_ID, secondSecret.secret, 'service-b');
  check('the new secret issues tokens immediately', newWorks.status === 200, newWorks.body);

  section('9. Revocation takes effect at once');
  const doomedToken = await requestToken(PROBE_ID, secondSecret.secret, 'service-b', 'orders:read');
  // Mint the introspecting token from the *other* secret: revoking a secret
  // kills every token it issued, which would otherwise take this test's own
  // introspection token down with it.
  const probeIntrospector = await requestToken(PROBE_ID, firstSecret.secret, 'tra-auth', 'introspect');

  const beforeRevoke = await introspect(doomedToken.body.access_token, probeIntrospector.body.access_token);
  check('the token introspects as active beforehand', beforeRevoke.active === true, beforeRevoke);
  check('introspection carries the caller profile', beforeRevoke.app?.team === 'platform-qa', beforeRevoke.app);

  const revoked = await fetch(
    `${AUTH}/admin/applications/${PROBE_ID}/secrets/${secondSecret.id}?reason=smoke-test`,
    {method: 'DELETE', headers: {'x-admin-key': ADMIN_KEY}},
  );
  const revokedBody = await revoked.json();
  check('revoking the secret also revoked its live tokens', revokedBody.revokedTokens >= 1, revokedBody);

  const afterRevoke = await introspect(doomedToken.body.access_token, probeIntrospector.body.access_token).catch(() => ({active: false}));
  check('the token is now inactive', afterRevoke.active === false, afterRevoke);

  const deadSecret = await requestToken(PROBE_ID, secondSecret.secret, 'service-b');
  check('the revoked secret can no longer mint tokens', deadSecret.status === 401, deadSecret.body);
  console.log(
    `      (service B stops accepting it once its introspection cache turns over — ` +
      `INTROSPECTION_CACHE_MS, default 30s)`,
  );

  section('10. Suspending an application is a kill switch');
  await admin('POST', `/admin/applications/${PROBE_ID}/suspend`, {reason: 'smoke test'});
  const suspended = await requestToken(PROBE_ID, firstSecret.secret, 'service-b');
  check('a suspended application cannot get tokens', suspended.status === 403, suspended.body);
  await admin('POST', `/admin/applications/${PROBE_ID}/activate`);
  const reactivated = await requestToken(PROBE_ID, firstSecret.secret, 'service-b');
  check('reactivating restores it', reactivated.status === 200, reactivated.body);

  section('11. Everything was written to the audit trail');
  const audit = await admin('GET', `/admin/audit?appId=${PROBE_ID}&limit=100`);
  const types = new Set(audit.map(event => event.type));
  for (const type of ['app.created', 'secret.issued', 'secret.rotated', 'secret.revoked', 'token.issued', 'token.denied', 'app.suspended']) {
    check(`recorded ${type}`, types.has(type));
  }
  check('no plaintext secret leaked into the audit trail', !JSON.stringify(audit).includes(firstSecret.secret));

  await admin('DELETE', `/admin/applications/${PROBE_ID}`);
  console.log(`\ncleaned up the ${PROBE_ID} application`);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch(err => {
  console.error('\nsmoke test error:', err.message);
  process.exit(1);
});
