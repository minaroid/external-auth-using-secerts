#!/usr/bin/env node
'use strict';
/**
 * Generates the Postman collection.
 *
 * Kept as a generator rather than a hand-edited JSON file so the collection
 * stays in step with the API: change an endpoint here and regenerate, instead
 * of discovering months later that the collection drifted.
 */
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'postman', 'tra-auth.postman_collection.json');

const JSON_HEADER = {key: 'Content-Type', value: 'application/json'};
const ADMIN_HEADER = {key: 'x-admin-key', value: '{{adminKey}}'};

/** Builds a Postman url object from a path and optional query parameters. */
function url(base, segments, query) {
  const raw =
    `{{${base}}}/${segments.join('/')}` +
    (query && query.length
      ? '?' + query.map(q => `${q.key}=${q.value}`).join('&')
      : '');
  return {
    raw,
    host: [`{{${base}}}`],
    path: segments,
    ...(query && query.length ? {query} : {}),
  };
}

function script(lines) {
  return [{listen: 'test', script: {type: 'text/javascript', exec: lines}}];
}

function request({
  name,
  method = 'GET',
  base = 'authUrl',
  segments,
  query,
  headers = [],
  body,
  auth,
  description,
  tests,
}) {
  const item = {name, request: {method, header: headers, url: url(base, segments, query)}};
  if (description) item.request.description = description;
  if (auth) item.request.auth = auth;
  if (body) item.request.body = body;
  if (tests) item.event = script(tests);
  return item;
}

function jsonBody(value) {
  return {
    mode: 'raw',
    raw: JSON.stringify(value, null, 2),
    options: {raw: {language: 'json'}},
  };
}

function formBody(pairs) {
  return {
    mode: 'urlencoded',
    urlencoded: Object.entries(pairs).map(([key, value]) => ({
      key,
      value,
      type: 'text',
    })),
  };
}

const basicAuth = {
  type: 'basic',
  basic: [
    {key: 'username', value: '{{clientId}}', type: 'string'},
    {key: 'password', value: '{{clientSecret}}', type: 'string'},
  ],
};

const bearer = variable => ({
  type: 'bearer',
  bearer: [{key: 'token', value: `{{${variable}}}`, type: 'string'}],
});

// ---------------------------------------------------------------------------
// 1. Health
// ---------------------------------------------------------------------------
const health = {
  name: '1. Health',
  description: 'Unauthenticated liveness probes. Start here to confirm all three services are up.',
  item: [
    request({name: 'auth-service', segments: ['health']}),
    request({name: 'service-a', base: 'serviceAUrl', segments: ['health']}),
    request({name: 'service-b', base: 'serviceBUrl', segments: ['health']}),
  ],
};

// ---------------------------------------------------------------------------
// 2. OAuth
// ---------------------------------------------------------------------------
const oauth = {
  name: '2. OAuth — secret to token',
  description:
    'The exchange at the heart of the design. `POST /oauth/token` is the only ' +
    'endpoint in the whole system that accepts an application secret; ' +
    'everything downstream carries the short lived token it returns.\n\n' +
    'Run **Get access token** first — it saves `accessToken` into the ' +
    'environment, which every service-b request below then uses.',
  item: [
    request({
      name: 'Get access token (for service-b)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: basicAuth,
      body: formBody({
        grant_type: 'client_credentials',
        audience: 'service-b',
        scope: 'orders:read',
      }),
      description:
        'Credentials go in the Authorization header as HTTP Basic. The token ' +
        'comes back scoped to one audience and expires in minutes.\n\n' +
        'Saves `accessToken` for the rest of the collection.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.test('token is opaque, not a JWT', () => pm.expect(body.access_token).to.match(/^tra_at_[0-9a-f]{16}\\./));",
        "pm.test('bound to one audience', () => pm.expect(body.audience).to.eql('service-b'));",
        "pm.test('short lived', () => pm.expect(body.expires_in).to.be.at.most(3600));",
        "pm.environment.set('accessToken', body.access_token);",
        "console.log('saved accessToken, expires in ' + body.expires_in + 's');",
      ],
    }),
    request({
      name: 'Get introspection token (for tra-auth)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: basicAuth,
      body: formBody({
        grant_type: 'client_credentials',
        audience: 'tra-auth',
        scope: 'introspect',
      }),
      description:
        'A token for the auth service itself. This is what a resource server ' +
        'uses to call `/oauth/introspect` — so even verification never sends ' +
        'a secret.\n\nSaves `introspectToken`.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "pm.environment.set('introspectToken', pm.response.json().access_token);",
      ],
    }),
    request({
      name: 'Get access token (credentials in body)',
      method: 'POST',
      segments: ['oauth', 'token'],
      body: formBody({
        grant_type: 'client_credentials',
        audience: 'service-b',
        scope: 'orders:read',
        client_id: '{{clientId}}',
        client_secret: '{{clientSecret}}',
      }),
      description:
        'The RFC 6749 alternative to Basic auth. Sending both at once is ' +
        'rejected rather than silently resolved.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Introspect a token',
      method: 'POST',
      segments: ['oauth', 'introspect'],
      auth: bearer('introspectToken'),
      body: formBody({token: '{{accessToken}}'}),
      description:
        'RFC 7662. What service B calls on every request (cached for 30s).\n\n' +
        'The response carries the calling application\'s registry profile — ' +
        'team, owner, environment, tags, metadata — which the caller cannot ' +
        'forge because it never touches it.\n\n' +
        'Requires **Get introspection token** to have run.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.test('token is active', () => pm.expect(body.active).to.be.true);",
        "pm.test('caller profile is included', () => pm.expect(body.app).to.have.property('team'));",
      ],
    }),
    request({
      name: 'Get a disposable token',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: basicAuth,
      body: formBody({
        grant_type: 'client_credentials',
        audience: 'service-b',
        scope: 'orders:read',
      }),
      description:
        'A throwaway token for the revocation demonstration below, so the ' +
        '`accessToken` the rest of the collection depends on stays alive.\n\n' +
        'Saves `disposableToken`.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "pm.environment.set('disposableToken', pm.response.json().access_token);",
      ],
    }),
    request({
      name: 'Revoke the disposable token',
      method: 'POST',
      segments: ['oauth', 'revoke'],
      auth: bearer('introspectToken'),
      body: formBody({token: '{{disposableToken}}'}),
      description:
        'RFC 7009. Always answers 200 whether or not the token existed, so it ' +
        'cannot be used to probe for valid tokens.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Introspect the revoked token',
      method: 'POST',
      segments: ['oauth', 'introspect'],
      auth: bearer('introspectToken'),
      body: formBody({token: '{{disposableToken}}'}),
      description:
        'Now inactive. Revocation is immediate at the auth service because the ' +
        'token is opaque and has to be checked here — a signed JWT would stay ' +
        'valid until it expired.\n\n' +
        '`active: false` covers every failure mode (expired, revoked, ' +
        'malformed, unknown), so probing this endpoint reveals nothing.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "pm.test('token is no longer active', () => pm.expect(pm.response.json().active).to.be.false);",
      ],
    }),
  ],
};

// ---------------------------------------------------------------------------
// 3. Rejections
// ---------------------------------------------------------------------------
const rejections = {
  name: '3. Rejections — what failure looks like',
  description:
    'Each request here is expected to fail, and the test asserts the failure. ' +
    'Together they are the authorisation model stated as behaviour.',
  item: [
    request({
      name: 'Wrong secret (401 invalid_client)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: {
        type: 'basic',
        basic: [
          {key: 'username', value: '{{clientId}}', type: 'string'},
          {
            key: 'password',
            value: 'tra_sk_0000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            type: 'string',
          },
        ],
      },
      body: formBody({grant_type: 'client_credentials', audience: 'service-b'}),
      description:
        'A wrong secret, an unknown application and a malformed credential all ' +
        'return this same response. The endpoint also burns one scrypt ' +
        'verification on the failure path so response timing does not leak ' +
        'whether the application exists.',
      tests: [
        "pm.test('401', () => pm.response.to.have.status(401));",
        "pm.test('invalid_client', () => pm.expect(pm.response.json().error).to.eql('invalid_client'));",
      ],
    }),
    request({
      name: 'Unknown application (same 401)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: {
        type: 'basic',
        basic: [
          {key: 'username', value: 'no-such-app', type: 'string'},
          {key: 'password', value: '{{clientSecret}}', type: 'string'},
        ],
      },
      body: formBody({grant_type: 'client_credentials', audience: 'service-b'}),
      description: 'Indistinguishable from a wrong secret, on purpose.',
      tests: [
        "pm.test('401', () => pm.response.to.have.status(401));",
        "pm.test('invalid_client', () => pm.expect(pm.response.json().error).to.eql('invalid_client'));",
      ],
    }),
    request({
      name: 'Audience the app may not call (403)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: basicAuth,
      body: formBody({grant_type: 'client_credentials', audience: 'some-other-service'}),
      description:
        'An application can only request tokens for audiences on its ' +
        '`allowedAudiences` list.',
      tests: [
        "pm.test('403', () => pm.response.to.have.status(403));",
        "pm.test('unauthorized_client', () => pm.expect(pm.response.json().error).to.eql('unauthorized_client'));",
      ],
    }),
    request({
      name: 'Scope never granted (400 invalid_scope)',
      method: 'POST',
      segments: ['oauth', 'token'],
      auth: basicAuth,
      body: formBody({
        grant_type: 'client_credentials',
        audience: 'service-b',
        scope: 'orders:write',
      }),
      description:
        '`allowedScopes` is a ceiling, not a grant: a request may ask for a ' +
        'subset of it, never more. The demo service-a is read only.',
      tests: [
        "pm.test('400', () => pm.response.to.have.status(400));",
        "pm.test('invalid_scope', () => pm.expect(pm.response.json().error).to.eql('invalid_scope'));",
      ],
    }),
    request({
      name: 'No token at service B (401)',
      base: 'serviceBUrl',
      segments: ['orders', '1001'],
      description: 'Resource endpoints require a bearer token.',
      tests: ["pm.test('401', () => pm.response.to.have.status(401));"],
    }),
    request({
      name: 'Garbage token at service B (401)',
      base: 'serviceBUrl',
      segments: ['orders', '1001'],
      headers: [
        {
          key: 'Authorization',
          value:
            'Bearer tra_at_0000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      ],
      description:
        'Tokens are opaque, so nothing can be forged from the format alone — ' +
        'the auth service is the only thing that can say a token is real.',
      tests: ["pm.test('401', () => pm.response.to.have.status(401));"],
    }),
    request({
      name: 'Token for the wrong audience (401)',
      base: 'serviceBUrl',
      segments: ['orders', '1001'],
      auth: bearer('introspectToken'),
      description:
        'A token minted for `tra-auth` is refused by service B. This is what ' +
        'stops a service replaying the tokens it receives against a third party.',
      tests: ["pm.test('401', () => pm.response.to.have.status(401));"],
    }),
    request({
      name: 'Valid token, missing scope (403)',
      method: 'POST',
      base: 'serviceBUrl',
      segments: ['orders'],
      headers: [JSON_HEADER],
      auth: bearer('accessToken'),
      body: jsonBody({reference: 'TRA-LIC-9999', amount: 500, currency: 'AED'}),
      description:
        'Authentication succeeded; authorisation did not. `POST /orders` needs ' +
        '`orders:write`, which the token does not carry.',
      tests: [
        "pm.test('403', () => pm.response.to.have.status(403));",
        "pm.test('says which scope is missing', () => pm.expect(pm.response.text()).to.include('orders:write'));",
      ],
    }),
  ],
};

// ---------------------------------------------------------------------------
// 4. Service B
// ---------------------------------------------------------------------------
const serviceB = {
  name: '4. Service B — the protected resource',
  description:
    'Called directly with a bearer token. Service B introspects it at the auth ' +
    'service before any controller code runs.\n\n' +
    'Run **2. OAuth → Get access token** first.',
  item: [
    request({
      name: 'Who am I',
      base: 'serviceBUrl',
      segments: ['whoami'],
      auth: bearer('accessToken'),
      description:
        'Everything service B knows about the caller. The most useful endpoint ' +
        'when wiring up a new client: it shows exactly which registry fields ' +
        'and scopes arrived with the token.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.test('profile carries team and metadata', () => {",
        '  pm.expect(body.profile).to.have.property("team");',
        '  pm.expect(body.profile.metadata).to.have.property("tenantId");',
        '});',
      ],
    }),
    request({
      name: 'Get order',
      base: 'serviceBUrl',
      segments: ['orders', '1001'],
      auth: bearer('accessToken'),
      description:
        'Requires `orders:read`. Visibility is scoped by the caller\'s ' +
        '`metadata.tenantId` from the registry — not by anything in the ' +
        'request — so a service cannot reach another tenant\'s data by asking.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Get order from another tenant (403)',
      base: 'serviceBUrl',
      segments: ['orders', '2001'],
      auth: bearer('accessToken'),
      description:
        'Order 2001 belongs to `other-tenant`. The caller is registered under ' +
        '`tdra`, so service B refuses.',
      tests: ["pm.test('403', () => pm.response.to.have.status(403));"],
    }),
    request({
      name: 'List orders',
      base: 'serviceBUrl',
      segments: ['orders'],
      auth: bearer('accessToken'),
      description: 'Filtered to the caller\'s tenant.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Create order (needs orders:write)',
      method: 'POST',
      base: 'serviceBUrl',
      segments: ['orders'],
      headers: [JSON_HEADER],
      auth: bearer('accessToken'),
      body: jsonBody({reference: 'TRA-LIC-3001', amount: 7800, currency: 'AED'}),
      description:
        'Returns 403 with the seeded service-a credentials. To see it succeed, ' +
        'add `orders:write` to the application\'s `allowedScopes` (see ' +
        '**5. Applications → Update application**), then request a new token ' +
        'with `scope=orders:read orders:write`.',
    }),
  ],
};

// ---------------------------------------------------------------------------
// 5. Service A
// ---------------------------------------------------------------------------
const serviceA = {
  name: '5. Service A — the caller',
  description:
    'Service A holds its own secret and turns it into tokens on demand, so ' +
    'none of these requests take a credential. Each one triggers the full ' +
    'chain: secret → token → call to service B → introspection → response.',
  item: [
    request({
      name: 'Fetch an order through service A',
      base: 'serviceAUrl',
      segments: ['demo', 'orders', '1001'],
      description: 'The end-to-end path, in one request.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'List orders through service A',
      base: 'serviceAUrl',
      segments: ['demo', 'orders'],
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'What service B sees about service A',
      base: 'serviceAUrl',
      segments: ['demo', 'whoami'],
      description:
        'The registry profile that travels with the token, as service B ' +
        'receives it.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Create an order (expected 403)',
      method: 'POST',
      base: 'serviceAUrl',
      segments: ['demo', 'orders'],
      headers: [JSON_HEADER],
      body: jsonBody({reference: 'TRA-LIC-4001', amount: 2200, currency: 'AED'}),
      description:
        'Service A passes service B\'s status code through rather than ' +
        'flattening it into a 500, so you see the real 403.',
      tests: ["pm.test('403', () => pm.response.to.have.status(403));"],
    }),
    request({
      name: 'Drop the cached token',
      method: 'POST',
      base: 'serviceAUrl',
      segments: ['demo', 'refresh-token'],
      description:
        'Forces the next call to mint a fresh token. Use after rotating ' +
        'service A\'s secret.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
  ],
};

// ---------------------------------------------------------------------------
// 6. Applications
// ---------------------------------------------------------------------------
const applications = {
  name: '6. Admin — Applications',
  description:
    'The registry. Everything written here reaches resource servers with the ' +
    'token, so this is where you describe a caller well enough for service B ' +
    'to make decisions about it — and for an on-call engineer to know who to ' +
    'contact.\n\n' +
    'Authenticated with `x-admin-key`. This is a different trust domain from ' +
    'service traffic: it creates the credentials everything else depends on.',
  item: [
    request({
      name: 'Create application (with first secret)',
      method: 'POST',
      segments: ['admin', 'applications'],
      query: [
        {key: 'issueSecret', value: 'true'},
        {key: 'secretLabel', value: 'initial'},
        {key: 'secretTtlDays', value: '90'},
      ],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({
        id: 'billing-worker',
        name: 'Billing Worker',
        description: 'Nightly invoice reconciliation',
        team: 'finance-platform',
        owner: 'Finance Engineering',
        contactEmail: 'finance-eng@example.ae',
        environment: 'dev',
        tags: ['batch', 'internal'],
        metadata: {
          tenantId: 'tdra',
          rateLimitTier: 'gold',
          dataResidency: 'ae',
          costCentre: 'CC-4410',
        },
        audience: 'billing-worker',
        allowedAudiences: ['service-b', 'tra-auth'],
        allowedScopes: ['orders:read', 'introspect'],
        tokenTtlSeconds: 600,
        allowedIps: [],
      }),
      description:
        '`metadata` is free-form: put whatever a resource server needs to ' +
        'route, meter or restrict this caller.\n\n' +
        '`allowedAudiences` is which services it may request tokens for. ' +
        '`allowedScopes` is the ceiling on what it can ever be granted.\n\n' +
        'With `?issueSecret=true` the response includes the plaintext secret — ' +
        'once. It is stored only as a scrypt hash and cannot be recovered.\n\n' +
        'Saves `newAppId` and `newSecretId`.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.environment.set('newAppId', body.application.id);",
        'if (body.secret) {',
        "  pm.environment.set('newSecretId', body.secret.id);",
        "  console.log('SECRET (shown once): ' + body.secret.secret);",
        '}',
      ],
    }),
    request({
      name: 'List applications',
      segments: ['admin', 'applications'],
      query: [
        {key: 'environment', value: 'dev', disabled: true},
        {key: 'team', value: 'finance-platform', disabled: true},
        {key: 'tag', value: 'batch', disabled: true},
        {key: 'status', value: 'active', disabled: true},
      ],
      headers: [ADMIN_HEADER],
      description: 'All filters are optional; enable the ones you need.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Get application',
      segments: ['admin', 'applications', '{{newAppId}}'],
      headers: [ADMIN_HEADER],
      description:
        'Returns the registry entry, a summary of its secrets (metadata only, ' +
        'never hashes) and how many live tokens it currently holds.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Update application',
      method: 'PATCH',
      segments: ['admin', 'applications', '{{newAppId}}'],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({
        environment: 'prod',
        tags: ['batch', 'internal', 'pci'],
        metadata: {
          tenantId: 'tdra',
          rateLimitTier: 'platinum',
          dataResidency: 'ae',
          costCentre: 'CC-4410',
        },
        allowedScopes: ['orders:read', 'orders:write', 'introspect'],
      }),
      description:
        'Changes reach resource servers as soon as their introspection cache ' +
        'turns over — 30 seconds by default. Widening `allowedScopes` does not ' +
        'change tokens already issued; those carry the scopes they were minted ' +
        'with.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Suspend application',
      method: 'POST',
      segments: ['admin', 'applications', '{{newAppId}}', 'suspend'],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({reason: 'investigating unusual traffic'}),
      description:
        'Reversible kill switch: no new tokens, and every outstanding token is ' +
        'revoked. The audit history survives.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Activate application',
      method: 'POST',
      segments: ['admin', 'applications', '{{newAppId}}', 'activate'],
      headers: [ADMIN_HEADER],
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Delete application',
      method: 'DELETE',
      segments: ['admin', 'applications', '{{newAppId}}'],
      headers: [ADMIN_HEADER],
      description:
        'Prefer suspend. Deletion removes secrets and tokens but keeps the ' +
        'audit trail.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
  ],
};

// ---------------------------------------------------------------------------
// 7. Secrets
// ---------------------------------------------------------------------------
const secrets = {
  name: '7. Admin — Secrets',
  description:
    'An application may hold up to five secrets at once. That is what makes ' +
    'rotation possible without a moment where nothing works.\n\n' +
    'These requests act on `{{appId}}` (default `service-a`). Run ' +
    '**Issue secret** first to populate `{{secretId}}`.\n\n' +
    '> **These change real credentials.** Issue, rotate and revoke take effect ' +
    'immediately on whichever application `{{appId}}` names. Harmless against ' +
    'a local stack; point `authUrl` at a shared environment and you are ' +
    'rotating that environment\'s credentials for real.',
  item: [
    request({
      name: 'Issue secret',
      method: 'POST',
      segments: ['admin', 'applications', '{{appId}}', 'secrets'],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({label: 'ci-runner', ttlDays: 90}),
      description:
        'Send `ttlDays`, or `expiresAt` for an exact instant (it wins if both ' +
        'are present). `ttlDays: 0` means no expiry and is discouraged.\n\n' +
        'The plaintext is in the response once and never again.\n\n' +
        'Saves `secretId`.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.test('has an expiry', () => pm.expect(body.expiresAt).to.be.ok);",
        "pm.environment.set('secretId', body.id);",
        "console.log('SECRET (shown once): ' + body.secret);",
      ],
    }),
    request({
      name: 'List secrets',
      segments: ['admin', 'applications', '{{appId}}', 'secrets'],
      headers: [ADMIN_HEADER],
      description:
        'Metadata only — status, expiry, `lastUsedAt`, `useCount`. Use it to ' +
        'find stale credentials before revoking them, and to confirm a ' +
        'rotation has taken effect.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Rotate secret',
      method: 'POST',
      segments: ['admin', 'applications', '{{appId}}', 'secrets', '{{secretId}}', 'rotate'],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({label: 'ci-runner-2026-q4', graceMinutes: 60, ttlDays: 180}),
      description:
        'Issues the replacement immediately and puts the old secret on a ' +
        'countdown, so a running fleet can pick up the new value without a gap. ' +
        '`graceMinutes: 0` revokes the old one at once.\n\n' +
        'Rotation never extends a secret\'s life: an earlier expiry stands.\n\n' +
        'Saves the new id as `secretId`.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        'const body = pm.response.json();',
        "pm.environment.set('secretId', body.secret.id);",
        "console.log('NEW SECRET (shown once): ' + body.secret.secret);",
        "console.log('old secret stops working at: ' + body.previous.stopsWorkingAt);",
      ],
    }),
    request({
      name: 'Change expiry',
      method: 'PATCH',
      segments: ['admin', 'applications', '{{appId}}', 'secrets', '{{secretId}}', 'expiry'],
      headers: [JSON_HEADER, ADMIN_HEADER],
      body: jsonBody({ttlDays: 7}),
      description:
        'Shorten the life of a suspect credential, or extend one about to ' +
        'lapse before a rotation can be scheduled. Send `ttlDays`, or ' +
        '`expiresAt` for an exact instant, or `"expiresAt": null` to clear the ' +
        'expiry entirely (discouraged).\n\n' +
        'A revoked secret cannot be revived this way.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Revoke secret',
      method: 'DELETE',
      segments: ['admin', 'applications', '{{appId}}', 'secrets', '{{secretId}}'],
      query: [{key: 'reason', value: 'leaked in CI logs'}],
      headers: [ADMIN_HEADER],
      description:
        'Break-glass path. The secret stops working at once and every access ' +
        'token it minted is revoked with it — `revokedTokens` in the response ' +
        'tells you how many. Resource servers stop honouring those tokens once ' +
        'their introspection cache turns over.',
      tests: [
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "console.log('revoked tokens: ' + pm.response.json().revokedTokens);",
      ],
    }),
  ],
};

// ---------------------------------------------------------------------------
// 8. Audit
// ---------------------------------------------------------------------------
const audit = {
  name: '8. Admin — Audit',
  description:
    'Append-only record of everything that touches credentials. Without it, ' +
    '"which service used the leaked secret, and when" has no answer.',
  item: [
    request({
      name: 'List audit events',
      segments: ['admin', 'audit'],
      query: [
        {key: 'limit', value: '100'},
        {key: 'appId', value: 'service-a', disabled: true},
        {key: 'type', value: 'token.denied', disabled: true},
        {key: 'outcome', value: 'failure', disabled: true},
      ],
      headers: [ADMIN_HEADER],
      description:
        'Newest first. Event types: `token.issued`, `token.denied`, ' +
        '`token.throttled`, `token.revoked`, `secret.issued`, `secret.rotated`, ' +
        '`secret.revoked`, `secret.expired`, `secret.expiry_changed`, ' +
        '`app.created`, `app.updated`, `app.suspended`, `app.activated`, ' +
        '`app.deleted`.\n\n' +
        'Admin actions are recorded under an `admin:<fingerprint>` actor — the ' +
        'key itself never appears.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
    request({
      name: 'Trace one secret',
      segments: ['admin', 'audit'],
      query: [
        {key: 'appId', value: '{{appId}}'},
        {key: 'limit', value: '1000'},
      ],
      headers: [ADMIN_HEADER],
      description:
        'After a leak, this is the input to deciding what was actually done ' +
        'with the credential: every token issued from it, with source IP and ' +
        'timestamp. Filter the response by `secretId`.',
      tests: ["pm.test('200 OK', () => pm.response.to.have.status(200));"],
    }),
  ],
};

const collection = {
  info: {
    _postman_id: 'b3f1a7c2-6d54-4e18-9f0a-2c7d5e8a1b40',
    name: 'TRA — Service-to-service authentication',
    description:
      '# Service-to-service authentication\n\n' +
      'Three services: an auth service, a caller (service A) and a protected ' +
      'resource (service B).\n\n' +
      'A long lived **application secret** is exchanged for a short lived, ' +
      'audience-bound **access token** at `POST /oauth/token`. That is the only ' +
      'request in the system carrying a secret. Everything downstream carries ' +
      'the token, which service B verifies by calling `POST /oauth/introspect`.\n\n' +
      '## Getting started\n\n' +
      '1. Select the **TRA — local** environment (top right).\n' +
      '2. Fill in `adminKey` and `clientSecret`, or generate the environment ' +
      'pre-filled with `npm run postman:env`.\n' +
      '3. Run **1. Health** to confirm the services are up.\n' +
      '4. Run **2. OAuth → Get access token**. It saves `accessToken`, which ' +
      'every service-b request then uses.\n\n' +
      'Folders 1-5 are the runtime flow; 6-8 are the management API. Requests ' +
      'that are meant to fail say so in their name, and their tests assert the ' +
      'failure — so *Run collection* should come out green end to end.\n\n' +
      '> **Running the whole collection mutates state.** It creates and then ' +
      'deletes a `billing-worker` application, and it issues, rotates and ' +
      'revokes secrets on `{{appId}}`. Safe against a local stack; think ' +
      'before pointing it at anything shared.\n\n' +
      '## Variables\n\n' +
      '| Variable | Meaning |\n|---|---|\n' +
      '| `authUrl`, `serviceAUrl`, `serviceBUrl` | Where each service listens |\n' +
      '| `adminKey` | `ADMIN_API_KEY` from `packages/auth-service/.env` |\n' +
      '| `clientId`, `clientSecret` | From `packages/service-a/.env` |\n' +
      '| `accessToken`, `introspectToken` | Filled in by the OAuth requests |\n' +
      '| `appId`, `secretId`, `newAppId`, `newSecretId` | Filled in by the admin requests |\n',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
  },
  item: [health, oauth, rejections, serviceB, serviceA, applications, secrets, audit],
  variable: [
    {key: 'authUrl', value: 'http://localhost:3000'},
    {key: 'serviceAUrl', value: 'http://localhost:3001'},
    {key: 'serviceBUrl', value: 'http://localhost:3002'},
    {key: 'clientId', value: 'service-a'},
    {key: 'appId', value: 'service-a'},
  ],
};

fs.mkdirSync(path.dirname(OUT), {recursive: true});
fs.writeFileSync(OUT, JSON.stringify(collection, null, 2) + '\n');

const count = collection.item.reduce((sum, folder) => sum + folder.item.length, 0);
console.log(`wrote ${OUT}`);
console.log(`${collection.item.length} folders, ${count} requests`);
