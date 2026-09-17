# Service-to-service authentication

Three LoopBack 4 services demonstrating how service A calls service B without
either of them ever putting a long-lived secret on the wire between them.

```
                    ┌──────────────────┐
                    │   auth-service   │  application registry
                    │                  │  secret lifecycle
                    │  /oauth/token    │  token issuance
                    │  /oauth/introspect  token verification
                    └──────────────────┘
                       ▲            ▲
        ① secret →     │            │   ③ is this token real?
           token       │            │      who is the caller?
                       │            │
              ┌────────────┐   ┌────────────┐
              │ service-a  │──▶│ service-b  │
              └────────────┘ ② └────────────┘
                          Bearer <short-lived token>
```

1. **Service A exchanges its secret for a token.** The secret goes to exactly
   one endpoint, `POST /oauth/token`, and nowhere else.
2. **Service A calls service B with the token.** It expires in ten minutes and
   is valid only for service B.
3. **Service B asks the auth service whether the token is real.** The answer
   carries the caller's registry profile: team, owner, environment, tenant and
   any other attributes you have recorded.

The secret never reaches service B, so a compromised service B cannot
impersonate service A anywhere. That is the property you asked for: the secret
generates something else, and only that something else travels.

## Why this shape

| Decision | Reason |
|---|---|
| **No certificates** | No CA, no rotation of key material on every host, no TLS stack surgery. A secret is a string; every language and every deployment tool already knows how to carry one. |
| **Opaque tokens, not JWTs** | A JWT is valid until it expires, because nothing checks back. An opaque token is checked against the issuer, so revocation is immediate. It also means no signing keys to distribute or rotate. |
| **Tokens minted per audience** | A token for service B is rejected by service C. Service B cannot replay what it receives. |
| **Scopes on every endpoint** | A valid token still gets a 403 if it was not granted the scope. Authentication and authorisation stay separate. |
| **Several secrets per application** | Rotation with an overlap window, so a running fleet moves over without a gap. |
| **Introspection is itself authenticated** | Service B holds credentials too, and uses a token to call the auth service. Nothing anywhere sends a secret on a routine request. |

## Quick start

```bash
npm install
npm run bootstrap        # creates a .env per service, generates the auth
                         # service's TOKEN_PEPPER and ADMIN_API_KEY
npm run build

npm run start:auth       # terminal 1 — port 3000
npm run seed             # terminal 2 — registers service-a and service-b,
                         #              writes each secret into that service's
                         #              own .env
npm run start:b          # terminal 3 — port 3002
npm run start:a          # terminal 4 — port 3001

npm run smoke            # end-to-end check: 40 assertions
```

`npm run start:all` runs all three in one terminal once seeding is done.

Ports come from each service's own `.env` (`AUTH_PORT`, `A_PORT`, `B_PORT`);
change them if something else on your machine already holds 3000-3002.

Try it:

```bash
curl localhost:3001/demo/orders/1001   # service A → service B → auth service
curl localhost:3001/demo/whoami        # what service B sees about service A
```

API explorers: `localhost:3000/explorer`, `:3001/explorer`, `:3002/explorer`.

### Architecture overview (PDF)

[docs/architecture-overview.pdf](docs/architecture-overview.pdf) — a nine page,
diagram-led summary for people who need the shape of the system rather than the
code: the three services, the request flow, the registry and how to manage it,
the secret lifecycle, and the containment options.

```bash
npm run docs:pdf         # re-render from docs/architecture-overview.html
```

It is authored as HTML with inline SVG and rendered with headless Chrome, so
the diagrams stay editable text and vector art.

### Postman

```bash
npm run postman          # regenerates the collection and a filled-in environment
```

Import both files from [postman/](postman/):

- `tra-auth.postman_collection.json` — 42 requests across 8 folders
- `tra-auth.postman_environment.json` — generated from your service `.env`
  files, so `adminKey` and `clientSecret` are already filled in. It is
  gitignored; `…environment.template.json` beside it is the committed,
  secret-free version.

Pick the **TRA — local** environment, run **2. OAuth → Get access token**, and
everything else works — the test script saves the token into the environment
for the rest of the collection.

The collection doubles as a test suite: requests that are meant to fail say so
in their name and assert the failure, so *Run collection* comes out green end
to end (42 requests, 51 assertions). It is generated by
[scripts/build-postman.js](scripts/build-postman.js) rather than hand-edited,
so it stays in step with the API.

Note that a full run mutates state: it creates and deletes a `billing-worker`
application, and issues, rotates and revokes secrets on `{{appId}}`.

## The flow in detail

### Getting a token

```bash
curl -u "service-a:$SERVICE_A_CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d audience=service-b \
  -d scope="orders:read" \
  localhost:3000/oauth/token
```

```json
{
  "access_token": "tra_at_9f2c4ab1e0d73a15.KZ8v...",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "orders:read",
  "audience": "service-b"
}
```

Service A does this automatically. `ServiceTokenClient` caches the token,
refreshes it a minute before expiry, collapses concurrent refreshes into one
request, and retries once with a fresh token if a downstream call returns 401.

### Calling service B

```bash
curl -H "Authorization: Bearer $TOKEN" localhost:3002/orders/1001
```

### What service B does with it

`@authenticate('service-token')` introspects the token before the controller
method runs; `@requireScopes('orders:read')` checks the granted scopes. The
result is bound as the current principal:

```ts
@authenticate(SERVICE_TOKEN_STRATEGY)
export class OrdersController {
  constructor(@inject(SecurityBindings.USER) private caller: ServicePrincipal) {}

  @requireScopes('orders:read')
  @get('/orders/{id}')
  async findById(@param.path.string('id') id: string) {
    const tenantId = this.caller.app?.metadata?.tenantId;
    // ...
  }
}
```

Introspection results are cached for 30 seconds (`INTROSPECTION_CACHE_MS`).
That is the dial between revocation latency and load on the auth service: at 30
seconds a revoked token stops working within 30 seconds, and the auth service
sees at most two calls a minute per distinct token.

## Knowing who is calling

Every field on the application registry entry reaches the resource server with
the token. The caller cannot assert any of it — only an admin of the auth
service can change it — so service B can make real decisions from it.

```bash
curl -X POST localhost:3000/admin/applications \
  -H "x-admin-key: $ADMIN_API_KEY" -H 'content-type: application/json' -d '{
    "id": "billing-worker",
    "name": "Billing Worker",
    "description": "Nightly invoice reconciliation",
    "team": "finance-platform",
    "owner": "Finance Engineering",
    "contactEmail": "finance-eng@example.ae",
    "environment": "prod",
    "tags": ["batch", "internal"],
    "metadata": {
      "tenantId": "tdra",
      "rateLimitTier": "gold",
      "dataResidency": "ae",
      "costCentre": "CC-4410"
    },
    "allowedAudiences": ["service-b", "tra-auth"],
    "allowedScopes": ["orders:read", "introspect"]
  }'
```

Service B receives:

```json
{
  "appId": "billing-worker",
  "scopes": ["orders:read"],
  "audience": "service-b",
  "secretId": "3e71291032bbfe02",
  "profile": {
    "id": "billing-worker",
    "name": "Billing Worker",
    "team": "finance-platform",
    "owner": "Finance Engineering",
    "contactEmail": "finance-eng@example.ae",
    "environment": "prod",
    "tags": ["batch", "internal"],
    "metadata": {"tenantId": "tdra", "rateLimitTier": "gold", "dataResidency": "ae", "costCentre": "CC-4410"}
  }
}
```

`metadata` is free-form, so this is the extension point: add whatever a
resource server needs to route, meter or restrict a caller. `service-b` uses
`metadata.tenantId` to scope order visibility and logs `metadata.rateLimitTier`
on every access — see [orders.controller.ts](packages/service-b/src/controllers/orders.controller.ts).

Updates reach resource servers as soon as their introspection cache turns over.

## Secrets

An application holds up to five secrets at once, each with its own label,
expiry and usage record.

```bash
APP=service-a
ADMIN="-H x-admin-key:$ADMIN_API_KEY"

# Issue — the plaintext is returned once and is not recoverable afterwards
curl -X POST localhost:3000/admin/applications/$APP/secrets $ADMIN \
  -H 'content-type: application/json' -d '{"label":"ci-runner","ttlDays":90}'

# List — metadata only: status, expiry, last use
curl localhost:3000/admin/applications/$APP/secrets $ADMIN

# Rotate — new secret now, old one keeps working for the grace window
curl -X POST localhost:3000/admin/applications/$APP/secrets/$SECRET_ID/rotate $ADMIN \
  -H 'content-type: application/json' -d '{"graceMinutes":60,"ttlDays":180}'

# Change expiry — shorten a suspect credential, or extend one about to lapse
curl -X PATCH localhost:3000/admin/applications/$APP/secrets/$SECRET_ID/expiry $ADMIN \
  -H 'content-type: application/json' -d '{"ttlDays":7}'

# Revoke — immediate, and kills every token the secret minted
curl -X DELETE "localhost:3000/admin/applications/$APP/secrets/$SECRET_ID?reason=leaked" $ADMIN
```

### Expiry

Secrets expire. `SECRET_DEFAULT_TTL_DAYS` (180 by default) applies when a
request does not say otherwise; `ttlDays: 0` means no expiry and is
discouraged. Expiry is enforced at the moment a secret is used, so it is exact
rather than dependent on a sweeper. A background sweeper runs once a minute to
mark lapsed secrets `expired` in the API and to purge tokens that died over an
hour ago.

Rotation never extends a secret's life: if the old secret was already going to
expire before the grace window ends, that earlier date stands.

### Rotating without downtime

1. `POST .../rotate` with a grace window longer than your deploy takes.
2. Deploy the new secret.
3. Watch `lastUsedAt` on the old secret stop moving.
4. Revoke it, or let the grace window close on its own.

## Revocation, in order of blast radius

| Action | Effect | Latency |
|---|---|---|
| `POST /oauth/revoke` | One token | Next introspection |
| `DELETE .../secrets/{id}` | That secret, and every token it minted | Immediate at the auth service; up to `INTROSPECTION_CACHE_MS` at resource servers |
| `POST .../suspend` | The whole application: no new tokens, all live tokens revoked | Same |
| Rotate `TOKEN_PEPPER` | Every token everywhere | Immediate |

## Security properties

**Secrets at rest.** Stored as scrypt hashes (N=16384, r=8, p=1, 16-byte salt).
A database leak yields nothing usable. The plaintext is returned once at
creation and never again.

**Tokens at rest.** Stored as HMAC-SHA256 under a server-side pepper held in
the environment, not the database. A token is 256 bits of random, so a slow
hash would defend against nothing; the pepper means database access alone does
not let you verify a stolen token, and rotating it invalidates every token at
once.

**Failure responses reveal nothing.** A wrong secret, an unknown application
and a malformed credential all return the same `401 invalid_client`. A failed
lookup still burns one scrypt verification so response timing does not leak
whether the application exists.

**Brute force.** Ten failed token requests per `client_id`+IP within 15 minutes
triggers a five-minute lockout with `Retry-After`. In-memory, so behind more
than one replica move `RateLimiterService` to Redis — the interface does not
change.

**Fail closed.** If the auth service cannot be reached, service B answers 503
rather than serving the request. An unavailable verifier is not permission.

**Audit.** Every issuance, denial, rotation, revocation and registry change is
recorded with actor, IP and reason. Admin keys appear as fingerprints, never in
the clear. `GET /admin/audit?appId=…&type=…`.

### Before production

- **TLS everywhere.** The secret crosses the network once, at
  `POST /oauth/token`. That hop must be TLS; so must the rest.
- **Move off the memory connector.** Set `DB_CONNECTOR=postgresql` and
  `DB_URL`. The memory connector writes a JSON file and is for local work only.
- **Replace `ADMIN_API_KEY` with real operator identity.** A shared key behind
  an SSO proxy or an internal-only network is the minimum; per-operator
  credentials with their own audit identity is better. The management API
  creates the credentials everything else depends on, so it is a different
  trust domain from service traffic and does not ride on the tokens it issues.
- **Back up `TOKEN_PEPPER`,** and treat losing it as "every service must
  re-authenticate" rather than a disaster — which it is, by design.
- **Run more than one replica** of the auth service. Every service depends on
  it. The introspection cache absorbs brief outages; nothing absorbs a long one.
- **Set `TRUST_PROXY`** to match your load balancer so client IPs in the audit
  trail and the rate limiter are real.

## Layout

```
packages/
  auth-service/        the auth service, and the client SDK other services use
    src/
      client/          ← published as @tra/auth-service/client
        token-client.ts        get and cache tokens (the calling side)
        introspection-client.ts verify tokens, with cache (the receiving side)
        strategy.ts            LoopBack authentication strategy
        scopes.ts              @requireScopes and its interceptor
        setup.ts               one call to wire a service up
      models/          Application, ClientSecret, AccessToken, AuditEvent
      services/        crypto, token issuance, secret lifecycle, audit, rate limiting
      controllers/     /oauth/*, /admin/*
      auth/            admin key and local bearer strategies
      observers/       expiry sweeper
  service-a/           the caller
  service-b/           the resource server
  */.env               one per service, from the .env.example beside it
postman/               importable collection + environment template
scripts/
  bootstrap.js         create each service's .env, generate the auth secrets
  build-postman.js     regenerate the Postman collection
  postman-env.js       fill a Postman environment from the service .env files
  seed.js              register the demo applications
  smoke-test.js        40 end-to-end assertions
  start-all.js         run all three locally
```

## Adding a new service

```ts
setupServiceAuth(this, {
  authBaseUrl: process.env.AUTH_BASE_URL,
  clientId: process.env.MY_CLIENT_ID,
  clientSecret: process.env.MY_CLIENT_SECRET,
  selfAudience: 'my-service',
});
```

Then `@authenticate('service-token')` and `@requireScopes('...')` on the
endpoints you want protected. To call another service, construct a
`ServiceTokenClient` with that service's audience and use its `fetch` —
[service-b.client.ts](packages/service-a/src/clients/service-b.client.ts) is a
worked example.

See [docs/operations.md](docs/operations.md) for the runbooks: onboarding a
service, rotating on a schedule, and responding to a leaked secret.

## Configuration

Each service has its own `.env`, next to its `package.json`, created from the
`.env.example` beside it. Nothing is shared.

```
packages/auth-service/.env    TOKEN_PEPPER, ADMIN_API_KEY, TTLs, database
packages/service-a/.env       CLIENT_ID, CLIENT_SECRET, where to find auth and B
packages/service-b/.env       CLIENT_ID, CLIENT_SECRET, introspection cache
```

This is not tidiness. A single shared file would put the token pepper, the
admin key and *every* service's secret into every process — so any one
compromised service could mint credentials for all the others. Split, service A
holds one secret: its own. It cannot read service B's, and it cannot reach the
values that would let it forge tokens or issue itself new credentials.

In production these come from your secret store or orchestrator rather than a
file; the variable names are the same either way.

### auth-service

| Variable | Default | Meaning |
|---|---|---|
| `TOKEN_PEPPER` | — | HMAC key for tokens at rest. 32+ bytes. Rotating it invalidates every token. |
| `ADMIN_API_KEY` | — | Management API key. Whoever holds it can issue credentials for any application. |
| `AUTH_PORT` | 3000 | Listen port. |
| `ACCESS_TOKEN_TTL_SECONDS` | 600 | Token lifetime. Refused above 3600. |
| `SECRET_DEFAULT_TTL_DAYS` | 180 | Default secret lifetime. |
| `ROTATION_GRACE_MINUTES` | 60 | Default overlap window on rotation. |
| `MAX_FAILED_ATTEMPTS` / `LOCKOUT_SECONDS` | 10 / 300 | Token endpoint throttling. |
| `TRUST_PROXY` | loopback | Express `trust proxy` setting. |
| `DB_CONNECTOR` / `DB_URL` | memory | `postgresql` for real deployments. |

The auth service refuses to start on a missing or placeholder `TOKEN_PEPPER` or
`ADMIN_API_KEY`, a pepper under 32 bytes, or a token TTL over an hour.

### service-a and service-b

| Variable | Meaning |
|---|---|
| `CLIENT_ID` / `CLIENT_SECRET` | This service's own identity at the auth service. Written by `npm run seed`. |
| `AUTH_BASE_URL` | Where the auth service is. |
| `SELF_AUDIENCE` | The audience id this service answers to. Tokens for anyone else are rejected. |
| `INTROSPECTION_CACHE_MS` (B) | How long a verification result may be reused. Revocation latency. Default 30000. |
| `SERVICE_B_BASE_URL` / `SERVICE_B_AUDIENCE` / `SERVICE_B_SCOPES` (A) | Which downstream service to call, and what to ask for. |

Both read their credentials in `application.ts` and hand them to
`setupServiceAuth`; the secret goes no further than the token request.
