# Runbooks

All commands assume:

```bash
AUTH=https://auth.internal
# The admin key lives in the auth service's own environment and nowhere else.
ADMIN="-H x-admin-key:$ADMIN_API_KEY -H content-type:application/json"
```

---

## Onboard a new service

**1. Register it.** Fill in the descriptive fields properly — resource servers
see them, and they are what an on-call engineer reads at 3am when this
application starts behaving badly.

```bash
curl -X POST $AUTH/admin/applications $ADMIN -d '{
  "id": "billing-worker",
  "name": "Billing Worker",
  "description": "Nightly invoice reconciliation",
  "team": "finance-platform",
  "owner": "Finance Engineering",
  "contactEmail": "finance-eng@example.ae",
  "environment": "prod",
  "tags": ["batch"],
  "metadata": {"tenantId": "tdra", "rateLimitTier": "silver"},
  "allowedAudiences": ["service-b", "tra-auth"],
  "allowedScopes": ["orders:read", "introspect"]
}'
```

`allowedAudiences` is the list of services it may request tokens for. Include
`tra-auth` with the `introspect` scope only if it also receives calls and needs
to verify tokens.

`allowedScopes` is the ceiling, not the grant: a token request may ask for a
subset, never more.

**2. Issue a secret.**

```bash
curl -X POST $AUTH/admin/applications/billing-worker/secrets $ADMIN \
  -d '{"label":"initial","ttlDays":180}'
```

The response contains `secret` exactly once. Put it straight into your secret
store. There is no endpoint that returns it again.

**3. Give the application its audience** if other services will call it:
`"audience": "billing-worker"`, then add that to the *callers'*
`allowedAudiences`.

**4. Deploy** with the service's own environment:

```
AUTH_BASE_URL=https://auth.internal
CLIENT_ID=billing-worker
CLIENT_SECRET=<from your secret store>
SELF_AUDIENCE=billing-worker
```

Give each service only its own credentials. A shared environment holding every
service's secret — or worse, the token pepper and admin key — means one
compromised service compromises all of them. Locally this is enforced by a
separate `.env` per package; in production it is your secret store's access
policy doing the same job.

---

## Scheduled rotation

Rotate on a schedule, not only after an incident. The overlap window is what
makes it uneventful.

```bash
SECRET_ID=$(curl -s $AUTH/admin/applications/$APP/secrets \
  -H "x-admin-key:$ADMIN_API_KEY" | jq -r '.[] | select(.usable) | .id' | head -1)

curl -X POST $AUTH/admin/applications/$APP/secrets/$SECRET_ID/rotate $ADMIN \
  -d '{"graceMinutes": 120, "ttlDays": 180}'
```

Then:

1. Write the new `secret` to your secret store.
2. Roll the deployment.
3. Confirm the change took: `lastUsedAt` on the old secret stops advancing
   while `useCount` on the new one climbs.

```bash
curl -s $AUTH/admin/applications/$APP/secrets -H "x-admin-key:$ADMIN_API_KEY" \
  | jq '.[] | {id, label, status, lastUsedAt, useCount, expiresInDays}'
```

4. Revoke the old one, or let the grace window close it.

**Grace window too short?** The old secret lapses before the rollout finishes
and instances still holding it start getting `401 invalid_client`. Extend it:

```bash
curl -X PATCH $AUTH/admin/applications/$APP/secrets/$OLD_ID/expiry $ADMIN \
  -d '{"ttlDays": 1}'
```

---

## A secret has leaked

**1. Revoke it.** This is immediate and also kills every access token the
secret minted.

```bash
curl -X DELETE "$AUTH/admin/applications/$APP/secrets/$SECRET_ID?reason=leaked-in-ci-logs" \
  -H "x-admin-key:$ADMIN_API_KEY"
```

The response reports how many live tokens went with it. Resource servers stop
honouring those tokens once their introspection cache turns over — 30 seconds
by default.

**2. Issue a replacement and deploy it.**

**3. Find out what it was used for.**

```bash
curl -s "$AUTH/admin/audit?appId=$APP&limit=1000" -H "x-admin-key:$ADMIN_API_KEY" \
  | jq '.[] | select(.secretId == "'$SECRET_ID'") | {createdAt, type, clientIp, detail}'
```

That gives you every token issued from the secret, with source IP and
timestamp — which is the input to deciding whether anything was actually
accessed with it.

**4. If you cannot scope the damage,** suspend the application while you work
it out. This is reversible.

```bash
curl -X POST $AUTH/admin/applications/$APP/suspend $ADMIN -d '{"reason":"investigating"}'
# ... later
curl -X POST $AUTH/admin/applications/$APP/activate -H "x-admin-key:$ADMIN_API_KEY"
```

---

## The blast radius options

Reach for the narrowest one that covers the problem.

| Scope | Command |
|---|---|
| One token | `POST /oauth/revoke` (the holder does this) |
| One secret, and its tokens | `DELETE /admin/applications/{app}/secrets/{id}` |
| One application entirely | `POST /admin/applications/{app}/suspend` |
| Every token issued by anyone | rotate `TOKEN_PEPPER` and restart the auth service |

Rotating `TOKEN_PEPPER` is the fleet-wide reset: every service re-authenticates
on its next call, using secrets it already holds. It does **not** invalidate
secrets, so nothing needs redeploying — services recover on their own within a
token lifetime.

---

## The admin key has leaked

The admin key can create applications and issue secrets, so treat this as the
most serious case.

1. Set a new `ADMIN_API_KEY` and restart the auth service. The old key stops
   working at once.
2. Read the audit trail for what was done with it — admin actions are recorded
   under an `admin:<fingerprint>` actor:

```bash
curl -s "$AUTH/admin/audit?limit=1000" -H "x-admin-key:$NEW_ADMIN_API_KEY" \
  | jq '.[] | select(.actor | startswith("admin:")) | {createdAt, type, appId, secretId, actor}'
```

3. Revoke any secret issued in the exposure window, and delete any application
   you did not create.

---

## Monitoring

Worth alerting on, from the audit trail:

| Signal | Query | Why |
|---|---|---|
| Token denials | `?type=token.denied` | A spike means a bad rollout or someone guessing. |
| Throttling | `?type=token.throttled` | Brute force, or a client in a retry loop. |
| Secrets near expiry | `GET /admin/applications/{id}/secrets`, `expiresInDays` | Rotate before it lapses, not after. |
| Unused secrets | `lastUsedAt` older than a week, status `active` | Dead credentials that should be revoked. |
| Introspection failures | 503s from resource servers | The auth service is unreachable and everything is failing closed. |

The auth service is on the critical path of every inter-service call. Run more
than one replica, and alert on `GET /health` as you would a database.

---

## Moving to PostgreSQL

```bash
DB_CONNECTOR=postgresql
DB_URL=postgres://user:pass@host:5432/tra_auth
DB_SSL=true
```

Models carry their table names (`applications`, `client_secrets`,
`access_tokens`, `audit_events`). Create the schema once with LoopBack's
automigrate, then manage it with your normal migration tooling.

Indexes worth having beyond the primary keys:

```sql
CREATE INDEX ON client_secrets (appid, status);
CREATE INDEX ON access_tokens  (secretid) WHERE revokedat IS NULL;
CREATE INDEX ON access_tokens  (expiresat);
CREATE INDEX ON audit_events   (appid, createdat DESC);
```

The token table is written on every token issuance and read on every
introspection, so it is the one to watch as traffic grows. Raising
`INTROSPECTION_CACHE_MS` reduces reads at the cost of revocation latency; the
sweeper keeps the table from growing without bound.
