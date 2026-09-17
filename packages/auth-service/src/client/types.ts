/**
 * Shapes exchanged between the auth service and its clients.
 * Modelled on RFC 6749 (client credentials) and RFC 7662 (introspection)
 * so the wire format stays boring and recognisable.
 */

/** Successful response of `POST /oauth/token`. */
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  audience: string;
}

/**
 * Descriptive information about the calling application.
 *
 * This is the registry entry, not the token: a resource server learns who is
 * calling (team, environment, contact, arbitrary tags) without the caller
 * being able to assert any of it itself. Only an admin of the auth service can
 * change these fields, so service B can trust them for routing, quotas,
 * logging and support escalation.
 */
export interface AppProfile {
  id: string;
  name: string;
  description?: string;
  /** Owning team or department, e.g. "licensing-platform". */
  team?: string;
  /** Person or group accountable for the app. */
  owner?: string;
  /** Contact address used when the caller misbehaves. */
  contactEmail?: string;
  /** Deployment environment: dev | staging | prod. */
  environment?: string;
  /** Free-form labels for grouping, e.g. ["internal", "batch"]. */
  tags?: string[];
  /**
   * Arbitrary key/value attributes the resource server may need, such as
   * `{"tenantId": "tdra", "rateLimitTier": "gold", "dataResidency": "ae"}`.
   */
  metadata?: Record<string, unknown>;
}

/** Response of `POST /oauth/introspect`. */
export interface IntrospectionResponse {
  active: boolean;
  /** Application (client) the token was issued to. */
  client_id?: string;
  app_name?: string;
  /** Intended recipient — the resource service must check this is itself. */
  aud?: string;
  /** Space delimited granted scopes. */
  scope?: string;
  /** Secret that minted this token; useful for audit trails. */
  sid?: string;
  /** Seconds since epoch. */
  exp?: number;
  iat?: number;
  jti?: string;
  token_type?: 'Bearer';
  /** Registry details about the caller (non-standard, additive). */
  app?: AppProfile;
}

/** Introspection result after the strategy has normalised it. */
export interface CallerIdentity {
  appId: string;
  appName?: string;
  scopes: string[];
  audience?: string;
  secretId?: string;
  tokenId?: string;
  expiresAt?: Date;
  /** Everything the registry knows about the caller. */
  app?: AppProfile;
}

export class TokenClientError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'TokenClientError';
  }
}
