import {BindingScope, inject, injectable, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {AppProfile, IntrospectionResponse, TokenResponse} from '../client';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';
import {AccessToken, Application, ClientSecret} from '../models';
import {
  AccessTokenRepository,
  ApplicationRepository,
  ClientSecretRepository,
} from '../repositories';
import {AuditService} from './audit.service';
import {CryptoService, SECRET_PREFIX, TOKEN_PREFIX} from './crypto.service';
import {OAuthError} from './errors';
import {RateLimiterService} from './rate-limiter.service';

export interface TokenRequest {
  clientId: string;
  clientSecret: string;
  audience: string;
  /** Space delimited, as sent on the wire. */
  scope?: string;
  clientIp?: string;
}

/** Everything an inactive token reports, and nothing else. */
const INACTIVE: IntrospectionResponse = {active: false};

@injectable({scope: BindingScope.SINGLETON})
export class TokenService {
  constructor(
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
    @repository(ApplicationRepository) private appRepo: ApplicationRepository,
    @repository(ClientSecretRepository)
    private secretRepo: ClientSecretRepository,
    @repository(AccessTokenRepository) private tokenRepo: AccessTokenRepository,
    @service(CryptoService) private crypto: CryptoService,
    @service(AuditService) private audit: AuditService,
    @service(RateLimiterService) private limiter: RateLimiterService,
  ) {}

  /**
   * The client credentials grant: a long lived secret is exchanged for a short
   * lived token scoped to one audience.
   *
   * This is the only place the plaintext secret is ever accepted, which is what
   * keeps it off every other hop.
   */
  async issueToken(request: TokenRequest): Promise<TokenResponse> {
    const limiterKey = `${request.clientId}|${request.clientIp ?? 'unknown'}`;
    const retryAfter = this.limiter.retryAfter(limiterKey);
    if (retryAfter > 0) {
      await this.audit.record({
        type: 'token.throttled',
        outcome: 'failure',
        appId: request.clientId,
        clientIp: request.clientIp,
        reason: 'too many failed attempts',
      });
      throw new OAuthError(
        'slow_down',
        'too many failed attempts; try again later',
        429,
        {'Retry-After': String(retryAfter)},
      );
    }

    try {
      const {app, secret} = await this.authenticateClient(request);
      const scopes = this.resolveScopes(app, request.audience, request.scope);
      const ttl = app.tokenTtlSeconds ?? this.config.accessTokenTtlSeconds;

      const {id, plaintext} = this.crypto.mintCredential(TOKEN_PREFIX);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttl * 1000);

      await this.tokenRepo.create(
        new AccessToken({
          id,
          tokenHash: this.crypto.hashToken(plaintext),
          appId: app.id,
          secretId: secret.id,
          audience: request.audience,
          scopes,
          issuedAt: now,
          expiresAt,
          clientIp: request.clientIp,
        }),
      );

      // Best effort usage accounting; never block issuance on it.
      this.secretRepo
        .updateById(secret.id, {
          lastUsedAt: now,
          useCount: (secret.useCount ?? 0) + 1,
        })
        .catch(err => console.error('[token] usage update failed', err));

      this.limiter.recordSuccess(limiterKey);
      await this.audit.record({
        type: 'token.issued',
        outcome: 'success',
        appId: app.id,
        secretId: secret.id,
        clientIp: request.clientIp,
        detail: {audience: request.audience, scopes, jti: id, ttl},
      });

      return {
        access_token: plaintext,
        token_type: 'Bearer',
        expires_in: ttl,
        scope: scopes.join(' '),
        audience: request.audience,
      };
    } catch (err) {
      if (err instanceof OAuthError && err.status === 401) {
        this.limiter.recordFailure(limiterKey);
      }
      if (err instanceof OAuthError) {
        await this.audit.record({
          type: 'token.denied',
          outcome: 'failure',
          appId: request.clientId,
          clientIp: request.clientIp,
          reason: `${err.code}: ${err.description}`,
          detail: {audience: request.audience},
        });
      }
      throw err;
    }
  }

  /**
   * Verifies a bearer token on behalf of a resource server.
   *
   * Deliberately returns `{active: false}` for every failure mode — expired,
   * revoked, malformed, unknown — so that a caller probing the endpoint learns
   * nothing beyond yes/no.
   */
  async introspect(token: string): Promise<IntrospectionResponse> {
    const parsed = this.crypto.parseCredential(token);
    if (!parsed || parsed.kind !== TOKEN_PREFIX) return INACTIVE;

    const record = await this.tokenRepo.findById(parsed.id).catch(() => null);
    if (!record) return INACTIVE;
    if (!this.crypto.tokenHashMatches(token, record.tokenHash)) return INACTIVE;
    if (record.revokedAt) return INACTIVE;
    if (record.expiresAt.getTime() <= Date.now()) return INACTIVE;

    // The app may have been suspended, or its secret revoked, after the token
    // was minted. Both must take effect immediately.
    const app = await this.appRepo.findById(record.appId).catch(() => null);
    if (!app || app.status !== 'active') return INACTIVE;

    const secret = await this.secretRepo
      .findById(record.secretId)
      .catch(() => null);
    if (!secret || secret.status === 'revoked') return INACTIVE;

    return {
      active: true,
      client_id: app.id,
      app_name: app.name,
      aud: record.audience,
      scope: record.scopes.join(' '),
      sid: record.secretId,
      jti: record.id,
      token_type: 'Bearer',
      iat: Math.floor(record.issuedAt.getTime() / 1000),
      exp: Math.floor(record.expiresAt.getTime() / 1000),
      app: toAppProfile(app),
    };
  }

  /** Lets a service hand back a token it no longer needs. */
  async revokeToken(token: string, actor?: string): Promise<void> {
    const parsed = this.crypto.parseCredential(token);
    if (!parsed || parsed.kind !== TOKEN_PREFIX) return;

    const record = await this.tokenRepo.findById(parsed.id).catch(() => null);
    if (!record || record.revokedAt) return;
    if (!this.crypto.tokenHashMatches(token, record.tokenHash)) return;

    await this.tokenRepo.updateById(record.id, {revokedAt: new Date()});
    await this.audit.record({
      type: 'token.revoked',
      outcome: 'success',
      appId: record.appId,
      secretId: record.secretId,
      actor,
      detail: {jti: record.id},
    });
  }

  // ---- internals ----

  private async authenticateClient(
    request: TokenRequest,
  ): Promise<{app: Application; secret: ClientSecret}> {
    const parsed = this.crypto.parseCredential(request.clientSecret);
    if (!parsed || parsed.kind !== SECRET_PREFIX) {
      await this.equaliseTiming();
      throw OAuthError.invalidClient();
    }

    const secret = await this.secretRepo.findById(parsed.id).catch(() => null);
    if (!secret || secret.appId !== request.clientId) {
      // Spend the same time we would on a real verification so the response
      // time does not reveal whether the secret id exists.
      await this.equaliseTiming();
      throw OAuthError.invalidClient();
    }

    const valid = await this.crypto.verifySecret(
      request.clientSecret,
      secret.secretHash,
    );
    if (!valid) throw OAuthError.invalidClient();

    if (secret.status === 'revoked') {
      throw OAuthError.invalidClient('secret has been revoked');
    }
    if (secret.expiresAt && secret.expiresAt.getTime() <= Date.now()) {
      if (secret.status !== 'expired') {
        await this.secretRepo.updateById(secret.id, {status: 'expired'});
      }
      throw OAuthError.invalidClient('secret has expired');
    }

    const app = await this.appRepo.findById(request.clientId).catch(() => null);
    if (!app) throw OAuthError.invalidClient();
    if (app.status !== 'active') {
      throw new OAuthError(
        'unauthorized_client',
        'application is suspended',
        403,
      );
    }

    if (app.allowedIps?.length && request.clientIp) {
      if (!app.allowedIps.includes(request.clientIp)) {
        throw new OAuthError(
          'unauthorized_client',
          'source address is not allowed for this application',
          403,
        );
      }
    }

    return {app, secret};
  }

  private resolveScopes(
    app: Application,
    audience: string,
    requested?: string,
  ): string[] {
    if (!audience) {
      throw new OAuthError('invalid_request', 'audience is required');
    }
    if (!app.allowedAudiences?.includes(audience)) {
      throw new OAuthError(
        'unauthorized_client',
        `application is not allowed to request tokens for "${audience}"`,
        403,
      );
    }

    const allowed = new Set(app.allowedScopes ?? []);
    const asked = (requested ?? '').split(/\s+/).filter(Boolean);

    // No scope asked for means "everything I am entitled to", which keeps
    // simple callers simple.
    if (!asked.length) return [...allowed];

    const denied = asked.filter(scope => !allowed.has(scope));
    if (denied.length) {
      throw new OAuthError(
        'invalid_scope',
        `scope not granted to this application: ${denied.join(', ')}`,
      );
    }
    return asked;
  }

  /** Burns roughly one scrypt verification worth of time. */
  private async equaliseTiming(): Promise<void> {
    await this.crypto.verifySecret(
      'tra_sk_0000000000000000.' + 'A'.repeat(43),
      DUMMY_HASH,
    );
  }
}

/**
 * A real scrypt hash of a value nobody holds, used only to keep failure paths
 * as slow as success paths.
 */
const DUMMY_HASH =
  'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/** Projects the registry entry into the profile resource servers receive. */
export function toAppProfile(app: Application): AppProfile {
  return {
    id: app.id,
    name: app.name,
    description: app.description,
    team: app.team,
    owner: app.owner,
    contactEmail: app.contactEmail,
    environment: app.environment,
    tags: app.tags ?? [],
    metadata: app.metadata ?? {},
  };
}
