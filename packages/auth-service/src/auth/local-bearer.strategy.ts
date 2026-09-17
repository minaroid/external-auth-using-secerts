import {AuthenticationStrategy} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {ServicePrincipal} from '../client';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';
import {TokenService} from '../services';

export const LOCAL_BEARER_STRATEGY = 'local-bearer';

/**
 * Verifies bearer tokens presented to the auth service itself, for example by
 * a resource server calling `/oauth/introspect`.
 *
 * Same rules as everywhere else, minus the network hop: this service is the
 * issuer, so it checks its own store directly.
 */
export class LocalBearerStrategy implements AuthenticationStrategy {
  readonly name = LOCAL_BEARER_STRATEGY;

  constructor(
    @service(TokenService) private tokens: TokenService,
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
  ) {}

  async authenticate(request: Request): Promise<UserProfile> {
    const header = request.headers.authorization;
    if (!header) throw unauthorized('authorization header is missing');

    const [scheme, token] = header.split(/\s+/);
    if (!/^bearer$/i.test(scheme ?? '') || !token) {
      throw unauthorized('expected an "Authorization: Bearer <token>" header');
    }

    const result = await this.tokens.introspect(token);
    if (!result.active || !result.client_id) {
      throw unauthorized('token is expired, revoked or unknown');
    }
    if (result.aud !== this.config.selfAudience) {
      throw unauthorized(
        `token audience "${result.aud}" is not this service`,
      );
    }

    const principal: ServicePrincipal = {
      [securityId]: result.client_id,
      name: result.app_name,
      appId: result.client_id,
      appName: result.app_name,
      scopes: result.scope ? result.scope.split(' ') : [],
      audience: result.aud,
      secretId: result.sid,
      tokenId: result.jti,
      app: result.app,
    };
    return principal;
  }
}

function unauthorized(description: string): HttpErrors.HttpError {
  const err = new HttpErrors.Unauthorized(description);
  err.headers = {
    'WWW-Authenticate': `Bearer error="invalid_token", error_description="${description}"`,
  };
  return err;
}
