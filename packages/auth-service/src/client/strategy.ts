import {AuthenticationStrategy} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {IntrospectionClient} from './introspection-client';
import {ServiceAuthBindings, SERVICE_TOKEN_STRATEGY} from './keys';
import {CallerIdentity} from './types';

/** The authenticated caller, as seen by controllers. */
export interface ServicePrincipal extends UserProfile, CallerIdentity {}

/**
 * Authenticates inbound service-to-service calls by introspecting the bearer
 * token at the auth service.
 *
 * Nothing is trusted from the token string itself — it is an opaque random
 * value, so the only way to learn anything about it is to ask the issuer.
 * That is what makes revocation immediate.
 */
export class ServiceTokenStrategy implements AuthenticationStrategy {
  readonly name = SERVICE_TOKEN_STRATEGY;

  constructor(
    @inject(ServiceAuthBindings.INTROSPECTION_CLIENT)
    private introspection: IntrospectionClient,
    @inject(ServiceAuthBindings.SELF_AUDIENCE)
    private selfAudience: string,
  ) {}

  async authenticate(request: Request): Promise<UserProfile> {
    const token = extractBearerToken(request);

    let result;
    try {
      result = await this.introspection.introspect(token);
    } catch (err) {
      // Fail closed: if we cannot verify, we do not serve.
      throw new HttpErrors.ServiceUnavailable(
        'unable to verify credentials with the auth service',
      );
    }

    const identity = IntrospectionClient.toIdentity(result);
    if (!identity) {
      throw unauthorized('token is expired, revoked or unknown');
    }

    // A token minted for another service must not be usable here, otherwise a
    // downstream service could replay the tokens it receives.
    if (identity.audience !== this.selfAudience) {
      throw unauthorized(
        `token audience "${identity.audience}" does not match this service`,
      );
    }

    const principal: ServicePrincipal = {
      [securityId]: identity.appId,
      name: identity.appName,
      ...identity,
    };
    return principal;
  }
}

function extractBearerToken(request: Request): string {
  const header = request.headers.authorization;
  if (!header) throw unauthorized('authorization header is missing');

  const [scheme, value] = header.split(/\s+/);
  if (!/^bearer$/i.test(scheme ?? '')) {
    throw unauthorized('authorization header must use the Bearer scheme');
  }
  if (!value) throw unauthorized('bearer token is empty');
  return value;
}

function unauthorized(description: string): HttpErrors.HttpError {
  const err = new HttpErrors.Unauthorized(description);
  err.headers = {
    'WWW-Authenticate': `Bearer error="invalid_token", error_description="${description}"`,
  };
  return err;
}
