import {
  AuthenticationComponent,
  registerAuthenticationStrategy,
} from '@loopback/authentication';
import {Application} from '@loopback/core';
import {IntrospectionClient} from './introspection-client';
import {ServiceAuthBindings} from './keys';
import {scopeCheckInterceptor} from './scopes';
import {ServiceTokenStrategy} from './strategy';
import {ServiceTokenClient} from './token-client';

export interface ServiceAuthConfig {
  /** Base URL of the auth service. */
  authBaseUrl: string;
  /** This service's own application id and secret. */
  clientId: string;
  clientSecret: string;
  /**
   * The audience id this service answers to. Tokens issued for any other
   * audience are rejected.
   */
  selfAudience: string;
  /** Scopes this service needs at the auth service. Defaults to introspect. */
  authScopes?: string[];
  /** Positive introspection cache TTL in ms. Default 30_000. */
  cacheTtlMs?: number;
}

/**
 * Wires a LoopBack application as a resource server: it can verify inbound
 * bearer tokens and enforce `@requireScopes`.
 *
 * Returns the token client so the same application can also make outbound
 * authenticated calls.
 */
export function setupServiceAuth(
  app: Application,
  config: ServiceAuthConfig,
): ServiceTokenClient {
  app.component(AuthenticationComponent);

  const tokenClient = new ServiceTokenClient({
    authBaseUrl: config.authBaseUrl,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    // To talk to the auth service itself we need a token for the auth service.
    audience: 'tra-auth',
    scopes: config.authScopes ?? ['introspect'],
  });

  const introspection = new IntrospectionClient({
    authBaseUrl: config.authBaseUrl,
    tokenClient,
    cacheTtlMs: config.cacheTtlMs,
  });

  app.bind(ServiceAuthBindings.TOKEN_CLIENT).to(tokenClient);
  app.bind(ServiceAuthBindings.INTROSPECTION_CLIENT).to(introspection);
  app.bind(ServiceAuthBindings.SELF_AUDIENCE).to(config.selfAudience);

  registerAuthenticationStrategy(app, ServiceTokenStrategy);
  app.interceptor(scopeCheckInterceptor, {
    global: true,
    group: 'authorization',
  });

  return tokenClient;
}
