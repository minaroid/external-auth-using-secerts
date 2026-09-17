import {AuthenticationStrategy} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';
import {CryptoService} from '../services';

export const ADMIN_KEY_STRATEGY = 'admin-key';
export const ADMIN_KEY_HEADER = 'x-admin-key';

/**
 * Protects the management API with a shared admin key.
 *
 * Management is a different trust domain from service traffic: it creates the
 * credentials everything else depends on, so it does not ride on the same
 * tokens it hands out. In production put this behind an internal network, an
 * SSO proxy, or both.
 */
export class AdminKeyStrategy implements AuthenticationStrategy {
  readonly name = ADMIN_KEY_STRATEGY;

  constructor(
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
    @service(CryptoService) private crypto: CryptoService,
  ) {}

  async authenticate(request: Request): Promise<UserProfile> {
    const provided = request.headers[ADMIN_KEY_HEADER];
    const key = Array.isArray(provided) ? provided[0] : provided;

    if (!key || !this.crypto.constantTimeEquals(key, this.config.adminApiKey)) {
      throw new HttpErrors.Unauthorized('invalid or missing admin key');
    }

    // The audit trail records a fingerprint, never the key itself.
    const actor = `admin:${this.crypto.fingerprint(key)}`;
    return {[securityId]: actor, name: actor, scopes: ['admin']};
  }
}
