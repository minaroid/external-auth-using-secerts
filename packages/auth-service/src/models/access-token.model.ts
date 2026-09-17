import {Entity, model, property} from '@loopback/repository';

/**
 * A short lived bearer token.
 *
 * Tokens are opaque random strings, not JWTs: nothing can be learned or
 * forged from the string itself, and revoking one takes effect on the next
 * introspection rather than at the end of its lifetime.
 */
@model({settings: {postgresql: {table: 'access_tokens'}}})
export class AccessToken extends Entity {
  /** The `jti`, embedded in the token string for O(1) lookup. */
  @property({type: 'string', id: true, required: true})
  id: string;

  /** HMAC-SHA256 of the token under the server pepper. */
  @property({type: 'string', required: true})
  tokenHash: string;

  @property({type: 'string', required: true})
  appId: string;

  /** Which secret minted it — revoking that secret revokes this token. */
  @property({type: 'string', required: true})
  secretId: string;

  @property({type: 'string', required: true})
  audience: string;

  @property.array(String, {default: () => []})
  scopes: string[];

  @property({type: 'date', defaultFn: 'now'})
  issuedAt: Date;

  @property({type: 'date', required: true})
  expiresAt: Date;

  @property({type: 'date'})
  revokedAt?: Date;

  @property({type: 'string'})
  clientIp?: string;

  constructor(data?: Partial<AccessToken>) {
    super(data);
  }
}
