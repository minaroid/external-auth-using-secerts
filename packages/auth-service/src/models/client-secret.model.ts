import {belongsTo, Entity, model, property} from '@loopback/repository';
import {Application} from './application.model';

export type SecretStatus = 'active' | 'rotated' | 'revoked' | 'expired';

/**
 * One credential belonging to an application. An application may hold several
 * at once, which is what makes zero-downtime rotation possible.
 *
 * The plaintext is shown exactly once, at creation. Only a scrypt hash is
 * stored, so a database leak does not yield usable credentials.
 */
@model({settings: {postgresql: {table: 'client_secrets'}}})
export class ClientSecret extends Entity {
  /** Embedded in the secret string so lookup costs one read, not a table scan. */
  @property({type: 'string', id: true, required: true})
  id: string;

  @belongsTo(() => Application, {keyTo: 'id'}, {type: 'string', required: true})
  appId: string;

  /** Human label, e.g. "ci-runner" or "2026-q1". */
  @property({type: 'string', required: true})
  label: string;

  /** `scrypt$N$r$p$salt$hash` — never leaves the auth service. */
  @property({type: 'string', required: true})
  secretHash: string;

  /** Safe to display, e.g. `tra_sk_9f2c…a41d`. */
  @property({type: 'string', required: true})
  displayHint: string;

  @property({type: 'string', default: 'active'})
  status: SecretStatus;

  @property({type: 'date', defaultFn: 'now'})
  createdAt: Date;

  @property({type: 'string'})
  createdBy?: string;

  /** Hard expiry. A secret that is never rotated still dies on its own. */
  @property({type: 'date'})
  expiresAt?: Date;

  @property({type: 'date'})
  revokedAt?: Date;

  @property({type: 'string'})
  revokedReason?: string;

  /** Set when this secret was superseded by a rotation. */
  @property({type: 'string'})
  replacedBySecretId?: string;

  /** Lets an operator see which secrets are dead weight before revoking. */
  @property({type: 'date'})
  lastUsedAt?: Date;

  @property({type: 'number', default: 0})
  useCount: number;

  constructor(data?: Partial<ClientSecret>) {
    super(data);
  }
}

/** The one and only time the plaintext is returned. */
export interface IssuedSecret {
  id: string;
  appId: string;
  label: string;
  /** Store this now — it cannot be retrieved again. */
  secret: string;
  displayHint: string;
  expiresAt?: Date;
  createdAt: Date;
}
