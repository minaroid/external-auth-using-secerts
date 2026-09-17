import {Entity, model, property} from '@loopback/repository';

export type AuditOutcome = 'success' | 'failure';

/**
 * Append-only record of everything that touches credentials. Without this,
 * "which service used the leaked secret and when" has no answer.
 */
@model({settings: {postgresql: {table: 'audit_events'}}})
export class AuditEvent extends Entity {
  @property({type: 'string', id: true, required: true})
  id: string;

  /** e.g. token.issued, token.denied, secret.rotated, app.suspended */
  @property({type: 'string', required: true})
  type: string;

  @property({type: 'string', required: true})
  outcome: AuditOutcome;

  @property({type: 'string'})
  appId?: string;

  @property({type: 'string'})
  secretId?: string;

  /** Who performed it: an admin key fingerprint, or the app itself. */
  @property({type: 'string'})
  actor?: string;

  @property({type: 'string'})
  clientIp?: string;

  @property({type: 'string'})
  reason?: string;

  @property({type: 'object', default: () => ({})})
  detail: Record<string, unknown>;

  @property({type: 'date', defaultFn: 'now'})
  createdAt: Date;

  constructor(data?: Partial<AuditEvent>) {
    super(data);
  }
}
