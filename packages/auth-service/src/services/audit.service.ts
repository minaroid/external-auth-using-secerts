import {BindingScope, injectable, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {AuditEvent, AuditOutcome} from '../models';
import {AuditEventRepository} from '../repositories';
import {CryptoService} from './crypto.service';

export interface AuditInput {
  type: string;
  outcome: AuditOutcome;
  appId?: string;
  secretId?: string;
  actor?: string;
  clientIp?: string;
  reason?: string;
  detail?: Record<string, unknown>;
}

/**
 * Writes the credential audit trail.
 *
 * Failures here are logged but never propagated: an audit backend having a bad
 * day must not take authentication down with it.
 */
@injectable({scope: BindingScope.SINGLETON})
export class AuditService {
  constructor(
    @repository(AuditEventRepository)
    private auditRepo: AuditEventRepository,
    @service(CryptoService) private crypto: CryptoService,
  ) {}

  async record(input: AuditInput): Promise<void> {
    try {
      await this.auditRepo.create(
        new AuditEvent({
          id: this.crypto.newUuid(),
          detail: {},
          ...input,
          createdAt: new Date(),
        }),
      );
    } catch (err) {
      console.error('[audit] failed to record event', input.type, err);
    }
  }
}
