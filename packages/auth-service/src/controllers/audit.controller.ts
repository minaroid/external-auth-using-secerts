import {authenticate} from '@loopback/authentication';
import {repository} from '@loopback/repository';
import {get, param} from '@loopback/rest';
import {ADMIN_KEY_STRATEGY} from '../auth';
import {AuditEvent} from '../models';
import {AuditEventRepository} from '../repositories';

/** Read access to the credential audit trail. */
@authenticate(ADMIN_KEY_STRATEGY)
export class AuditController {
  constructor(
    @repository(AuditEventRepository)
    private auditRepo: AuditEventRepository,
  ) {}

  @get('/admin/audit', {
    tags: ['Administration'],
    summary: 'Read credential audit events, newest first',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async list(
    @param.query.string('appId') appId?: string,
    @param.query.string('type') type?: string,
    @param.query.string('outcome') outcome?: string,
    @param.query.number('limit') limit = 100,
  ): Promise<AuditEvent[]> {
    const where: Record<string, unknown> = {};
    if (appId) where.appId = appId;
    if (type) where.type = type;
    if (outcome) where.outcome = outcome;

    return this.auditRepo.find({
      where,
      order: ['createdAt DESC'],
      limit: Math.min(Math.max(limit, 1), 1000),
    });
  }
}
