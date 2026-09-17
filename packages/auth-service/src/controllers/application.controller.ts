import {authenticate} from '@loopback/authentication';
import {service} from '@loopback/core';
import {Filter, repository} from '@loopback/repository';
import {
  del,
  get,
  getModelSchemaRef,
  HttpErrors,
  param,
  patch,
  post,
  requestBody,
} from '@loopback/rest';
import {inject} from '@loopback/core';
import {SecurityBindings, UserProfile} from '@loopback/security';
import {ADMIN_KEY_STRATEGY} from '../auth';
import {Application, IssuedSecret} from '../models';
import {
  AccessTokenRepository,
  ApplicationRepository,
  ClientSecretRepository,
} from '../repositories';
import {AuditService, SecretManagerService} from '../services';

/** Ids are used as `client_id` and appear in logs, so keep them readable. */
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;

interface CreateApplicationBody extends Partial<Application> {
  name: string;
}

interface CreateApplicationResponse {
  application: Application;
  /** Present only when `issueSecret` was requested. Shown once. */
  secret?: IssuedSecret;
}

/**
 * Management API for the application registry.
 *
 * Everything written here — team, owner, environment, tags, metadata — is
 * handed to resource servers at introspection time, so this is where you
 * describe a caller well enough for service B to make decisions about it.
 */
@authenticate(ADMIN_KEY_STRATEGY)
export class ApplicationController {
  constructor(
    @repository(ApplicationRepository) private appRepo: ApplicationRepository,
    @repository(ClientSecretRepository)
    private secretRepo: ClientSecretRepository,
    @repository(AccessTokenRepository) private tokenRepo: AccessTokenRepository,
    @service(SecretManagerService) private secrets: SecretManagerService,
    @service(AuditService) private audit: AuditService,
    @inject(SecurityBindings.USER) private admin: UserProfile,
  ) {}

  @post('/admin/applications', {
    tags: ['Administration'],
    summary: 'Register an application',
    description:
      'Pass ?issueSecret=true to receive a first secret in the same call. ' +
      'It is returned once and cannot be retrieved afterwards.',
    security: [{adminKey: []}],
    responses: {
      '200': {
        description:
          'The registry entry, plus the first secret when one was requested.',
      },
    },
  })
  async create(
    @requestBody({
      description:
        'Descriptive fields are optional but recommended: they are what ' +
        'resource servers see about the caller.',
      content: {
        'application/json': {
          schema: getModelSchemaRef(Application, {
            title: 'NewApplication',
            exclude: ['createdAt', 'updatedAt'],
            optional: ['id', 'environment', 'tags', 'metadata', 'status'],
          }),
        },
      },
    })
    body: CreateApplicationBody,
    @param.query.boolean('issueSecret') issueSecret?: boolean,
    @param.query.string('secretLabel') secretLabel?: string,
    @param.query.number('secretTtlDays') secretTtlDays?: number,
  ): Promise<CreateApplicationResponse> {
    const id = (body.id ?? slugify(body.name)).toLowerCase();
    if (!ID_PATTERN.test(id)) {
      throw new HttpErrors.BadRequest(
        'id must be 2-63 characters of lowercase letters, digits and dashes',
      );
    }
    if (await this.appRepo.exists(id)) {
      throw new HttpErrors.Conflict(`application "${id}" already exists`);
    }
    if (body.audience) {
      const clash = await this.appRepo.findByAudience(body.audience);
      if (clash) {
        throw new HttpErrors.Conflict(
          `audience "${body.audience}" is already claimed by ${clash.id}`,
        );
      }
    }

    const now = new Date();
    const application = await this.appRepo.create(
      new Application({
        environment: 'dev',
        tags: [],
        metadata: {},
        allowedAudiences: [],
        allowedScopes: [],
        allowedIps: [],
        status: 'active',
        ...body,
        id,
        createdAt: now,
        updatedAt: now,
      }),
    );

    await this.audit.record({
      type: 'app.created',
      outcome: 'success',
      appId: id,
      actor: this.admin.name,
      detail: {
        audience: application.audience,
        allowedAudiences: application.allowedAudiences,
        allowedScopes: application.allowedScopes,
      },
    });

    const response: CreateApplicationResponse = {application};
    if (issueSecret) {
      response.secret = await this.secrets.issue(id, {
        label: secretLabel ?? 'initial',
        ttlDays: secretTtlDays,
        actor: this.admin.name,
      });
    }
    return response;
  }

  @get('/admin/applications', {
    tags: ['Administration'],
    summary: 'List registered applications',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async list(
    @param.query.string('environment') environment?: string,
    @param.query.string('team') team?: string,
    @param.query.string('tag') tag?: string,
    @param.query.string('status') status?: string,
  ): Promise<Application[]> {
    const where: Record<string, unknown> = {};
    if (environment) where.environment = environment;
    if (team) where.team = team;
    if (status) where.status = status;

    const filter: Filter<Application> = {where, order: ['id ASC']};
    const apps = await this.appRepo.find(filter);
    // Array containment differs per connector, so filter tags in memory.
    return tag ? apps.filter(app => app.tags?.includes(tag)) : apps;
  }

  @get('/admin/applications/{id}', {
    tags: ['Administration'],
    summary: 'Get one application with a summary of its credentials',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async findById(@param.path.string('id') id: string): Promise<object> {
    const application = await this.appRepo.findById(id);
    const secrets = await this.secrets.list(id);
    const {count: liveTokens} = await this.tokenRepo.count({
      appId: id,
      revokedAt: undefined,
      expiresAt: {gt: new Date()},
    } as object);

    return {
      application,
      secrets: secrets.map(redactSecret),
      liveTokens,
    };
  }

  @patch('/admin/applications/{id}', {
    tags: ['Administration'],
    summary: 'Update an application',
    description:
      'Changes to descriptive fields reach resource servers as soon as their ' +
      'introspection cache turns over.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async update(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Application, {
            title: 'ApplicationPatch',
            partial: true,
            exclude: ['id', 'createdAt', 'updatedAt'],
          }),
        },
      },
    })
    patchBody: Partial<Application>,
  ): Promise<Application> {
    await this.appRepo.findById(id);

    if (patchBody.audience) {
      const clash = await this.appRepo.findByAudience(patchBody.audience);
      if (clash && clash.id !== id) {
        throw new HttpErrors.Conflict(
          `audience "${patchBody.audience}" is already claimed by ${clash.id}`,
        );
      }
    }

    await this.appRepo.updateById(id, {...patchBody, updatedAt: new Date()});
    await this.audit.record({
      type: 'app.updated',
      outcome: 'success',
      appId: id,
      actor: this.admin.name,
      detail: {fields: Object.keys(patchBody)},
    });
    return this.appRepo.findById(id);
  }

  @post('/admin/applications/{id}/suspend', {
    tags: ['Administration'],
    summary: 'Suspend an application and kill its live tokens',
    description:
      'Reversible kill switch. Token issuance stops and every outstanding ' +
      'token is revoked, without destroying the audit history.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async suspend(
    @param.path.string('id') id: string,
    @requestBody({
      required: false,
      content: {
        'application/json': {
          schema: {type: 'object', properties: {reason: {type: 'string'}}},
        },
      },
    })
    body: {reason?: string} = {},
  ): Promise<{status: string; revokedTokens: number}> {
    await this.appRepo.findById(id);
    await this.appRepo.updateById(id, {
      status: 'suspended',
      updatedAt: new Date(),
    });
    const revokedTokens = await this.tokenRepo.revokeByApp(id);

    await this.audit.record({
      type: 'app.suspended',
      outcome: 'success',
      appId: id,
      actor: this.admin.name,
      reason: body.reason,
      detail: {revokedTokens},
    });
    return {status: 'suspended', revokedTokens};
  }

  @post('/admin/applications/{id}/activate', {
    tags: ['Administration'],
    summary: 'Lift a suspension',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async activate(
    @param.path.string('id') id: string,
  ): Promise<{status: string}> {
    await this.appRepo.findById(id);
    await this.appRepo.updateById(id, {
      status: 'active',
      updatedAt: new Date(),
    });
    await this.audit.record({
      type: 'app.activated',
      outcome: 'success',
      appId: id,
      actor: this.admin.name,
    });
    return {status: 'active'};
  }

  @del('/admin/applications/{id}', {
    tags: ['Administration'],
    summary: 'Delete an application and all of its credentials',
    description:
      'Prefer suspend. Deletion removes the secrets and tokens but keeps the ' +
      'audit trail.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async delete(
    @param.path.string('id') id: string,
  ): Promise<{deleted: true; secrets: number; tokens: number}> {
    await this.appRepo.findById(id);

    const tokens = await this.tokenRepo.deleteAll({appId: id});
    const secrets = await this.secretRepo.deleteAll({appId: id});
    await this.appRepo.deleteById(id);

    await this.audit.record({
      type: 'app.deleted',
      outcome: 'success',
      appId: id,
      actor: this.admin.name,
      detail: {secrets: secrets.count, tokens: tokens.count},
    });
    return {deleted: true, secrets: secrets.count, tokens: tokens.count};
  }
}

/** Never let a hash out of the service, even to an admin. */
export function redactSecret(secret: {secretHash?: string}): object {
  const {secretHash, ...rest} = secret as Record<string, unknown> & {
    secretHash?: string;
  };
  return rest;
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
}
