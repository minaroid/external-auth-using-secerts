import {authenticate} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {
  del,
  get,
  HttpErrors,
  param,
  patch,
  post,
  requestBody,
  SchemaObject,
} from '@loopback/rest';
import {SecurityBindings, UserProfile} from '@loopback/security';
import {ADMIN_KEY_STRATEGY} from '../auth';
import {ClientSecret, IssuedSecret} from '../models';
import {ClientSecretRepository} from '../repositories';
import {AuditService, SecretManagerService} from '../services';
import {redactSecret} from './application.controller';

const ISSUE_BODY: SchemaObject = {
  type: 'object',
  properties: {
    label: {
      type: 'string',
      description: 'Human label, e.g. "ci-runner" or "2026-q1"',
    },
    ttlDays: {
      type: 'number',
      description:
        'Lifetime in days. 0 means no expiry (discouraged). Defaults to SECRET_DEFAULT_TTL_DAYS.',
    },
    expiresAt: {
      type: 'string',
      format: 'date-time',
      description:
        'Exact expiry instant. Takes precedence over ttlDays when both are sent.',
    },
  },
  additionalProperties: false,
};

const ROTATE_BODY: SchemaObject = {
  type: 'object',
  properties: {
    label: {type: 'string'},
    ttlDays: {type: 'number'},
    expiresAt: {type: 'string', format: 'date-time'},
    graceMinutes: {
      type: 'number',
      description:
        'How long the old secret keeps working so running instances can pick ' +
        'up the new one. 0 revokes it immediately.',
    },
  },
  additionalProperties: false,
};

interface IssueBody {
  label?: string;
  ttlDays?: number;
  expiresAt?: string;
}

interface RotateBody extends IssueBody {
  graceMinutes?: number;
}

/** A secret view with its expiry spelled out for operators. */
function describeSecret(secret: ClientSecret): object {
  const base = redactSecret(secret) as Record<string, unknown>;
  const expiresAt = secret.expiresAt ? new Date(secret.expiresAt) : undefined;
  return {
    ...base,
    expiresAt,
    expiresInDays: expiresAt
      ? Math.round((expiresAt.getTime() - Date.now()) / 86_400_000)
      : null,
    expired: expiresAt ? expiresAt.getTime() <= Date.now() : false,
    usable: secret.status === 'active' && !isPast(expiresAt),
  };
}

function isPast(date?: Date): boolean {
  return Boolean(date && date.getTime() <= Date.now());
}

/**
 * Secret lifecycle for one application.
 *
 * An application may hold several secrets at once. That is deliberate: it is
 * what lets you introduce a new one, roll it out, and retire the old one
 * without a moment where nothing works.
 */
@authenticate(ADMIN_KEY_STRATEGY)
export class SecretController {
  constructor(
    @service(SecretManagerService) private secrets: SecretManagerService,
    @repository(ClientSecretRepository)
    private secretRepo: ClientSecretRepository,
    @service(AuditService) private audit: AuditService,
    @inject(SecurityBindings.USER) private admin: UserProfile,
  ) {}

  @post('/admin/applications/{appId}/secrets', {
    tags: ['Secrets'],
    summary: 'Issue a new secret',
    description:
      'The plaintext is returned exactly once. It is stored only as a scrypt ' +
      'hash, so it cannot be recovered later — losing it means issuing another.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async issue(
    @param.path.string('appId') appId: string,
    @requestBody({required: false, content: {'application/json': {schema: ISSUE_BODY}}})
    body: IssueBody = {},
  ): Promise<IssuedSecret & {warning: string}> {
    const issued = await this.secrets.issue(appId, {
      label: body.label,
      ttlDays: resolveTtlDays(body),
      actor: this.admin.name,
    });
    return {
      ...issued,
      warning:
        'Store this secret now. It will never be shown again and cannot be recovered.',
    };
  }

  @get('/admin/applications/{appId}/secrets', {
    tags: ['Secrets'],
    summary: 'List an application\'s secrets (metadata only)',
    description:
      'Shows status, expiry and last use, so you can see which credentials ' +
      'are stale before revoking them.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async list(@param.path.string('appId') appId: string): Promise<object[]> {
    const secrets = await this.secrets.list(appId);
    return secrets.map(describeSecret);
  }

  @post('/admin/applications/{appId}/secrets/{secretId}/rotate', {
    tags: ['Secrets'],
    summary: 'Rotate a secret with an overlap window',
    description:
      'Issues a replacement immediately and gives the old secret a grace ' +
      'period, so a running fleet can pick up the new value without downtime.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async rotate(
    @param.path.string('appId') appId: string,
    @param.path.string('secretId') secretId: string,
    @requestBody({required: false, content: {'application/json': {schema: ROTATE_BODY}}})
    body: RotateBody = {},
  ): Promise<object> {
    const result = await this.secrets.rotate(appId, secretId, {
      label: body.label,
      ttlDays: resolveTtlDays(body),
      graceMinutes: body.graceMinutes,
      actor: this.admin.name,
    });

    return {
      secret: result.issued,
      previous: {
        id: result.previousSecretId,
        status: 'rotated',
        stopsWorkingAt: result.previousExpiresAt,
      },
      warning:
        'Store this secret now. Deploy it before the previous secret stops working.',
    };
  }

  @patch('/admin/applications/{appId}/secrets/{secretId}/expiry', {
    tags: ['Secrets'],
    summary: 'Change when a secret expires',
    description:
      'Use to shorten the life of a suspect credential, or to extend one that ' +
      'is about to lapse before a rotation can be scheduled.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async setExpiry(
    @param.path.string('appId') appId: string,
    @param.path.string('secretId') secretId: string,
    @requestBody({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            properties: {
              expiresAt: {
                type: 'string',
                format: 'date-time',
                description: 'null clears the expiry (discouraged).',
                nullable: true,
              },
              ttlDays: {
                type: 'number',
                description: 'Alternative to expiresAt: days from now.',
              },
            },
            additionalProperties: false,
          },
        },
      },
    })
    body: {expiresAt?: string | null; ttlDays?: number},
  ): Promise<object> {
    const secret = await this.secretRepo.findById(secretId);
    if (secret.appId !== appId) {
      throw new HttpErrors.NotFound(
        `secret ${secretId} does not belong to application ${appId}`,
      );
    }
    if (secret.status === 'revoked') {
      throw new HttpErrors.Conflict('a revoked secret cannot be revived');
    }

    let expiresAt: Date | undefined;
    if (body.expiresAt === null) {
      expiresAt = undefined;
    } else if (body.expiresAt) {
      expiresAt = new Date(body.expiresAt);
      if (Number.isNaN(expiresAt.getTime())) {
        throw new HttpErrors.BadRequest('expiresAt is not a valid date');
      }
    } else if (typeof body.ttlDays === 'number') {
      expiresAt =
        body.ttlDays > 0
          ? new Date(Date.now() + body.ttlDays * 86_400_000)
          : undefined;
    } else {
      throw new HttpErrors.BadRequest('send either expiresAt or ttlDays');
    }

    await this.secretRepo.updateById(secretId, {
      expiresAt,
      // A secret marked expired becomes usable again if pushed into the future.
      status:
        secret.status === 'expired' && expiresAt && expiresAt > new Date()
          ? 'active'
          : secret.status,
    });

    await this.audit.record({
      type: 'secret.expiry_changed',
      outcome: 'success',
      appId,
      secretId,
      actor: this.admin.name,
      detail: {
        from: secret.expiresAt?.toISOString() ?? null,
        to: expiresAt?.toISOString() ?? null,
      },
    });

    return describeSecret(await this.secretRepo.findById(secretId));
  }

  @del('/admin/applications/{appId}/secrets/{secretId}', {
    tags: ['Secrets'],
    summary: 'Revoke a secret immediately',
    description:
      'Break-glass path for a leaked credential: the secret stops working at ' +
      'once and every access token it minted is revoked with it.',
    security: [{adminKey: []}],
    responses: {'200': {description: 'OK'}},
  })
  async revoke(
    @param.path.string('appId') appId: string,
    @param.path.string('secretId') secretId: string,
    @param.query.string('reason') reason = 'revoked by administrator',
  ): Promise<{revoked: true; revokedTokens: number}> {
    const {revokedTokens} = await this.secrets.revoke(
      appId,
      secretId,
      reason,
      this.admin.name,
    );
    return {revoked: true, revokedTokens};
  }
}

/** `expiresAt` wins over `ttlDays` when both are supplied. */
function resolveTtlDays(body: IssueBody): number | undefined {
  if (body.expiresAt) {
    const target = new Date(body.expiresAt);
    if (Number.isNaN(target.getTime())) {
      throw new HttpErrors.BadRequest('expiresAt is not a valid date');
    }
    const days = (target.getTime() - Date.now()) / 86_400_000;
    if (days <= 0) {
      throw new HttpErrors.BadRequest('expiresAt must be in the future');
    }
    return days;
  }
  return body.ttlDays;
}
