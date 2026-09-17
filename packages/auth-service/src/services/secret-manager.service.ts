import {BindingScope, inject, injectable, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';
import {ClientSecret, IssuedSecret} from '../models';
import {
  AccessTokenRepository,
  ApplicationRepository,
  ClientSecretRepository,
} from '../repositories';
import {AuditService} from './audit.service';
import {CryptoService, SECRET_PREFIX} from './crypto.service';

export interface IssueSecretOptions {
  label?: string;
  /** Lifetime in days; falls back to the service default. */
  ttlDays?: number;
  actor?: string;
}

export interface RotateOptions extends IssueSecretOptions {
  /**
   * Minutes the old secret keeps working. Defaults to the configured grace
   * period; 0 revokes it immediately.
   */
  graceMinutes?: number;
}

export interface RotationResult {
  issued: IssuedSecret;
  previousSecretId: string;
  /** When the previous secret stops working. */
  previousExpiresAt: Date;
}

/** Guard rail: an app hoarding credentials is a smell, not a feature. */
const MAX_ACTIVE_SECRETS = 5;

/**
 * The lifecycle of application secrets: issue, rotate, revoke.
 *
 * Rotation never has a gap — the new secret is live before the old one dies —
 * which is the only way a running fleet can rotate without a deploy.
 */
@injectable({scope: BindingScope.SINGLETON})
export class SecretManagerService {
  constructor(
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
    @repository(ApplicationRepository) private appRepo: ApplicationRepository,
    @repository(ClientSecretRepository)
    private secretRepo: ClientSecretRepository,
    @repository(AccessTokenRepository) private tokenRepo: AccessTokenRepository,
    @service(CryptoService) private crypto: CryptoService,
    @service(AuditService) private audit: AuditService,
  ) {}

  /** Creates a new secret. The plaintext is returned once and never stored. */
  async issue(
    appId: string,
    options: IssueSecretOptions = {},
  ): Promise<IssuedSecret> {
    const app = await this.appRepo.findById(appId);

    const active = await this.secretRepo.countActive(app.id);
    if (active >= MAX_ACTIVE_SECRETS) {
      throw new HttpErrors.Conflict(
        `application already has ${active} active secrets (max ${MAX_ACTIVE_SECRETS}); revoke one first`,
      );
    }

    return this.mint(appId, options);
  }

  /**
   * Issues a replacement and puts the old secret on a countdown.
   *
   * The caller deploys the new value during the grace window; once traffic has
   * moved, `lastUsedAt` on the old secret confirms it is safe to forget.
   */
  async rotate(
    appId: string,
    secretId: string,
    options: RotateOptions = {},
  ): Promise<RotationResult> {
    const previous = await this.secretRepo.findById(secretId);
    if (previous.appId !== appId) {
      throw new HttpErrors.NotFound(
        `secret ${secretId} does not belong to application ${appId}`,
      );
    }
    if (previous.status === 'revoked') {
      throw new HttpErrors.Conflict('cannot rotate a revoked secret');
    }

    const issued = await this.mint(appId, {
      ...options,
      label: options.label ?? `${previous.label} (rotated)`,
    });

    const graceMinutes = options.graceMinutes ?? this.config.rotationGraceMinutes;
    const previousExpiresAt = new Date(Date.now() + graceMinutes * 60_000);

    await this.secretRepo.updateById(previous.id, {
      status: 'rotated',
      // Never extend a secret's life: if it was already going to die sooner,
      // keep that date.
      expiresAt:
        previous.expiresAt && previous.expiresAt < previousExpiresAt
          ? previous.expiresAt
          : previousExpiresAt,
      replacedBySecretId: issued.id,
    });

    await this.audit.record({
      type: 'secret.rotated',
      outcome: 'success',
      appId,
      secretId: previous.id,
      actor: options.actor,
      detail: {
        newSecretId: issued.id,
        graceMinutes,
        previousExpiresAt: previousExpiresAt.toISOString(),
      },
    });

    return {issued, previousSecretId: previous.id, previousExpiresAt};
  }

  /**
   * Kills a secret now, along with every access token it minted.
   *
   * This is the break-glass path for a leaked credential, so it must not wait
   * for anything to expire.
   */
  async revoke(
    appId: string,
    secretId: string,
    reason: string,
    actor?: string,
  ): Promise<{revokedTokens: number}> {
    const secret = await this.secretRepo.findById(secretId);
    if (secret.appId !== appId) {
      throw new HttpErrors.NotFound(
        `secret ${secretId} does not belong to application ${appId}`,
      );
    }
    if (secret.status === 'revoked') {
      return {revokedTokens: 0};
    }

    const now = new Date();
    await this.secretRepo.updateById(secret.id, {
      status: 'revoked',
      revokedAt: now,
      revokedReason: reason,
    });
    const revokedTokens = await this.tokenRepo.revokeBySecret(secret.id, now);

    await this.audit.record({
      type: 'secret.revoked',
      outcome: 'success',
      appId,
      secretId,
      actor,
      reason,
      detail: {revokedTokens},
    });

    return {revokedTokens};
  }

  /** Metadata only — the plaintext is gone and cannot be listed. */
  async list(appId: string): Promise<ClientSecret[]> {
    await this.appRepo.findById(appId);
    const secrets = await this.secretRepo.findByApp(appId);
    return secrets.map(secret => {
      // Report a lapsed secret honestly even if nothing has swept it yet.
      if (
        secret.status === 'active' &&
        secret.expiresAt &&
        secret.expiresAt.getTime() <= Date.now()
      ) {
        secret.status = 'expired';
      }
      return secret;
    });
  }

  private async mint(
    appId: string,
    options: IssueSecretOptions,
  ): Promise<IssuedSecret> {
    const {id, plaintext} = this.crypto.mintCredential(SECRET_PREFIX);
    const ttlDays = options.ttlDays ?? this.config.secretDefaultTtlDays;
    const now = new Date();
    const expiresAt =
      ttlDays > 0 ? new Date(now.getTime() + ttlDays * 86_400_000) : undefined;

    const record = await this.secretRepo.create(
      new ClientSecret({
        id,
        appId,
        label: options.label ?? 'default',
        secretHash: await this.crypto.hashSecret(plaintext),
        displayHint: this.crypto.displayHint(plaintext),
        status: 'active',
        createdAt: now,
        createdBy: options.actor,
        expiresAt,
        useCount: 0,
      }),
    );

    await this.audit.record({
      type: 'secret.issued',
      outcome: 'success',
      appId,
      secretId: id,
      actor: options.actor,
      detail: {label: record.label, expiresAt: expiresAt?.toISOString()},
    });

    return {
      id,
      appId,
      label: record.label,
      secret: plaintext,
      displayHint: record.displayHint,
      expiresAt,
      createdAt: now,
    };
  }
}
