import {
  inject,
  lifeCycleObserver,
  LifeCycleObserver,
  service,
} from '@loopback/core';
import {repository} from '@loopback/repository';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';
import {
  AccessTokenRepository,
  ClientSecretRepository,
} from '../repositories';
import {AuditService} from '../services';

/** Once a minute is often enough; expiry is already enforced on every use. */
const SWEEP_INTERVAL_MS = 60_000;

/**
 * Keeps stored state in step with the clock.
 *
 * Expiry is always enforced at the moment a credential is used, so this is
 * housekeeping rather than a control: it marks lapsed secrets so operators see
 * the truth in the API, and drops expired tokens so the table does not grow
 * without bound.
 */
@lifeCycleObserver('sweeper')
export class ExpirySweeperObserver implements LifeCycleObserver {
  private timer?: NodeJS.Timeout;

  constructor(
    @repository(ClientSecretRepository)
    private secretRepo: ClientSecretRepository,
    @repository(AccessTokenRepository)
    private tokenRepo: AccessTokenRepository,
    @service(AuditService) private audit: AuditService,
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
  ) {}

  async start(): Promise<void> {
    await this.sweep();
    this.timer = setInterval(() => {
      this.sweep().catch(err => console.error('[sweeper] failed', err));
    }, SWEEP_INTERVAL_MS);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async sweep(): Promise<void> {
    const now = new Date();

    // Mark secrets whose expiry has passed. They already stopped working.
    const lapsed = await this.secretRepo.find({
      where: {
        status: {inq: ['active', 'rotated']},
        expiresAt: {lt: now},
      } as object,
      fields: {id: true, appId: true, label: true},
    });

    for (const secret of lapsed) {
      await this.secretRepo.updateById(secret.id, {status: 'expired'});
      await this.audit.record({
        type: 'secret.expired',
        outcome: 'success',
        appId: secret.appId,
        secretId: secret.id,
        actor: 'system',
        detail: {label: secret.label},
      });
    }

    // Keep expired tokens around briefly so late introspections still answer
    // authoritatively, then drop them.
    const cutoff = new Date(now.getTime() - 3600_000);
    const purged = await this.tokenRepo.purgeExpired(cutoff);

    if (lapsed.length || purged) {
      console.log(
        `[sweeper] expired secrets: ${lapsed.length}, purged tokens: ${purged}`,
      );
    }
  }
}
