import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {DbDataSource} from '../datasources/db.datasource';
import {AccessToken} from '../models';

export class AccessTokenRepository extends DefaultCrudRepository<
  AccessToken,
  typeof AccessToken.prototype.id,
  {}
> {
  constructor(@inject('datasources.db') dataSource: DbDataSource) {
    super(AccessToken, dataSource);
  }

  /** Revokes every live token minted by a secret. Used when it is revoked. */
  async revokeBySecret(secretId: string, at = new Date()): Promise<number> {
    const {count} = await this.updateAll(
      {revokedAt: at},
      {secretId, revokedAt: undefined},
    );
    return count;
  }

  async revokeByApp(appId: string, at = new Date()): Promise<number> {
    const {count} = await this.updateAll(
      {revokedAt: at},
      {appId, revokedAt: undefined},
    );
    return count;
  }

  /** Housekeeping: expired tokens carry no information worth keeping. */
  async purgeExpired(before = new Date()): Promise<number> {
    const {count} = await this.deleteAll({expiresAt: {lt: before}} as object);
    return count;
  }
}
