import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {DbDataSource} from '../datasources/db.datasource';
import {ClientSecret} from '../models';

export class ClientSecretRepository extends DefaultCrudRepository<
  ClientSecret,
  typeof ClientSecret.prototype.id,
  {}
> {
  constructor(@inject('datasources.db') dataSource: DbDataSource) {
    super(ClientSecret, dataSource);
  }

  async findByApp(appId: string): Promise<ClientSecret[]> {
    return this.find({where: {appId}, order: ['createdAt DESC']});
  }

  async countActive(appId: string): Promise<number> {
    const {count} = await this.count({appId, status: 'active'});
    return count;
  }
}
