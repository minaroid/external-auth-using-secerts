import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {DbDataSource} from '../datasources/db.datasource';
import {Application} from '../models';

export class ApplicationRepository extends DefaultCrudRepository<
  Application,
  typeof Application.prototype.id,
  {}
> {
  constructor(@inject('datasources.db') dataSource: DbDataSource) {
    super(Application, dataSource);
  }

  /** Looks up the application that owns an audience id. */
  async findByAudience(audience: string): Promise<Application | null> {
    return this.findOne({where: {audience}});
  }
}
