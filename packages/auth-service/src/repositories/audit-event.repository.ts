import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {DbDataSource} from '../datasources/db.datasource';
import {AuditEvent} from '../models';

export class AuditEventRepository extends DefaultCrudRepository<
  AuditEvent,
  typeof AuditEvent.prototype.id,
  {}
> {
  constructor(@inject('datasources.db') dataSource: DbDataSource) {
    super(AuditEvent, dataSource);
  }
}
