import {inject, lifeCycleObserver, LifeCycleObserver} from '@loopback/core';
import {juggler} from '@loopback/repository';
import {mkdirSync} from 'fs';
import {dirname} from 'path';

/**
 * Storage for the registry.
 *
 * Defaults to the in-memory connector so the whole thing runs with no
 * infrastructure; point DB_CONNECTOR at postgresql for a real deployment.
 */
function buildConfig(): object {
  const connector = process.env.DB_CONNECTOR ?? 'memory';

  if (connector === 'postgresql') {
    return {
      name: 'db',
      connector: 'postgresql',
      url: process.env.DB_URL,
      ssl: process.env.DB_SSL === 'true',
      max: Number(process.env.DB_POOL_MAX ?? 10),
    };
  }

  // Survives restarts during development; drop the file to reset.
  const file = process.env.DB_FILE ?? './data/auth-db.json';
  // The connector writes the file but will not create its directory.
  mkdirSync(dirname(file), {recursive: true});

  return {
    name: 'db',
    connector: 'memory',
    localStorage: '',
    file,
  };
}

@lifeCycleObserver('datasource')
export class DbDataSource
  extends juggler.DataSource
  implements LifeCycleObserver
{
  static dataSourceName = 'db';

  constructor(
    @inject('datasources.config.db', {optional: true})
    dsConfig: object = buildConfig(),
  ) {
    super(dsConfig);
  }
}
