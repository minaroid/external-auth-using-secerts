import {ApplicationConfig, AuthServiceApplication} from './application';

export * from './application';
export * from './config';
export * from './models';
export * from './repositories';
export * from './services';

export async function main(
  options: ApplicationConfig = {},
): Promise<AuthServiceApplication> {
  const app = new AuthServiceApplication(options);
  await app.boot();
  await app.start();

  const url = app.restServer.url;
  console.log(`auth-service listening on ${url}`);
  console.log(`API explorer: ${url}/explorer`);
  return app;
}

if (require.main === module) {
  const config: ApplicationConfig = {
    rest: {
      port: +(process.env.AUTH_PORT ?? 3000),
      host: process.env.HOST ?? '0.0.0.0',
      gracePeriodForClose: 5000,
      openApiSpec: {setServersFromRequest: true},
      // Needed for a correct client IP behind a load balancer.
      expressSettings: {'trust proxy': process.env.TRUST_PROXY ?? 'loopback'},
      requestBodyParser: {json: {limit: '64kb'}, urlencoded: {limit: '64kb', extended: false}},
    },
  };

  main(config).catch(err => {
    console.error('failed to start auth-service:', err.message);
    process.exit(1);
  });
}
