import {ApplicationConfig, ServiceAApplication} from './application';

export * from './application';

export async function main(
  options: ApplicationConfig = {},
): Promise<ServiceAApplication> {
  const app = new ServiceAApplication(options);
  await app.boot();
  await app.start();
  console.log(`service-a listening on ${app.restServer.url}`);
  return app;
}

if (require.main === module) {
  main({
    rest: {
      port: +(process.env.A_PORT ?? 3001),
      host: process.env.HOST ?? '0.0.0.0',
      gracePeriodForClose: 5000,
      openApiSpec: {setServersFromRequest: true},
    },
  }).catch(err => {
    console.error('failed to start service-a:', err.message);
    process.exit(1);
  });
}
