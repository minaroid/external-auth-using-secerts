import {ApplicationConfig, ServiceBApplication} from './application';

export * from './application';

export async function main(
  options: ApplicationConfig = {},
): Promise<ServiceBApplication> {
  const app = new ServiceBApplication(options);
  await app.boot();
  await app.start();
  console.log(`service-b listening on ${app.restServer.url}`);
  return app;
}

if (require.main === module) {
  main({
    rest: {
      port: +(process.env.B_PORT ?? 3002),
      host: process.env.HOST ?? '0.0.0.0',
      gracePeriodForClose: 5000,
      openApiSpec: {setServersFromRequest: true},
    },
  }).catch(err => {
    console.error('failed to start service-b:', err.message);
    process.exit(1);
  });
}
