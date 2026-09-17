import {BootMixin} from '@loopback/boot';
import {ApplicationConfig} from '@loopback/core';
import {RestApplication} from '@loopback/rest';
import {
  RestExplorerBindings,
  RestExplorerComponent,
} from '@loopback/rest-explorer';
import {ServiceTokenClient, setupServiceAuth} from '@tra/auth-service/client';
import {SERVICE_B_CLIENT, ServiceBClient} from './clients/service-b.client';

export {ApplicationConfig};

export const SELF_AUDIENCE = process.env.SELF_AUDIENCE ?? 'service-a';

export class ServiceAApplication extends BootMixin(RestApplication) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    // Read from this package's own .env (or the secret store in production).
    // Service A has no way to reach service B's credentials or the auth
    // service's pepper and admin key.
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error(
        'CLIENT_ID and CLIENT_SECRET must be set in packages/service-a/.env. ' +
          'Run `npm run seed` to register the demo applications.',
      );
    }

    const authBaseUrl = process.env.AUTH_BASE_URL ?? 'http://localhost:3000';

    // Service A is both a caller and (optionally) a resource server, so it
    // gets the same setup as service B.
    setupServiceAuth(this, {
      authBaseUrl,
      clientId,
      clientSecret,
      selfAudience: SELF_AUDIENCE,
    });

    // A separate token client per audience: a token for service B is useless
    // anywhere else, which is what stops service B replaying it upstream.
    const serviceBTokens = new ServiceTokenClient({
      authBaseUrl,
      clientId,
      clientSecret,
      audience: process.env.SERVICE_B_AUDIENCE ?? 'service-b',
      scopes: (process.env.SERVICE_B_SCOPES ?? 'orders:read').split(/\s+/),
    });

    this.bind(SERVICE_B_CLIENT).to(
      new ServiceBClient(
        process.env.SERVICE_B_BASE_URL ?? 'http://localhost:3002',
        serviceBTokens,
      ),
    );

    this.configure(RestExplorerBindings.COMPONENT).to({path: '/explorer'});
    this.component(RestExplorerComponent);
    this.api({
      openapi: '3.0.0',
      info: {
        title: 'Service A',
        version: '1.0.0',
        description:
          'Demonstrates the calling side: it holds an application secret, ' +
          'exchanges it for short lived tokens, and calls service B.',
      },
      paths: {},
      components: {
        securitySchemes: {bearerAuth: {type: 'http', scheme: 'bearer'}},
      },
      servers: [{url: '/'}],
    });

    this.projectRoot = __dirname;
    this.bootOptions = {
      controllers: {
        dirs: ['controllers'],
        extensions: ['.controller.js'],
        nested: true,
      },
    };
  }
}
