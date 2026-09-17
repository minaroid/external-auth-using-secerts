import {BootMixin} from '@loopback/boot';
import {ApplicationConfig} from '@loopback/core';
import {RestApplication} from '@loopback/rest';
import {
  RestExplorerBindings,
  RestExplorerComponent,
} from '@loopback/rest-explorer';
import {setupServiceAuth} from '@tra/auth-service/client';

export {ApplicationConfig};

/** This service's audience id. Tokens minted for anyone else are refused. */
export const SELF_AUDIENCE = process.env.SELF_AUDIENCE ?? 'service-b';

export class ServiceBApplication extends BootMixin(RestApplication) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    // Read from this package's own .env (or the secret store in production).
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error(
        'CLIENT_ID and CLIENT_SECRET must be set in packages/service-b/.env. ' +
          'Run `npm run seed` to register the demo applications.',
      );
    }

    // Service B holds credentials of its own, because verifying a token is
    // itself an authenticated call. Its secret never leaves this process: it
    // is exchanged for a token at the auth service and nothing else.
    setupServiceAuth(this, {
      authBaseUrl: process.env.AUTH_BASE_URL ?? 'http://localhost:3000',
      clientId,
      clientSecret,
      selfAudience: SELF_AUDIENCE,
      cacheTtlMs: Number(process.env.INTROSPECTION_CACHE_MS ?? 30_000),
    });

    this.configure(RestExplorerBindings.COMPONENT).to({path: '/explorer'});
    this.component(RestExplorerComponent);
    this.api({
      openapi: '3.0.0',
      info: {
        title: 'Service B',
        version: '1.0.0',
        description:
          'A protected downstream service. Every endpoint below requires a ' +
          'bearer token issued by the auth service for audience "service-b".',
      },
      paths: {},
      components: {
        securitySchemes: {
          bearerAuth: {type: 'http', scheme: 'bearer'},
        },
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
