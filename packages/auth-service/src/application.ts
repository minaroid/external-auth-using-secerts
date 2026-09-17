import {
  AuthenticationComponent,
  registerAuthenticationStrategy,
} from '@loopback/authentication';
import {BootMixin} from '@loopback/boot';
import {ApplicationConfig} from '@loopback/core';
import {RepositoryMixin} from '@loopback/repository';
import {RestApplication} from '@loopback/rest';
import {
  RestExplorerBindings,
  RestExplorerComponent,
} from '@loopback/rest-explorer';
import path from 'path';
import {AdminKeyStrategy, LocalBearerStrategy} from './auth';
import {scopeCheckInterceptor} from './client';
import {AUTH_CONFIG, loadConfig} from './config';

export {ApplicationConfig};

export class AuthServiceApplication extends BootMixin(
  RepositoryMixin(RestApplication),
) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    // Fail fast on a bad configuration rather than at the first token request.
    this.bind(AUTH_CONFIG).to(loadConfig());

    this.component(AuthenticationComponent);
    registerAuthenticationStrategy(this, AdminKeyStrategy);
    registerAuthenticationStrategy(this, LocalBearerStrategy);
    this.interceptor(scopeCheckInterceptor, {
      global: true,
      group: 'authorization',
    });

    this.configure(RestExplorerBindings.COMPONENT).to({path: '/explorer'});
    this.component(RestExplorerComponent);
    this.addSecuritySchemes();

    this.projectRoot = __dirname;
    this.bootOptions = {
      controllers: {dirs: ['controllers'], extensions: ['.controller.js'], nested: true},
      repositories: {dirs: ['repositories'], extensions: ['.repository.js'], nested: true},
      services: {dirs: ['services'], extensions: ['.service.js'], nested: true},
      datasources: {dirs: ['datasources'], extensions: ['.datasource.js'], nested: true},
      observers: {dirs: ['observers'], extensions: ['.observer.js'], nested: true},
    };
  }

  /** Documents the three ways to authenticate, for the API explorer. */
  private addSecuritySchemes(): void {
    this.api({
      openapi: '3.0.0',
      info: {
        title: 'TRA Authentication Service',
        version: '1.0.0',
        description:
          'Application registry, secret lifecycle, and token issuance and ' +
          'verification for service-to-service calls.',
      },
      paths: {},
      components: {
        securitySchemes: {
          basicAuth: {
            type: 'http',
            scheme: 'basic',
            description:
              'client_id and client_secret, used only at POST /oauth/token.',
          },
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            description: 'A short lived access token from POST /oauth/token.',
          },
          adminKey: {
            type: 'apiKey',
            in: 'header',
            name: 'x-admin-key',
            description: 'Management API key for the /admin endpoints.',
          },
        },
      },
      servers: [{url: '/'}],
    });
  }
}
