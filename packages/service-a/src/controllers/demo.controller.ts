import {inject} from '@loopback/core';
import {get, HttpErrors, param, post, requestBody} from '@loopback/rest';
import {ServiceAuthBindings, ServiceTokenClient} from '@tra/auth-service/client';
import {
  SERVICE_B_CLIENT,
  ServiceBClient,
  ServiceBError,
} from '../clients/service-b.client';

/**
 * The calling side of the flow, exposed as plain HTTP so it is easy to try.
 *
 * None of these endpoints take a credential: service A already holds its own
 * secret, and turns it into a short lived token on demand.
 */
export class DemoController {
  constructor(
    @inject(SERVICE_B_CLIENT) private serviceB: ServiceBClient,
    @inject(ServiceAuthBindings.TOKEN_CLIENT)
    private authTokens: ServiceTokenClient,
  ) {}

  @get('/demo/orders/{id}', {
    tags: ['Demo'],
    summary: 'Fetch an order from service B',
    description:
      'The full path: secret → access token → call to service B → service B ' +
      'introspects the token with the auth service → data comes back.',
    responses: {'200': {description: 'The order as service B returned it'}},
  })
  async getOrder(@param.path.string('id') id: string): Promise<unknown> {
    return this.call(() => this.serviceB.getOrder(id));
  }

  @get('/demo/orders', {
    tags: ['Demo'],
    summary: 'List orders from service B',
    responses: {'200': {description: 'OK'}},
  })
  async listOrders(): Promise<unknown> {
    return this.call(() => this.serviceB.listOrders());
  }

  @post('/demo/orders', {
    tags: ['Demo'],
    summary: 'Try to create an order in service B',
    description:
      'Expected to fail with 403 in the seeded setup: service A is granted ' +
      'orders:read but not orders:write. That is the scope check working.',
    responses: {'200': {description: 'OK'}},
  })
  async createOrder(
    @requestBody({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['reference', 'amount'],
            properties: {
              reference: {type: 'string'},
              amount: {type: 'number'},
              currency: {type: 'string'},
            },
          },
        },
      },
    })
    body: {reference: string; amount: number; currency?: string},
  ): Promise<unknown> {
    return this.call(() => this.serviceB.createOrder(body));
  }

  @get('/demo/whoami', {
    tags: ['Demo'],
    summary: 'Ask service B what it knows about service A',
    description:
      'Shows the registry profile that travels with the token: team, owner, ' +
      'environment, tags and metadata.',
    responses: {'200': {description: 'OK'}},
  })
  async whoAmI(): Promise<unknown> {
    return this.call(() => this.serviceB.whoAmI());
  }

  @post('/demo/refresh-token', {
    tags: ['Demo'],
    summary: 'Drop the cached access token',
    description:
      'Forces the next call to mint a fresh token. Useful after rotating this ' +
      'application\'s secret.',
    responses: {'200': {description: 'OK'}},
  })
  async refreshToken(): Promise<{refreshed: true}> {
    this.authTokens.invalidate();
    return {refreshed: true};
  }

  /** Surfaces service B's status codes instead of flattening them to 500. */
  private async call<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof ServiceBError) {
        // A 401 or 403 from service B is a real answer about this request, so
        // pass it through rather than flattening it into a 500.
        const status = err.status >= 500 ? 502 : err.status;
        throw HttpErrors(
          status,
          `service-b refused the call: ${JSON.stringify(err.body)}`,
        );
      }
      throw err;
    }
  }
}
