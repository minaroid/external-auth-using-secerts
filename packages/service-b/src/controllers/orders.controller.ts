import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {get, HttpErrors, param, post, requestBody} from '@loopback/rest';
import {SecurityBindings} from '@loopback/security';
import {
  requireScopes,
  SERVICE_TOKEN_STRATEGY,
  ServicePrincipal,
} from '@tra/auth-service/client';

interface Order {
  id: string;
  reference: string;
  amount: number;
  currency: string;
  status: string;
  tenantId: string;
}

/** Stand-in for whatever this service actually owns. */
const ORDERS: Record<string, Order> = {
  '1001': {
    id: '1001',
    reference: 'TRA-LIC-1001',
    amount: 4500,
    currency: 'AED',
    status: 'approved',
    tenantId: 'tdra',
  },
  '1002': {
    id: '1002',
    reference: 'TRA-LIC-1002',
    amount: 12750,
    currency: 'AED',
    status: 'pending',
    tenantId: 'tdra',
  },
  '2001': {
    id: '2001',
    reference: 'OTHER-2001',
    amount: 900,
    currency: 'AED',
    status: 'approved',
    tenantId: 'other-tenant',
  },
};

/**
 * The protected resource.
 *
 * Every method states the scope it needs. The token is verified against the
 * auth service before the method body runs, and the caller's registry profile
 * arrives with it — so decisions about tenancy, rate limiting or environment
 * can be made from facts the caller cannot forge.
 */
@authenticate(SERVICE_TOKEN_STRATEGY)
export class OrdersController {
  constructor(
    @inject(SecurityBindings.USER) private caller: ServicePrincipal,
  ) {}

  @requireScopes('orders:read')
  @get('/orders/{id}', {
    tags: ['Orders'],
    summary: 'Read one order',
    security: [{bearerAuth: []}],
    responses: {
      '200': {description: 'The order'},
      '401': {description: 'Missing, expired or revoked token'},
      '403': {description: 'Token lacks the orders:read scope'},
    },
  })
  async findById(@param.path.string('id') id: string): Promise<object> {
    const order = ORDERS[id];
    if (!order) throw new HttpErrors.NotFound(`no order ${id}`);

    // The caller's tenant comes from the registry, not from the request, so a
    // service cannot reach another tenant's data by asking nicely.
    const tenantId = this.caller.app?.metadata?.tenantId as string | undefined;
    if (tenantId && order.tenantId !== tenantId) {
      throw new HttpErrors.Forbidden(
        `application ${this.caller.appId} may not read orders of tenant ${order.tenantId}`,
      );
    }

    this.logAccess('read', id);
    return {order, servedTo: this.describeCaller()};
  }

  @requireScopes('orders:read')
  @get('/orders', {
    tags: ['Orders'],
    summary: 'List orders visible to the calling application',
    security: [{bearerAuth: []}],
    responses: {'200': {description: 'OK'}},
  })
  async list(): Promise<object> {
    const tenantId = this.caller.app?.metadata?.tenantId as string | undefined;
    const orders = Object.values(ORDERS).filter(
      order => !tenantId || order.tenantId === tenantId,
    );

    this.logAccess('list', `${orders.length} orders`);
    return {orders, servedTo: this.describeCaller()};
  }

  @requireScopes('orders:write')
  @post('/orders', {
    tags: ['Orders'],
    summary: 'Create an order',
    description:
      'Requires the orders:write scope, which the demo service-a application ' +
      'is not granted — a useful way to see a 403 from a valid token.',
    security: [{bearerAuth: []}],
    responses: {'200': {description: 'OK'}},
  })
  async create(
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
  ): Promise<object> {
    const id = String(Math.floor(Math.random() * 9000) + 1000);
    const order: Order = {
      id,
      reference: body.reference,
      amount: body.amount,
      currency: body.currency ?? 'AED',
      status: 'pending',
      tenantId: (this.caller.app?.metadata?.tenantId as string) ?? 'tdra',
    };
    ORDERS[id] = order;

    this.logAccess('create', id);
    return {order, createdBy: this.describeCaller()};
  }

  @get('/whoami', {
    tags: ['Diagnostics'],
    summary: 'Echo back everything this service knows about the caller',
    description:
      'Useful while wiring up a new client: it shows exactly which registry ' +
      'fields and scopes arrived with the token.',
    security: [{bearerAuth: []}],
    responses: {'200': {description: 'OK'}},
  })
  async whoami(): Promise<object> {
    return {
      appId: this.caller.appId,
      scopes: this.caller.scopes,
      audience: this.caller.audience,
      tokenExpiresAt: this.caller.expiresAt,
      // Which secret minted the token — handy when tracing a rotation.
      secretId: this.caller.secretId,
      profile: this.caller.app,
    };
  }

  /** The profile fields worth returning to the caller or writing to logs. */
  private describeCaller(): object {
    return {
      appId: this.caller.appId,
      name: this.caller.app?.name,
      team: this.caller.app?.team,
      environment: this.caller.app?.environment,
      contactEmail: this.caller.app?.contactEmail,
    };
  }

  private logAccess(action: string, target: string): void {
    const app = this.caller.app;
    console.log(
      `[service-b] ${action} ${target} for ${this.caller.appId}` +
        ` (${app?.team ?? 'no team'}, ${app?.environment ?? 'no env'})` +
        ` scopes=[${this.caller.scopes.join(' ')}] tier=${
          app?.metadata?.rateLimitTier ?? 'default'
        }`,
    );
  }
}
