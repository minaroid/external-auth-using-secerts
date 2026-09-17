import {BindingKey} from '@loopback/core';
import {ServiceTokenClient} from '@tra/auth-service/client';

export const SERVICE_B_CLIENT = BindingKey.create<ServiceBClient>(
  'clients.service-b',
);

export class ServiceBError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = 'ServiceBError';
  }
}

/**
 * Typed wrapper around service B.
 *
 * Note what is absent: no secret, no header juggling. `tokenClient.fetch`
 * attaches a current access token and retries once if the token turned out to
 * be revoked, so callers here just make requests.
 */
export class ServiceBClient {
  constructor(
    private readonly baseUrl: string,
    private readonly tokens: ServiceTokenClient,
  ) {}

  async getOrder(id: string): Promise<unknown> {
    return this.request('GET', `/orders/${encodeURIComponent(id)}`);
  }

  async listOrders(): Promise<unknown> {
    return this.request('GET', '/orders');
  }

  async createOrder(body: {
    reference: string;
    amount: number;
    currency?: string;
  }): Promise<unknown> {
    return this.request('POST', '/orders', body);
  }

  /** Asks service B what it sees about us — handy for verifying the wiring. */
  async whoAmI(): Promise<unknown> {
    return this.request('GET', '/whoami');
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const response = await this.tokens.fetch(`${this.baseUrl}${path}`, {
      method,
      headers: body
        ? {'content-type': 'application/json', accept: 'application/json'}
        : {accept: 'application/json'},
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
    });

    const payload = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw new ServiceBError(
        `service-b ${method} ${path} failed with ${response.status}`,
        response.status,
        payload,
      );
    }
    return payload;
  }
}
