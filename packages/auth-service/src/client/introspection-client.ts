import {createHash} from 'crypto';
import {ServiceTokenClient} from './token-client';
import {CallerIdentity, IntrospectionResponse} from './types';

export interface IntrospectionClientOptions {
  authBaseUrl: string;
  /**
   * The resource server's own token client. Introspection is itself an
   * authenticated call: the resource server proves who it is with a bearer
   * token rather than putting its secret on every request.
   */
  tokenClient: ServiceTokenClient;
  /** How long a positive result may be reused. Default 30s. */
  cacheTtlMs?: number;
  /** How long a negative result is remembered. Default 5s. */
  negativeCacheTtlMs?: number;
  /** Cache size cap. Default 5000. */
  maxCacheEntries?: number;
  timeoutMs?: number;
}

interface CacheEntry {
  value: IntrospectionResponse;
  expiresAt: number;
}

/**
 * Calls `POST /oauth/introspect` on the auth service and caches the answer for
 * a few seconds.
 *
 * The cache is the knob that trades revocation latency against load on the
 * auth service: a 30s TTL means a revoked token stops working within 30s while
 * the auth service sees at most 2 calls per minute per distinct token.
 */
export class IntrospectionClient {
  private readonly opts: Required<IntrospectionClientOptions>;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inflight = new Map<string, Promise<IntrospectionResponse>>();

  constructor(options: IntrospectionClientOptions) {
    this.opts = {
      cacheTtlMs: 30_000,
      negativeCacheTtlMs: 5_000,
      maxCacheEntries: 5_000,
      timeoutMs: 5_000,
      ...options,
      authBaseUrl: options.authBaseUrl.replace(/\/+$/, ''),
    };
  }

  async introspect(token: string): Promise<IntrospectionResponse> {
    // Never key the cache on the raw token: a heap dump should not hand over
    // usable credentials.
    const key = createHash('sha256').update(token).digest('base64url');

    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > Date.now()) return hit.value;
    this.cache.delete(key);

    let pending = this.inflight.get(key);
    if (!pending) {
      pending = this.callAuthService(token)
        .then(result => {
          this.store(key, result);
          return result;
        })
        .finally(() => this.inflight.delete(key));
      this.inflight.set(key, pending);
    }
    return pending;
  }

  /** Normalises a raw introspection response into a caller identity. */
  static toIdentity(res: IntrospectionResponse): CallerIdentity | undefined {
    if (!res.active || !res.client_id) return undefined;
    return {
      appId: res.client_id,
      appName: res.app_name,
      scopes: res.scope ? res.scope.split(' ').filter(Boolean) : [],
      audience: res.aud,
      secretId: res.sid,
      tokenId: res.jti,
      expiresAt: res.exp ? new Date(res.exp * 1000) : undefined,
      app: res.app,
    };
  }

  private store(key: string, value: IntrospectionResponse): void {
    const now = Date.now();
    let ttl = value.active ? this.opts.cacheTtlMs : this.opts.negativeCacheTtlMs;
    if (value.active && value.exp) {
      // Never outlive the token itself.
      ttl = Math.min(ttl, value.exp * 1000 - now);
    }
    if (ttl <= 0) return;

    if (this.cache.size >= this.opts.maxCacheEntries) {
      // Map preserves insertion order, so the first key is the oldest.
      const oldest = this.cache.keys().next();
      if (!oldest.done) this.cache.delete(oldest.value);
    }
    this.cache.set(key, {value, expiresAt: now + ttl});
  }

  private async callAuthService(
    token: string,
  ): Promise<IntrospectionResponse> {
    const response = await this.opts.tokenClient.fetch(
      `${this.opts.authBaseUrl}/oauth/introspect`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({token}),
        signal: AbortSignal.timeout(this.opts.timeoutMs),
      },
    );

    if (!response.ok) {
      // Fail closed. An auth service that cannot answer is not permission to
      // let the request through.
      throw new Error(
        `introspection failed with status ${response.status}`,
      );
    }
    return (await response.json()) as IntrospectionResponse;
  }
}
