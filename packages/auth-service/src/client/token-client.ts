import {TokenClientError, TokenResponse} from './types';

export interface TokenClientOptions {
  /** Base URL of the auth service, e.g. `http://localhost:3000`. */
  authBaseUrl: string;
  /** Application id issued by the auth service. */
  clientId: string;
  /**
   * The long lived application secret. It is sent to exactly one endpoint
   * (`POST /oauth/token`) and never travels to any other service.
   */
  clientSecret: string;
  /** Which service this token is for (the resource server's audience id). */
  audience: string;
  /** Scopes to request; the auth service grants the subset the app is allowed. */
  scopes?: string[];
  /** Refresh this many seconds before the token actually expires. Default 60. */
  refreshSkewSeconds?: number;
  /** Request timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Retries on 5xx / network failure. Default 2. */
  maxRetries?: number;
}

interface CachedToken {
  accessToken: string;
  /** Epoch ms after which the token must be replaced. */
  refreshAt: number;
  expiresAt: number;
  scope: string;
}

/**
 * Acquires and caches short lived access tokens using the client credentials
 * grant.
 *
 * The point of this class is that the application secret stays inside the
 * process: outbound calls to other services only ever carry a bearer token
 * that expires in minutes and is scoped to a single audience.
 */
export class ServiceTokenClient {
  private readonly opts: Required<TokenClientOptions>;
  private cached?: CachedToken;
  /** Single flight guard so a burst of callers triggers one token request. */
  private inflight?: Promise<CachedToken>;

  constructor(options: TokenClientOptions) {
    if (!options.clientId || !options.clientSecret) {
      throw new TokenClientError(
        'ServiceTokenClient requires clientId and clientSecret',
      );
    }
    this.opts = {
      scopes: [],
      refreshSkewSeconds: 60,
      timeoutMs: 5000,
      maxRetries: 2,
      ...options,
      authBaseUrl: options.authBaseUrl.replace(/\/+$/, ''),
    };
  }

  /** Returns a valid access token, fetching or refreshing it when needed. */
  async getToken(): Promise<string> {
    const now = Date.now();
    if (this.cached && now < this.cached.refreshAt) {
      return this.cached.accessToken;
    }
    if (!this.inflight) {
      this.inflight = this.fetchToken().finally(() => {
        this.inflight = undefined;
      });
    }
    const token = await this.inflight;
    return token.accessToken;
  }

  /**
   * Drops the cached token. Call this when a downstream service answers 401 so
   * the next attempt mints a fresh token instead of replaying a revoked one.
   */
  invalidate(): void {
    this.cached = undefined;
  }

  /** `fetch` wrapper that attaches the bearer token and retries once on 401. */
  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const send = async () => {
      const token = await this.getToken();
      const headers = new Headers(init.headers);
      headers.set('authorization', `Bearer ${token}`);
      return fetch(url, {...init, headers});
    };

    let response = await send();
    if (response.status === 401) {
      // The token was revoked or the auth service restarted its pepper.
      this.invalidate();
      response = await send();
    }
    return response;
  }

  private async fetchToken(): Promise<CachedToken> {
    const url = `${this.opts.authBaseUrl}/oauth/token`;
    const basic = Buffer.from(
      `${encodeURIComponent(this.opts.clientId)}:${encodeURIComponent(
        this.opts.clientSecret,
      )}`,
    ).toString('base64');

    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      audience: this.opts.audience,
    });
    if (this.opts.scopes.length) {
      body.set('scope', this.opts.scopes.join(' '));
    }

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.opts.maxRetries; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            authorization: `Basic ${basic}`,
            'content-type': 'application/x-www-form-urlencoded',
            accept: 'application/json',
          },
          body,
          signal: AbortSignal.timeout(this.opts.timeoutMs),
        });

        if (response.status >= 500) {
          lastError = new TokenClientError(
            `auth service returned ${response.status}`,
            response.status,
          );
          await delay(backoffMs(attempt));
          continue;
        }

        const payload = (await response.json().catch(() => ({}))) as
          | TokenResponse
          | {error?: string; error_description?: string};

        if (!response.ok) {
          const err = payload as {error?: string; error_description?: string};
          // 4xx means our credentials or configuration are wrong: do not retry.
          throw new TokenClientError(
            err.error_description ?? err.error ?? 'token request rejected',
            response.status,
            err.error,
          );
        }

        const token = payload as TokenResponse;
        const now = Date.now();
        const lifetimeMs = token.expires_in * 1000;
        const skewMs = Math.min(
          this.opts.refreshSkewSeconds * 1000,
          Math.floor(lifetimeMs / 2),
        );
        this.cached = {
          accessToken: token.access_token,
          expiresAt: now + lifetimeMs,
          refreshAt: now + lifetimeMs - skewMs,
          scope: token.scope,
        };
        return this.cached;
      } catch (err) {
        if (err instanceof TokenClientError && err.status && err.status < 500) {
          throw err;
        }
        lastError = err;
        if (attempt < this.opts.maxRetries) await delay(backoffMs(attempt));
      }
    }
    throw new TokenClientError(
      `unable to obtain access token: ${String(
        (lastError as Error)?.message ?? lastError,
      )}`,
    );
  }
}

function backoffMs(attempt: number): number {
  // 100ms, 300ms, 700ms ... with jitter.
  return (2 ** attempt * 100 + Math.random() * 100) | 0;
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
