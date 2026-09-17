import {BindingScope, inject, injectable} from '@loopback/core';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';

interface Attempt {
  failures: number;
  firstFailureAt: number;
  lockedUntil?: number;
}

/**
 * Throttles credential guessing at the token endpoint.
 *
 * In-memory on purpose: it is a speed bump, not a distributed quota. Behind
 * more than one replica, move this to Redis — the interface stays the same.
 */
@injectable({scope: BindingScope.SINGLETON})
export class RateLimiterService {
  private readonly attempts = new Map<string, Attempt>();
  private readonly windowMs = 15 * 60 * 1000;

  constructor(@inject(AUTH_CONFIG) private config: AuthServiceConfig) {
    // Keep the map from growing without bound in a long lived process.
    const timer = setInterval(() => this.sweep(), 60_000);
    timer.unref?.();
  }

  /** Seconds remaining in a lockout, or 0 when the caller may proceed. */
  retryAfter(key: string): number {
    const entry = this.attempts.get(key);
    if (!entry?.lockedUntil) return 0;
    const remaining = entry.lockedUntil - Date.now();
    if (remaining <= 0) {
      this.attempts.delete(key);
      return 0;
    }
    return Math.ceil(remaining / 1000);
  }

  recordFailure(key: string): void {
    const now = Date.now();
    const entry = this.attempts.get(key);

    if (!entry || now - entry.firstFailureAt > this.windowMs) {
      this.attempts.set(key, {failures: 1, firstFailureAt: now});
      return;
    }

    entry.failures += 1;
    if (entry.failures >= this.config.maxFailedAttempts) {
      entry.lockedUntil = now + this.config.lockoutSeconds * 1000;
      entry.failures = 0;
      entry.firstFailureAt = now;
    }
  }

  recordSuccess(key: string): void {
    this.attempts.delete(key);
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.attempts) {
      const expired =
        (entry.lockedUntil ?? 0) < now &&
        now - entry.firstFailureAt > this.windowMs;
      if (expired) this.attempts.delete(key);
    }
  }
}
