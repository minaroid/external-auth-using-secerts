import {BindingKey} from '@loopback/core';

export interface AuthServiceConfig {
  /** Secret used to HMAC access tokens at rest. Rotating it kills all tokens. */
  tokenPepper: string;
  /** Bootstrap key for the management API. */
  adminApiKey: string;
  accessTokenTtlSeconds: number;
  /** Default lifetime for a newly issued application secret. */
  secretDefaultTtlDays: number;
  /** How long the previous secret keeps working after a rotation. */
  rotationGraceMinutes: number;
  /** Failed token requests per client before a temporary lockout. */
  maxFailedAttempts: number;
  lockoutSeconds: number;
  /** Audience id of this auth service itself. */
  selfAudience: string;
}

export const AUTH_CONFIG = BindingKey.create<AuthServiceConfig>(
  'tra.auth.config',
);

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(
      `${name} must be set. Generate one with: openssl rand -base64 48`,
    );
  }
  if (value.startsWith('change-me')) {
    throw new Error(`${name} still holds the placeholder value from .env.example`);
  }
  return value;
}

function num(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be a number`);
  return parsed;
}

export function loadConfig(): AuthServiceConfig {
  const config: AuthServiceConfig = {
    tokenPepper: required('TOKEN_PEPPER'),
    adminApiKey: required('ADMIN_API_KEY'),
    accessTokenTtlSeconds: num('ACCESS_TOKEN_TTL_SECONDS', 600),
    secretDefaultTtlDays: num('SECRET_DEFAULT_TTL_DAYS', 180),
    rotationGraceMinutes: num('ROTATION_GRACE_MINUTES', 60),
    maxFailedAttempts: num('MAX_FAILED_ATTEMPTS', 10),
    lockoutSeconds: num('LOCKOUT_SECONDS', 300),
    selfAudience: process.env.AUTH_AUDIENCE ?? 'tra-auth',
  };

  if (Buffer.from(config.tokenPepper).length < 32) {
    throw new Error('TOKEN_PEPPER must be at least 32 bytes');
  }
  if (config.accessTokenTtlSeconds > 3600) {
    throw new Error(
      'ACCESS_TOKEN_TTL_SECONDS above one hour defeats the point of short lived tokens',
    );
  }
  return config;
}
