import {BindingScope, inject, injectable} from '@loopback/core';
import {
  createHmac,
  randomBytes,
  randomUUID,
  scrypt as scryptCb,
  timingSafeEqual,
} from 'crypto';
import {promisify} from 'util';
import {AUTH_CONFIG, AuthServiceConfig} from '../config';

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: {N: number; r: number; p: number; maxmem: number},
) => Promise<Buffer>;

/** scrypt cost. 16384/8/1 is ~16MB and ~50ms — fine for a rare endpoint. */
const SCRYPT = {N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024};

export const SECRET_PREFIX = 'tra_sk';
export const TOKEN_PREFIX = 'tra_at';

/** `tra_sk_<16 hex id>.<43 char body>` */
const CREDENTIAL_RE = /^(tra_(?:sk|at))_([0-9a-f]{16})\.([A-Za-z0-9_-]{43})$/;

export interface ParsedCredential {
  kind: 'tra_sk' | 'tra_at';
  id: string;
  body: string;
}

/**
 * All credential material passes through here.
 *
 * Two different treatments on purpose:
 *  - application secrets are hashed with scrypt, because they are long lived
 *    and verified rarely (once per token request, minutes apart);
 *  - access tokens are hashed with a peppered HMAC, because they are verified
 *    on every introspection and are already 256 bits of entropy, which leaves
 *    nothing for a slow hash to defend against.
 */
@injectable({scope: BindingScope.SINGLETON})
export class CryptoService {
  constructor(
    @inject(AUTH_CONFIG) private config: AuthServiceConfig,
  ) {}

  /** 16 hex characters — enough to be unguessable as a lookup handle. */
  newId(): string {
    return randomBytes(8).toString('hex');
  }

  newUuid(): string {
    return randomUUID();
  }

  /**
   * Mints a credential string. The id travels in the string so verification is
   * a single indexed read rather than a scan over every stored hash.
   */
  mintCredential(prefix: typeof SECRET_PREFIX | typeof TOKEN_PREFIX): {
    id: string;
    plaintext: string;
  } {
    const id = this.newId();
    const body = randomBytes(32).toString('base64url');
    return {id, plaintext: `${prefix}_${id}.${body}`};
  }

  parseCredential(value: string): ParsedCredential | undefined {
    const match = CREDENTIAL_RE.exec(value.trim());
    if (!match) return undefined;
    return {
      kind: match[1] as ParsedCredential['kind'],
      id: match[2],
      body: match[3],
    };
  }

  /** Safe to store and display: identifies a secret without revealing it. */
  displayHint(plaintext: string): string {
    const parsed = this.parseCredential(plaintext);
    if (!parsed) return '****';
    return `${parsed.kind}_${parsed.id}…${parsed.body.slice(-4)}`;
  }

  // ---- application secrets (scrypt) ----

  async hashSecret(plaintext: string): Promise<string> {
    const salt = randomBytes(16);
    const hash = await scrypt(plaintext, salt, SCRYPT.keylen, SCRYPT);
    return [
      'scrypt',
      SCRYPT.N,
      SCRYPT.r,
      SCRYPT.p,
      salt.toString('base64url'),
      hash.toString('base64url'),
    ].join('$');
  }

  async verifySecret(plaintext: string, stored: string): Promise<boolean> {
    const parts = stored.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

    const [, n, r, p, saltB64, hashB64] = parts;
    const expected = Buffer.from(hashB64, 'base64url');
    let actual: Buffer;
    try {
      actual = await scrypt(
        plaintext,
        Buffer.from(saltB64, 'base64url'),
        expected.length,
        {
          N: Number(n),
          r: Number(r),
          p: Number(p),
          maxmem: SCRYPT.maxmem,
        },
      );
    } catch {
      return false;
    }
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  // ---- access tokens (peppered HMAC) ----

  hashToken(plaintext: string): string {
    return createHmac('sha256', this.config.tokenPepper)
      .update(plaintext)
      .digest('base64url');
  }

  tokenHashMatches(plaintext: string, storedHash: string): boolean {
    const computed = Buffer.from(this.hashToken(plaintext));
    const stored = Buffer.from(storedHash);
    return (
      computed.length === stored.length && timingSafeEqual(computed, stored)
    );
  }

  /** Constant-time comparison for the admin API key. */
  constantTimeEquals(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      // Compare against itself so the timing does not leak the length.
      timingSafeEqual(bufA, bufA);
      return false;
    }
    return timingSafeEqual(bufA, bufB);
  }

  /** Short non-reversible label for an actor, safe to write to the audit log. */
  fingerprint(value: string): string {
    return createHmac('sha256', this.config.tokenPepper)
      .update(`fingerprint:${value}`)
      .digest('hex')
      .slice(0, 12);
  }
}
