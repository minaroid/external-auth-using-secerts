/**
 * RFC 6749 §5.2 / RFC 7662 style error. Carries the exact status and body the
 * OAuth endpoints must return, which the generic LoopBack error shape does not
 * match.
 */
export class OAuthError extends Error {
  constructor(
    readonly code:
      | 'invalid_request'
      | 'invalid_client'
      | 'invalid_grant'
      | 'invalid_scope'
      | 'unauthorized_client'
      | 'unsupported_grant_type'
      | 'access_denied'
      | 'slow_down'
      | 'server_error',
    readonly description: string,
    readonly status = 400,
    readonly headers: Record<string, string> = {},
  ) {
    super(description);
    this.name = 'OAuthError';
  }

  static invalidClient(description = 'client authentication failed'): OAuthError {
    // 401 + WWW-Authenticate, and deliberately vague: the caller does not get
    // to learn whether the id or the secret was the wrong one.
    return new OAuthError('invalid_client', description, 401, {
      'WWW-Authenticate': 'Basic realm="tra-auth", charset="UTF-8"',
    });
  }

  toJSON(): {error: string; error_description: string} {
    return {error: this.code, error_description: this.description};
  }
}
