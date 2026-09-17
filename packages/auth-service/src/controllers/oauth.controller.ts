import {authenticate} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {
  post,
  Request,
  requestBody,
  Response,
  RestBindings,
  SchemaObject,
} from '@loopback/rest';
import {SecurityBindings} from '@loopback/security';
import {requireScopes, ServicePrincipal} from '../client';
import {LOCAL_BEARER_STRATEGY} from '../auth';
import {OAuthError, TokenService} from '../services';

/** Accepted as `application/x-www-form-urlencoded` or JSON. */
const TOKEN_REQUEST_SCHEMA: SchemaObject = {
  type: 'object',
  required: ['grant_type', 'audience'],
  properties: {
    grant_type: {type: 'string', enum: ['client_credentials']},
    /** The service being called, e.g. `service-b`. */
    audience: {type: 'string'},
    scope: {type: 'string', description: 'space delimited'},
    /** Only when not using the Basic authorization header. */
    client_id: {type: 'string'},
    client_secret: {type: 'string'},
  },
  additionalProperties: false,
};

const TOKEN_CONTENT = {
  'application/x-www-form-urlencoded': {schema: TOKEN_REQUEST_SCHEMA},
  'application/json': {schema: TOKEN_REQUEST_SCHEMA},
};

const INTROSPECT_SCHEMA: SchemaObject = {
  type: 'object',
  required: ['token'],
  properties: {token: {type: 'string'}},
  additionalProperties: false,
};

const INTROSPECT_CONTENT = {
  'application/x-www-form-urlencoded': {schema: INTROSPECT_SCHEMA},
  'application/json': {schema: INTROSPECT_SCHEMA},
};

interface TokenRequestBody {
  grant_type?: string;
  audience?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

/**
 * The OAuth 2.0 surface: one endpoint that turns a secret into a token, and
 * one that tells a resource server whether a token is real.
 */
export class OAuthController {
  constructor(
    @service(TokenService) private tokens: TokenService,
    @inject(RestBindings.Http.REQUEST) private request: Request,
    @inject(RestBindings.Http.RESPONSE) private response: Response,
  ) {}

  @post('/oauth/token', {
    tags: ['OAuth'],
    summary: 'Exchange an application secret for a short lived access token',
    description:
      'Send credentials with HTTP Basic (recommended) or in the body. The ' +
      'returned token is the only credential that should appear on calls to ' +
      'other services.',
    security: [{basicAuth: []}],
    responses: {
      '200': {
        description: 'Access token issued',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                access_token: {type: 'string'},
                token_type: {type: 'string'},
                expires_in: {type: 'number'},
                scope: {type: 'string'},
                audience: {type: 'string'},
              },
            },
          },
        },
      },
      '401': {description: 'invalid_client'},
      '429': {description: 'slow_down — too many failed attempts'},
    },
  })
  async token(
    @requestBody({content: TOKEN_CONTENT, required: true})
    body: TokenRequestBody,
  ): Promise<Response> {
    // Token responses must never be cached anywhere on the path (RFC 6749 §5.1).
    this.response.setHeader('Cache-Control', 'no-store');
    this.response.setHeader('Pragma', 'no-cache');

    try {
      if (body.grant_type !== 'client_credentials') {
        throw new OAuthError(
          'unsupported_grant_type',
          'only client_credentials is supported',
        );
      }

      const credentials = this.readCredentials(body);
      const result = await this.tokens.issueToken({
        clientId: credentials.clientId,
        clientSecret: credentials.clientSecret,
        audience: body.audience ?? '',
        scope: body.scope,
        clientIp: this.clientIp(),
      });
      return this.response.status(200).send(result);
    } catch (err) {
      return this.sendOAuthError(err);
    }
  }

  @authenticate(LOCAL_BEARER_STRATEGY)
  @requireScopes('introspect')
  @post('/oauth/introspect', {
    tags: ['OAuth'],
    summary: 'Verify a bearer token (RFC 7662)',
    description:
      'Called by resource servers. The caller authenticates with its own ' +
      'access token, so no application secret is ever sent here. The response ' +
      'includes the registry profile of the calling application.',
    security: [{bearerAuth: []}],
    responses: {
      '200': {
        description:
          'Introspection result. `active: false` covers every failure mode.',
        content: {'application/json': {schema: {type: 'object'}}},
      },
    },
  })
  async introspect(
    @requestBody({content: INTROSPECT_CONTENT, required: true})
    body: {token: string},
    @inject(SecurityBindings.USER) caller: ServicePrincipal,
  ): Promise<Response> {
    this.response.setHeader('Cache-Control', 'no-store');
    const result = await this.tokens.introspect(body.token ?? '');
    return this.response.status(200).send(result);
  }

  @authenticate(LOCAL_BEARER_STRATEGY)
  @post('/oauth/revoke', {
    tags: ['OAuth'],
    summary: 'Revoke an access token (RFC 7009)',
    description:
      'Always answers 200, whether or not the token existed, so it cannot be ' +
      'used to probe for valid tokens.',
    security: [{bearerAuth: []}],
    responses: {'200': {description: 'Processed'}},
  })
  async revoke(
    @requestBody({content: INTROSPECT_CONTENT, required: true})
    body: {token: string},
    @inject(SecurityBindings.USER) caller: ServicePrincipal,
  ): Promise<Response> {
    this.response.setHeader('Cache-Control', 'no-store');
    await this.tokens.revokeToken(body.token ?? '', caller.appId);
    return this.response.status(200).send({revoked: true});
  }

  /**
   * Basic authorization header first, body parameters second. Sending both is
   * rejected rather than silently resolved.
   */
  private readCredentials(body: TokenRequestBody): {
    clientId: string;
    clientSecret: string;
  } {
    const header = this.request.headers.authorization;
    const fromHeader = header?.startsWith('Basic ')
      ? decodeBasic(header.slice('Basic '.length))
      : undefined;

    const hasBodyCredentials = Boolean(body.client_id ?? body.client_secret);

    if (fromHeader && hasBodyCredentials) {
      throw new OAuthError(
        'invalid_request',
        'send client credentials either in the Authorization header or in the body, not both',
      );
    }
    if (fromHeader) return fromHeader;

    if (!body.client_id || !body.client_secret) {
      throw OAuthError.invalidClient('client credentials are missing');
    }
    return {clientId: body.client_id, clientSecret: body.client_secret};
  }

  private clientIp(): string | undefined {
    const forwarded = this.request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length) {
      return forwarded.split(',')[0].trim();
    }
    return this.request.ip;
  }

  private sendOAuthError(err: unknown): Response {
    if (err instanceof OAuthError) {
      for (const [name, value] of Object.entries(err.headers)) {
        this.response.setHeader(name, value);
      }
      return this.response.status(err.status).send(err.toJSON());
    }
    console.error('[oauth] unexpected failure', err);
    return this.response
      .status(500)
      .send({error: 'server_error', error_description: 'unexpected failure'});
  }
}

function decodeBasic(
  encoded: string,
): {clientId: string; clientSecret: string} | undefined {
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator < 0) return undefined;
  return {
    // RFC 6749 §2.3.1 requires form-encoding the two halves.
    clientId: safeDecode(decoded.slice(0, separator)),
    clientSecret: safeDecode(decoded.slice(separator + 1)),
  };
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
