import {Entity, model, property} from '@loopback/repository';

export type ApplicationStatus = 'active' | 'suspended';

/**
 * A registered application (an OAuth "client").
 *
 * Everything a resource server may want to know about a caller lives here and
 * only here. The caller cannot assert any of it — it is attached to the token
 * by the auth service at introspection time — so service B can trust these
 * fields for routing, quotas, tenancy and support escalation.
 */
@model({
  settings: {
    postgresql: {table: 'applications'},
    indexes: {name_idx: {keys: {name: 1}, options: {unique: true}}},
  },
})
export class Application extends Entity {
  /** Stable, human readable id such as `service-a`. Used as `client_id`. */
  @property({type: 'string', id: true, required: true})
  id: string;

  @property({type: 'string', required: true})
  name: string;

  @property({type: 'string'})
  description?: string;

  /** Owning team or department, e.g. "licensing-platform". */
  @property({type: 'string'})
  team?: string;

  /** Person or group accountable for this application. */
  @property({type: 'string'})
  owner?: string;

  /** Where to reach the owner when the app misbehaves. */
  @property({type: 'string'})
  contactEmail?: string;

  /** dev | staging | prod */
  @property({type: 'string', default: 'dev'})
  environment: string;

  /** Free-form labels used for grouping and filtering. */
  @property.array(String, {default: () => []})
  tags: string[];

  /**
   * Arbitrary attributes a resource server may need, for example
   * `{"tenantId": "tdra", "rateLimitTier": "gold", "dataResidency": "ae"}`.
   * Handed to resource servers verbatim.
   */
  @property({type: 'object', default: () => ({})})
  metadata: Record<string, unknown>;

  /**
   * The audience id this application answers to when it acts as a resource
   * server. Callers ask for a token `audience: <this value>`.
   */
  @property({type: 'string'})
  audience?: string;

  /** Audiences this application is allowed to request tokens for. */
  @property.array(String, {default: () => []})
  allowedAudiences: string[];

  /** The maximum set of scopes this application may ever be granted. */
  @property.array(String, {default: () => []})
  allowedScopes: string[];

  /** Suspending an app stops token issuance without deleting its history. */
  @property({type: 'string', default: 'active'})
  status: ApplicationStatus;

  /** Overrides the global access token TTL for this application. */
  @property({type: 'number'})
  tokenTtlSeconds?: number;

  /**
   * Optional allowlist of source IPs / CIDRs for token requests. Empty means
   * no restriction.
   */
  @property.array(String, {default: () => []})
  allowedIps: string[];

  @property({type: 'date', defaultFn: 'now'})
  createdAt: Date;

  @property({type: 'date', defaultFn: 'now'})
  updatedAt: Date;

  constructor(data?: Partial<Application>) {
    super(data);
  }
}
