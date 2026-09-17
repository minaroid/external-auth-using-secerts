import {BindingKey} from '@loopback/core';
import {IntrospectionClient} from './introspection-client';
import {ServiceTokenClient} from './token-client';

export namespace ServiceAuthBindings {
  /** The resource server's own credentials, used to call the auth service. */
  export const TOKEN_CLIENT = BindingKey.create<ServiceTokenClient>(
    'tra.service-auth.token-client',
  );
  export const INTROSPECTION_CLIENT = BindingKey.create<IntrospectionClient>(
    'tra.service-auth.introspection-client',
  );
  /** This service's own audience id; tokens for anyone else are rejected. */
  export const SELF_AUDIENCE = BindingKey.create<string>(
    'tra.service-auth.self-audience',
  );
}

export const SERVICE_TOKEN_STRATEGY = 'service-token';
