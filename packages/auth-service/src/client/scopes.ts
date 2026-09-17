import {
  Interceptor,
  InvocationContext,
  MetadataInspector,
  MethodDecoratorFactory,
  Next,
} from '@loopback/core';
import {HttpErrors} from '@loopback/rest';
import {SecurityBindings, UserProfile} from '@loopback/security';
import {ServicePrincipal} from './strategy';

export const REQUIRED_SCOPES_KEY = 'tra:required-scopes';

/**
 * Declares the scopes a controller method needs. Applied together with
 * `@authenticate('service-token')`.
 *
 * All listed scopes must be present (AND), which keeps the rule easy to read
 * in an audit.
 */
export function requireScopes(...scopes: string[]) {
  return MethodDecoratorFactory.createDecorator<string[]>(
    REQUIRED_SCOPES_KEY,
    scopes,
    {decoratorName: '@requireScopes'},
  );
}

/** Reads the scopes declared on a controller method, if any. */
export function getRequiredScopes(
  targetClass: Function,
  methodName: string,
): string[] | undefined {
  return MetadataInspector.getMethodMetadata<string[]>(
    REQUIRED_SCOPES_KEY,
    targetClass.prototype,
    methodName,
  );
}

/** Throws 403 unless every required scope was granted. */
export function assertScopes(
  principal: ServicePrincipal | UserProfile | undefined,
  required: string[],
): void {
  const granted = new Set((principal as ServicePrincipal)?.scopes ?? []);
  const missing = required.filter(scope => !granted.has(scope));
  if (missing.length) {
    throw new HttpErrors.Forbidden(
      `insufficient scope; missing: ${missing.join(', ')}`,
    );
  }
}

/**
 * Global interceptor enforcing `@requireScopes`. Registered by
 * `setupServiceAuth`, so a method that declares scopes cannot accidentally
 * ship without the check.
 */
export const scopeCheckInterceptor: Interceptor = async (
  invocationCtx: InvocationContext,
  next: Next,
) => {
  const targetClass =
    invocationCtx.targetClass ??
    (invocationCtx.target as object)?.constructor;

  const required =
    targetClass && invocationCtx.methodName
      ? getRequiredScopes(targetClass, invocationCtx.methodName)
      : undefined;

  if (required?.length) {
    const principal = await invocationCtx.get<UserProfile | undefined>(
      SecurityBindings.USER,
      {optional: true},
    );
    if (!principal) {
      throw new HttpErrors.Unauthorized('authentication is required');
    }
    assertScopes(principal, required);
  }
  return next();
};
