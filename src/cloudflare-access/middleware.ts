/**
 * Cloudflare Access authentication middleware helpers
 */

import {
  extractAccessToken,
  verifyAccessToken,
  extractAccessUser,
} from './verify';
import type {
  CloudflareAccessPayload,
  AccessUser,
  AccessGuardOptions,
  AccessGuardResult,
} from './types';

/** Create a JSON error response */
function errorResult(message: string, status: number): AccessGuardResult {
  return {
    success: false,
    errorResponse: new Response(
      JSON.stringify({ error: message }),
      { status, headers: { 'Content-Type': 'application/json' } }
    ),
  };
}

/** Check if request is from localhost for dev bypass */
function isLocalhost(request: Request): boolean {
  const url = new URL(request.url);
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
}

/** Check if email domain is in the allowed list */
function isDomainAllowed(email: string, allowedDomains: string[]): boolean {
  const domain = email.split('@')[1];
  return allowedDomains.includes(domain);
}

/**
 * Authentication guard for Cloudflare Pages Functions
 *
 * @example
 * ```typescript
 * const auth = await accessGuard(request, env, {
 *   getTeamDomain: (env) => env.CF_ACCESS_TEAM_DOMAIN,
 *   allowedDomains: ['aid-on.org'],
 * });
 * ```
 */
export async function accessGuard<Env = unknown>(
  request: Request,
  env: Env,
  options: AccessGuardOptions<Env>
): Promise<AccessGuardResult> {
  const {
    getTeamDomain,
    getAudience,
    verifySignature = true,
    allowedDomains,
    allowDevBypass = false,
  } = options;

  if (allowDevBypass && isLocalhost(request)) {
    const devUser: AccessUser = {
      id: 'dev-user-001',
      email: 'dev@example.com',
      name: 'Dev User',
    };
    return { success: true, user: devUser };
  }

  const token = extractAccessToken(request);
  if (!token) {
    return errorResult('Unauthorized: No access token provided', 401);
  }

  const teamDomain = getTeamDomain(env);
  if (!teamDomain) {
    return errorResult('Server configuration error: Missing team domain', 500);
  }

  const audience = getAudience?.(env);
  const result = await verifyAccessToken(token, { teamDomain, audience, verifySignature });

  if (!result.success || !result.payload) {
    return errorResult(`Unauthorized: ${result.error || 'Invalid token'}`, 401);
  }

  if (allowedDomains && allowedDomains.length > 0) {
    if (!isDomainAllowed(result.payload.email, allowedDomains)) {
      return errorResult('Forbidden: Email domain not allowed', 403);
    }
  }

  const user = extractAccessUser(result.payload);
  return { success: true, user, payload: result.payload };
}

/**
 * Require authentication helper - throws on failure
 *
 * @example
 * ```typescript
 * import { requireAccessAuth } from '@aid-on/gauth/cloudflare-access';
 *
 * export const onRequestGet: PagesFunction<Env> = async (context) => {
 *   try {
 *     const { user, payload } = await requireAccessAuth(context.request, context.env, {
 *       getTeamDomain: (env) => env.CF_ACCESS_TEAM_DOMAIN,
 *     });
 *
 *     return new Response(JSON.stringify({ user }));
 *   } catch (error) {
 *     if (error instanceof Response) {
 *       return error;
 *     }
 *     throw error;
 *   }
 * };
 * ```
 */
export async function requireAccessAuth<Env = unknown>(
  request: Request,
  env: Env,
  options: AccessGuardOptions<Env>
): Promise<{ user: AccessUser; payload: CloudflareAccessPayload }> {
  const result = await accessGuard(request, env, options);

  if (!result.success) {
    throw result.errorResponse;
  }

  if (!result.user || !result.payload) {
    throw new Response(
      JSON.stringify({ error: 'Unexpected: missing user or payload after successful guard' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return {
    user: result.user,
    payload: result.payload,
  };
}

/**
 * Simple auth context getter for lightweight usage
 *
 * @example
 * ```typescript
 * import { getAuthContext } from '@aid-on/gauth/cloudflare-access';
 *
 * export const onRequestGet: PagesFunction<Env> = async (context) => {
 *   const auth = await getAuthContext(context.request, {
 *     teamDomain: 'myteam',
 *     allowDevBypass: true,
 *   });
 *
 *   if (!auth.isAuthenticated) {
 *     return new Response('Unauthorized', { status: 401 });
 *   }
 *
 *   return new Response(`Hello, ${auth.user!.name}!`);
 * };
 * ```
 */
export { getAccessAuthContext as getAuthContext } from './verify';

/**
 * Error class for authentication failures
 */
export class AccessAuthError extends Error {
  constructor(
    message: string,
    public status: number = 401
  ) {
    super(message);
    this.name = 'AccessAuthError';
  }
}
