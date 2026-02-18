/**
 * Cloudflare Access authentication middleware helpers
 */

import {
  extractAccessToken,
  verifyAccessToken,
  extractAccessUser,
  getAccessAuthContext,
} from './verify';
import type {
  CloudflareAccessPayload,
  AccessUser,
  AccessGuardOptions,
  AccessGuardResult,
} from './types';

/**
 * Authentication guard for Cloudflare Pages Functions
 *
 * @example
 * ```typescript
 * import { accessGuard } from '@aid-on/gauth/cloudflare-access';
 *
 * export const onRequestGet: PagesFunction<Env> = async (context) => {
 *   const auth = await accessGuard(context.request, context.env, {
 *     getTeamDomain: (env) => env.CF_ACCESS_TEAM_DOMAIN,
 *     getAudience: (env) => env.CF_ACCESS_AUD,
 *     allowedDomains: ['aid-on.org'],
 *     allowDevBypass: true,
 *   });
 *
 *   if (!auth.success) {
 *     return auth.errorResponse!;
 *   }
 *
 *   // User is authenticated
 *   console.log('User:', auth.user!.email);
 * };
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

  // Dev bypass check
  if (allowDevBypass) {
    const url = new URL(request.url);
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      const devUser: AccessUser = {
        id: 'dev-user-001',
        email: 'dev@example.com',
        name: 'Dev User',
      };
      return { success: true, user: devUser };
    }
  }

  // Extract token
  const token = extractAccessToken(request);
  if (!token) {
    return {
      success: false,
      errorResponse: new Response(
        JSON.stringify({ error: 'Unauthorized: No access token provided' }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    };
  }

  // Get options from env
  const teamDomain = getTeamDomain(env);
  if (!teamDomain) {
    return {
      success: false,
      errorResponse: new Response(
        JSON.stringify({ error: 'Server configuration error: Missing team domain' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    };
  }

  const audience = getAudience?.(env);

  // Verify token
  const result = await verifyAccessToken(token, {
    teamDomain,
    audience,
    verifySignature,
  });

  if (!result.success || !result.payload) {
    return {
      success: false,
      errorResponse: new Response(
        JSON.stringify({ error: `Unauthorized: ${result.error || 'Invalid token'}` }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    };
  }

  // Domain restriction check
  if (allowedDomains && allowedDomains.length > 0) {
    const email = result.payload.email;
    const domain = email.split('@')[1];
    if (!allowedDomains.includes(domain)) {
      return {
        success: false,
        errorResponse: new Response(
          JSON.stringify({ error: 'Forbidden: Email domain not allowed' }),
          {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          }
        ),
      };
    }
  }

  const user = extractAccessUser(result.payload);

  return {
    success: true,
    user,
    payload: result.payload,
  };
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

  return {
    user: result.user!,
    payload: result.payload!,
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
export { getAccessAuthContext as getAuthContext };

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
