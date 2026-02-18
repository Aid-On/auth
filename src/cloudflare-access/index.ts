/**
 * @aid-on/gauth - Cloudflare Access Module
 *
 * Authentication for apps protected by Cloudflare Access.
 *
 * @example
 * ```typescript
 * import { accessGuard, getAuthContext } from '@aid-on/gauth/cloudflare-access';
 *
 * // Using accessGuard (recommended for Pages Functions)
 * export const onRequestGet: PagesFunction<Env> = async (context) => {
 *   const auth = await accessGuard(context.request, context.env, {
 *     getTeamDomain: (env) => env.CF_ACCESS_TEAM_DOMAIN,
 *     allowedDomains: ['aid-on.org'],
 *     allowDevBypass: true,
 *   });
 *
 *   if (!auth.success) {
 *     return auth.errorResponse!;
 *   }
 *
 *   return new Response(`Hello, ${auth.user!.name}!`);
 * };
 *
 * // Using getAuthContext (lightweight)
 * const auth = await getAuthContext(request, {
 *   teamDomain: 'myteam',
 *   allowDevBypass: true,
 * });
 *
 * if (auth.isAuthenticated) {
 *   console.log('User:', auth.user!.email);
 * }
 * ```
 */

// Core verification
export {
  extractAccessToken,
  decodeAccessToken,
  verifyAccessToken,
  extractAccessUser,
  getAccessAuthContext,
} from './verify';

// Middleware helpers
export {
  accessGuard,
  requireAccessAuth,
  getAuthContext,
  AccessAuthError,
} from './middleware';

// Types
export type {
  CloudflareAccessPayload,
  JWTHeader,
  JWK,
  JWKSResponse,
  VerifyAccessOptions,
  VerifyAccessResult,
  AccessUser,
  AccessAuthContext,
  AccessGuardOptions,
  AccessGuardResult,
} from './types';
