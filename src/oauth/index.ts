/**
 * OAuth module for @aid-on/auth
 * 
 * Provides fluent API for OAuth 2.0 redirect flow
 * 
 * @example
 * ```typescript
 * import { OAuthFlow, OAuthCallback } from '@aid-on/auth/oauth';
 * 
 * // 1. Generate authorization URL
 * export const onRequestGet: PagesFunction = async (context) => {
 *   const authUrl = OAuthFlow
 *     .google()
 *     .withClientId(context.env.GOOGLE_CLIENT_ID)
 *     .withRedirectUri('https://example.com/api/auth/callback')
 *     .withRandomState()
 *     .withOfflineAccess()
 *     .buildAuthUrl();
 *   
 *   return Response.redirect(authUrl);
 * };
 * 
 * // 2. Handle OAuth callback
 * export const onRequestGet: PagesFunction = async (context) => {
 *   const result = await OAuthCallback
 *     .fromUrl(context.request.url)
 *     .withClientId(context.env.GOOGLE_CLIENT_ID)
 *     .withClientSecret(context.env.GOOGLE_CLIENT_SECRET)
 *     .withRedirectUri('https://example.com/api/auth/callback')
 *     .exchange();
 *   
 *   if (!result.success) {
 *     return new Response(`Error: ${result.error}`, { status: 400 });
 *   }
 *   
 *   // Create session with user info
 *   const session = await SessionBuilder
 *     .create({
 *       id: result.user.id,
 *       email: result.user.email,
 *       name: result.user.name,
 *     })
 *     .withSecret(context.env.SESSION_SECRET)
 *     .withDuration('7d')
 *     .build();
 *   
 *   return new Response(null, {
 *     status: 302,
 *     headers: {
 *       Location: '/',
 *       'Set-Cookie': session.cookieString,
 *     },
 *   });
 * };
 * ```
 */

export { OAuthFlow, OAuthCallback, OAUTH_PROVIDERS } from './oauth';
export { 
  generateState, 
  parseState, 
  verifyState,
  createStateCookie,
  extractStateFromCookies 
} from './state';
export type {
  OAuthConfig,
  OAuthProviderConfig,
  OAuthTokenResponse,
  OAuthUserInfo,
  OAuthCallbackResult,
} from './types';
export type { StateData } from './state';