/**
 * Guest user module for @aid-on/auth
 * 
 * Provides fluent API for creating and managing guest/anonymous users
 * 
 * @example
 * ```typescript
 * import { GuestBuilder, isGuestId } from '@aid-on/auth/guest';
 * 
 * // Create a guest user with 24-hour session
 * const { user, session } = await GuestBuilder
 *   .create()
 *   .withName('Guest User')
 *   .withSessionDuration('24h')
 *   .withSecret(env.SESSION_SECRET)
 *   .build();
 * 
 * // Set cookie and return response
 * return new Response(JSON.stringify({ user }), {
 *   headers: {
 *     'Set-Cookie': session.cookieString,
 *   },
 * });
 * 
 * // Check if a user is a guest
 * if (isGuestId(userId)) {
 *   console.log('This is a guest user');
 * }
 * ```
 */

export { GuestBuilder, isGuestId, parseGuestEmail } from './guest';
export type {
  GuestUser,
  GuestOptions,
  GuestCreateResult,
} from './types';