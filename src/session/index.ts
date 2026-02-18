/**
 * Session management module for @aid-on/auth
 * 
 * Provides fluent API for creating and verifying signed sessions
 * 
 * @example
 * ```typescript
 * import { SessionBuilder, SessionVerifier } from '@aid-on/auth/session';
 * 
 * // Create a Google OAuth session (7 days)
 * const googleSession = await SessionBuilder
 *   .create({ id: user.id, email: user.email, name: user.name })
 *   .withSecret(env.SESSION_SECRET)
 *   .withDuration('7d')
 *   .asAuthenticated()
 *   .build();
 * 
 * // Create a guest session (24 hours)
 * const guestSession = await SessionBuilder
 *   .create({ id: guestId, email: 'guest@example.com', name: 'Guest' })
 *   .withSecret(env.SESSION_SECRET)
 *   .asGuest()
 *   .build();
 * 
 * // Verify session from request
 * const result = await SessionVerifier
 *   .fromRequest(request)
 *   .withSecret(env.SESSION_SECRET)
 *   .verify();
 * 
 * if (result.valid) {
 *   console.log('User:', result.payload);
 * }
 * ```
 */

export { SessionBuilder, SessionVerifier } from './session';
export type {
  SessionPayload,
  SignedSessionData,
  SessionCookieOptions,
  SessionCreateResult,
  SessionVerifyResult,
} from './types';