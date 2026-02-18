/**
 * Fluent API for session management
 * 
 * @example
 * ```typescript
 * // Create a session with custom duration
 * const session = await SessionBuilder
 *   .create(userData)
 *   .withSecret(env.SESSION_SECRET)
 *   .withDuration('7d')
 *   .withCookie({ httpOnly: true, secure: true })
 *   .build();
 * 
 * // Verify a session
 * const result = await SessionVerifier
 *   .fromToken(token)
 *   .withSecret(env.SESSION_SECRET)
 *   .verify();
 * ```
 */

import type {
  SessionPayload,
  SignedSessionData,
  SessionCookieOptions,
  SessionCreateResult,
} from './types';
import { encodeBase64UrlJson } from '../utils/base64';
import { signHmac } from './hmac';

/** Parse duration string to milliseconds */
function parseDuration(duration: string | number): number {
  if (typeof duration === 'number') return duration;
  
  const match = duration.match(/^(\d+)([dhms])$/);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Use format like "7d", "24h", "30m", "60s"`);
  }
  
  const [, value, unit] = match;
  const num = parseInt(value, 10);
  
  switch (unit) {
    case 'd': return num * 24 * 60 * 60 * 1000;
    case 'h': return num * 60 * 60 * 1000;
    case 'm': return num * 60 * 1000;
    case 's': return num * 1000;
    default: throw new Error(`Unknown duration unit: ${unit}`);
  }
}

/**
 * Fluent Session Builder
 */
export class SessionBuilder<T extends SessionPayload = SessionPayload> {
  private payload: T;
  private secret?: string;
  private duration: number = 7 * 24 * 60 * 60 * 1000; // Default 7 days
  private cookieOptions: SessionCookieOptions = {
    name: 'session',
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
  };

  private constructor(payload: T) {
    this.payload = payload;
  }

  static create<T extends SessionPayload = SessionPayload>(payload: T): SessionBuilder<T> {
    return new SessionBuilder(payload);
  }

  /**
   * Set session secret for HMAC signing
   */
  withSecret(secret: string): this {
    this.secret = secret;
    return this;
  }

  /**
   * Set session duration
   * @param duration Duration string (e.g., "7d", "24h") or milliseconds
   */
  withDuration(duration: string | number): this {
    this.duration = parseDuration(duration);
    return this;
  }

  /**
   * Configure cookie options
   */
  withCookie(options: SessionCookieOptions): this {
    this.cookieOptions = { ...this.cookieOptions, ...options };
    return this;
  }

  /**
   * Set custom cookie name
   */
  withCookieName(name: string): this {
    this.cookieOptions.name = name;
    return this;
  }

  /**
   * Make session for guest users (24h default)
   */
  asGuest(): this {
    this.duration = parseDuration('24h');
    this.payload = { ...this.payload, isAnonymous: true };
    return this;
  }

  /**
   * Make session for authenticated users (7d default)
   */
  asAuthenticated(): this {
    this.duration = parseDuration('7d');
    this.payload = { ...this.payload, isAnonymous: false };
    return this;
  }

  /**
   * Build the session
   */
  async build(): Promise<SessionCreateResult> {
    if (!this.secret) {
      throw new Error('Session secret is required. Call .withSecret() first');
    }

    // Calculate expiration
    const expiresAt = new Date(Date.now() + this.duration);
    const payloadWithExp = {
      ...this.payload,
      exp: expiresAt.getTime(),
    };

    // Create signed session (Unicode-safe)
    const data = JSON.stringify(payloadWithExp);
    const signature = await signHmac(data, this.secret);
    const signedData: SignedSessionData = { data, sig: signature };
    const token = encodeBase64UrlJson(signedData);

    // Build cookie string
    const maxAge = Math.floor(this.duration / 1000);
    const cookieParts = [
      `${this.cookieOptions.name}=${token}`,
      `Path=${this.cookieOptions.path}`,
      `Max-Age=${maxAge}`,
    ];

    if (this.cookieOptions.httpOnly) cookieParts.push('HttpOnly');
    if (this.cookieOptions.secure) cookieParts.push('Secure');
    if (this.cookieOptions.sameSite) cookieParts.push(`SameSite=${this.cookieOptions.sameSite}`);
    if (this.cookieOptions.domain) cookieParts.push(`Domain=${this.cookieOptions.domain}`);

    return {
      token,
      cookieString: cookieParts.join('; '),
      expiresAt,
    };
  }
}

// SessionVerifier is in ./session-verifier.ts
export { SessionVerifier } from './session-verifier';