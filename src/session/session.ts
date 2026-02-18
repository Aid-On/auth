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
  SessionVerifyResult 
} from './types';
import { encodeBase64UrlJson, decodeBase64UrlJson } from '../utils/base64';

/**
 * HMAC-SHA256 signing utilities
 */
async function signHmac(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  // Use proper Base64URL encoding for binary data
  const binString = String.fromCharCode(...new Uint8Array(signature));
  return btoa(binString)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function verifyHmac(data: string, signature: string, secret: string): Promise<boolean> {
  const expectedSig = await signHmac(data, secret);
  return signature === expectedSig;
}

/**
 * Parse duration string to milliseconds
 * @example "7d" -> 7 days, "24h" -> 24 hours, "30m" -> 30 minutes
 */
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

/**
 * Fluent Session Verifier
 */
export class SessionVerifier<T extends SessionPayload = SessionPayload> {
  private token?: string;
  private secrets: string[] = [];
  private checkExpiry: boolean = true;

  private constructor() {}

  static fromToken<T extends SessionPayload = SessionPayload>(token: string): SessionVerifier<T> {
    const verifier = new SessionVerifier<T>();
    verifier.token = token;
    return verifier;
  }

  static fromCookies<T extends SessionPayload = SessionPayload>(
    cookieHeader: string, 
    cookieName: string = 'session'
  ): SessionVerifier<T> {
    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(c => {
        const [key, ...val] = c.trim().split('=');
        return [key, val.join('=')];
      })
    );
    
    const verifier = new SessionVerifier<T>();
    verifier.token = cookies[cookieName];
    return verifier;
  }

  static fromRequest<T extends SessionPayload = SessionPayload>(
    request: Request,
    cookieName: string = 'session'
  ): SessionVerifier<T> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) {
      return new SessionVerifier<T>();
    }
    return SessionVerifier.fromCookies<T>(cookieHeader, cookieName);
  }

  /**
   * Set session secret for verification
   */
  withSecret(secret: string): this {
    this.secrets = [secret];
    return this;
  }

  /**
   * Set multiple session secrets for key rotation
   * Verification will try each secret in order until one succeeds
   * @param secrets Array of secrets, with the newest/primary secret first
   */
  withSecrets(secrets: string[]): this {
    if (secrets.length === 0) {
      throw new Error('At least one secret is required');
    }
    this.secrets = secrets;
    return this;
  }

  /**
   * Skip expiry check (useful for debugging)
   */
  skipExpiryCheck(): this {
    this.checkExpiry = false;
    return this;
  }

  /**
   * Verify the session
   */
  async verify(): Promise<SessionVerifyResult<T>> {
    if (!this.token) {
      return { valid: false, error: 'No token provided' };
    }

    if (this.secrets.length === 0) {
      return { valid: false, error: 'Session secret is required' };
    }

    try {
      // Decode session data (Unicode-safe)
      const decoded: SignedSessionData = decodeBase64UrlJson<SignedSessionData>(this.token);
      
      // Try each secret until one succeeds (key rotation support)
      let isValid = false;
      for (const secret of this.secrets) {
        if (await verifyHmac(decoded.data, decoded.sig, secret)) {
          isValid = true;
          break;
        }
      }
      
      if (!isValid) {
        return { valid: false, error: 'Invalid signature' };
      }

      // Parse payload
      const payload = JSON.parse(decoded.data) as T;

      // Check expiry
      if (this.checkExpiry && payload.exp) {
        if (Date.now() >= payload.exp) {
          return { valid: false, expired: true, error: 'Session expired' };
        }
      }

      return { valid: true, payload };
    } catch (error) {
      return { 
        valid: false, 
        error: `Failed to verify session: ${error instanceof Error ? error.message : 'Unknown error'}` 
      };
    }
  }

  /**
   * Verify and throw if invalid
   */
  async verifyOrThrow(): Promise<T> {
    const result = await this.verify();
    if (!result.valid || !result.payload) {
      throw new Error(result.error || 'Session verification failed');
    }
    return result.payload;
  }
}