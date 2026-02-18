/**
 * Session management types for @aid-on/auth
 * 
 * Fluent API design for flexible session configuration
 */

export interface SessionPayload {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string | null;
  isAnonymous?: boolean;
  exp?: number; // Expiration timestamp in milliseconds (auto-calculated if not provided)
  [key: string]: unknown; // Allow custom fields
}

export interface SignedSessionData {
  data: string;
  sig: string;
}

export interface SessionCookieOptions {
  name?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
  path?: string;
  domain?: string;
}

export interface SessionVerifyResult<T = SessionPayload> {
  valid: boolean;
  payload?: T;
  expired?: boolean;
  error?: string;
}

export interface SessionCreateResult {
  token: string;
  cookieString: string;
  expiresAt: Date;
}