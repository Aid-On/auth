/**
 * Guest user types for @aid-on/auth
 * 
 * Support for anonymous/guest authentication
 */

export interface GuestUser {
  id: string;
  name: string;
  email?: string;
  isAnonymous: true;
  createdAt: Date;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface GuestOptions {
  /** Guest ID prefix (default: 'anon_') */
  idPrefix?: string;
  /** Guest ID generator function */
  idGenerator?: () => string;
  /** Default guest name */
  defaultName?: string;
  /** Guest email domain (e.g., 'anonymous.local') */
  emailDomain?: string;
  /** Session duration for guests */
  sessionDuration?: string | number;
  /** Custom metadata to attach */
  metadata?: Record<string, unknown>;
}

export interface GuestCreateResult {
  user: GuestUser;
  session: {
    token: string;
    cookieString: string;
    expiresAt: Date;
  };
}