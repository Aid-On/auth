/**
 * Fluent API for guest user management
 * 
 * @example
 * ```typescript
 * // Create a guest user with session
 * const guest = await GuestBuilder
 *   .create()
 *   .withIdPrefix('guest_')
 *   .withName('Guest User')
 *   .withSessionDuration('24h')
 *   .withSecret(env.SESSION_SECRET)
 *   .build();
 * ```
 */

import { SessionBuilder } from '../session/session';
import type { SessionPayload } from '../session/types';
import type { GuestUser, GuestOptions, GuestCreateResult } from './types';

/**
 * Default guest ID generator
 */
function generateGuestId(prefix: string = 'anon_'): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}${timestamp}_${random}`;
}

/**
 * Parse duration string to milliseconds
 */
function parseDuration(duration: string | number): number {
  if (typeof duration === 'number') return duration;
  
  const match = duration.match(/^(\d+)([dhms])$/);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}`);
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
 * Fluent Guest Builder
 */
export class GuestBuilder {
  private options: GuestOptions = {
    idPrefix: 'anon_',
    defaultName: 'Guest',
    emailDomain: 'anonymous.local',
    sessionDuration: '24h',
  };
  private secret?: string;
  private cookieName: string = 'session';

  private constructor() {
    // private: use GuestBuilder.create() instead
  }

  static create(): GuestBuilder {
    return new GuestBuilder();
  }

  /**
   * Set custom ID prefix
   */
  withIdPrefix(prefix: string): this {
    this.options.idPrefix = prefix;
    return this;
  }

  /**
   * Set custom ID generator
   */
  withIdGenerator(generator: () => string): this {
    this.options.idGenerator = generator;
    return this;
  }

  /**
   * Set guest name
   */
  withName(name: string): this {
    this.options.defaultName = name;
    return this;
  }

  /**
   * Set email domain for guest users
   */
  withEmailDomain(domain: string): this {
    this.options.emailDomain = domain;
    return this;
  }

  /**
   * Set session duration
   */
  withSessionDuration(duration: string | number): this {
    this.options.sessionDuration = duration;
    return this;
  }

  /**
   * Set session secret
   */
  withSecret(secret: string): this {
    this.secret = secret;
    return this;
  }

  /**
   * Set cookie name
   */
  withCookieName(name: string): this {
    this.cookieName = name;
    return this;
  }

  /**
   * Add custom metadata
   */
  withMetadata(metadata: Record<string, unknown>): this {
    this.options.metadata = { ...this.options.metadata, ...metadata };
    return this;
  }

  /**
   * Build the guest user and session
   */
  async build(): Promise<GuestCreateResult> {
    if (!this.secret) {
      throw new Error('Session secret is required. Call .withSecret() first');
    }

    // Generate guest ID
    const guestId = this.options.idGenerator 
      ? this.options.idGenerator()
      : generateGuestId(this.options.idPrefix);

    // Calculate expiration
    const duration = parseDuration(this.options.sessionDuration || '24h');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + duration);

    // Create guest user
    const user: GuestUser = {
      id: guestId,
      name: this.options.defaultName || 'Guest',
      email: `${guestId}@${this.options.emailDomain}`,
      isAnonymous: true,
      createdAt: now,
      expiresAt,
      metadata: this.options.metadata,
    };

    // Create session payload
    const sessionPayload: SessionPayload = {
      id: user.id,
      email: user.email || '',
      name: user.name,
      isAnonymous: true,
      exp: expiresAt.getTime(),
    };

    // Build session using SessionBuilder
    const session = await SessionBuilder
      .create(sessionPayload)
      .withSecret(this.secret)
      .withDuration(duration)
      .withCookieName(this.cookieName)
      .build();

    return {
      user,
      session,
    };
  }
}

/**
 * Check if a user ID is a guest ID
 */
export function isGuestId(
  userId: string, 
  prefix: string = 'anon_'
): boolean {
  return userId.startsWith(prefix);
}

/**
 * Parse guest email
 */
export function parseGuestEmail(
  guestId: string,
  domain: string = 'anonymous.local'
): string {
  return `${guestId}@${domain}`;
}