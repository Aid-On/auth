/**
 * Fluent API for audit logging
 * 
 * @example
 * ```typescript
 * // Create audit log entry
 * const entry = AuditBuilder
 *   .create('login')
 *   .withUser(userId)
 *   .fromRequest(request)
 *   .withDetails({ provider: 'google' })
 *   .build();
 * 
 * // Log to your storage (D1, DO, KV, etc.)
 * await db.insert('audit_logs').values(entry);
 * 
 * // Or use with custom logger
 * const logger = new MyAuditLogger(db);
 * await AuditBuilder
 *   .create('login_failed')
 *   .withUser(email)
 *   .fromRequest(request)
 *   .withError('Invalid credentials')
 *   .logWith(logger);
 * ```
 */

import type { AuditLog, AuditAction, AuditContext, AuditLogger } from './types';

/**
 * Extract audit info from request
 */
export function extractAuditInfo(request: Request): {
  ipAddress: string | null;
  userAgent: string | null;
} {
  return {
    ipAddress: 
      request.headers.get('CF-Connecting-IP') || 
      request.headers.get('X-Forwarded-For') ||
      request.headers.get('X-Real-IP') ||
      null,
    userAgent: request.headers.get('User-Agent')?.substring(0, 255) || null,
  };
}

/**
 * Generate audit log ID
 */
function generateAuditId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `audit_${timestamp}_${random}`;
}

/**
 * Fluent Audit Log Builder
 */
export class AuditBuilder {
  private entry: Partial<AuditLog> = {
    timestamp: new Date(),
  };

  private constructor(action: AuditAction) {
    this.entry.action = action;
  }

  /**
   * Create a new audit log builder
   */
  static create(action: AuditAction): AuditBuilder {
    return new AuditBuilder(action);
  }

  /**
   * Common audit actions
   */
  static login(userId: string): AuditBuilder {
    return new AuditBuilder('login').withUser(userId);
  }

  static loginFailed(userId: string, reason?: string): AuditBuilder {
    return new AuditBuilder('login_failed')
      .withUser(userId)
      .withSuccess(false)
      .withError(reason || 'Authentication failed');
  }

  static logout(userId: string): AuditBuilder {
    return new AuditBuilder('logout').withUser(userId);
  }

  static guestLogin(guestId: string): AuditBuilder {
    return new AuditBuilder('guest_login').withUser(guestId);
  }

  static sessionCreated(userId: string, sessionId?: string): AuditBuilder {
    const builder = new AuditBuilder('session_created').withUser(userId);
    if (sessionId) {
      builder.withResource('session', sessionId);
    }
    return builder;
  }

  /**
   * Set user ID
   */
  withUser(userId: string): this {
    this.entry.userId = userId;
    return this;
  }

  /**
   * Set resource information
   */
  withResource(type: string, id: string): this {
    this.entry.resourceType = type;
    this.entry.resourceId = id;
    return this;
  }

  /**
   * Extract information from request
   */
  fromRequest(request: Request): this {
    const { ipAddress, userAgent } = extractAuditInfo(request);
    this.entry.ipAddress = ipAddress;
    this.entry.userAgent = userAgent;
    return this;
  }

  /**
   * Set IP address manually
   */
  withIpAddress(ip: string): this {
    this.entry.ipAddress = ip;
    return this;
  }

  /**
   * Set user agent manually
   */
  withUserAgent(userAgent: string): this {
    this.entry.userAgent = userAgent?.substring(0, 255);
    return this;
  }

  /**
   * Add custom details
   */
  withDetails(details: Record<string, unknown>): this {
    this.entry.details = { ...this.entry.details, ...details };
    return this;
  }

  /**
   * Set success status
   */
  withSuccess(success: boolean): this {
    this.entry.success = success;
    return this;
  }

  /**
   * Set error message
   */
  withError(message: string): this {
    this.entry.errorMessage = message;
    this.entry.success = false;
    return this;
  }

  /**
   * Set custom ID
   */
  withId(id: string): this {
    this.entry.id = id;
    return this;
  }

  /**
   * Generate auto ID
   */
  withAutoId(): this {
    this.entry.id = generateAuditId();
    return this;
  }

  /**
   * Build the audit log entry
   */
  build(): AuditLog {
    if (!this.entry.userId) {
      throw new Error('User ID is required for audit log');
    }

    if (!this.entry.action) {
      throw new Error('Action is required for audit log');
    }

    // Set defaults
    if (this.entry.success === undefined) {
      this.entry.success = true;
    }

    if (!this.entry.id) {
      this.entry.id = generateAuditId();
    }

    return this.entry as AuditLog;
  }

  /**
   * Build and log with a custom logger
   */
  async logWith(logger: AuditLogger): Promise<void> {
    const entry = this.build();
    await logger.log(entry);
  }
}

/**
 * Create audit context from request
 */
export function createAuditContext(
  request: Request,
  userId?: string,
  sessionId?: string
): AuditContext {
  return {
    request,
    userId,
    sessionId,
  };
}