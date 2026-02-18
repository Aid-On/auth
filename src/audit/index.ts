/**
 * Audit logging module for @aid-on/auth
 * 
 * Provides fluent API for creating audit log entries
 * Storage implementation is left to the user
 * 
 * @example
 * ```typescript
 * import { AuditBuilder } from '@aid-on/auth/audit';
 * 
 * // Create audit log for successful login
 * const loginAudit = AuditBuilder
 *   .login(user.id)
 *   .fromRequest(request)
 *   .withDetails({ provider: 'google', mfa: false })
 *   .build();
 * 
 * // Store in D1 (example)
 * await db.prepare(`
 *   INSERT INTO audit_logs (id, timestamp, user_id, action, ip_address, user_agent, details)
 *   VALUES (?, ?, ?, ?, ?, ?, ?)
 * `).bind(
 *   loginAudit.id,
 *   loginAudit.timestamp.toISOString(),
 *   loginAudit.userId,
 *   loginAudit.action,
 *   loginAudit.ipAddress,
 *   loginAudit.userAgent,
 *   JSON.stringify(loginAudit.details)
 * ).run();
 * 
 * // Or with custom logger implementation
 * class D1AuditLogger implements AuditLogger {
 *   constructor(private db: D1Database) {}
 *   
 *   async log(entry: AuditLog): Promise<void> {
 *     // Implementation
 *   }
 * }
 * 
 * const logger = new D1AuditLogger(db);
 * await AuditBuilder
 *   .loginFailed(email, 'Invalid password')
 *   .fromRequest(request)
 *   .logWith(logger);
 * ```
 */

export { AuditBuilder, extractAuditInfo, createAuditContext } from './audit';
export type {
  AuditLog,
  AuditAction,
  AuditContext,
  AuditLogger,
  AuditQueryFilters,
} from './types';