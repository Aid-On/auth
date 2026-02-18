/**
 * Audit log types for @aid-on/auth
 * 
 * Provides interfaces for tracking authentication events
 * Storage implementation is left to the user (D1, DO, KV, etc.)
 */

export interface AuditLog {
  id?: string;
  timestamp: Date;
  userId: string;
  action: AuditAction;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  details?: Record<string, unknown>;
  success?: boolean;
  errorMessage?: string;
}

export type AuditAction = 
  | 'login'
  | 'logout'
  | 'login_failed'
  | 'guest_login'
  | 'guest_conversion'
  | 'session_created'
  | 'session_expired'
  | 'session_revoked'
  | 'token_refreshed'
  | 'password_changed'
  | 'mfa_enabled'
  | 'mfa_disabled'
  | string; // Allow custom actions

export interface AuditContext {
  request: Request;
  userId?: string;
  sessionId?: string;
}

export interface AuditLogger {
  log(entry: AuditLog): Promise<void>;
  query?(filters: AuditQueryFilters): Promise<AuditLog[]>;
}

export interface AuditQueryFilters {
  userId?: string;
  action?: AuditAction;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}