/**
 * Cloudflare Access authentication types
 */

/**
 * Cloudflare Access JWT payload structure
 */
export interface CloudflareAccessPayload {
  /** Issuer (https://<team>.cloudflareaccess.com) */
  iss: string;
  /** Subject (user ID) */
  sub: string;
  /** Audience (Application AUD tag) */
  aud: string | string[];
  /** Expiration time (Unix timestamp) */
  exp: number;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Not before (Unix timestamp) */
  nbf?: number;
  /** User's email address */
  email: string;
  /** Identity nonce */
  identity_nonce?: string;
  /** Custom claims (optional) */
  custom?: Record<string, unknown>;
  /** User's name (may not always be present) */
  name?: string;
  /** Authentication method */
  amr?: string[];
}

/**
 * JWT header structure
 */
export interface JWTHeader {
  alg: string;
  kid: string;
  typ: string;
}

/**
 * JWK (JSON Web Key) structure
 */
export interface JWK {
  kty: string;
  use: string;
  kid: string;
  n: string;
  e: string;
  alg?: string;
}

/**
 * JWKS (JSON Web Key Set) response
 */
export interface JWKSResponse {
  keys: JWK[];
  public_cert: {
    kid: string;
    cert: string;
  };
  public_certs: Array<{
    kid: string;
    cert: string;
  }>;
}

/**
 * Options for verifying Cloudflare Access JWT
 */
export interface VerifyAccessOptions {
  /** Team domain (e.g., "myteam" for myteam.cloudflareaccess.com) */
  teamDomain: string;
  /** Application AUD tag(s) to validate against */
  audience?: string | string[];
  /** Whether to verify JWT signature (default: true) */
  verifySignature?: boolean;
  /** JWKS cache duration in milliseconds (default: 60 minutes) */
  cacheDurationMs?: number;
}

/**
 * Verification result
 */
export interface VerifyAccessResult {
  success: boolean;
  payload?: CloudflareAccessPayload;
  error?: string;
}

/**
 * User information extracted from Cloudflare Access JWT
 */
export interface AccessUser {
  /** User ID (sub claim) */
  id: string;
  /** User's email address */
  email: string;
  /** User's name (if available) */
  name: string | null;
}

/**
 * Authentication context
 */
export interface AccessAuthContext {
  user: AccessUser | null;
  isAuthenticated: boolean;
  payload?: CloudflareAccessPayload;
}

/**
 * Options for the access auth guard
 */
export interface AccessGuardOptions<Env = unknown> {
  /** Get team domain from environment */
  getTeamDomain: (env: Env) => string;
  /** Get audience from environment (optional) */
  getAudience?: (env: Env) => string | string[] | undefined;
  /** Whether to verify signature (default: true in production, false in dev) */
  verifySignature?: boolean;
  /** Allowed email domains (e.g., ['aid-on.org']) */
  allowedDomains?: string[];
  /** Allow localhost/dev mode bypass */
  allowDevBypass?: boolean;
}

/**
 * Access guard result
 */
export interface AccessGuardResult {
  success: boolean;
  user?: AccessUser;
  payload?: CloudflareAccessPayload;
  errorResponse?: Response;
}
