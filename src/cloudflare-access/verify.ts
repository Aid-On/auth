/**
 * Cloudflare Access JWT Verification
 *
 * Verifies Cloudflare Access JWTs by:
 * 1. Extracting JWT from CF-Access-JWT-Assertion header
 * 2. Optionally verifying RS256 signature against Cloudflare's JWKS
 * 3. Validating claims (iss, aud, exp)
 */

import type {
  CloudflareAccessPayload,
  JWTHeader,
  JWK,
  JWKSResponse,
  VerifyAccessOptions,
  VerifyAccessResult,
  AccessUser,
  AccessAuthContext,
} from './types';
import { decodeBase64Url } from '../utils/base64';

// Default cache duration: 60 minutes
const DEFAULT_CACHE_DURATION_MS = 60 * 60 * 1000;

// JWKS cache per team domain
const jwksCache = new Map<string, { data: JWKSResponse; expiry: number }>();

/**
 * Extract JWT from CF-Access-JWT-Assertion header
 */
export function extractAccessToken(request: Request): string | null {
  return request.headers.get('CF-Access-JWT-Assertion');
}

/**
 * Base64URL decode to string (Unicode-safe wrapper)
 */
function base64UrlDecode(str: string): string {
  // JWT tokens typically don't have Unicode in headers/signatures,
  // but payload might contain Unicode characters in claims
  try {
    return decodeBase64Url(str);
  } catch (e) {
    // Fallback to non-Unicode decoding for backward compatibility
    // (JWT headers and signatures are usually ASCII-only)
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad && pad !== 1) {
      base64 += '='.repeat(4 - pad);
    }
    return atob(base64);
  }
}

/**
 * Base64URL decode to Uint8Array
 */
function base64UrlDecodeToUint8Array(str: string): Uint8Array {
  const decoded = base64UrlDecode(str);
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) {
    bytes[i] = decoded.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decode JWT without verification
 */
export function decodeAccessToken(token: string): {
  header: JWTHeader;
  payload: CloudflareAccessPayload;
} {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const header = JSON.parse(base64UrlDecode(parts[0])) as JWTHeader;
  const payload = JSON.parse(base64UrlDecode(parts[1])) as CloudflareAccessPayload;

  return { header, payload };
}

/**
 * Fetch Cloudflare Access JWKS
 */
async function fetchAccessJWKS(
  teamDomain: string,
  cacheDurationMs: number = DEFAULT_CACHE_DURATION_MS
): Promise<JWKSResponse> {
  const now = Date.now();
  const cached = jwksCache.get(teamDomain);

  if (cached && cached.expiry > now) {
    return cached.data;
  }

  const url = `https://${teamDomain}.cloudflareaccess.com/cdn-cgi/access/certs`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch Cloudflare Access JWKS: ${response.status}`);
  }

  const jwks = (await response.json()) as JWKSResponse;

  jwksCache.set(teamDomain, {
    data: jwks,
    expiry: now + cacheDurationMs,
  });

  return jwks;
}

/**
 * Import JWK as CryptoKey
 */
async function importJWK(jwk: JWK): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'jwk',
    {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      alg: jwk.alg || 'RS256',
      ext: true,
    },
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['verify']
  );
}

/**
 * Verify JWT signature
 */
async function verifySignature(
  token: string,
  publicKey: CryptoKey
): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const signedData = `${parts[0]}.${parts[1]}`;
  const signedDataBytes = new TextEncoder().encode(signedData);
  const signatureBytes = base64UrlDecodeToUint8Array(parts[2]);

  // Cast to BufferSource to satisfy TypeScript with @cloudflare/workers-types
  return await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    signatureBytes as unknown as BufferSource,
    signedDataBytes as unknown as BufferSource
  );
}

/**
 * Verify Cloudflare Access JWT
 *
 * @example
 * ```typescript
 * const result = await verifyAccessToken(token, {
 *   teamDomain: 'myteam',
 *   audience: 'your-application-aud',
 * });
 *
 * if (result.success) {
 *   console.log('User:', result.payload!.email);
 * }
 * ```
 */
export async function verifyAccessToken(
  token: string,
  options: VerifyAccessOptions
): Promise<VerifyAccessResult> {
  const {
    teamDomain,
    audience,
    verifySignature: shouldVerify = true,
    cacheDurationMs = DEFAULT_CACHE_DURATION_MS,
  } = options;

  try {
    // Decode JWT
    const { header, payload } = decodeAccessToken(token);

    // Verify signature if requested
    if (shouldVerify) {
      if (header.alg !== 'RS256') {
        return { success: false, error: `Unsupported algorithm: ${header.alg}` };
      }

      const jwks = await fetchAccessJWKS(teamDomain, cacheDurationMs);

      // Find matching key
      const jwk = jwks.keys.find((key) => key.kid === header.kid);
      if (!jwk) {
        return { success: false, error: `Public key not found for kid: ${header.kid}` };
      }

      const publicKey = await importJWK(jwk);
      const isValid = await verifySignature(token, publicKey);

      if (!isValid) {
        return { success: false, error: 'Invalid signature' };
      }
    }

    // Validate claims
    const now = Math.floor(Date.now() / 1000);

    // Expiration check
    if (payload.exp < now) {
      return { success: false, error: 'Token expired' };
    }

    // Not before check
    if (payload.nbf && payload.nbf > now) {
      return { success: false, error: 'Token not yet valid' };
    }

    // Issuer check
    const expectedIssuer = `https://${teamDomain}.cloudflareaccess.com`;
    if (payload.iss !== expectedIssuer) {
      return { success: false, error: `Invalid issuer: ${payload.iss}` };
    }

    // Audience check (if specified)
    if (audience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const expectedAud = Array.isArray(audience) ? audience : [audience];
      const hasValidAud = expectedAud.some((aud) => tokenAud.includes(aud));

      if (!hasValidAud) {
        return { success: false, error: 'Invalid audience' };
      }
    }

    // Required fields check
    if (!payload.email || !payload.sub) {
      return { success: false, error: 'Missing required fields (email, sub)' };
    }

    return { success: true, payload };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Verification failed',
    };
  }
}

/**
 * Extract user information from Cloudflare Access payload
 */
export function extractAccessUser(payload: CloudflareAccessPayload): AccessUser {
  return {
    id: payload.sub,
    email: payload.email,
    name: payload.name || payload.email.split('@')[0],
  };
}

/**
 * Get authentication context from request
 *
 * @example
 * ```typescript
 * const auth = await getAccessAuthContext(request, {
 *   teamDomain: 'myteam',
 *   allowDevBypass: true,
 * });
 *
 * if (auth.isAuthenticated) {
 *   console.log('User:', auth.user!.email);
 * }
 * ```
 */
export async function getAccessAuthContext(
  request: Request,
  options: VerifyAccessOptions & { allowDevBypass?: boolean }
): Promise<AccessAuthContext> {
  // Dev bypass
  if (options.allowDevBypass) {
    const url = new URL(request.url);
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      return {
        user: {
          id: 'dev-user-001',
          email: 'dev@example.com',
          name: 'Dev User',
        },
        isAuthenticated: true,
      };
    }
  }

  const token = extractAccessToken(request);
  if (!token) {
    return { user: null, isAuthenticated: false };
  }

  const result = await verifyAccessToken(token, options);

  if (!result.success || !result.payload) {
    return { user: null, isAuthenticated: false };
  }

  return {
    user: extractAccessUser(result.payload),
    isAuthenticated: true,
    payload: result.payload,
  };
}
