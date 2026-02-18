/** Cloudflare Access JWT Verification */
import type {
  CloudflareAccessPayload, JWTHeader, JWK, JWKSResponse,
  VerifyAccessOptions, VerifyAccessResult, AccessUser, AccessAuthContext,
} from './types';
import { decodeBase64Url } from '../utils/base64';

const DEFAULT_CACHE_DURATION_MS = 60 * 60 * 1000;
const jwksCache = new Map<string, { data: JWKSResponse; expiry: number }>();

/** Extract JWT from CF-Access-JWT-Assertion header */
export function extractAccessToken(request: Request): string | null {
  return request.headers.get('CF-Access-JWT-Assertion');
}

/** Base64URL decode to string (Unicode-safe wrapper) */
function base64UrlDecode(str: string): string {
  try {
    return decodeBase64Url(str);
  } catch (_decodeError) {
    // Fallback for ASCII-only JWT headers/signatures
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad && pad !== 1) {
      base64 += '='.repeat(4 - pad);
    }
    return atob(base64);
  }
}

/** Base64URL decode to Uint8Array */
function base64UrlDecodeToUint8Array(str: string): Uint8Array {
  const decoded = base64UrlDecode(str);
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) {
    bytes[i] = decoded.charCodeAt(i);
  }
  return bytes;
}

/** Decode JWT without verification */
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

/** Fetch Cloudflare Access JWKS */
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

/** Import JWK as CryptoKey */
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

/** Verify JWT signature */
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

/** Validate JWT claims. Returns error message if invalid, null if valid. */
function validateClaims(
  payload: CloudflareAccessPayload,
  teamDomain: string,
  audience?: string | string[]
): string | null {
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp < now) return 'Token expired';
  if (payload.nbf && payload.nbf > now) return 'Token not yet valid';

  const expectedIssuer = `https://${teamDomain}.cloudflareaccess.com`;
  if (payload.iss !== expectedIssuer) return `Invalid issuer: ${payload.iss}`;

  if (audience) {
    const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const expectedAud = Array.isArray(audience) ? audience : [audience];
    if (!expectedAud.some((aud) => tokenAud.includes(aud))) return 'Invalid audience';
  }

  if (!payload.email || !payload.sub) return 'Missing required fields (email, sub)';

  return null;
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
    const claimsError = validateClaims(payload, teamDomain, audience);
    if (claimsError) {
      return { success: false, error: claimsError };
    }

    return { success: true, payload };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Verification failed',
    };
  }
}

/** Extract user information from Cloudflare Access payload */
export function extractAccessUser(payload: CloudflareAccessPayload): AccessUser {
  return {
    id: payload.sub,
    email: payload.email,
    name: payload.name || payload.email.split('@')[0],
  };
}

/** Get authentication context from request */
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
