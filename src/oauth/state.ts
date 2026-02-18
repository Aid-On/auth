/**
 * OAuth state parameter helpers for CSRF protection
 * 
 * The state parameter is crucial for preventing CSRF attacks in OAuth flows.
 * It should be generated before redirect and verified in the callback.
 */

import { encodeBase64Url, decodeBase64Url } from '../utils/base64';

export interface StateData {
  /** Random token for CSRF protection */
  token: string;
  /** Timestamp when state was created */
  timestamp: number;
  /** Optional redirect URL after successful auth */
  redirectTo?: string;
  /** Any additional data to preserve across the OAuth flow */
  metadata?: Record<string, unknown>;
}

/**
 * Generate a secure state parameter for OAuth
 * @param redirectTo Optional URL to redirect after authentication
 * @param metadata Optional data to preserve
 * @returns Base64URL encoded state string
 */
export function generateState(
  redirectTo?: string,
  metadata?: Record<string, unknown>
): string {
  const stateData: StateData = {
    token: crypto.randomUUID(),
    timestamp: Date.now(),
    redirectTo,
    metadata,
  };
  
  return encodeBase64Url(JSON.stringify(stateData));
}

/**
 * Parse and validate OAuth state parameter
 * @param state The state parameter from OAuth callback
 * @param maxAge Maximum age of state in milliseconds (default: 10 minutes)
 * @returns Parsed state data
 * @throws Error if state is invalid or expired
 */
export function parseState(
  state: string,
  maxAge: number = 10 * 60 * 1000 // 10 minutes
): StateData {
  try {
    const json = decodeBase64Url(state);
    const stateData: StateData = JSON.parse(json);
    
    // Validate timestamp
    const age = Date.now() - stateData.timestamp;
    if (age > maxAge) {
      throw new Error('State parameter expired');
    }
    
    if (!stateData.token) {
      throw new Error('Invalid state: missing token');
    }
    
    return stateData;
  } catch (error) {
    if (error instanceof Error && error.message.includes('expired')) {
      throw error;
    }
    throw new Error('Invalid state parameter');
  }
}

/**
 * Create a state cookie value
 * Stores the state securely for later verification
 */
export function createStateCookie(
  state: string,
  options?: {
    maxAge?: number;
    domain?: string;
    secure?: boolean;
    sameSite?: 'Lax' | 'Strict' | 'None';
  }
): string {
  const {
    maxAge = 600, // 10 minutes
    secure = true,
    sameSite = 'Lax',
    domain,
  } = options || {};
  
  const parts = [
    `oauth_state=${state}`,
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'Path=/',
  ];
  
  if (secure) parts.push('Secure');
  if (sameSite) parts.push(`SameSite=${sameSite}`);
  if (domain) parts.push(`Domain=${domain}`);
  
  return parts.join('; ');
}

/**
 * Extract state from cookies
 */
export function extractStateFromCookies(cookieHeader: string): string | null {
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [key, ...val] = c.trim().split('=');
      return [key, val.join('=')];
    })
  );
  
  return cookies.oauth_state || null;
}

/**
 * Verify state parameter matches stored state
 * @param receivedState State from OAuth callback
 * @param storedState State from cookie/storage
 * @throws Error if states don't match or are invalid
 */
export function verifyState(
  receivedState: string | null,
  storedState: string | null
): void {
  if (!receivedState || !storedState) {
    throw new Error('Missing state parameter');
  }
  
  if (receivedState !== storedState) {
    throw new Error('State mismatch - possible CSRF attack');
  }
  
  // Also validate the state is not expired
  parseState(storedState); // This will throw if expired
}