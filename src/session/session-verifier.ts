/** Fluent Session Verifier */
import type {
  SessionPayload,
  SignedSessionData,
  SessionVerifyResult,
} from './types';
import { decodeBase64UrlJson } from '../utils/base64';
import { verifyHmac } from './hmac';

export class SessionVerifier<T extends SessionPayload = SessionPayload> {
  private token?: string;
  private secrets: string[] = [];
  private checkExpiry: boolean = true;

  private constructor() {
    // private: use SessionVerifier.fromToken/fromCookies/fromRequest instead
  }

  static fromToken<T extends SessionPayload = SessionPayload>(token: string): SessionVerifier<T> {
    const verifier = new SessionVerifier<T>();
    verifier.token = token;
    return verifier;
  }

  static fromCookies<T extends SessionPayload = SessionPayload>(
    cookieHeader: string,
    cookieName: string = 'session'
  ): SessionVerifier<T> {
    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(c => {
        const [key, ...val] = c.trim().split('=');
        return [key, val.join('=')];
      })
    );

    const verifier = new SessionVerifier<T>();
    verifier.token = cookies[cookieName];
    return verifier;
  }

  static fromRequest<T extends SessionPayload = SessionPayload>(
    request: Request,
    cookieName: string = 'session'
  ): SessionVerifier<T> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) {
      return new SessionVerifier<T>();
    }
    return SessionVerifier.fromCookies<T>(cookieHeader, cookieName);
  }

  /** Set session secret for verification */
  withSecret(secret: string): this {
    this.secrets = [secret];
    return this;
  }

  /**
   * Set multiple session secrets for key rotation.
   * Verification will try each secret in order until one succeeds.
   */
  withSecrets(secrets: string[]): this {
    if (secrets.length === 0) {
      throw new Error('At least one secret is required');
    }
    this.secrets = secrets;
    return this;
  }

  /** Skip expiry check (useful for debugging) */
  skipExpiryCheck(): this {
    this.checkExpiry = false;
    return this;
  }

  /** Verify the session */
  async verify(): Promise<SessionVerifyResult<T>> {
    if (!this.token) {
      return { valid: false, error: 'No token provided' };
    }

    if (this.secrets.length === 0) {
      return { valid: false, error: 'Session secret is required' };
    }

    try {
      const decoded: SignedSessionData = decodeBase64UrlJson<SignedSessionData>(this.token);

      const isValid = await this.verifyWithSecrets(decoded);
      if (!isValid) {
        return { valid: false, error: 'Invalid signature' };
      }

      const payload = JSON.parse(decoded.data) as T;

      if (this.checkExpiry && payload.exp && Date.now() >= payload.exp) {
        return { valid: false, expired: true, error: 'Session expired' };
      }

      return { valid: true, payload };
    } catch (error) {
      return {
        valid: false,
        error: `Failed to verify session: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /** Verify and throw if invalid */
  async verifyOrThrow(): Promise<T> {
    const result = await this.verify();
    if (!result.valid || !result.payload) {
      throw new Error(result.error || 'Session verification failed');
    }
    return result.payload;
  }

  private async verifyWithSecrets(decoded: SignedSessionData): Promise<boolean> {
    for (const secret of this.secrets) {
      if (await verifyHmac(decoded.data, decoded.sig, secret)) {
        return true;
      }
    }
    return false;
  }
}
