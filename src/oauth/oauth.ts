/**
 * Fluent API for OAuth 2.0 redirect flow
 * 
 * @example
 * ```typescript
 * // Build authorization URL
 * const authUrl = OAuthFlow
 *   .google()
 *   .withClientId(env.GOOGLE_CLIENT_ID)
 *   .withRedirectUri('https://example.com/auth/callback')
 *   .withScope('openid email profile')
 *   .buildAuthUrl();
 * 
 * // Handle callback
 * const result = await OAuthCallback
 *   .google()
 *   .withClientId(env.GOOGLE_CLIENT_ID)
 *   .withClientSecret(env.GOOGLE_CLIENT_SECRET)
 *   .withCode(code)
 *   .withRedirectUri('https://example.com/auth/callback')
 *   .exchange();
 * ```
 */

import type {
  OAuthConfig,
  OAuthProviderConfig,
} from './types';

/**
 * Built-in OAuth provider configurations
 */
export const OAUTH_PROVIDERS = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    defaultScope: 'openid email profile',
  },
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    defaultScope: 'read:user user:email',
  },
} as const;

/** Fluent OAuth Authorization Flow Builder */
export class OAuthFlow {
  private providerConfig: OAuthProviderConfig;
  private config: Partial<OAuthConfig> = {};

  private constructor(providerConfig: OAuthProviderConfig) {
    this.providerConfig = providerConfig;
  }

  /**
   * Use Google OAuth
   */
  static google(): OAuthFlow {
    return new OAuthFlow(OAUTH_PROVIDERS.google);
  }

  /**
   * Use GitHub OAuth
   */
  static github(): OAuthFlow {
    return new OAuthFlow(OAUTH_PROVIDERS.github);
  }

  /**
   * Use a custom OAuth provider
   * @param config Provider configuration
   */
  static custom(config: OAuthProviderConfig): OAuthFlow {
    return new OAuthFlow(config);
  }

  /**
   * Set client ID
   */
  withClientId(clientId: string): this {
    this.config.clientId = clientId;
    return this;
  }

  /**
   * Set redirect URI
   */
  withRedirectUri(uri: string): this {
    this.config.redirectUri = uri;
    return this;
  }

  /**
   * Set scope
   */
  withScope(scope: string): this {
    this.config.scope = scope;
    return this;
  }

  /**
   * Set state parameter
   */
  withState(state: string): this {
    this.config.state = state;
    return this;
  }

  /**
   * Generate random state
   */
  withRandomState(): this {
    this.config.state = crypto.randomUUID();
    return this;
  }

  /**
   * Set prompt type
   */
  withPrompt(prompt: 'none' | 'consent' | 'select_account'): this {
    this.config.prompt = prompt;
    return this;
  }

  /**
   * Set access type
   */
  withAccessType(accessType: 'online' | 'offline'): this {
    this.config.accessType = accessType;
    return this;
  }

  /**
   * Request offline access (refresh token)
   */
  withOfflineAccess(): this {
    this.config.accessType = 'offline';
    this.config.prompt = 'consent';
    return this;
  }

  /**
   * Build authorization URL
   */
  buildAuthUrl(): string {
    if (!this.config.clientId) {
      throw new Error('Client ID is required');
    }

    const url = new URL(this.providerConfig.authUrl);

    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('response_type', 'code');
    
    if (this.config.redirectUri) {
      url.searchParams.set('redirect_uri', this.config.redirectUri);
    }
    
    url.searchParams.set('scope', this.config.scope || this.providerConfig.defaultScope);
    
    if (this.config.state) {
      url.searchParams.set('state', this.config.state);
    }
    
    if (this.config.accessType) {
      url.searchParams.set('access_type', this.config.accessType);
    }
    
    if (this.config.prompt) {
      url.searchParams.set('prompt', this.config.prompt);
    }

    return url.toString();
  }
}

// OAuthCallback is in ./oauth-callback.ts
export { OAuthCallback } from './oauth-callback';