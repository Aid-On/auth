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
  OAuthTokenResponse, 
  OAuthUserInfo, 
  OAuthCallbackResult 
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

type BuiltInProvider = keyof typeof OAUTH_PROVIDERS;

/**
 * Fluent OAuth Authorization Flow Builder
 */
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

/**
 * Fluent OAuth Callback Handler
 */
export class OAuthCallback {
  private providerConfig: OAuthProviderConfig;
  private config: Partial<OAuthConfig> = {};
  private code?: string;
  private error?: string;
  private errorDescription?: string;

  private constructor(providerConfig: OAuthProviderConfig) {
    this.providerConfig = providerConfig;
  }

  static google(): OAuthCallback {
    return new OAuthCallback(OAUTH_PROVIDERS.google);
  }

  static github(): OAuthCallback {
    return new OAuthCallback(OAUTH_PROVIDERS.github);
  }

  static custom(config: OAuthProviderConfig): OAuthCallback {
    return new OAuthCallback(config);
  }

  /**
   * Parse callback from URL with a specific provider
   */
  static fromUrl(url: URL | string, providerOrConfig: BuiltInProvider | OAuthProviderConfig = 'google'): OAuthCallback {
    const urlObj = typeof url === 'string' ? new URL(url) : url;
    const config = typeof providerOrConfig === 'string' 
      ? OAUTH_PROVIDERS[providerOrConfig]
      : providerOrConfig;
    
    const callback = new OAuthCallback(config);
    
    const code = urlObj.searchParams.get('code');
    const error = urlObj.searchParams.get('error');
    const errorDescription = urlObj.searchParams.get('error_description');
    
    if (code) callback.code = code;
    if (error) callback.error = error;
    if (errorDescription) callback.errorDescription = errorDescription;
    
    return callback;
  }

  /**
   * Set client ID
   */
  withClientId(clientId: string): this {
    this.config.clientId = clientId;
    return this;
  }

  /**
   * Set client secret
   */
  withClientSecret(clientSecret: string): this {
    this.config.clientSecret = clientSecret;
    return this;
  }

  /**
   * Set authorization code
   */
  withCode(code: string): this {
    this.code = code;
    return this;
  }

  /**
   * Set redirect URI (must match the one used in auth flow)
   */
  withRedirectUri(uri: string): this {
    this.config.redirectUri = uri;
    return this;
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchange(): Promise<OAuthCallbackResult> {
    // Check for errors first
    if (this.error) {
      return {
        success: false,
        error: this.error,
        errorDescription: this.errorDescription,
      };
    }

    if (!this.code) {
      return {
        success: false,
        error: 'no_code',
        errorDescription: 'Authorization code is missing',
      };
    }

    if (!this.config.clientId || !this.config.clientSecret) {
      return {
        success: false,
        error: 'config_error',
        errorDescription: 'Client ID and secret are required',
      };
    }

    try {
      // Exchange code for tokens
      const tokenParams = new URLSearchParams({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code: this.code,
        grant_type: 'authorization_code',
      });

      if (this.config.redirectUri) {
        tokenParams.set('redirect_uri', this.config.redirectUri);
      }

      const tokenResponse = await fetch(this.providerConfig.tokenUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json', // GitHub requires this
        },
        body: tokenParams,
      });

      const tokens = await tokenResponse.json() as OAuthTokenResponse;

      if (tokens.error) {
        return {
          success: false,
          error: tokens.error,
          errorDescription: tokens.error_description,
        };
      }

      if (!tokens.access_token) {
        return {
          success: false,
          error: 'invalid_response',
          errorDescription: 'No access token in response',
        };
      }

      // Get user info
      const userResponse = await fetch(this.providerConfig.userInfoUrl, {
        headers: { 
          Authorization: `Bearer ${tokens.access_token}`,
          'User-Agent': '@aid-on/auth', // GitHub requires User-Agent
        },
      });

      const user = await userResponse.json() as OAuthUserInfo;

      return {
        success: true,
        user,
        tokens,
      };
    } catch (error) {
      return {
        success: false,
        error: 'exchange_failed',
        errorDescription: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Exchange and get user only
   */
  async exchangeForUser(): Promise<OAuthUserInfo | null> {
    const result = await this.exchange();
    return result.success ? result.user || null : null;
  }
}