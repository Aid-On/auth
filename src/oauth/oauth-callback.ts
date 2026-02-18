/** Fluent OAuth Callback Handler */
import type {
  OAuthConfig,
  OAuthProviderConfig,
  OAuthTokenResponse,
  OAuthUserInfo,
  OAuthCallbackResult,
} from './types';
import { OAUTH_PROVIDERS } from './oauth';

type BuiltInProvider = keyof typeof OAUTH_PROVIDERS;

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

  /** Parse callback from URL with a specific provider */
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

  /** Set client ID */
  withClientId(clientId: string): this {
    this.config.clientId = clientId;
    return this;
  }

  /** Set client secret */
  withClientSecret(clientSecret: string): this {
    this.config.clientSecret = clientSecret;
    return this;
  }

  /** Set authorization code */
  withCode(code: string): this {
    this.code = code;
    return this;
  }

  /** Set redirect URI (must match the one used in auth flow) */
  withRedirectUri(uri: string): this {
    this.config.redirectUri = uri;
    return this;
  }

  /** Exchange authorization code for tokens */
  async exchange(): Promise<OAuthCallbackResult> {
    if (this.error) {
      return { success: false, error: this.error, errorDescription: this.errorDescription };
    }

    if (!this.code) {
      return { success: false, error: 'no_code', errorDescription: 'Authorization code is missing' };
    }

    if (!this.config.clientId || !this.config.clientSecret) {
      return { success: false, error: 'config_error', errorDescription: 'Client ID and secret are required' };
    }

    try {
      const tokens = await this.fetchTokens(this.config.clientId, this.config.clientSecret, this.code);

      if (tokens.error) {
        return { success: false, error: tokens.error, errorDescription: tokens.error_description };
      }

      if (!tokens.access_token) {
        return { success: false, error: 'invalid_response', errorDescription: 'No access token in response' };
      }

      const user = await this.fetchUserInfo(tokens.access_token);
      return { success: true, user, tokens };
    } catch (error) {
      return {
        success: false,
        error: 'exchange_failed',
        errorDescription: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /** Exchange and get user only */
  async exchangeForUser(): Promise<OAuthUserInfo | null> {
    const result = await this.exchange();
    return result.success ? result.user || null : null;
  }

  private async fetchTokens(clientId: string, clientSecret: string, code: string): Promise<OAuthTokenResponse> {
    const tokenParams = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      grant_type: 'authorization_code',
    });

    if (this.config.redirectUri) {
      tokenParams.set('redirect_uri', this.config.redirectUri);
    }

    const response = await fetch(this.providerConfig.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: tokenParams,
    });

    return await response.json() as OAuthTokenResponse;
  }

  private async fetchUserInfo(accessToken: string): Promise<OAuthUserInfo> {
    const response = await fetch(this.providerConfig.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': '@aid-on/auth',
      },
    });

    return await response.json() as OAuthUserInfo;
  }
}
