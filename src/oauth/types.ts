/**
 * OAuth types for @aid-on/auth
 * 
 * Support for OAuth 2.0 redirect flow
 */

export interface OAuthProviderConfig {
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  defaultScope: string;
}

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri?: string;
  scope?: string;
  state?: string;
  prompt?: 'none' | 'consent' | 'select_account';
  accessType?: 'online' | 'offline';
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  error?: string;
  error_description?: string;
}

export interface OAuthUserInfo {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  verified_email?: boolean;
  locale?: string;
}

export interface OAuthCallbackResult {
  success: boolean;
  user?: OAuthUserInfo;
  tokens?: OAuthTokenResponse;
  error?: string;
  errorDescription?: string;
}