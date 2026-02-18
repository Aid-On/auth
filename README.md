# @aid-on/auth

**Edge-native authentication library with Fluent API for Cloudflare Workers**

Zero Node.js dependencies. Pure Web Crypto API.

```typescript
// Fluent API - Simple, Type-safe, Powerful
await SessionBuilder.create(user).withSecret(secret).withDuration('7d').build()
await GuestBuilder.create().withSessionDuration('24h').build()
await OAuthFlow.google().withClientId(id).buildAuthUrl()
await AuditBuilder.login(userId).fromRequest(request).build()
```

## Features

- **Session Management** - HMAC-SHA256 signed sessions with key rotation support
- **Guest Users** - Anonymous authentication with automatic expiration
- **OAuth 2.0** - Complete OAuth flow with CSRF protection (Google, GitHub, custom)
- **Audit Logging** - Flexible audit trail with storage-agnostic design
- **Cloudflare Access** - Zero Trust integration support
- **Unicode Support** - Full support for Japanese, emoji, and all Unicode characters
- **Edge Native** - Built for Cloudflare Workers, no Node.js dependencies
- **Fluent API** - Intuitive method chaining for better DX

## Installation

```bash
npm install @aid-on/auth
```

## Quick Start

### Session Management

```typescript
import { SessionBuilder, SessionVerifier } from '@aid-on/auth/session';

// Create session
const session = await SessionBuilder
  .create({ id: user.id, email: user.email, name: user.name })
  .withSecret(env.SESSION_SECRET)
  .withDuration('7d')  // '24h', '30m', '60s' or milliseconds
  .build();

// Set cookie
return new Response('Success', {
  headers: { 'Set-Cookie': session.cookieString }
});

// Verify session
const result = await SessionVerifier
  .fromRequest(request)
  .withSecret(env.SESSION_SECRET)
  .verify();

if (result.valid) {
  console.log('User:', result.payload);
}
```

### Guest Users

```typescript
import { GuestBuilder, isGuestId } from '@aid-on/auth/guest';

// Create guest user
const { user, session } = await GuestBuilder
  .create()
  .withName('Guest')
  .withSessionDuration('24h')
  .withSecret(env.SESSION_SECRET)
  .build();

// Check if user is guest
if (isGuestId(userId)) {
  // Handle guest user
}
```

### OAuth 2.0 Flow (with CSRF Protection)

```typescript
import { OAuthFlow, OAuthCallback, generateState, verifyState, createStateCookie } from '@aid-on/auth/oauth';

// 1. Generate auth URL with state parameter
const state = generateState('/dashboard'); // Optional redirect after auth
const authUrl = OAuthFlow
  .google()
  .withClientId(env.GOOGLE_CLIENT_ID)
  .withRedirectUri('https://example.com/callback')
  .withState(state) // CSRF protection
  .withOfflineAccess()
  .buildAuthUrl();

// Store state in cookie for later verification
return Response.redirect(authUrl, {
  headers: {
    'Set-Cookie': createStateCookie(state),
  },
});

// 2. Handle callback with state verification
const url = new URL(request.url);
const receivedState = url.searchParams.get('state');
const storedState = extractStateFromCookies(request.headers.get('Cookie') || '');

// Verify state to prevent CSRF attacks
try {
  verifyState(receivedState, storedState);
} catch (error) {
  return new Response('Invalid state - possible CSRF attack', { status: 403 });
}

// Exchange code for tokens
const result = await OAuthCallback
  .fromUrl(request.url)
  .withClientId(env.GOOGLE_CLIENT_ID)
  .withClientSecret(env.GOOGLE_CLIENT_SECRET)
  .exchange();

if (result.success) {
  // Parse state to get redirect URL
  const stateData = parseState(storedState!);
  
  // Create session
  const session = await SessionBuilder
    .create(result.user)
    .withSecret(env.SESSION_SECRET)
    .build();
    
  return Response.redirect(stateData.redirectTo || '/', {
    headers: {
      'Set-Cookie': session.cookieString,
    },
  });
}
```

### Audit Logging

```typescript
import { AuditBuilder } from '@aid-on/auth/audit';

// Log authentication events
const entry = AuditBuilder
  .login(user.id)
  .fromRequest(request)
  .withDetails({ provider: 'google' })
  .build();

// Store in your preferred storage (D1, DO, KV, etc.)
await storeAuditLog(entry);
```

### Cloudflare Access Integration

```typescript
import { accessGuard } from '@aid-on/auth/access';

// Protect routes with CF Access
const auth = await accessGuard(request, env, {
  getTeamDomain: (env) => env.CF_TEAM_DOMAIN,
  allowDevBypass: true,
});

if (!auth.success) {
  return auth.errorResponse;
}
```

## API Reference

### `@aid-on/auth/session`

```typescript
class SessionBuilder {
  static create(payload: SessionPayload): SessionBuilder
  withSecret(secret: string): this
  withDuration(duration: string | number): this
  withCookie(options: SessionCookieOptions): this
  asAuthenticated(): this  // 7 days default
  asGuest(): this          // 24 hours default
  build(): Promise<SessionCreateResult>
}

class SessionVerifier {
  static fromToken(token: string): SessionVerifier
  static fromRequest(request: Request): SessionVerifier
  static fromCookies(cookieHeader: string): SessionVerifier
  withSecret(secret: string): this
  withSecrets(secrets: string[]): this  // Key rotation support
  skipExpiryCheck(): this
  verify(): Promise<SessionVerifyResult>
  verifyOrThrow(): Promise<SessionPayload>
}
```

### `@aid-on/auth/guest`

```typescript
class GuestBuilder {
  static create(): GuestBuilder
  withIdPrefix(prefix: string): this
  withName(name: string): this
  withEmailDomain(domain: string): this
  withSessionDuration(duration: string | number): this
  withSecret(secret: string): this
  withMetadata(metadata: Record<string, unknown>): this
  build(): Promise<GuestCreateResult>
}

function isGuestId(userId: string, prefix?: string): boolean
function parseGuestEmail(guestId: string, domain?: string): string
```

### `@aid-on/auth/oauth`

```typescript
class OAuthFlow {
  static google(): OAuthFlow
  static github(): OAuthFlow  // GitHub support
  static custom(config: OAuthProviderConfig): OAuthFlow  // Custom providers
  withClientId(clientId: string): this
  withRedirectUri(uri: string): this
  withScope(scope: string): this
  withState(state: string): this
  withRandomState(): this
  withOfflineAccess(): this
  buildAuthUrl(): string
}

class OAuthCallback {
  static fromUrl(url: string | URL, provider?: string | OAuthProviderConfig): OAuthCallback
  static google(): OAuthCallback
  static github(): OAuthCallback
  static custom(config: OAuthProviderConfig): OAuthCallback
  withClientId(clientId: string): this
  withClientSecret(clientSecret: string): this
  withRedirectUri(uri: string): this
  exchange(): Promise<OAuthCallbackResult>
  exchangeForUser(): Promise<OAuthUserInfo | null>
}

// State parameter helpers for CSRF protection
function generateState(redirectTo?: string, metadata?: object): string
function parseState(state: string, maxAge?: number): StateData
function verifyState(received: string, stored: string): void
function createStateCookie(state: string, options?: CookieOptions): string
function extractStateFromCookies(cookieHeader: string): string | null
```

### `@aid-on/auth/audit`

```typescript
class AuditBuilder {
  static create(action: AuditAction): AuditBuilder
  static login(userId: string): AuditBuilder
  static loginFailed(userId: string, reason?: string): AuditBuilder
  static logout(userId: string): AuditBuilder
  static guestLogin(guestId: string): AuditBuilder
  withUser(userId: string): this
  fromRequest(request: Request): this
  withDetails(details: Record<string, unknown>): this
  withError(message: string): this
  build(): AuditLog
  logWith(logger: AuditLogger): Promise<void>
}

function extractAuditInfo(request: Request): AuditInfo
```

### `@aid-on/auth/access`

```typescript
function accessGuard(request: Request, env: Env, options: AccessOptions): Promise<AuthResult>
function getAuthContext(request: Request, options: AccessOptions): Promise<AuthContext>
```

## Duration Formats

```typescript
// String formats
.withDuration('7d')     // 7 days
.withDuration('24h')    // 24 hours
.withDuration('30m')    // 30 minutes
.withDuration('60s')    // 60 seconds

// Milliseconds
.withDuration(86400000) // 1 day in ms

// Presets
.asAuthenticated()      // 7 days
.asGuest()             // 24 hours
```

## Real-world Example

Complete authentication flow in a Cloudflare Pages Function:

```typescript
import { Hono } from 'hono';
import { SessionBuilder, SessionVerifier } from '@aid-on/auth/session';
import { GuestBuilder } from '@aid-on/auth/guest';
import { OAuthFlow, OAuthCallback } from '@aid-on/auth/oauth';
import { AuditBuilder } from '@aid-on/auth/audit';

const app = new Hono();

// OAuth login
app.get('/auth/login', (c) => {
  const authUrl = OAuthFlow
    .google()
    .withClientId(c.env.GOOGLE_CLIENT_ID)
    .withRedirectUri(`${c.req.url.origin}/auth/callback`)
    .buildAuthUrl();
  
  return c.redirect(authUrl);
});

// OAuth callback
app.get('/auth/callback', async (c) => {
  const result = await OAuthCallback
    .fromUrl(c.req.url)
    .withClientId(c.env.GOOGLE_CLIENT_ID)
    .withClientSecret(c.env.GOOGLE_CLIENT_SECRET)
    .exchange();

  if (!result.success) {
    return c.json({ error: result.error }, 400);
  }

  // Create session
  const session = await SessionBuilder
    .create(result.user)
    .withSecret(c.env.SESSION_SECRET)
    .withDuration('7d')
    .build();

  // Audit log
  await AuditBuilder
    .login(result.user.id)
    .fromRequest(c.req.raw)
    .logWith(auditLogger);

  return c.redirect('/', {
    headers: { 'Set-Cookie': session.cookieString }
  });
});

// Guest login
app.post('/auth/guest', async (c) => {
  const { user, session } = await GuestBuilder
    .create()
    .withSessionDuration('24h')
    .withSecret(c.env.SESSION_SECRET)
    .build();

  return c.json({ user }, {
    headers: { 'Set-Cookie': session.cookieString }
  });
});

// Protected route
app.get('/api/user', async (c) => {
  const result = await SessionVerifier
    .fromRequest(c.req.raw)
    .withSecret(c.env.SESSION_SECRET)
    .verify();

  if (!result.valid) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return c.json({ user: result.payload });
});
```

## Advanced Features

### Session Key Rotation

Rotate secrets without logging out users:

```typescript
// Old secret still works during transition
const result = await SessionVerifier
  .fromRequest(request)
  .withSecrets([
    env.SESSION_SECRET_NEW,  // Try new secret first
    env.SESSION_SECRET_OLD,  // Fall back to old secret
  ])
  .verify();
```

### Custom OAuth Providers

Add any OAuth 2.0 provider:

```typescript
const discordFlow = OAuthFlow.custom({
  authUrl: 'https://discord.com/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  defaultScope: 'identify email',
});

const authUrl = discordFlow
  .withClientId(env.DISCORD_CLIENT_ID)
  .buildAuthUrl();
```

### Unicode and International Support

Full support for international characters:

```typescript
// Works perfectly with Japanese names, emoji, etc.
const session = await SessionBuilder
  .create({
    id: 'user-123',
    email: 'tanaka@example.com',
    name: '田中太郎',
  })
  .withSecret(secret)
  .build();
```

## Why @aid-on/auth?

### Production-Tested

Extracted from [fast-llm-chat](https://github.com/Aid-On/fast-llm-chat), serving real users in production on Cloudflare Pages.

### Security-First

- CSRF protection built into OAuth flow
- Session key rotation without downtime
- HMAC-SHA256 signatures
- Secure defaults (HttpOnly, Secure, SameSite cookies)

### True Edge Native

- **Zero Node.js dependencies** - Pure Web Crypto API
- **No polyfills** - Built for V8 isolates
- **Lightweight** - ~8KB total
- **Fast** - Optimized for Cloudflare Workers

### Developer Experience

- **Fluent API** - Intuitive method chaining
- **Type-safe** - Full TypeScript support with inference
- **Well-documented** - Comprehensive examples
- **Extensible** - Easy to add custom providers

## License

MIT