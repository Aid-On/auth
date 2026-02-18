# @aid-on/auth

## 概要

`@aid-on/auth`は、Cloudflare Workers/Pagesでのエッジネイティブな認証を提供するライブラリです。セッション管理、OAuth、ゲストユーザー、監査ログ機能を統一されたFluent APIで利用できます。Node.js依存関係を持たず、Web Cryptography APIを使用してエッジ環境で高速に動作します。

## 主な特徴

- **Fluent API**: 直感的で読みやすい連鎖メソッド
- **エッジネイティブ**: Cloudflare Workers/Pagesでの最適化
- **セッション管理**: HMAC-SHA256による署名付きセッション
- **OAuth 2.0 サポート**: Google等のプロバイダーとの連携
- **ゲストユーザー**: 匿名ユーザーでの機能利用
- **監査ログ**: セキュリティイベントの追跡
- **Cloudflare Access**: 企業向けアクセス制御
- **暗号学的セキュリティ**: Web Crypto APIによる安全性
- **Unicode対応**: 多言語文字列の安全な処理
- **キーローテーション**: セキュリティキーの更新対応

## アーキテクチャ

### モジュール構成

```
@aid-on/auth/
├── session      - セッション管理（SessionBuilder、SessionVerifier）
├── oauth        - OAuth 2.0 フロー（OAuthFlow、OAuthCallback）
├── guest        - ゲストユーザー管理（GuestBuilder）
├── audit        - 監査ログ（AuditBuilder）
└── access       - Cloudflare Access（accessGuard）
```

### セキュリティ設計

- **署名**: HMAC-SHA256による改ざん検出
- **エンコード**: Base64URLによる安全なデータ転送
- **暗号化**: Web Crypto APIによるブラウザネイティブ暗号化
- **検証**: トークン有効期限とシグネチャの二重検証

## APIリファレンス

### Session モジュール

```typescript
import { SessionBuilder, SessionVerifier } from '@aid-on/auth/session';

// セッション作成
const session = await SessionBuilder
  .create({ id: 'user123', email: 'user@example.com', name: 'User' })
  .withSecret(env.SESSION_SECRET)
  .withDuration('7d')
  .asAuthenticated()
  .build();

// セッション検証
const result = await SessionVerifier
  .fromRequest(request)
  .withSecret(env.SESSION_SECRET)
  .verify();
```

### OAuth モジュール

```typescript
import { OAuthFlow, OAuthCallback } from '@aid-on/auth/oauth';

// OAuth認証URL生成
const authUrl = OAuthFlow
  .google()
  .withClientId(env.GOOGLE_CLIENT_ID)
  .withRedirectUri('https://example.com/auth/callback')
  .withRandomState()
  .withOfflineAccess()
  .buildAuthUrl();

// OAuthコールバック処理
const result = await OAuthCallback
  .fromUrl(request.url)
  .withClientId(env.GOOGLE_CLIENT_ID)
  .withClientSecret(env.GOOGLE_CLIENT_SECRET)
  .withRedirectUri('https://example.com/auth/callback')
  .exchange();
```

### Guest モジュール

```typescript
import { GuestBuilder, isGuestId } from '@aid-on/auth/guest';

// ゲストユーザー作成
const { user, session } = await GuestBuilder
  .create()
  .withName('ゲストユーザー')
  .withSessionDuration('24h')
  .withSecret(env.SESSION_SECRET)
  .build();

// ゲストユーザー判定
if (isGuestId(userId)) {
  console.log('ゲストユーザーです');
}
```

### Audit モジュール

```typescript
import { AuditBuilder } from '@aid-on/auth/audit';

// ログイン監査記録
const loginAudit = AuditBuilder
  .login(user.id)
  .fromRequest(request)
  .withDetails({ provider: 'google', mfa: false })
  .build();

// D1データベースへ保存
await db.prepare(`
  INSERT INTO audit_logs (id, timestamp, user_id, action, ip_address, user_agent, details)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`).bind(
  loginAudit.id,
  loginAudit.timestamp.toISOString(),
  loginAudit.userId,
  loginAudit.action,
  loginAudit.ipAddress,
  loginAudit.userAgent,
  JSON.stringify(loginAudit.details)
).run();
```

### Cloudflare Access モジュール

```typescript
import { accessGuard, getAuthContext } from '@aid-on/auth/access';

// Pages Functionでのアクセス制御
export const onRequestGet: PagesFunction<Env> = async (context) => {
  const auth = await accessGuard(context.request, context.env, {
    getTeamDomain: (env) => env.CF_ACCESS_TEAM_DOMAIN,
    allowedDomains: ['aid-on.org'],
    allowDevBypass: true,
  });

  if (!auth.success) {
    return auth.errorResponse!;
  }

  return new Response(`こんにちは、${auth.user!.name}さん！`);
};
```

## 使用例

### 基本的なセッション管理

```typescript
import { SessionBuilder, SessionVerifier } from '@aid-on/auth/session';

export async function createUserSession(userInfo: any, env: Env) {
  const session = await SessionBuilder
    .create({
      id: userInfo.id,
      email: userInfo.email,
      name: userInfo.name,
    })
    .withSecret(env.SESSION_SECRET)
    .withDuration('7d')
    .withCookie({
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      path: '/',
    })
    .build();

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Set-Cookie': session.cookieString,
      'Content-Type': 'application/json',
    },
  });
}

export async function verifyUserSession(request: Request, env: Env) {
  const result = await SessionVerifier
    .fromRequest(request)
    .withSecret(env.SESSION_SECRET)
    .verify();

  if (!result.valid) {
    return new Response('Unauthorized', { status: 401 });
  }

  return result.payload;
}
```

### OAuth認証フロー

```typescript
import { OAuthFlow, OAuthCallback } from '@aid-on/auth/oauth';
import { SessionBuilder } from '@aid-on/auth/session';

// 1. OAuth開始エンドポイント
export const onRequestGet: PagesFunction = async (context) => {
  const authUrl = OAuthFlow
    .google()
    .withClientId(context.env.GOOGLE_CLIENT_ID)
    .withRedirectUri('https://yourapp.com/api/auth/callback')
    .withRandomState()
    .withScopes(['email', 'profile'])
    .buildAuthUrl();
  
  return Response.redirect(authUrl);
};

// 2. OAuthコールバック処理
export const onRequestGet: PagesFunction = async (context) => {
  const result = await OAuthCallback
    .fromUrl(context.request.url)
    .withClientId(context.env.GOOGLE_CLIENT_ID)
    .withClientSecret(context.env.GOOGLE_CLIENT_SECRET)
    .withRedirectUri('https://yourapp.com/api/auth/callback')
    .exchange();
  
  if (!result.success) {
    return new Response(`エラー: ${result.error}`, { status: 400 });
  }
  
  // セッション作成
  const session = await SessionBuilder
    .create({
      id: result.user.id,
      email: result.user.email,
      name: result.user.name,
    })
    .withSecret(context.env.SESSION_SECRET)
    .withDuration('7d')
    .build();
  
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': session.cookieString,
    },
  });
};
```

### ゲストユーザー対応

```typescript
import { GuestBuilder, isGuestId } from '@aid-on/auth/guest';
import { SessionVerifier } from '@aid-on/auth/session';

export async function handleGuestAccess(request: Request, env: Env) {
  // 既存セッションを確認
  const sessionResult = await SessionVerifier
    .fromRequest(request)
    .withSecret(env.SESSION_SECRET)
    .verify();

  if (sessionResult.valid) {
    return sessionResult.payload;
  }

  // ゲストユーザー作成
  const { user, session } = await GuestBuilder
    .create()
    .withName('ゲストユーザー')
    .withSessionDuration('24h')
    .withSecret(env.SESSION_SECRET)
    .build();

  return new Response(JSON.stringify({ user }), {
    headers: {
      'Set-Cookie': session.cookieString,
      'Content-Type': 'application/json',
    },
  });
}

export function checkUserType(userId: string) {
  if (isGuestId(userId)) {
    return 'guest';
  }
  return 'authenticated';
}
```

### 監査ログの実装

```typescript
import { AuditBuilder } from '@aid-on/auth/audit';

export async function logSecurityEvent(
  action: string,
  userId: string,
  request: Request,
  env: Env,
  details?: any
) {
  const auditLog = AuditBuilder
    .custom(action, userId)
    .fromRequest(request)
    .withDetails(details)
    .build();

  // D1データベースへ保存
  await env.DB.prepare(`
    INSERT INTO audit_logs 
    (id, timestamp, user_id, action, ip_address, user_agent, details, risk_level)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    auditLog.id,
    auditLog.timestamp.toISOString(),
    auditLog.userId,
    auditLog.action,
    auditLog.ipAddress,
    auditLog.userAgent,
    JSON.stringify(auditLog.details),
    auditLog.riskLevel
  ).run();
}

// 使用例
await logSecurityEvent('password_change', user.id, request, env, {
  oldPasswordHash: 'redacted',
  method: 'user_initiated'
});
```

## 設定オプション

### 環境変数

```bash
# 必須設定
SESSION_SECRET=your-session-secret-key
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret

# Cloudflare Access (オプション)
CF_ACCESS_TEAM_DOMAIN=your-team-domain
CF_ACCESS_AUD=your-access-application-aud

# 開発環境設定
ENVIRONMENT=development  # 開発時のみ
```

### セッション設定

```typescript
const sessionConfig = {
  duration: '7d',           // セッション有効期限
  cookieName: 'session',    // Cookie名
  httpOnly: true,           // HttpOnlyフラグ
  secure: true,             // Secureフラグ（HTTPS必須）
  sameSite: 'Lax',         // SameSite属性
  path: '/',               // Cookieパス
  domain: '.example.com'   // Cookie対象ドメイン
};
```

### OAuth設定

```typescript
const oauthConfig = {
  provider: 'google',
  scopes: ['email', 'profile'],
  accessType: 'offline',    // リフレッシュトークン取得
  prompt: 'consent',        // ユーザー同意画面
  state: 'random-state'     // CSRF保護
};
```

### 監査ログ設定

```typescript
const auditConfig = {
  retentionDays: 365,       // ログ保持期間
  sensitiveFields: ['password', 'token'], // 機密情報フィールド
  ipAddressTracking: true,  // IPアドレス記録
  userAgentTracking: true,  // User-Agent記録
  geoLocationTracking: false // 位置情報記録
};
```

## パフォーマンス考慮事項

### セッション検証の最適化

- **並列処理**: 複数セッション検証時のPromise.all活用
- **キャッシュ**: 頻繁なセッション検証のメモリキャッシュ
- **キーローテーション**: 古いキーでの検証コスト考慮

```typescript
// 効率的なセッション検証
const results = await Promise.all([
  SessionVerifier.fromCookies(cookies, 'session1').withSecret(secret).verify(),
  SessionVerifier.fromCookies(cookies, 'session2').withSecret(secret).verify(),
]);
```

### OAuth フローの最適化

- **状態管理**: サーバーサイド状態保存の最小化
- **トークン交換**: 非同期処理による応答時間短縮
- **エラーハンドリング**: 適切なタイムアウト設定

### 監査ログの最適化

- **バッチ処理**: ログの一括書き込み
- **非同期処理**: UIブロックの回避
- **データ圧縮**: 大量ログのストレージ効率化

```typescript
// バッチ監査ログ
const auditLogs = events.map(event => 
  AuditBuilder.custom(event.action, event.userId).fromRequest(event.request).build()
);

await Promise.all(auditLogs.map(log => saveToDatabase(log)));
```

### メモリ使用量の最適化

- **使い捨てオブジェクト**: セッション検証後の即座なメモリ解放
- **大きなペイロード**: セッションデータサイズの制限
- **暗号化キー**: キーマテリアルの適切な破棄

### エッジ環境での考慮事項

- **コールドスタート**: 初回実行時のWebCrypto初期化コスト
- **CPU制限**: HMAC計算の実行時間制限
- **メモリ制限**: 大量セッション同時処理の制約
- **ネットワーク遅延**: OAuth プロバイダーとの通信最適化

## セキュリティベストプラクティス

### セッション管理

- **強力なシークレット**: 256bit以上のランダムキー使用
- **適切な有効期限**: セキュリティとユーザビリティのバランス
- **HTTPS必須**: 本番環境でのSecure Cookie強制

### OAuth実装

- **State パラメータ**: CSRF攻撃防止の必須実装
- **適切なスコープ**: 必要最小限の権限要求
- **リフレッシュトークン**: 安全な保存と更新

### 監査証跡

- **機密情報の除外**: パスワードやトークンの非記録
- **改ざん検出**: ログデータの整合性保護
- **アクセス制御**: 監査ログへの適切な権限管理