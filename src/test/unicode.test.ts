/**
 * Unicode (Japanese) support test
 */

import { describe, it, expect } from 'vitest';
import { SessionBuilder, SessionVerifier } from '../session/session';

describe('Unicode Support', () => {
  const SECRET = 'test-secret-key';

  it('should handle Japanese characters in session payload', async () => {
    // Create session with Japanese text
    const session = await SessionBuilder
      .create({
        id: 'user-123',
        email: 'tanaka@example.com',
        name: '田中太郎', // Japanese name
      })
      .withSecret(SECRET)
      .withDuration('1h')
      .build();

    // Verify session
    const result = await SessionVerifier
      .fromToken(session.token)
      .withSecret(SECRET)
      .verify();

    expect(result.valid).toBe(true);
    expect(result.payload?.name).toBe('田中太郎');
  });

  it('should handle emoji in session payload', async () => {
    const session = await SessionBuilder
      .create({
        id: 'user-456',
        email: 'emoji@example.com',
        name: 'User 🎉 with 🚀 emojis',
      })
      .withSecret(SECRET)
      .build();

    const result = await SessionVerifier
      .fromToken(session.token)
      .withSecret(SECRET)
      .verify();

    expect(result.valid).toBe(true);
    expect(result.payload?.name).toBe('User 🎉 with 🚀 emojis');
  });

  it('should handle mixed Unicode characters', async () => {
    const session = await SessionBuilder
      .create({
        id: 'user-789',
        email: 'mixed@example.com',
        name: '山田さん 🌸 (Yamada-san)',
        // Custom fields are supported in SessionPayload
        description: '春の桜が綺麗ですね 🌸🌸🌸',
        location: '東京都渋谷区',
      } as any)
      .withSecret(SECRET)
      .build();

    const result = await SessionVerifier
      .fromToken(session.token)
      .withSecret(SECRET)
      .verify();

    expect(result.valid).toBe(true);
    expect(result.payload?.name).toBe('山田さん 🌸 (Yamada-san)');
  });
});