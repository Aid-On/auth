/**
 * Session key rotation test
 */

import { describe, it, expect } from 'vitest';
import { SessionBuilder, SessionVerifier } from '../session/session';

describe('Session Key Rotation', () => {
  const OLD_SECRET = 'old-secret-key-2024';
  const NEW_SECRET = 'new-secret-key-2025';

  it('should verify sessions with rotated keys', async () => {
    // Create session with old secret
    const session = await SessionBuilder
      .create({
        id: 'user-123',
        email: 'user@example.com',
        name: 'Test User',
      })
      .withSecret(OLD_SECRET)
      .withDuration('7d')
      .build();

    // Verify with both old and new secret (key rotation)
    const resultWithRotation = await SessionVerifier
      .fromToken(session.token)
      .withSecrets([NEW_SECRET, OLD_SECRET]) // Try new first, then old
      .verify();

    expect(resultWithRotation.valid).toBe(true);
    expect(resultWithRotation.payload?.email).toBe('user@example.com');
  });

  it('should fail verification with only new secret', async () => {
    // Create session with old secret
    const session = await SessionBuilder
      .create({
        id: 'user-456',
        email: 'test@example.com',
        name: 'Another User',
      })
      .withSecret(OLD_SECRET)
      .build();

    // Try to verify with only new secret
    const result = await SessionVerifier
      .fromToken(session.token)
      .withSecret(NEW_SECRET) // Only new secret
      .verify();

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature');
  });

  it('should handle multiple rotation keys', async () => {
    const OLDEST_SECRET = 'oldest-secret-2023';
    const MIDDLE_SECRET = 'middle-secret-2024';
    const NEWEST_SECRET = 'newest-secret-2025';

    // Create session with middle secret
    const session = await SessionBuilder
      .create({
        id: 'user-789',
        email: 'multi@example.com',
        name: 'Multi Key User',
      })
      .withSecret(MIDDLE_SECRET)
      .build();

    // Verify with all three secrets
    const result = await SessionVerifier
      .fromToken(session.token)
      .withSecrets([NEWEST_SECRET, MIDDLE_SECRET, OLDEST_SECRET])
      .verify();

    expect(result.valid).toBe(true);
    expect(result.payload?.name).toBe('Multi Key User');
  });

  it('should throw error when no secrets provided', async () => {
    const verifier = SessionVerifier.fromToken('some-token');
    
    // Using withSecrets with empty array
    expect(() => verifier.withSecrets([])).toThrow('At least one secret is required');
  });
});