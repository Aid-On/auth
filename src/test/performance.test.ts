/**
 * Performance test for HMAC signature
 */

import { describe, it, expect } from 'vitest';

describe('HMAC Performance', () => {
  it('should handle HMAC-SHA256 signature (32 bytes) without issues', async () => {
    // HMAC-SHA256 produces exactly 32 bytes (256 bits)
    const signature = new Uint8Array(32);
    crypto.getRandomValues(signature);
    
    // This is safe - spread operator with 32 bytes won't cause stack overflow
    const binString = String.fromCharCode(...signature);
    
    expect(binString.length).toBe(32);
    expect(() => btoa(binString)).not.toThrow();
  });
  
  it('should handle larger data for reference (edge case)', () => {
    // JavaScript's Function.prototype.apply has a limit around 65,535 arguments
    // But HMAC-SHA256 is always 32 bytes, so this is just for reference
    const smallData = new Uint8Array(100);
    const mediumData = new Uint8Array(1000);
    
    // These are all safe
    expect(() => String.fromCharCode(...smallData)).not.toThrow();
    expect(() => String.fromCharCode(...mediumData)).not.toThrow();
    
    // This would fail (but we never have signatures this large)
    // const hugeData = new Uint8Array(100000);
    // expect(() => String.fromCharCode(...hugeData)).toThrow();
  });
});