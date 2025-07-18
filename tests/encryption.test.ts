/**
 * Tests for the encryption helpers. They ensure tokens round trip
 * correctly and that decryption fails when using the wrong secret.
 */
import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';

// Vitest runs under Node which already exposes `globalThis.crypto` in modern
// versions. Only install a shim when it's missing so the tests work on older
// Node releases without triggering a TypeError.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
  });
}
import { encryptPAT, decryptPAT } from '../src/auth';

const secret = 's3cret';

describe('encryptPAT/decryptPAT', () => {
  it('round trips a token', async () => {
    const enc = await encryptPAT('token', secret);
    const dec = await decryptPAT(enc, secret);
    expect(dec).toBe('token');
  });

  it('fails with wrong secret', async () => {
    const enc = await encryptPAT('token', secret);
    await expect(decryptPAT(enc, 'wrong')).rejects.toThrow();
  });

  it('rejects truncated data', async () => {
    await expect(decryptPAT('', secret)).rejects.toThrow('cipher too short');
  });
});
