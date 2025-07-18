/**
 * Tests for the encryption helpers. They ensure tokens round trip
 * correctly and that decryption fails when using the wrong secret.
 */
import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';

// Vitest runs in a Node environment where `crypto` is not globally available
// like it is in Cloudflare Workers. Expose it here for the helpers under test.
globalThis.crypto = webcrypto as unknown as Crypto;
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
