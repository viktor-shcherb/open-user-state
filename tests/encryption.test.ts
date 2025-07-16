/**
 * Tests for the encryption helpers. They ensure tokens round trip
 * correctly and that decryption fails when using the wrong secret.
 */
import { describe, it, expect } from 'vitest';
import { encryptPAT, decryptPAT } from '../src/index';

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
