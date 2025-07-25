/**
 * Unit tests for the cookie parsing helper. They verify that the
 * lightweight parser correctly handles typical header values and
 * edge cases like a null header.
 */
import { describe, it, expect } from 'vitest';
import { parseCookies } from '../src/auth';

describe('parseCookies', () => {
  it('parses key=value pairs', () => {
    const result = parseCookies('a=1; b=2');
    expect(result).toEqual({ a: '1', b: '2' });
  });

  it('handles null header', () => {
    expect(parseCookies(null)).toEqual({});
  });

  it('ignores malformed pairs', () => {
    const header = 'a=1; invalid; b=2; c=';
    expect(parseCookies(header)).toEqual({ a: '1', b: '2' });
  });
});
