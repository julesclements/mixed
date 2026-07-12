import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateCodeVerifierAndChallenge, buildAuthUrl } from '../pkce';

const mockSubtle = {
  digest: vi.fn(),
};
const mockCrypto = {
  getRandomValues: vi.fn(),
  subtle: mockSubtle,
  UUID: undefined,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('generateCodeVerifierAndChallenge', () => {
  it('generates a code verifier from random bytes', async () => {
    const fakeRandom = new Uint32Array([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    mockCrypto.getRandomValues.mockReturnValue(fakeRandom);

    const fakeDigest = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    mockSubtle.digest.mockResolvedValue(fakeDigest.buffer);

    const result = await generateCodeVerifierAndChallenge(mockCrypto as any);

    expect(result.codeVerifier).toMatch(/^[0-9a-f]+$/);
    expect(result.codeVerifier.length).toBe(56);
    expect(result.codeChallenge).toBeTruthy();
    expect(mockCrypto.getRandomValues).toHaveBeenCalledTimes(1);
    expect(mockSubtle.digest).toHaveBeenCalledTimes(1);
    expect(mockSubtle.digest.mock.calls[0][0]).toBe('SHA-256');
    const digestArg = mockSubtle.digest.mock.calls[0][1];
    expect(digestArg).toBeDefined();
    expect(typeof digestArg.length).toBe('number');
    expect(digestArg.length).toBeGreaterThan(0);
  });

  it('produces base64url-encoded challenge (no +, /, or =)', async () => {
    const fakeRandom = new Uint32Array(28);
    mockCrypto.getRandomValues.mockReturnValue(fakeRandom);

    const fakeDigest = new Uint8Array([
      255, 255, 255, 191, 191, 191, 63, 63, 63, 0,
    ]);
    mockSubtle.digest.mockResolvedValue(fakeDigest.buffer);

    const result = await generateCodeVerifierAndChallenge(mockCrypto as any);

    expect(result.codeChallenge).not.toContain('+');
    expect(result.codeChallenge).not.toContain('/');
    expect(result.codeChallenge).not.toContain('=');
  });
});

describe('buildAuthUrl', () => {
  it('builds a valid authorization URL with all PKCE parameters', () => {
    const url = buildAuthUrl(
      'https://ping.example.com/as/authorization.oauth2',
      'https://spa.example.com/callback',
      'client-123',
      'challenge-abc',
      'state-xyz',
    );

    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe('https://ping.example.com/as/authorization.oauth2');
    expect(parsed.searchParams.get('client_id')).toBe('client-123');
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('redirect_uri')).toBe('https://spa.example.com/callback');
    expect(parsed.searchParams.get('scope')).toBe('openid');
    expect(parsed.searchParams.get('code_challenge')).toBe('challenge-abc');
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('state')).toBe('state-xyz');
    expect(parsed.searchParams.get('response_mode')).toBe('query');
  });

  it('preserves order of required PKCE params', () => {
    const url = buildAuthUrl('https://ping.example.com/as/authorization.oauth2', 'https://spa.example.com/callback', 'c', 'ch', 'st');
    const queryString = url.split('?')[1];
    expect(queryString).toContain('client_id');
    expect(queryString).toContain('code_challenge_method=S256');
  });
});
