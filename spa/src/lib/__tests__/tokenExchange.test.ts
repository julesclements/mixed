import { describe, it, expect, vi } from 'vitest';
import {
  exchangeCodeForToken,
  resolveTokenEndpoint,
  resolveAuthEndpoint,
  resolveLogoffEndpoint,
} from '../tokenExchange';

describe('resolveTokenEndpoint', () => {
  it('returns as-is if already a token endpoint', () => {
    const url = 'https://ping.example.com/as/token.oauth2';
    expect(resolveTokenEndpoint(url)).toBe(url);
  });

  it('converts authorization endpoint to token endpoint', () => {
    expect(resolveTokenEndpoint('https://ping.example.com/as/authorization.oauth2')).toBe(
      'https://ping.example.com/as/token.oauth2',
    );
  });

  it('appends token path to base url', () => {
    expect(resolveTokenEndpoint('https://ping.example.com')).toBe(
      'https://ping.example.com/as/token.oauth2',
    );
  });

  it('strips trailing slash from base url', () => {
    expect(resolveTokenEndpoint('https://ping.example.com/')).toBe(
      'https://ping.example.com/as/token.oauth2',
    );
  });
});

describe('resolveAuthEndpoint', () => {
  it('returns as-is if already an authorization endpoint', () => {
    const url = 'https://ping.example.com/as/authorization.oauth2';
    expect(resolveAuthEndpoint(url)).toBe(url);
  });

  it('appends authorization path to base url', () => {
    expect(resolveAuthEndpoint('https://ping.example.com')).toBe(
      'https://ping.example.com/as/authorization.oauth2',
    );
  });

  it('strips trailing slash from base url', () => {
    expect(resolveAuthEndpoint('https://ping.example.com/')).toBe(
      'https://ping.example.com/as/authorization.oauth2',
    );
  });
});

describe('resolveLogoffEndpoint', () => {
  it('builds startSLO URL from base url', () => {
    expect(resolveLogoffEndpoint('https://ping.example.com')).toBe(
      'https://ping.example.com/idp/startSLO.ping',
    );
  });

  it('extracts base url from an /as/ path', () => {
    expect(resolveLogoffEndpoint('https://ping.example.com/as/token.oauth2')).toBe(
      'https://ping.example.com/idp/startSLO.ping',
    );
  });
});

describe('exchangeCodeForToken', () => {
  it('posts form-encoded body and returns parsed token response on success', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'token-abc',
        id_token: 'id-token-xyz',
        token_type: 'Bearer',
        expires_in: 3600,
      }),
    }) as any;

    const result = await exchangeCodeForToken(
      'code123',
      'verifier456',
      'client-789',
      'https://spa.example.com/callback',
      'https://ping.example.com/as/token.oauth2',
      mockFetch,
    );

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://ping.example.com/as/token.oauth2');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    const bodyStr = init.body.toString();
    expect(bodyStr).toContain('grant_type=authorization_code');
    expect(bodyStr).toContain('client_id=client-789');
    expect(bodyStr).toContain('code_verifier=verifier456');
    expect(bodyStr).toContain('code=code123');
    expect(bodyStr).toContain('redirect_uri=');

    expect(result.access_token).toBe('token-abc');
    expect(result.id_token).toBe('id-token-xyz');
    expect(result.token_type).toBe('Bearer');
    expect(result.expires_in).toBe(3600);
  });

  it('throws when response is not ok', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 400 }) as any;
    await expect(
      exchangeCodeForToken('c', 'v', 'cli', 'https://spa/cb', 'https://tok', mockFetch),
    ).rejects.toThrow('Failed to exchange code for token');
  });

  it('rethrows non-HTTP errors from fetch implementation', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new TypeError('network failure')) as any;
    await expect(
      exchangeCodeForToken('c', 'v', 'cli', 'https://spa/cb', 'https://tok', mockFetch),
    ).rejects.toThrow('network failure');
  });
});
