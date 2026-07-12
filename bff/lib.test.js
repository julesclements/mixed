const {
  escapeHtml,
  getMatchingRedirectUrl,
  validateEnvVars,
  buildCorsOptions,
  buildSessionConfig,
  shouldUseSecureCookies,
  parseList,
  normalizeIssuer,
  correctIssuerMetadata,
} = require('./lib');

describe('escapeHtml', () => {
  it('escapes all HTML special characters', () => {
    expect(escapeHtml('<script>alert("x" & \'y\')</script>')).toBe(
      '&lt;script&gt;alert(&quot;x&quot; &amp; &#039;y&#039;)&lt;/script&gt;'
    );
  });

  it('returns empty string for non-string input', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml(42)).toBe('');
    expect(escapeHtml({})).toBe('');
  });

  it('returns empty string for empty string', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('returns string unchanged if no special chars', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
  });

  it('handles each special character individually', () => {
    expect(escapeHtml('&')).toBe('&amp;');
    expect(escapeHtml('<')).toBe('&lt;');
    expect(escapeHtml('>')).toBe('&gt;');
    expect(escapeHtml('"')).toBe('&quot;');
    expect(escapeHtml("'")).toBe('&#039;');
  });
});

describe('getMatchingRedirectUrl', () => {
  const origins = ['http://localhost:1234', 'https://app.example.com'];
  const redirects = ['http://localhost:1234/', 'https://app.example.com/dashboard'];

  it('matches referer origin to corresponding redirect URL', () => {
    expect(getMatchingRedirectUrl('http://localhost:1234/page', origins, redirects)).toBe(
      'http://localhost:1234/'
    );
  });

  it('matches second origin', () => {
    expect(
      getMatchingRedirectUrl('https://app.example.com/dashboard/settings', origins, redirects)
    ).toBe('https://app.example.com/dashboard');
  });

  it('falls back to prefix match if origin not in list', () => {
    expect(
      getMatchingRedirectUrl('http://localhost:1234/deep/path', ['http://other.com'], redirects)
    ).toBe('http://localhost:1234/');
  });

  it('returns first redirect URL when referer is undefined', () => {
    expect(getMatchingRedirectUrl(undefined, origins, redirects)).toBe('http://localhost:1234/');
  });

  it('returns first redirect URL when referer is null', () => {
    expect(getMatchingRedirectUrl(null, origins, redirects)).toBe('http://localhost:1234/');
  });

  it('returns first redirect URL when referer is invalid URL string', () => {
    expect(getMatchingRedirectUrl('not-a-url', origins, redirects)).toBe('http://localhost:1234/');
  });

  it('returns undefined when allowedRedirectUrls is empty and referer is undefined', () => {
    expect(getMatchingRedirectUrl(undefined, origins, [])).toBeUndefined();
  });

  it('returns undefined when no match and list is empty', () => {
    expect(getMatchingRedirectUrl('http://localhost:1234/', origins, [])).toBeUndefined();
  });
});

describe('validateEnvVars', () => {
  it('returns valid true when all required vars present', () => {
    const env = {
      PING_ISSUER_URL: 'https://ping.example.com',
      PING_CLIENT_ID: 'client-id',
      PING_CLIENT_SECRET: 'secret',
      SESSION_SECRET: 'session-secret',
      FRONTEND_ORIGIN: 'http://localhost:1234',
      FRONTEND_REDIRECT_URL: 'http://localhost:1234/',
      BFF_BASE_URL: 'http://localhost:3001',
    };
    const result = validateEnvVars(env);
    expect(result.valid).toBe(true);
    expect(result.missing).toEqual([]);
  });

  it('returns valid false and lists missing vars', () => {
    const env = {
      PING_ISSUER_URL: 'https://ping.example.com',
    };
    const result = validateEnvVars(env);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain('PING_CLIENT_ID');
    expect(result.missing).toContain('PING_CLIENT_SECRET');
    expect(result.missing).toContain('SESSION_SECRET');
    expect(result.missing).toContain('FRONTEND_ORIGIN');
    expect(result.missing).toContain('FRONTEND_REDIRECT_URL');
    expect(result.missing).toContain('BFF_BASE_URL');
  });

  it('treats whitespace-only values as missing', () => {
    const env = {
      PING_ISSUER_URL: '   ',
      PING_CLIENT_ID: 'client-id',
      PING_CLIENT_SECRET: 'secret',
      SESSION_SECRET: 'session-secret',
      FRONTEND_ORIGIN: 'http://localhost:1234',
      FRONTEND_REDIRECT_URL: 'http://localhost:1234/',
      BFF_BASE_URL: 'http://localhost:3001',
    };
    const result = validateEnvVars(env);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain('PING_ISSUER_URL');
  });

  it('returns valid false for empty env object', () => {
    const result = validateEnvVars({});
    expect(result.valid).toBe(false);
    expect(result.missing.length).toBe(7);
  });
});

describe('buildCorsOptions', () => {
  it('allows requests with no origin', () => {
    const opts = buildCorsOptions(['http://localhost:1234']);
    let result;
    opts.origin(undefined, (err, ok) => { result = { err, ok }; });
    expect(result.err).toBeNull();
    expect(result.ok).toBe(true);
  });

  it('allows requests from allowed origins', () => {
    const opts = buildCorsOptions(['http://localhost:1234']);
    let result;
    opts.origin('http://localhost:1234', (err, ok) => { result = { err, ok }; });
    expect(result.err).toBeNull();
    expect(result.ok).toBe(true);
  });

  it('rejects requests from disallowed origins', () => {
    const opts = buildCorsOptions(['http://localhost:1234']);
    let result;
    opts.origin('http://evil.com', (err, ok) => { result = { err, ok }; });
    expect(result.err).toBeInstanceOf(Error);
    expect(result.ok).toBeUndefined();
  });

  it('has correct configuration values', () => {
    const opts = buildCorsOptions(['http://localhost:1234']);
    expect(opts.credentials).toBe(true);
    expect(opts.methods).toEqual(['GET', 'POST', 'OPTIONS']);
    expect(opts.allowedHeaders).toEqual(['Content-Type', 'X-Correlation-ID', 'Authorization']);
    expect(opts.exposedHeaders).toEqual(['Set-Cookie']);
    expect(opts.maxAge).toBe(86400);
  });
});

describe('buildSessionConfig', () => {
  it('builds config with secure cookies for secure mode', () => {
    const config = buildSessionConfig('my-secret', true);
    expect(config.secret).toBe('my-secret');
    expect(config.resave).toBe(false);
    expect(config.saveUninitialized).toBe(true);
    expect(config.cookie.secure).toBe(true);
    expect(config.cookie.httpOnly).toBe(true);
    expect(config.cookie.sameSite).toBe('None');
    expect(config.cookie.maxAge).toBe(24 * 60 * 60 * 1000);
  });

  it('builds config with lax cookies for non-secure mode', () => {
    const config = buildSessionConfig('my-secret', false);
    expect(config.cookie.secure).toBe(false);
    expect(config.cookie.sameSite).toBe('Lax');
  });
});

describe('shouldUseSecureCookies', () => {
  it('returns true for production', () => {
    expect(shouldUseSecureCookies('production', 'http://localhost:3001')).toBe(true);
  });

  it('returns true for https base URL', () => {
    expect(shouldUseSecureCookies('development', 'https://bff.example.com')).toBe(true);
  });

  it('returns false for non-production and http', () => {
    expect(shouldUseSecureCookies('development', 'http://localhost:3001')).toBe(false);
  });

  it('returns false for undefined nodeEnv and http', () => {
    expect(shouldUseSecureCookies(undefined, 'http://localhost:3001')).toBe(false);
  });
});

describe('parseList', () => {
  it('parses comma-separated values', () => {
    expect(parseList('a,b,c')).toEqual(['a', 'b', 'c']);
  });

  it('trims whitespace', () => {
    expect(parseList(' a , b , c ')).toEqual(['a', 'b', 'c']);
  });

  it('returns empty array for undefined', () => {
    expect(parseList(undefined)).toEqual([]);
  });

  it('returns empty array for empty string', () => {
    expect(parseList('')).toEqual([]);
  });

  it('filters out empty entries', () => {
    expect(parseList('a,,b,')).toEqual(['a', 'b']);
  });

  it('handles single value', () => {
    expect(parseList('only')).toEqual(['only']);
  });
});

describe('normalizeIssuer', () => {
  it('removes trailing slash for root path', () => {
    expect(normalizeIssuer('https://example.com/')).toBe('https://example.com');
  });

  it('keeps URL with path unchanged', () => {
    expect(normalizeIssuer('https://example.com/path/')).toBe('https://example.com/path/');
  });

  it('keeps URL without trailing slash unchanged', () => {
    expect(normalizeIssuer('https://example.com')).toBe('https://example.com');
  });

  it('returns non-string input unchanged', () => {
    expect(normalizeIssuer(null)).toBeNull();
    expect(normalizeIssuer(42)).toBe(42);
  });

  it('returns invalid URL string unchanged', () => {
    expect(normalizeIssuer('not-a-url')).toBe('not-a-url');
  });
});

describe('correctIssuerMetadata', () => {
  const baseMetadata = {
    issuer: 'https://localhost:9031',
    authorization_endpoint: 'https://localhost:9031/as/authorization.oauth2',
    end_session_endpoint: 'https://localhost:9031/idp/startSLO.server',
    token_endpoint: 'https://localhost:9031/as/token.oauth2',
    jwks_uri: 'https://localhost:9031/pf/JWKS',
    introspection_endpoint: 'https://localhost:9031/as/introspect.oauth2',
    userinfo_endpoint: 'https://localhost:9031/idp/userinfo.openid',
  };

  it('returns original metadata when internal URL is invalid', () => {
    const result = correctIssuerMetadata(baseMetadata, 'not-a-url', '');
    expect(result).toBe(baseMetadata);
  });

  it('corrects localhost issuer to internal URL when both are localhost', () => {
    const result = correctIssuerMetadata(baseMetadata, 'https://localhost:9031', '');
    expect(result.issuer).toBe('https://localhost:9031');
  });

  it('corrects localhost endpoints when internal URL is external', () => {
    const result = correctIssuerMetadata(
      baseMetadata,
      'https://ping.example.com:9031',
      ''
    );
    expect(result.issuer).toBe('https://ping.example.com:9031');
    expect(result.token_endpoint).toBe('https://ping.example.com:9031/as/token.oauth2');
    expect(result.jwks_uri).toBe('https://ping.example.com:9031/pf/JWKS');
    expect(result.authorization_endpoint).toBe('https://ping.example.com:9031/as/authorization.oauth2');
  });

  it('uses browser-facing URL for authorization and end_session endpoints in split scenario', () => {
    const result = correctIssuerMetadata(
      baseMetadata,
      'https://internal.ping.com:9031',
      'https://browser.ping.com'
    );
    expect(result.issuer).toBe('https://browser.ping.com');
    expect(result.authorization_endpoint).toBe('https://browser.ping.com/as/authorization.oauth2');
    expect(result.end_session_endpoint).toBe('https://browser.ping.com/idp/startSLO.server');
    // Non-browser-facing endpoints should use internal URL
    expect(result.token_endpoint).toBe('https://internal.ping.com:9031/as/token.oauth2');
  });

  it('does not modify endpoints that are not localhost and no browser-facing URL', () => {
    const externalMetadata = {
      issuer: 'https://ping.example.com',
      authorization_endpoint: 'https://ping.example.com/as/authorization.oauth2',
      token_endpoint: 'https://ping.example.com/as/token.oauth2',
    };
    const result = correctIssuerMetadata(externalMetadata, 'https://ping.example.com', '');
    expect(result.issuer).toBe('https://ping.example.com');
    expect(result.authorization_endpoint).toBe('https://ping.example.com/as/authorization.oauth2');
  });

  it('handles invalid browser-facing URL gracefully', () => {
    const result = correctIssuerMetadata(
      baseMetadata,
      'https://localhost:9031',
      'not-a-url'
    );
    // Should fall back to non-split behavior
    expect(result.issuer).toBe('https://localhost:9031');
  });

  it('handles non-string issuer in metadata', () => {
    const metadata = { ...baseMetadata, issuer: 12345 };
    const result = correctIssuerMetadata(metadata, 'https://localhost:9031', '');
    expect(result.issuer).toBe(12345);
  });

  it('handles issuer that is not a valid URL string', () => {
    const metadata = { ...baseMetadata, issuer: 'not-a-url-string' };
    const result = correctIssuerMetadata(metadata, 'https://localhost:9031', '');
    expect(result.issuer).toBe('not-a-url-string');
  });

  it('preserves non-string metadata values', () => {
    const metadata = {
      ...baseMetadata,
      some_number: 42,
      some_boolean: true,
      some_object: { nested: 'value' },
    };
    const result = correctIssuerMetadata(metadata, 'https://localhost:9031', '');
    expect(result.some_number).toBe(42);
    expect(result.some_boolean).toBe(true);
    expect(result.some_object).toEqual({ nested: 'value' });
  });

  it('normalizes trailing slash on issuer', () => {
    const metadata = {
      ...baseMetadata,
      issuer: 'https://localhost:9031/',
    };
    const result = correctIssuerMetadata(metadata, 'https://localhost:9031', '');
    expect(result.issuer).toBe('https://localhost:9031');
  });

  it('skips correction for invalid endpoint URL', () => {
    const metadata = {
      ...baseMetadata,
      token_endpoint: '://invalid-url',
    };
    const result = correctIssuerMetadata(metadata, 'https://ping.example.com:9031', '');
    // Invalid endpoint URL should be skipped, not corrected
    expect(result.token_endpoint).toBe('://invalid-url');
  });

  it('handles external issuer that does not match internal URL', () => {
    const metadata = {
      ...baseMetadata,
      issuer: 'https://ping.example.com',
    };
    const result = correctIssuerMetadata(metadata, 'https://other.example.com:9031', '');
    // Both are external and different - issuer should be preserved
    expect(result.issuer).toBe('https://ping.example.com');
  });
});
