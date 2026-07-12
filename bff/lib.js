'use strict';

/**
 * Escape HTML special characters to prevent XSS when injecting values into HTML pages.
 * @param {string} unsafe
 * @returns {string}
 */
function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Determine the best redirect URL based on a referer string.
 * Matches the referer origin against allowedOrigins to find the corresponding allowedRedirectUrls entry.
 * @param {string|undefined} referer
 * @param {string[]} allowedOrigins
 * @param {string[]} allowedRedirectUrls
 * @returns {string|undefined}
 */
function getMatchingRedirectUrl(referer, allowedOrigins, allowedRedirectUrls) {
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = refererUrl.origin;
      const index = allowedOrigins.indexOf(refererOrigin);
      if (index !== -1 && allowedRedirectUrls[index]) {
        return allowedRedirectUrls[index];
      }
      const matchingUrl = allowedRedirectUrls.find((url) => referer.startsWith(url));
      if (matchingUrl) {
        return matchingUrl;
      }
    } catch (_e) {
      // Ignore invalid URL
    }
  }
  return allowedRedirectUrls[0];
}

/**
 * Validate that all required environment variables are present.
 * @param {Record<string, string|undefined>} env
 * @returns {{ valid: boolean, missing: string[] }}
 */
function validateEnvVars(env) {
  const required = [
    'PING_ISSUER_URL',
    'PING_CLIENT_ID',
    'PING_CLIENT_SECRET',
    'SESSION_SECRET',
    'FRONTEND_ORIGIN',
    'FRONTEND_REDIRECT_URL',
    'BFF_BASE_URL',
  ];
  const missing = required.filter((key) => !env[key] || String(env[key]).trim() === '');
  return { valid: missing.length === 0, missing };
}

/**
 * Build CORS options for the Express app.
 * @param {string[]} allowedOrigins
 * @returns {object}
 */
function buildCorsOptions(allowedOrigins) {
  return {
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Correlation-ID', 'Authorization'],
    exposedHeaders: ['Set-Cookie'],
    maxAge: 86400,
  };
}

/**
 * Build session configuration object for express-session.
 * @param {string} sessionSecret
 * @param {boolean} useSecureCookies
 * @returns {object}
 */
function buildSessionConfig(sessionSecret, useSecureCookies) {
  return {
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: useSecureCookies,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: useSecureCookies ? 'None' : 'Lax',
    },
  };
}

/**
 * Determine whether secure cookies should be used based on environment and protocol.
 * @param {string} nodeEnv
 * @param {string} bffBaseUrl
 * @returns {boolean}
 */
function shouldUseSecureCookies(nodeEnv, bffBaseUrl) {
  return nodeEnv === 'production' || bffBaseUrl.startsWith('https://');
}

/**
 * Parse a comma-separated env var into a trimmed array.
 * @param {string|undefined} value
 * @returns {string[]}
 */
function parseList(value) {
  if (!value) return [];
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * Normalize an issuer URL string by removing trailing slash if path is root.
 * @param {string} value
 * @returns {string}
 */
function normalizeIssuer(value) {
  if (typeof value !== 'string') return value;
  try {
    const u = new URL(value);
    if (u.pathname === '/' && value.endsWith('/')) {
      return value.slice(0, -1);
    }
  } catch (_e) {
    // not a valid URL, return as-is
  }
  return value;
}

/**
 * Correct OIDC issuer metadata for localhost and split-URL scenarios.
 * @param {object} metadata
 * @param {string} internalBaseUrlString
 * @param {string} browserFacingBaseUrlString
 * @returns {object}
 */
function correctIssuerMetadata(metadata, internalBaseUrlString, browserFacingBaseUrlString) {
  const newMetadata = JSON.parse(JSON.stringify(metadata));

  let internalUrlObj;
  try {
    internalUrlObj = new URL(internalBaseUrlString);
  } catch (e) {
    return metadata;
  }

  let browserFacingUrlObj = null;
  if (browserFacingBaseUrlString && browserFacingBaseUrlString.trim() !== '') {
    try {
      browserFacingUrlObj = new URL(browserFacingBaseUrlString);
    } catch (_e) {
      browserFacingUrlObj = null;
    }
  }

  const isSplitUrlScenario = browserFacingUrlObj && browserFacingUrlObj.hostname !== internalUrlObj.hostname;

  const originalDiscoveredIssuer = newMetadata.issuer;
  let finalIssuerValue = originalDiscoveredIssuer;

  if (typeof originalDiscoveredIssuer === 'string') {
    try {
      if (isSplitUrlScenario) {
        finalIssuerValue = browserFacingBaseUrlString;
      } else {
        const discoveredIssuerUrl = new URL(originalDiscoveredIssuer);
        if (internalUrlObj.hostname === 'localhost' && discoveredIssuerUrl.hostname === 'localhost') {
          finalIssuerValue = internalBaseUrlString;
        } else if (internalUrlObj.hostname !== 'localhost' && discoveredIssuerUrl.hostname === 'localhost') {
          discoveredIssuerUrl.protocol = internalUrlObj.protocol;
          discoveredIssuerUrl.hostname = internalUrlObj.hostname;
          discoveredIssuerUrl.port = internalUrlObj.port;
          finalIssuerValue = discoveredIssuerUrl.toString();
        }
      }

      finalIssuerValue = normalizeIssuer(finalIssuerValue);
    } catch (_e) {
      finalIssuerValue = originalDiscoveredIssuer;
    }

    if (newMetadata.issuer !== finalIssuerValue) {
      newMetadata.issuer = finalIssuerValue;
    }
  }

  for (const key of Object.keys(newMetadata)) {
    if (key === 'issuer') continue;
    const currentValue = newMetadata[key];
    if (typeof currentValue !== 'string') continue;

    const isBrowserFacingEndpoint = ['authorization_endpoint', 'end_session_endpoint'].includes(key);
    let targetObj = null;
    let correctionType = '';

    if (isBrowserFacingEndpoint && browserFacingUrlObj) {
      targetObj = browserFacingUrlObj;
      correctionType = 'BROWSER-FACING';
    } else if (currentValue.includes('://localhost') && internalUrlObj.hostname !== 'localhost') {
      targetObj = internalUrlObj;
      correctionType = 'INTERNAL from localhost';
    }

    if (targetObj) {
      try {
        let endpointUrl = new URL(currentValue);
        endpointUrl.protocol = targetObj.protocol;
        endpointUrl.hostname = targetObj.hostname;
        endpointUrl.port = targetObj.port;
        if (newMetadata[key] !== endpointUrl.toString()) {
          newMetadata[key] = endpointUrl.toString();
        }
      } catch (_e) {
        // skip
      }
    }
  }

  return newMetadata;
}

module.exports = {
  escapeHtml,
  getMatchingRedirectUrl,
  validateEnvVars,
  buildCorsOptions,
  buildSessionConfig,
  shouldUseSecureCookies,
  parseList,
  normalizeIssuer,
  correctIssuerMetadata,
};
