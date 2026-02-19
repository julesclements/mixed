// Load environment variables
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Issuer, custom } = require('openid-client');
const https = require('https');
const jose = require('jose');
const crypto = require('crypto');
const cors = require('cors'); // Moved to top-level requires
const path = require('path');

const app = express(); // Define app instance at a higher scope
let oidcClient; // Define oidcClient at a higher scope
let JWKS; // Global JWKS set for token validation
const port = process.env.BFF_PORT || 3001;
const pingIssuerUrl = process.env.PING_ISSUER_URL;
const pingBrowserFacingBaseUrl = process.env.PING_BROWSER_FACING_BASE_URL || ""; // Read new env var
const clientId = process.env.PING_CLIENT_ID;
const clientSecret = process.env.PING_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const bffBaseUrl = process.env.BFF_BASE_URL || `http://localhost:${port}`;
const redirectUri = `${bffBaseUrl}/auth/callback`;
const allowedOrigins = process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(o => o.trim()) : [];
const allowedRedirectUrls = process.env.FRONTEND_REDIRECT_URL ? process.env.FRONTEND_REDIRECT_URL.split(',').map(u => u.trim()) : [];
const allowSelfSignedCerts = process.env.ALLOW_SELF_SIGNED_CERTS === 'true';

/**
 * Helper to determine the best redirect URL based on the request's Referer header.
 * Matches the Referer origin against allowedOrigins to find the corresponding allowedRedirectUrls entry.
 */
function getMatchingRedirectUrl(req) {
  const referer = req.headers.referer;
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = refererUrl.origin;
      const index = allowedOrigins.indexOf(refererOrigin);
      if (index !== -1 && allowedRedirectUrls[index]) {
        return allowedRedirectUrls[index];
      }
      // Fallback: search for any allowed redirect URL that is a prefix of the referer
      const matchingUrl = allowedRedirectUrls.find(url => referer.startsWith(url));
      if (matchingUrl) {
        return matchingUrl;
      }
    } catch (e) {
      // Ignore invalid URL
    }
  }
  return allowedRedirectUrls[0];
}

// --- Helper Functions ---
function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return '';
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// --- Main Server Startup Logic with OIDC Discovery ---
async function startServer() {
  return new Promise((resolve, reject) => {
    // Log OIDC base URLs at startup
    console.log(`[OIDC Config] PING_ISSUER_URL (for BFF server-to-server calls): ${pingIssuerUrl}`);
    console.log(`[OIDC Config] PING_BROWSER_FACING_BASE_URL (for browser redirects, optional): ${pingBrowserFacingBaseUrl || 'Not set, will use PING_ISSUER_URL or its localhost-corrected version'}`);

    if (!pingIssuerUrl || !clientId || !clientSecret || !sessionSecret ||
        allowedOrigins.length === 0 || allowedRedirectUrls.length === 0 || !bffBaseUrl) {
      const errorMsg = 'Missing critical environment variables. Please check your .env file. Ensure PING_ISSUER_URL, PING_CLIENT_ID, PING_CLIENT_SECRET, SESSION_SECRET, FRONTEND_ORIGIN, FRONTEND_REDIRECT_URL, and BFF_BASE_URL are set.';
      console.error(errorMsg);
      return reject(new Error(errorMsg)); // Reject promise if config is missing
    }

    let customAgent;
    if (allowSelfSignedCerts) {
      console.warn('DEVELOPMENT MODE: Allowing self-signed SSL certificates for OIDC provider. DO NOT USE IN PRODUCTION.');
      customAgent = new https.Agent({ rejectUnauthorized: false });
      custom.setHttpOptionsDefaults({
        agent: customAgent,
        timeout: 5000,
      });
    }

    // Store original http_options for Issuer to restore later
    const originalHttpOptions = Issuer[custom.http_options];
    if (allowSelfSignedCerts && customAgent) {
      Issuer[custom.http_options] = (options) => ({ ...options, agent: customAgent });
    }

    // OIDC metadata correction function (Attempt 5 - Simplified Issuer Logic)
    function correctIssuerMetadata(metadata, internalBaseUrlString, browserFacingBaseUrlString) {
      const newMetadata = JSON.parse(JSON.stringify(metadata)); // Deep copy
      let internalUrlObj;
      try {
        internalUrlObj = new URL(internalBaseUrlString);
      } catch (e) {
        console.error(`[OIDC Meta] Invalid PING_ISSUER_URL: ${internalBaseUrlString}. Cannot proceed. Error: ${e.message}`);
        return metadata; // Return original metadata if internal URL is critically invalid
      }

      let browserFacingUrlObj = null;
      if (browserFacingBaseUrlString && browserFacingBaseUrlString.trim() !== "") {
        try {
          browserFacingUrlObj = new URL(browserFacingBaseUrlString);
          console.log('[OIDC Meta] Will use explicit browser-facing base URL for applicable parts:', browserFacingBaseUrlString);
        } catch (e) {
          console.warn(`[OIDC Meta] Invalid PING_BROWSER_FACING_BASE_URL '${browserFacingBaseUrlString}'. It will not be used. Error: ${e.message}`);
          browserFacingUrlObj = null;
        }
      } else {
        console.log('[OIDC Meta] No PING_BROWSER_FACING_BASE_URL provided.');
      }

      const isSplitUrlScenario = browserFacingUrlObj && browserFacingUrlObj.hostname !== internalUrlObj.hostname;
      console.log(`[OIDC Meta] Is split URL scenario? ${isSplitUrlScenario}`);

      // --- Refined issuer property handling (Attempt 5) ---
      const originalDiscoveredIssuer = newMetadata.issuer; // For logging and as a base
      let finalIssuerValue = originalDiscoveredIssuer; // Default to original

      if (typeof originalDiscoveredIssuer === 'string') { // Ensure issuer is a string before trying to parse/compare
        try {
            if (isSplitUrlScenario) {
                // Prefer the exact browser-facing URL string for 'issuer' in split URL scenarios.
                finalIssuerValue = browserFacingBaseUrlString;
            } else {
                const discoveredIssuerUrl = new URL(originalDiscoveredIssuer);
                if (internalUrlObj.hostname === 'localhost' && discoveredIssuerUrl.hostname === 'localhost') {
                    // Both PING_ISSUER_URL and discovered issuer are localhost. Use PING_ISSUER_URL string directly.
                    finalIssuerValue = internalBaseUrlString;
                } else if (internalUrlObj.hostname !== 'localhost' && discoveredIssuerUrl.hostname === 'localhost') {
                    // PING_ISSUER_URL is external, but discovered is localhost. Reconstruct with PING_ISSUER_URL's base.
                    discoveredIssuerUrl.protocol = internalUrlObj.protocol;
                    discoveredIssuerUrl.hostname = internalUrlObj.hostname;
                    discoveredIssuerUrl.port = internalUrlObj.port;
                    // Path is kept from originalDiscoveredIssuer
                    finalIssuerValue = discoveredIssuerUrl.toString();
                }
                // Else: Discovered issuer is not localhost OR (internal is external and discovered is external and they match or differ - preserve original)
                // This also covers cases where PING_ISSUER_URL is external and matches the discovered external URL.
            }

            // Normalize: remove trailing slash if it's the only char in path (e.g. "http://host/" -> "http://host")
            // but keep "http://host/path/" as is.
            if (finalIssuerValue.endsWith('/') && new URL(finalIssuerValue).pathname === '/') {
                finalIssuerValue = finalIssuerValue.slice(0, -1);
            }

        } catch (e) {
            console.warn(`[OIDC Meta] Error processing 'issuer' value '${originalDiscoveredIssuer}': ${e.message}. Original will be used.`);
            finalIssuerValue = originalDiscoveredIssuer; // Fallback to original on error
        }

        if (newMetadata.issuer !== finalIssuerValue) {
            console.log(`[OIDC Meta] Set 'issuer': ${newMetadata.issuer} -> ${finalIssuerValue}`);
            newMetadata.issuer = finalIssuerValue;
        }
      } else {
        console.warn(`[OIDC Meta] Original 'issuer' in metadata is not a string: ${originalDiscoveredIssuer}. Skipping 'issuer' correction.`);
      }

      // --- Endpoint Handling (same as Attempt 4) ---
      for (const key of Object.keys(newMetadata)) {
        if (key === 'issuer') {
          continue; // Already handled
        }
        const currentValue = newMetadata[key];
        if (typeof currentValue !== 'string') {
          continue;
        }

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
            // Path and query params are preserved from 'currentValue' by default with new URL() and selective part setting.
            if (newMetadata[key] !== endpointUrl.toString()) {
              console.log(`[OIDC Meta] Corrected ${correctionType} '${key}': ${newMetadata[key]} -> ${endpointUrl.toString()}`);
              newMetadata[key] = endpointUrl.toString();
            }
          } catch (e) {
            console.warn(`[OIDC Meta] Error correcting ${correctionType} '${key}' URL '${currentValue}': ${e.message}. Skipping.`);
          }
        }
      }
      console.log('[OIDC Meta] Finished metadata correction. Resulting metadata:', JSON.stringify(newMetadata, null, 2));
      return newMetadata;
    }

    Issuer.discover(pingIssuerUrl)
      .then(originalIssuer => { // Renamed to originalIssuer
        if (allowSelfSignedCerts) {
          Issuer[custom.http_options] = originalHttpOptions; // Restore after discovery
        }

        console.log('[OIDC Setup] Original issuer URL from discovery:', originalIssuer.issuer);
        if (originalIssuer.metadata && originalIssuer.metadata.authorization_endpoint) {
            console.log('[OIDC Setup] Original authorization_endpoint from discovery:', originalIssuer.metadata.authorization_endpoint);
        } else {
            console.log('[OIDC Setup] Original authorization_endpoint from discovery: Not found in metadata');
        }

        // Correct the issuer metadata using the refined strategy with both base URLs
        const correctedMetadata = correctIssuerMetadata(originalIssuer.metadata, pingIssuerUrl, pingBrowserFacingBaseUrl);
        const correctedIssuer = new Issuer(correctedMetadata); // Create new Issuer with corrected metadata

        console.log('[OIDC Setup] Corrected issuer URL via new Issuer instance:', correctedIssuer.issuer);
        if (correctedIssuer.metadata && correctedIssuer.metadata.authorization_endpoint) {
            console.log('[OIDC Setup] Corrected authorization_endpoint via new Issuer instance:', correctedIssuer.metadata.authorization_endpoint);
        } else {
            console.log('[OIDC Setup] Corrected authorization_endpoint via new Issuer instance: Not found in metadata');
        }
        console.log(`Using issuer for OIDC client: ${correctedIssuer.issuer}`);

        oidcClient = new correctedIssuer.Client({ // Use correctedIssuer
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uris: [redirectUri],
          response_types: ['code'],
        });

        // Initialize JWKS set for /api/check endpoint (caching and rotation handled by jose)
        const jwksUri = oidcClient.issuer.metadata.jwks_uri;
        if (jwksUri) {
          const jwksOptions = {};
          if (allowSelfSignedCerts && customAgent) {
            jwksOptions.agent = customAgent;
          }
          JWKS = jose.createRemoteJWKSet(new URL(jwksUri), jwksOptions);
          console.log(`[OIDC Setup] Initialized JWKS set for token validation: ${jwksUri}`);
        } else {
          console.warn('[OIDC Setup] JWKS URI not found in issuer metadata. /api/check will not work.');
        }

        // --- Express Middleware Setup (Should be configured before routes) ---
        // CORS options - critical for cross-site requests
        const corsOptions = {
          origin: function (origin, callback) {
            // Allow requests with no origin (like mobile apps or curl requests)
            if (!origin || allowedOrigins.includes(origin)) {
              callback(null, true);
            } else {
              console.warn(`[CORS] Origin ${origin} not allowed by configuration.`);
              callback(new Error('Not allowed by CORS'));
            }
          },
          credentials: true, // Allow cookies to be sent
          methods: ['GET', 'POST', 'OPTIONS'],
          allowedHeaders: ['Content-Type', 'X-Correlation-ID'],
          exposedHeaders: ['Set-Cookie'], // Expose Set-Cookie header to client
          maxAge: 86400, // 24 hours
        };
        app.use(cors(corsOptions)); // Enable CORS with options
        app.use(express.json()); // Middleware to parse JSON bodies

        const isProduction = process.env.NODE_ENV === 'production';
        const isHttps = bffBaseUrl.startsWith('https://');
        const useSecureCookies = isProduction || isHttps;

        if (useSecureCookies) {
          app.set('trust proxy', 1);
          console.log('[Session] Trust proxy enabled and secure cookies will be used (HTTPS or production).');
        }

        app.use(session({
          secret: sessionSecret,
          resave: false,
          saveUninitialized: true, // Changed to true to create session before redirect
          cookie: {
            secure: useSecureCookies,
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: useSecureCookies ? 'None' : 'Lax',
            // Cross-site scenarios require SameSite=None; Secure
            // Note: Browsers will block third-party cookies unless explicitly allowed
          }
        }));

        // Favicon serving
        app.get('/favicon.ico', (req, res) => {
          res.sendFile(path.join(__dirname, 'favicon.ico'));
        });

        // --- Express Routes ---
        const requestedScopes = ['openid', 'profile', 'email'];

        app.get('/', (req, res) => res.json({ status: 'up' }));

        app.get('/login', (req, res) => {
          const correlationId = req.query.correlationId;
          const returnTo = req.query.returnTo || getMatchingRedirectUrl(req);
          console.log(`/login route hit. Correlation ID from query: ${correlationId || 'N/A'}, returnTo: ${returnTo || 'N/A'}`);
          const confirmationPageHtml = `
            <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Confirm Login</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}h1{color:#333}p{color:#555;margin-bottom:20px}.scopes{font-size:0.9em;color:#666;margin-bottom:25px}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer}.button:hover{background-color:#0056b3}</style></head>
            <body><div class="container"><h1>Confirm Login</h1><p>You are about to be redirected to PingFederate to log in.</p>
            <p class="scopes">This application will request access to the following information: <strong>${requestedScopes.join(', ')}</strong>.</p>
            <form action="/initiate-ping-login" method="GET">
              ${correlationId ? `<input type="hidden" name="correlationId" value="${escapeHtml(correlationId)}" />` : ''}
              ${returnTo ? `<input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}" />` : ''}
              <button type="submit" class="button">Proceed to PingFederate</button>
            </form>
            </div></body></html>`;
          res.send(confirmationPageHtml);
        });

        app.get('/initiate-ping-login', (req, res, next) => {
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const correlationId = req.query.correlationId;
          const returnTo = req.query.returnTo || getMatchingRedirectUrl(req);
          console.log(`Initiating OIDC login. Correlation ID from query: ${correlationId || 'N/A'}, returnTo: ${returnTo || 'N/A'}`);

          if (returnTo) {
            if (allowedRedirectUrls.includes(returnTo)) {
              req.session.returnTo = returnTo;
              console.log(`Stored validated returnTo in session: ${returnTo}`);
            } else {
              console.warn(`[Login] Provided returnTo URL '${returnTo}' is not in the allowlist.`);
            }
          }

          const state = crypto.randomBytes(16).toString('hex');
          req.session.oidcState = state;
          if (correlationId) {
            req.session.correlationId = correlationId;
            console.log(`Stored correlationId in session: ${correlationId}`);
          }
          const authUrl = oidcClient.authorizationUrl({ scope: requestedScopes.join(' '), state });
          console.log(`Redirecting to PingFederate. Correlation ID: ${correlationId || 'N/A'}. Auth URL: ${authUrl}`);
          res.redirect(authUrl);
        });

        app.get('/auth/callback', async (req, res, next) => {
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const correlationId = req.session.correlationId;
          console.log(`/auth/callback hit. Correlation ID from session: ${correlationId || 'N/A'}`);
          try {
            const params = oidcClient.callbackParams(req);
            if (!req.session.oidcState || params.state !== req.session.oidcState) {
              if (req.session.oidcState) delete req.session.oidcState;
              if (req.session.correlationId) delete req.session.correlationId;
              return next(new Error('State mismatch or session state missing.'));
            }
            delete req.session.oidcState;

            if (params.error) {
              const errorDescription = params.error_description || 'No description provided.';
              const errorCode = params.error;
              console.error(`OIDC Error received in callback. Error: ${errorCode}. Description: ${errorDescription}. Correlation ID: ${correlationId || 'N/A'}`);

              const errorPageHtml = `
                <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Authentication Error</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center;max-width: 600px;}h1{color:#d9534f}p{color:#555;margin-bottom:10px}.diagnostic-info{background-color:#f8d7da;color:#721c24;border:1px solid #f5c6cb;padding:15px;border-radius:4px;margin-bottom:20px;text-align:left;word-break:break-all;font-family:monospace}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer;display:inline-block}.button:hover{background-color:#0056b3}</style></head>
                <body><div class="container"><h1>Authentication Error</h1>
                <p>An error occurred during authentication with PingFederate.</p>
                <div class="diagnostic-info">
                  <strong>Error:</strong> ${escapeHtml(errorCode)}<br>
                  <strong>Description:</strong> ${escapeHtml(errorDescription)}<br>
                  ${correlationId ? `<strong>Correlation ID:</strong> ${escapeHtml(correlationId)}` : ''}
                </div>
                <p>Please check your configuration or contact support if the issue persists.</p>
                <a href="/login${correlationId ? `?correlationId=${escapeHtml(correlationId)}` : ''}" class="button">Return to Login</a>
                </div></body></html>`;

              if (req.session.correlationId) delete req.session.correlationId;
              return res.status(400).send(errorPageHtml);
            }

            req.session.oidcCallbackParams = params;
            const authCode = params.code;
            const confirmationPageHtml = `
              <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Confirm Authorization Code</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}h1{color:#333}p{color:#555;margin-bottom:10px}.code-display{background-color:#e9e9e9;padding:10px;border-radius:4px;margin-bottom:20px;word-break:break-all;font-family:monospace}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer}.button:hover{background-color:#0056b3}</style></head>
              <body><div class="container"><h1>Authorization Code Received</h1><p>Auth code:</p><div class="code-display">${escapeHtml(authCode)}</div>
              <p>Click to exchange code for tokens and proceed.</p><form action="/exchange-code" method="GET"><button type="submit" class="button">Exchange Code & Proceed</button></form>
              </div></body></html>`;
            res.send(confirmationPageHtml);
          } catch (err) {
            if (req.session && req.session.oidcState) delete req.session.oidcState;
            if (req.session && req.session.correlationId) delete req.session.correlationId;
            console.error(`Error in /auth/callback. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`);
            next(err);
          }
        });

        app.get('/exchange-code', async (req, res, next) => {
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const correlationId = req.session.correlationId;
          console.log(`/exchange-code (GET) hit. Correlation ID from session: ${correlationId || 'N/A'}`);
          const storedParams = req.session.oidcCallbackParams;
          if (!storedParams) {
            if (req.session.correlationId) delete req.session.correlationId;
            return res.redirect('/login');
          }
          delete req.session.oidcCallbackParams;
          try {
            const tokenSet = await oidcClient.callback(redirectUri, storedParams, { state: storedParams.state });
            req.session.tokenSet = tokenSet;
            req.session.userInfo = tokenSet.claims();
            console.log(`Tokens received and stored in session. Correlation ID: ${correlationId || 'N/A'}. Session ID: ${req.sessionID}`);

            req.session.save((err) => {
              if (err) {
                console.error(`Error saving session during exchange-code. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`);
                return next(err);
              }
              // Log session cookie details for debugging cross-site issues
              console.log(`Session saved successfully. Setting session cookie with secure=${useSecureCookies}, sameSite=${'None'}`);
              
              const frontendUrl = req.session.returnTo || getMatchingRedirectUrl(req);
              const redirectUrl = new URL(frontendUrl);
              redirectUrl.searchParams.set('login_status', 'success');
              if (correlationId) {
                redirectUrl.searchParams.set('correlationId', correlationId);
              }
              // Also pass session ID for debugging if needed
              redirectUrl.searchParams.set('sessionId', req.sessionID);
              console.log(`Session saved successfully after token exchange. Redirecting to frontend. Correlation ID: ${correlationId || 'N/A'}. Frontend URL: ${redirectUrl.toString()}`);
              res.redirect(redirectUrl.toString());
            });
          } catch (err) {
            console.error(`Error in OIDC token exchange. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`, err.stack);

            const frontendUrl = req.session.returnTo || getMatchingRedirectUrl(req);
            const redirectUrl = new URL(frontendUrl);
            redirectUrl.searchParams.set('exchange_error', err.message);
            if (correlationId) {
                redirectUrl.searchParams.set('correlationId', correlationId);
            }
            console.log(`Redirecting to frontend with exchange error. URL: ${redirectUrl.toString()}`);
            res.redirect(redirectUrl.toString());
          }
        });

        // New POST endpoint for token exchange from SPA
        // SPA sends authorization code and code_verifier, BFF keeps access token server-side
        app.post('/exchange-code', async (req, res, next) => {
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          
          const { code, code_verifier, client_id } = req.body;
          const correlationIdFromHeader = req.headers['x-correlation-id'];
          
          console.log(`/exchange-code (POST) hit. Client ID: ${client_id}. Correlation ID: ${correlationIdFromHeader || 'N/A'}`);
          
          if (!code || !code_verifier) {
            return res.status(400).json({ error: 'Missing required fields: code and code_verifier' });
          }

          try {
            // Build the redirect URI for the specific client
            const redirectUri = `${bffBaseUrl}/callback`;
            
            // Exchange the code for tokens using the BFF's OIDC client
            const tokenSet = await oidcClient.callback(redirectUri, { code }, { code_verifier });
            
            // Store tokens in session (access token stays server-side)
            req.session.tokenSet = tokenSet;
            req.session.userInfo = tokenSet.claims();
            req.session.clientId = client_id; // Track which client authenticated
            
            console.log(`Tokens received and stored in session for SPA. Client: ${client_id}. Session ID: ${req.sessionID}. Correlation ID: ${correlationIdFromHeader || 'N/A'}`);

            req.session.save((err) => {
              if (err) {
                console.error(`Error saving session during POST exchange-code. Correlation ID: ${correlationIdFromHeader || 'N/A'}. Error: ${err.message}`);
                return next(err);
              }

              // Return only the ID token to the SPA (access token remains server-side)
              const response = {
                id_token: tokenSet.id_token,
                claims: tokenSet.claims(),
                session_id: req.sessionID, // For tracking purposes
              };
              
              console.log(`Session saved. Returning ID token to SPA. Session ID: ${req.sessionID}. Correlation ID: ${correlationIdFromHeader || 'N/A'}`);
              res.json(response);
            });
          } catch (err) {
            console.error(`Error in POST token exchange. Correlation ID: ${correlationIdFromHeader || 'N/A'}. Error: ${err.message}`, err.stack);
            res.status(400).json({ 
              error: 'Token exchange failed',
              details: err.message 
            });
          }
        });

        app.post('/api/introspect-token', async (req, res, next) => {
          const correlationIdFromHeader = req.headers['x-correlation-id'];
          console.log(`/api/introspect-token hit. Correlation ID from header: ${correlationIdFromHeader || 'N/A'}`);
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          if (!req.session.tokenSet) return res.status(401).json({ error: 'User not authenticated in BFF.' });
          const tokenToIntrospect = req.body.token_to_introspect;
          if (!tokenToIntrospect || typeof tokenToIntrospect !== 'string') {
            return res.status(400).json({ error: 'token_to_introspect is required and must be a string.' });
          }
          try {
            let httpOptions;
            if (correlationIdFromHeader) {
              httpOptions = { headers: { 'X-Correlation-ID': correlationIdFromHeader } };
              console.log(`Forwarding X-Correlation-ID ${correlationIdFromHeader} to PingFederate introspection endpoint.`);
            } else {
              console.log('No X-Correlation-ID to forward for introspection.');
            }
            const introspectionResult = await oidcClient.introspect(tokenToIntrospect, 'access_token', httpOptions ? { httpOptions } : undefined);
            res.json(introspectionResult);
          } catch (err) {
            console.error(`Error during token introspection. Correlation ID: ${correlationIdFromHeader || 'N/A'}. Error: ${err.message}`, err.stack);
            let errorResponse = { error: 'Token introspection failed.', message: err.message };
            if (err.data) errorResponse.details = err.data;
            res.status(err.statusCode || 500).json(errorResponse);
          }
        });

        app.get('/api/check', async (req, res) => {
          const authHeader = req.headers.authorization;
          const jwksUri = oidcClient?.issuer?.metadata?.jwks_uri;

          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(402).json({
              error: 'Missing or invalid Authorization header',
              jwks_endpoint: jwksUri || 'unknown'
            });
          }

          const token = authHeader.split(' ')[1];

          if (!JWKS) {
            return res.status(500).json({ error: 'OIDC JWKS set not initialized' });
          }

          try {
            const { payload } = await jose.jwtVerify(token, JWKS, {
              issuer: oidcClient.issuer.metadata.issuer,
            });

            res.status(200).json({
              status: 'valid',
              jwks_endpoint: jwksUri,
              payload
            });
          } catch (err) {
            console.error('Token validation failed:', err.message);
            res.status(402).json({
              status: 'invalid',
              error: err.message,
              jwks_endpoint: jwksUri
            });
          }
        });

        app.get('/api/user', (req, res) => {
          const correlationIdFromHeader = req.headers['x-correlation-id'];
          const hasUserInfo = !!req.session.userInfo;
          const hasTokenSet = !!req.session.tokenSet;

          console.log(`/api/user hit. Correlation ID from header: ${correlationIdFromHeader || 'N/A'}. Session ID: ${req.sessionID}. Has userInfo: ${hasUserInfo}, Has tokenSet: ${hasTokenSet}`);

          if (hasUserInfo && hasTokenSet) {
            res.json({
              message: "User is authenticated. Token details below.",
              id_token: req.session.tokenSet.id_token,
              access_token: req.session.tokenSet.access_token,
              claims: req.session.userInfo
            });
          } else {
            res.status(401).json({ error: 'User not authenticated or session incomplete.' });
          }
        });

        // New endpoint for cross-site token validation using query parameter
        // This is necessary because browsers block third-party cookies in cross-site scenarios
        app.get('/api/verify-login', (req, res) => {
          const sessionIdFromQuery = req.query.sessionId;
          const correlationIdFromHeader = req.headers['x-correlation-id'];
          
          console.log(`/api/verify-login hit. Session ID from query: ${sessionIdFromQuery || 'N/A'}. Current Session ID: ${req.sessionID}. Correlation ID: ${correlationIdFromHeader || 'N/A'}`);
          
          // Check if current session has user info (when cookies are properly sent)
          if (req.session.userInfo && req.session.tokenSet) {
            console.log(`/api/verify-login: User authenticated via session cookie`);
            return res.json({
              authenticated: true,
              message: "User is authenticated via session cookie.",
              id_token: req.session.tokenSet.id_token,
              access_token: req.session.tokenSet.access_token,
              claims: req.session.userInfo
            });
          }
          
          // If sessionId is provided as query param, this is a cross-site scenario
          // In production, you should validate this against your session store
          if (sessionIdFromQuery) {
            console.log(`/api/verify-login: Checking cross-site session validity for sessionId: ${sessionIdFromQuery}`);
            // Return an error indicating that cross-site session validation requires additional setup
            return res.status(401).json({ 
              error: 'Session not found. Cross-site cookies are blocked by browser. Please ensure third-party cookies are enabled for this domain.',
              hint: 'This is a known limitation of cross-site OIDC flows. Consider using a same-origin proxy or redirect-based pattern.'
            });
          }
          
          res.status(401).json({ error: 'User not authenticated.' });
        });

        app.get('/logout', async (req, res, next) => {
          const correlationId = req.session.correlationId || req.query.correlationId;
          const defaultRedirect = getMatchingRedirectUrl(req);
          const returnTo = req.query.returnTo || req.session.returnTo || defaultRedirect;
          console.log(`/logout hit. Correlation ID: ${correlationId || 'N/A'}, returnTo: ${returnTo}`);

          // Validate returnTo if it came from query
          const finalReturnTo = allowedRedirectUrls.includes(returnTo) ? returnTo : defaultRedirect;

          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const idToken = req.session.tokenSet ? req.session.tokenSet.id_token : undefined;
          req.session.destroy(err => {
            if (err) {
              console.error(`Error destroying session. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`);
              return next(err);
            }
            try {
              const endSessionUrl = oidcClient.endSessionUrl({ id_token_hint: idToken, post_logout_redirect_uri: finalReturnTo });
              console.log(`Redirecting to PingFederate end session URL. Correlation ID: ${correlationId || 'N/A'}. URL: ${endSessionUrl}`);
              res.redirect(endSessionUrl);
            } catch(e) {
              console.warn(`Could not construct end_session_url. Correlation ID: ${correlationId || 'N/A'}. Error: ${e.message}`);
              res.redirect(finalReturnTo);
            }
          });
        });

        app.use((err, req, res, next) => {
          const correlationId = req.session && req.session.correlationId ? req.session.correlationId : (req.query && req.query.correlationId ? req.query.correlationId : (req.headers && req.headers['x-correlation-id'] ? req.headers['x-correlation-id'] : 'N/A'));
          console.error(`Generic error handler. Correlation ID: ${correlationId}. Error: ${err.message}`, err.stack);
          res.status(500).send('Something broke on the server! Check BFF logs.');
        });

        const serverInstance = app.listen(port, () => {
          console.log(`BFF server listening at http://localhost:${port}`);
          if (!oidcClient) console.warn('OIDC client was not initialized by server start.');
          resolve(serverInstance); // Resolve with server instance
        });
        serverInstance.on('error', (err) => {
          console.error('Failed to start Express server:', err);
          reject(err);
        });
      })
      .catch(err => {
        if (allowSelfSignedCerts) {
          Issuer[custom.http_options] = originalHttpOptions; // Restore on discovery error
        }
        console.error('Failed to discover OIDC issuer or other critical setup error:', err.message);
        if ((err.message.includes('self-signed certificate') || err.message.includes('unable to verify the first certificate'))) {
            if (allowSelfSignedCerts) {
                console.error('Self-signed cert error despite ALLOW_SELF_SIGNED_CERTS=true. Check http_options/agent or PingFederate TLS.');
            } else {
                console.error('Self-signed cert error. For dev with self-signed cert on PingFederate, set ALLOW_SELF_SIGNED_CERTS=true in .env.');
            }
        }
        reject(err); // Reject the promise
      });
  });
}

// --- Retry Logic for Server Initialization ---
async function initializeWithRetries(maxRetries = 60, retryIntervalMs = 10000) { // Default: 10 minutes of retries
  for (let i = 0; i < maxRetries; i++) {
    console.log(`Attempt ${i + 1} of ${maxRetries} to start BFF server...`);
    try {
      await startServer();
      console.log('BFF server started successfully.');
      return; // Success
    } catch (error) {
      console.error(`Startup attempt ${i + 1} failed: ${error.message}`);
      if (i === maxRetries - 1) {
        console.error('Max retries reached. BFF could not start. Exiting.');
        process.exit(1);
      }
      console.log(`Retrying in ${retryIntervalMs / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, retryIntervalMs));
    }
  }
}

// --- Start the Server ---
initializeWithRetries();
