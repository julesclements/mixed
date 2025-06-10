// Load environment variables
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Issuer, custom } = require('openid-client');
const https = require('https');
const crypto = require('crypto');
const cors = require('cors'); // Moved to top-level requires

const app = express(); // Define app instance at a higher scope
let oidcClient; // Define oidcClient at a higher scope

// --- Configuration Constants ---
const port = process.env.BFF_PORT || 3001;
const pingIssuerUrl = process.env.PING_ISSUER_URL;
const pingBrowserFacingBaseUrl = process.env.PING_BROWSER_FACING_BASE_URL || ""; // Read new env var
const clientId = process.env.PING_CLIENT_ID;
const clientSecret = process.env.PING_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const bffBaseUrl = process.env.BFF_BASE_URL || `http://localhost:${port}`;
const redirectUri = `${bffBaseUrl}/auth/callback`;
const frontendOrigin = process.env.FRONTEND_ORIGIN;
const frontendRedirectUrl = process.env.FRONTEND_REDIRECT_URL;
const allowSelfSignedCerts = process.env.ALLOW_SELF_SIGNED_CERTS === 'true';

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
        !frontendOrigin || !frontendRedirectUrl || !bffBaseUrl) {
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

    // OIDC metadata correction function (Attempt 4)
    function correctIssuerMetadata(metadata, internalBaseUrlString, browserFacingBaseUrlString) {
      const newMetadata = JSON.parse(JSON.stringify(metadata)); // Deep copy
      let internalUrlObj;
      try {
        internalUrlObj = new URL(internalBaseUrlString);
      } catch (e) {
        console.error(`[OIDC Meta] Invalid PING_ISSUER_URL: ${internalBaseUrlString}. Cannot proceed with metadata correction. Error: ${e.message}`);
        return newMetadata; // Return original metadata if internal URL is invalid
      }

      let browserFacingUrlObj = null;
      if (browserFacingBaseUrlString && browserFacingBaseUrlString.trim() !== "") {
        try {
          browserFacingUrlObj = new URL(browserFacingBaseUrlString);
          console.log('[OIDC Meta] Attempting to use explicit browser-facing base URL:', browserFacingBaseUrlString);
        } catch (e) {
          console.warn(`[OIDC Meta] Invalid PING_BROWSER_FACING_BASE_URL '${browserFacingBaseUrlString}'. It will not be used for browser-facing endpoints. Error: ${e.message}`);
          browserFacingUrlObj = null; // Ensure it's null if parsing failed
        }
      } else {
        console.log('[OIDC Meta] No explicit PING_BROWSER_FACING_BASE_URL provided.');
      }

      const isSplitUrlScenario = browserFacingUrlObj && browserFacingUrlObj.hostname !== internalUrlObj.hostname;
      console.log(`[OIDC Meta] Is split URL scenario? ${isSplitUrlScenario}`);

      // Handle 'issuer' property first
      const originalIssuerValue = newMetadata.issuer;
      if (typeof originalIssuerValue === 'string') {
        try {
          if (isSplitUrlScenario) {
            const issuerUrl = new URL(originalIssuerValue);
            issuerUrl.protocol = browserFacingUrlObj.protocol;
            issuerUrl.hostname = browserFacingUrlObj.hostname;
            issuerUrl.port = browserFacingUrlObj.port;
            newMetadata.issuer = issuerUrl.toString();
            if (originalIssuerValue !== newMetadata.issuer) {
              console.log(`[OIDC Meta] Corrected 'issuer' for split URL: ${originalIssuerValue} -> ${newMetadata.issuer}`);
            }
          } else if (internalUrlObj.hostname !== 'localhost' && originalIssuerValue.includes('://localhost')) {
            const issuerUrl = new URL(originalIssuerValue);
            issuerUrl.protocol = internalUrlObj.protocol;
            issuerUrl.hostname = internalUrlObj.hostname;
            issuerUrl.port = internalUrlObj.port;
            newMetadata.issuer = issuerUrl.toString();
            if (originalIssuerValue !== newMetadata.issuer) {
              console.log(`[OIDC Meta] Corrected 'issuer' from localhost to internal: ${originalIssuerValue} -> ${newMetadata.issuer}`);
            }
          }
        } catch (e) {
          console.warn(`[OIDC Meta] Error correcting 'issuer' value '${originalIssuerValue}': ${e.message}`);
        }
      }


      // Iterate over metadata keys for endpoints
      for (const key of Object.keys(newMetadata)) {
        if (key === 'issuer') {
          continue; // Already handled
        }

        const currentValue = newMetadata[key];
        if (typeof currentValue !== 'string') {
          continue; // Skip non-string values
        }

        const isBrowserFacingEndpoint = ['authorization_endpoint', 'end_session_endpoint'].includes(key);
        let targetObj = null;
        let correctionType = '';

        if (isBrowserFacingEndpoint && browserFacingUrlObj) {
          targetObj = browserFacingUrlObj;
          correctionType = 'BROWSER-FACING';
        } else if (currentValue.includes('://localhost') && internalUrlObj.hostname !== 'localhost') {
          // This condition applies to any localhost URL if it's not a browser-facing one designated for browserFacingUrlObj,
          // OR if browserFacingUrlObj is not available/valid.
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
              console.log(`[OIDC Meta] Corrected ${correctionType} '${key}': ${newMetadata[key]} -> ${endpointUrl.toString()}`);
              newMetadata[key] = endpointUrl.toString();
            }
          } catch (e) {
            console.warn(`[OIDC Meta] Error correcting ${correctionType} '${key}' URL '${currentValue}': ${e.message}. Skipping correction for this key.`);
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

        // --- Express Middleware Setup (Should be configured before routes) ---
        // CORS options
        const corsOptions = {
          origin: frontendOrigin, // Use frontendOrigin for CORS
          credentials: true,
        };
        app.use(cors(corsOptions)); // Enable CORS with options
        app.use(express.json()); // Middleware to parse JSON bodies

        const isProduction = process.env.NODE_ENV === 'production';
        if (isProduction) {
          app.set('trust proxy', 1);
        }
        app.use(session({
          secret: sessionSecret,
          resave: false,
          saveUninitialized: false,
          cookie: {
            secure: isProduction,
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: isProduction ? 'None' : 'Lax'
          }
        }));

        // --- Express Routes ---
        const requestedScopes = ['openid', 'profile', 'email'];

        app.get('/login', (req, res) => {
          const correlationId = req.query.correlationId;
          console.log(`/login route hit. Correlation ID from query: ${correlationId || 'N/A'}`);
          const confirmationPageHtml = `
            <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Confirm Login</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}h1{color:#333}p{color:#555;margin-bottom:20px}.scopes{font-size:0.9em;color:#666;margin-bottom:25px}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer}.button:hover{background-color:#0056b3}</style></head>
            <body><div class="container"><h1>Confirm Login</h1><p>You are about to be redirected to PingFederate to log in.</p>
            <p class="scopes">This application will request access to the following information: <strong>${requestedScopes.join(', ')}</strong>.</p>
            <form action="/initiate-ping-login" method="GET">
              ${correlationId ? `<input type="hidden" name="correlationId" value="${escapeHtml(correlationId)}" />` : ''}
              <button type="submit" class="button">Proceed to PingFederate</button>
            </form>
            </div></body></html>`;
          res.send(confirmationPageHtml);
        });

        app.get('/initiate-ping-login', (req, res, next) => {
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const correlationId = req.query.correlationId;
          console.log(`Initiating OIDC login. Correlation ID from query: ${correlationId || 'N/A'}`);
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
          console.log(`/exchange-code hit. Correlation ID from session: ${correlationId || 'N/A'}`);
          const storedParams = req.session.oidcCallbackParams;
          if (!storedParams) {
            if (req.session.correlationId) delete req.session.correlationId;
            return res.redirect('/login');
          }
          delete req.session.oidcCallbackParams;
          if (req.session.correlationId) delete req.session.correlationId;
          try {
            const tokenSet = await oidcClient.callback(redirectUri, storedParams, { state: storedParams.state });
            req.session.tokenSet = tokenSet;
            req.session.userInfo = tokenSet.claims();
            console.log(`Tokens received and stored in session. Correlation ID: ${correlationId || 'N/A'}`);
            res.redirect(frontendRedirectUrl);
          } catch (err) {
            console.error(`Error in OIDC token exchange. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`, err.stack);
            res.status(500).send(`OIDC token exchange error: ${err.message}. <a href="/login">Retry</a>`);
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

        app.get('/api/user', (req, res) => {
          const correlationIdFromHeader = req.headers['x-correlation-id'];
          console.log(`/api/user hit. Correlation ID from header: ${correlationIdFromHeader || 'N/A'}`);
          if (req.session.userInfo && req.session.tokenSet) {
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

        app.get('/logout', async (req, res, next) => {
          const correlationId = req.session.correlationId || req.query.correlationId;
          console.log(`/logout hit. Correlation ID: ${correlationId || 'N/A'}`);
          if (!oidcClient) return next(new Error('OIDC client not initialized.'));
          const idToken = req.session.tokenSet ? req.session.tokenSet.id_token : undefined;
          req.session.destroy(err => {
            if (err) {
              console.error(`Error destroying session. Correlation ID: ${correlationId || 'N/A'}. Error: ${err.message}`);
              return next(err);
            }
            try {
              const endSessionUrl = oidcClient.endSessionUrl({ id_token_hint: idToken, post_logout_redirect_uri: frontendRedirectUrl });
              console.log(`Redirecting to PingFederate end session URL. Correlation ID: ${correlationId || 'N/A'}. URL: ${endSessionUrl}`);
              res.redirect(endSessionUrl);
            } catch(e) {
              console.warn(`Could not construct end_session_url. Correlation ID: ${correlationId || 'N/A'}. Error: ${e.message}`);
              res.redirect(frontendRedirectUrl);
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
