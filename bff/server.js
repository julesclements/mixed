// Load environment variables
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Issuer, custom } = require('openid-client'); // Ensure 'custom' is imported
const https = require('https'); // Required for custom agent

const app = express();
const port = process.env.BFF_PORT || 3001;

// --- Configuration ---
const pingIssuerUrl = process.env.PING_ISSUER_URL;
const clientId = process.env.PING_CLIENT_ID;
const clientSecret = process.env.PING_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const bffBaseUrl = process.env.BFF_BASE_URL || `http://localhost:${port}`;
const redirectUri = `${bffBaseUrl}/auth/callback`;
const frontendUrl = process.env.FRONTEND_URL;
const allowSelfSignedCerts = process.env.ALLOW_SELF_SIGNED_CERTS === 'true';

if (!pingIssuerUrl || !clientId || !clientSecret || !sessionSecret || !frontendUrl || !bffBaseUrl) {
  console.error('Missing critical environment variables. Please check your .env file. Ensure PING_ISSUER_URL, PING_CLIENT_ID, PING_CLIENT_SECRET, SESSION_SECRET, FRONTEND_URL, and BFF_BASE_URL are set.');
  process.exit(1);
}

// --- OIDC HTTP Options Customization (for self-signed certs in DEV) ---
let customAgent;
if (allowSelfSignedCerts) {
  console.warn('DEVELOPMENT MODE: Allowing self-signed SSL certificates for OIDC provider. DO NOT USE IN PRODUCTION.');
  customAgent = new https.Agent({ rejectUnauthorized: false });

  // Set defaults for all openid-client requests, including those made by the client instance later
  custom.setHttpOptionsDefaults({
    agent: customAgent,
    timeout: 5000, // Example: ensure timeout is explicitly set or keep default
    // rejectUnauthorized: false is implicitly handled by the agent
  });
}

// --- Express Session Setup ---
const cors = require('cors'); // Require CORS middleware

// CORS options
const corsOptions = {
  origin: frontendUrl, // Dynamically set from process.env.FRONTEND_URL
  credentials: true,    // Allow cookies to be sent across origins
};
app.use(cors(corsOptions)); // Enable CORS with options
app.use(express.json()); // Middleware to parse JSON bodies

const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) {
  app.set('trust proxy', 1); // Trust first proxy if using a reverse proxy in production
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction, // True if NODE_ENV is 'production', false otherwise
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: isProduction ? 'None' : 'Lax' // 'None' for production (requires Secure), 'Lax' for local dev
  }
}));

// --- OIDC Client Setup ---
let oidcClient;

// Store original http_options if any, to restore later.
const originalHttpOptions = Issuer[custom.http_options];

if (allowSelfSignedCerts && customAgent) {
  // Temporarily override http_options for Issuer for the .discover() call
  // This is a more direct intervention for the discovery step if global defaults are not picked up.
  Issuer[custom.http_options] = (options) => ({
    ...options,
    agent: customAgent, // Ensure discovery uses the custom agent
  });
}

Issuer.discover(pingIssuerUrl)
  .then(issuer => {
    if (allowSelfSignedCerts) {
      // Restore original http_options on Issuer after discover has used the override
      Issuer[custom.http_options] = originalHttpOptions;
    }
    console.log(`Discovered issuer ${issuer.issuer}`);

    let clientOptions = {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      response_types: ['code'],
    };

    // The custom.setHttpOptionsDefaults should ensure that the oidcClient
    // instance also uses the customAgent for its requests (token, userinfo, etc.)
    // because it modifies the default request options used by openid-client's internal request utility.
    // If it didn't, we would need to pass agent options here too:
    // if (allowSelfSignedCerts && customAgent) {
    //   clientOptions[custom.http_options] = (options) => ({ ...options, agent: customAgent });
    // }

    oidcClient = new issuer.Client(clientOptions);

    // --- Express Routes ---

    const requestedScopes = ['openid', 'profile', 'email']; // Define scopes centrally

    // Login route: Serves a confirmation page
    app.get('/login', (req, res) => {
      const confirmationPageHtml = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Confirm Login</title>
          <style>
            body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f4f4f4; color: #333; }
            .container { background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #333; }
            p { color: #555; margin-bottom: 20px; }
            .scopes { font-size: 0.9em; color: #666; margin-bottom:25px; }
            .button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; text-decoration: none; font-size: 16px; cursor: pointer; }
            .button:hover { background-color: #0056b3; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Confirm Login</h1>
            <p>You are about to be redirected to PingFederate to log in.</p>
            <p class="scopes">This application will request access to the following information: <strong>${requestedScopes.join(', ')}</strong>.</p>
            <form action="/initiate-ping-login" method="GET">
              <button type="submit" class="button">Proceed to PingFederate</button>
            </form>
          </div>
        </body>
        </html>
      `;
      res.send(confirmationPageHtml);
    });

    // New route to actually initiate OIDC login and redirect to PingFederate
    app.get('/initiate-ping-login', (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /initiate-ping-login');
        return next(new Error('OIDC client not initialized. Please check server logs.'));
      }
      // Add a state parameter for CSRF protection
      const state = require('crypto').randomBytes(16).toString('hex');
      req.session.oidcState = state; // Store state in session to verify on callback

      const authUrl = oidcClient.authorizationUrl({
        scope: requestedScopes.join(' '), // Use the centrally defined scopes, space-separated
        state: state,
      });
      console.log(`Redirecting to PingFederate for login via /initiate-ping-login: ${authUrl}`);
      res.redirect(authUrl);
    });

    // Callback route: Handles redirect from PingFederate, displays code, and asks for confirmation to exchange
    app.get('/auth/callback', async (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /auth/callback');
        return next(new Error('OIDC client not initialized. Please check server logs.'));
      }
      try {
        const params = oidcClient.callbackParams(req);

        // Verify state parameter
        if (!req.session.oidcState || params.state !== req.session.oidcState) {
            console.error('OIDC state mismatch or session state missing. Possible CSRF attack or session issue.');
            // It's important to clear the potentially compromised oidcState from session if it exists
            if (req.session.oidcState) delete req.session.oidcState;
            return next(new Error('State mismatch or session state missing. Possible CSRF attack or session issue.'));
        }
        delete req.session.oidcState; // State validated, remove from session

        // Store OIDC callback parameters in session to be used in the next step
        req.session.oidcCallbackParams = params;
        console.log('OIDC callback parameters stored in session.');

        const authCode = params.code;
        const confirmationPageHtml = `
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Confirm Authorization Code</title>
            <style>
              body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f4f4f4; color: #333; }
              .container { background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); text-align: center; }
              h1 { color: #333; }
              p { color: #555; margin-bottom: 10px; }
              .code-display { background-color: #e9e9e9; padding: 10px; border-radius: 4px; margin-bottom: 20px; word-break: break-all; font-family: monospace; }
              .button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; text-decoration: none; font-size: 16px; cursor: pointer; }
              .button:hover { background-color: #0056b3; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Authorization Code Received</h1>
              <p>The following authorization code was received from PingFederate:</p>
              <div class="code-display">${authCode}</div>
              <p>Click below to exchange this code for tokens and proceed.</p>
              <form action="/exchange-code" method="GET">
                <button type="submit" class="button">Exchange Code & Proceed</button>
              </form>
            </div>
          </body>
          </html>
        `;
        res.send(confirmationPageHtml);

      } catch (err) {
        console.error('Error in OIDC callback (before token exchange):', err.message, err.stack);
        // Ensure oidcState is cleared on error too, if it exists and wasn't cleared yet
        if (req.session && req.session.oidcState) delete req.session.oidcState;
        res.status(500).send(`OIDC callback error: ${err.message}. Check BFF logs.`);
      }
    });

    // New route to perform token exchange
    app.get('/exchange-code', async (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /exchange-code');
        return next(new Error('OIDC client not initialized.'));
      }
      const storedParams = req.session.oidcCallbackParams;
      if (!storedParams) {
        console.log('No OIDC callback parameters found in session for /exchange-code. Redirecting to login.');
        return res.redirect('/login'); // Or an error page
      }
      delete req.session.oidcCallbackParams; // Clear after retrieval, before any async operation

      try {
        // The redirectUri here must match the one used when initiating login
        // and registered in PingFederate.
        // 'state' from storedParams is used by oidcClient.callback for final validation if it needs to.
        const tokenSet = await oidcClient.callback(redirectUri, storedParams, {
          state: storedParams.state
          // If a nonce was used in authorizationUrl, it should be stored in session
          // and passed here, e.g., { state: storedParams.state, nonce: req.session.nonce }
          // delete req.session.nonce; // then delete it
        });

        req.session.tokenSet = tokenSet;
        req.session.userInfo = tokenSet.claims();
        console.log('Tokens received via /exchange-code and stored in session.');
        res.redirect(frontendUrl);
      } catch (err) {
        console.error('Error in OIDC token exchange (/exchange-code):', err.message, err.stack);
        // Optionally, inform the user more gracefully
        res.status(500).send(`OIDC token exchange error: ${err.message}. Check BFF logs. <a href="/login">Try logging in again</a>`);
      }
    });

    // API User route: Returns user info, ID token, and access token if authenticated
    app.post('/api/introspect-token', async (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /api/introspect-token');
        return next(new Error('OIDC client not initialized.'));
      }
      if (!req.session.tokenSet) { // Check for active BFF session providing the tokens
        return res.status(401).json({ error: 'User not authenticated in BFF. Please login first to obtain tokens.' });
      }

      const tokenToIntrospect = req.body.token_to_introspect; // Expecting this in the POST body

      if (!tokenToIntrospect || typeof tokenToIntrospect !== 'string') {
        return res.status(400).json({ error: 'token_to_introspect is required in the request body and must be a string.' });
      }

      try {
        console.log(`Introspecting token (first 20 chars): ${tokenToIntrospect.substring(0, 20)}...`);
        // Use the access_token from the user's session for authentication at introspection endpoint,
        // if PingFederate introspection endpoint requires client authentication or specific token types.
        // Here, we assume the client is configured to introspect any token it has client_id/secret for.
        // If the token being introspected is the session's access_token, that's fine.
        // If it's another token, the client's ability to introspect depends on PingFederate config.
        const introspectionResult = await oidcClient.introspect(tokenToIntrospect);

        res.json(introspectionResult);
      } catch (err) {
        console.error('Error during token introspection:', err.message, err.stack);
        let errorResponse = { error: 'Token introspection failed.', message: err.message };
        if (err.data) {
          errorResponse.details = err.data; // err.data often contains the body from the IDP error response
        }
        res.status(err.statusCode || 500).json(errorResponse);
      }
    });

    app.get('/api/user', (req, res) => {
      if (req.session.userInfo && req.session.tokenSet) { // Ensure both userInfo and tokenSet exist
        res.json({
          message: "User is authenticated. Token details below.",
          id_token: req.session.tokenSet.id_token,
          access_token: req.session.tokenSet.access_token,
          claims: req.session.userInfo // This is req.session.tokenSet.claims()
        });
      } else {
        // If either is missing, consider the user not fully authenticated in the context of this API
        res.status(401).json({ error: 'User not authenticated or session is incomplete. Please login.' });
      }
    });

    // Logout route
    app.get('/logout', async (req, res, next) => {
      if (!oidcClient) {
         console.error('OIDC client not initialized at /logout');
        return next(new Error('OIDC client not initialized. Please check server logs.'));
      }

      const idToken = req.session.tokenSet ? req.session.tokenSet.id_token : undefined;

      req.session.destroy(err => {
        if (err) {
          console.error('Error destroying session:', err);
          return next(err);
        }

        try {
            const endSessionUrl = oidcClient.endSessionUrl({
                id_token_hint: idToken,
                post_logout_redirect_uri: frontendUrl,
            });
            console.log(`Redirecting to PingFederate end session URL: ${endSessionUrl}`);
            res.redirect(endSessionUrl);
        } catch(e) {
            console.warn("Could not construct end_session_url, redirecting to frontend. Is end_session_endpoint configured in OIDC provider metadata?", e.message);
            res.redirect(frontendUrl);
        }
      });
    });

    // Basic error handler
    app.use((err, req, res, next) => {
      console.error("Generic error handler caught:", err.message, err.stack);
      res.status(500).send('Something broke on the server!');
    });

    // Start server
    app.listen(port, () => {
      console.log(`BFF server listening at http://localhost:${port}`);
      if (!oidcClient) {
        console.warn('OIDC client was not initialized by the time server started. Check OIDC discovery logs.');
      }
    });

  })
  .catch(err => {
    if (allowSelfSignedCerts) {
      // Restore original http_options in case of error during discover too
      Issuer[custom.http_options] = originalHttpOptions;
    }
    console.error('Failed to discover OIDC issuer or other critical OIDC setup error:', err.message, err.stack);
    if ((err.message.includes('self-signed certificate') || err.message.includes('unable to verify the first certificate')) && allowSelfSignedCerts) {
        console.error('Self-signed certificate error occurred despite ALLOW_SELF_SIGNED_CERTS=true. The http_options override for Issuer.discover or global customAgent setting might not be effective, or there could be other SSL/TLS issues.');
    } else if (err.message.includes('self-signed certificate') || err.message.includes('unable to verify the first certificate')) {
        console.error('Self-signed certificate error. If this is a development environment with a self-signed cert on PingFederate, set ALLOW_SELF_SIGNED_CERTS=true in your .env file.');
    }
    process.exit(1);
  });
