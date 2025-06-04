// Load environment variables
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { Issuer, Strategy } = require('openid-client');

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

if (!pingIssuerUrl || !clientId || !clientSecret || !sessionSecret || !frontendUrl || !bffBaseUrl) {
  console.error('Missing critical environment variables. Please check your .env file. Ensure PING_ISSUER_URL, PING_CLIENT_ID, PING_CLIENT_SECRET, SESSION_SECRET, FRONTEND_URL, and BFF_BASE_URL are set.');
  process.exit(1);
}

// --- Express Session Setup ---
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// --- OIDC Client Setup ---
let oidcClient;

Issuer.discover(pingIssuerUrl)
  .then(issuer => {
    console.log(`Discovered issuer ${issuer.issuer}`);
    oidcClient = new issuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      response_types: ['code'],
    });

    // --- Express Routes ---

    // Login route: Initiates OIDC flow
    app.get('/login', (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /login');
        return next(new Error('OIDC client not initialized. Please check server logs.'));
      }
      // Add a state parameter for CSRF protection
      const state = require('crypto').randomBytes(16).toString('hex');
      req.session.oidcState = state; // Store state in session to verify on callback

      const authUrl = oidcClient.authorizationUrl({
        scope: 'openid profile email', // Adjust scopes as needed
        state: state,
      });
      console.log(`Redirecting to PingFederate for login: ${authUrl}`);
      res.redirect(authUrl);
    });

    // Callback route: Handles redirect from PingFederate
    app.get('/auth/callback', async (req, res, next) => {
      if (!oidcClient) {
        console.error('OIDC client not initialized at /auth/callback');
        return next(new Error('OIDC client not initialized. Please check server logs.'));
      }
      try {
        const params = oidcClient.callbackParams(req);

        // Verify state parameter
        if (params.state !== req.session.oidcState) {
            console.error('OIDC state mismatch. Possible CSRF attack.');
            return next(new Error('State mismatch. Possible CSRF attack.'));
        }
        delete req.session.oidcState; // State validated, remove from session

        const tokenSet = await oidcClient.callback(redirectUri, params, { state: params.state });

        req.session.tokenSet = tokenSet;
        req.session.userInfo = tokenSet.claims();

        console.log('Tokens received and stored in session.');
        res.redirect(frontendUrl);
      } catch (err) {
        console.error('Error in OIDC callback:', err.message, err.stack);
        res.status(500).send(`OIDC callback error: ${err.message}. Check BFF logs.`);
      }
    });

    // API User route: Returns user info if authenticated
    app.get('/api/user', (req, res) => {
      if (req.session.userInfo) {
        res.json(req.session.userInfo);
      } else {
        res.status(401).json({ error: 'User not authenticated. Please login.' });
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
    console.error('Failed to discover OIDC issuer or other critical OIDC setup error:', err.message, err.stack);
    process.exit(1);
  });
