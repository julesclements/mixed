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
const redirectUri = `${bffBaseUrl}/auth/callback`; // This is the BFF's own redirect URI for OIDC provider
const frontendOrigin = process.env.FRONTEND_ORIGIN; // For CORS
const frontendRedirectUrl = process.env.FRONTEND_REDIRECT_URL; // For application redirects
const allowSelfSignedCerts = process.env.ALLOW_SELF_SIGNED_CERTS === 'true';

if (!pingIssuerUrl || !clientId || !clientSecret || !sessionSecret ||
    !frontendOrigin || !frontendRedirectUrl || !bffBaseUrl) {
  console.error('Missing critical environment variables. Please check your .env file. Ensure PING_ISSUER_URL, PING_CLIENT_ID, PING_CLIENT_SECRET, SESSION_SECRET, FRONTEND_ORIGIN, FRONTEND_REDIRECT_URL, and BFF_BASE_URL are set.');
  process.exit(1);
}

// --- OIDC HTTP Options Customization (for self-signed certs in DEV) ---
let customAgent;
if (allowSelfSignedCerts) {
  console.warn('DEVELOPMENT MODE: Allowing self-signed SSL certificates for OIDC provider. DO NOT USE IN PRODUCTION.');
  customAgent = new https.Agent({ rejectUnauthorized: false });

  custom.setHttpOptionsDefaults({
    agent: customAgent,
    timeout: 5000,
  });
}

// --- Express Middleware Setup ---
const cors = require('cors');
app.use(cors({
  origin: frontendOrigin, // Use frontendOrigin for CORS
  credentials: true,
}));
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

// --- OIDC Client Setup ---
let oidcClient;
const originalHttpOptions = Issuer[custom.http_options]; // Store original for potential restoration

if (allowSelfSignedCerts && customAgent) {
  Issuer[custom.http_options] = (options) => ({
    ...options,
    agent: customAgent,
  });
}

Issuer.discover(pingIssuerUrl)
  .then(issuer => {
    if (allowSelfSignedCerts) {
      Issuer[custom.http_options] = originalHttpOptions; // Restore after discovery
    }
    console.log(`Discovered issuer ${issuer.issuer}`);

    oidcClient = new issuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri], // BFF's own redirect URI
      response_types: ['code'],
    });

    // --- Express Routes ---
    const requestedScopes = ['openid', 'profile', 'email'];

    app.get('/login', (req, res) => {
      const confirmationPageHtml = `
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirm Login</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}h1{color:#333}p{color:#555;margin-bottom:20px}.scopes{font-size:0.9em;color:#666;margin-bottom:25px}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer}.button:hover{background-color:#0056b3}</style></head>
        <body><div class="container"><h1>Confirm Login</h1><p>You are about to be redirected to PingFederate to log in.</p>
        <p class="scopes">This application will request access to the following information: <strong>${requestedScopes.join(', ')}</strong>.</p>
        <form action="/initiate-ping-login" method="GET"><button type="submit" class="button">Proceed to PingFederate</button></form>
        </div></body></html>`;
      res.send(confirmationPageHtml);
    });

    app.get('/initiate-ping-login', (req, res, next) => {
      if (!oidcClient) return next(new Error('OIDC client not initialized.'));
      const state = require('crypto').randomBytes(16).toString('hex');
      req.session.oidcState = state;
      const authUrl = oidcClient.authorizationUrl({ scope: requestedScopes.join(' '), state });
      console.log(`Redirecting to PingFederate for login: ${authUrl}`);
      res.redirect(authUrl);
    });

    app.get('/auth/callback', async (req, res, next) => {
      if (!oidcClient) return next(new Error('OIDC client not initialized.'));
      try {
        const params = oidcClient.callbackParams(req);
        if (!req.session.oidcState || params.state !== req.session.oidcState) {
          if (req.session.oidcState) delete req.session.oidcState;
          return next(new Error('State mismatch or session state missing.'));
        }
        delete req.session.oidcState;
        req.session.oidcCallbackParams = params;
        const authCode = params.code;
        const confirmationPageHtml = `
          <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Confirm Authorization Code</title><style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}h1{color:#333}p{color:#555;margin-bottom:10px}.code-display{background-color:#e9e9e9;padding:10px;border-radius:4px;margin-bottom:20px;word-break:break-all;font-family:monospace}.button{background-color:#007bff;color:white;padding:10px 20px;border:none;border-radius:5px;text-decoration:none;font-size:16px;cursor:pointer}.button:hover{background-color:#0056b3}</style></head>
          <body><div class="container"><h1>Authorization Code Received</h1><p>Auth code:</p><div class="code-display">${authCode}</div>
          <p>Click to exchange code for tokens and proceed.</p><form action="/exchange-code" method="GET"><button type="submit" class="button">Exchange Code & Proceed</button></form>
          </div></body></html>`;
        res.send(confirmationPageHtml);
      } catch (err) {
        if (req.session && req.session.oidcState) delete req.session.oidcState;
        next(err); // Pass to generic error handler
      }
    });

    app.get('/exchange-code', async (req, res, next) => {
      if (!oidcClient) return next(new Error('OIDC client not initialized.'));
      const storedParams = req.session.oidcCallbackParams;
      if (!storedParams) return res.redirect('/login');
      delete req.session.oidcCallbackParams;

      try {
        const tokenSet = await oidcClient.callback(redirectUri, storedParams, { state: storedParams.state });
        req.session.tokenSet = tokenSet;
        req.session.userInfo = tokenSet.claims();
        console.log('Tokens received and stored in session.');
        res.redirect(frontendRedirectUrl); // Use frontendRedirectUrl
      } catch (err) {
        console.error('Error in OIDC token exchange:', err.message, err.stack);
        res.status(500).send(`OIDC token exchange error: ${err.message}. <a href="/login">Retry</a>`);
      }
    });

    app.post('/api/introspect-token', async (req, res, next) => {
      if (!oidcClient) return next(new Error('OIDC client not initialized.'));
      if (!req.session.tokenSet) return res.status(401).json({ error: 'User not authenticated in BFF.' });
      const tokenToIntrospect = req.body.token_to_introspect;
      if (!tokenToIntrospect || typeof tokenToIntrospect !== 'string') {
        return res.status(400).json({ error: 'token_to_introspect is required and must be a string.' });
      }
      try {
        const introspectionResult = await oidcClient.introspect(tokenToIntrospect);
        res.json(introspectionResult);
      } catch (err) {
        let errorResponse = { error: 'Token introspection failed.', message: err.message };
        if (err.data) errorResponse.details = err.data;
        res.status(err.statusCode || 500).json(errorResponse);
      }
    });

    app.get('/api/user', (req, res) => {
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
      if (!oidcClient) return next(new Error('OIDC client not initialized.'));
      const idToken = req.session.tokenSet ? req.session.tokenSet.id_token : undefined;
      req.session.destroy(err => {
        if (err) return next(err);
        try {
          const endSessionUrl = oidcClient.endSessionUrl({
            id_token_hint: idToken,
            post_logout_redirect_uri: frontendRedirectUrl, // Use frontendRedirectUrl
          });
          console.log(`Redirecting to PingFederate end session URL: ${endSessionUrl}`);
          res.redirect(endSessionUrl);
        } catch(e) {
          console.warn("Could not construct end_session_url:", e.message);
          res.redirect(frontendRedirectUrl); // Fallback redirect
        }
      });
    });

    // Basic error handler
    app.use((err, req, res, next) => {
      console.error("Generic error handler:", err.message, err.stack);
      res.status(500).send('Something broke on the server! Check BFF logs.');
    });

    app.listen(port, () => {
      console.log(`BFF server listening at http://localhost:${port}`);
      if (!oidcClient) console.warn('OIDC client not initialized by server start.');
    });
  })
  .catch(err => {
    if (allowSelfSignedCerts) {
      Issuer[custom.http_options] = originalHttpOptions; // Restore on error
    }
    console.error('Failed to discover OIDC issuer or other critical setup error:', err.message, err.stack);
    if ((err.message.includes('self-signed certificate') || err.message.includes('unable to verify the first certificate'))) {
        if (allowSelfSignedCerts) {
            console.error('Self-signed cert error despite ALLOW_SELF_SIGNED_CERTS=true. Check http_options/agent settings or PingFederate TLS setup.');
        } else {
            console.error('Self-signed cert error. For dev with self-signed cert on PingFederate, set ALLOW_SELF_SIGNED_CERTS=true in .env.');
        }
    }
    process.exit(1);
  });
