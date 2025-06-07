import express from 'express';
import axios from 'axios';
import { config } from '../config.js';
import { generateRandomString } from '../utils/helpers.js';

const router = express.Router();

// Login route - redirects to Entra ID login page
router.get('/login', (req, res) => {
  const state = generateRandomString(16);
  const nonce = generateRandomString(16);
  
  // Store state in session for CSRF protection
  req.session.authState = state;
  
  const queryParams = new URLSearchParams({
    client_id: config.auth.clientId,
    response_type: 'code',
    redirect_uri: config.auth.redirectUri,
    response_mode: 'query',
    scope: config.scopes.join(' '),
    state: state,
    nonce: nonce
  });

  const authorizationUrl = `${config.endpoints.authorizeEndpoint}?${queryParams.toString()}`;
  res.redirect(authorizationUrl);
});

// Callback route - processes the authorization code
router.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  // Validate state to prevent CSRF attacks
  if (state !== req.session.authState) {
    return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
  }
  
  // Check for errors
  if (error) {
    return res.status(400).send(`Authentication error: ${error}`);
  }
  
  if (!code) {
    return res.status(400).send('Authorization code is missing.');
  }
  
  try {
    // Exchange authorization code for tokens
    const tokenResponse = await axios.post(config.endpoints.tokenEndpoint, 
      new URLSearchParams({
        client_id: config.auth.clientId,
        client_secret: config.auth.clientSecret,
        code: code,
        redirect_uri: config.auth.redirectUri,
        grant_type: 'authorization_code',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    // Store user info and tokens in session
    req.session.user = {
      isAuthenticated: true,
      authCode: code, // Store the auth code to display
      accessToken: tokenResponse.data.access_token,
      // Don't store sensitive information like refresh tokens in the session directly in production
    };
    
    // Redirect to auth code display page
    res.redirect('/auth/code');
    
  } catch (error) {
    console.error('Token exchange error:', error.response?.data || error.message);
    res.status(500).send('Failed to authenticate with Entra ID.');
  }
});

// Display auth code route
router.get('/code', (req, res) => {
  if (!req.session.user || !req.session.user.isAuthenticated) {
    return res.redirect('/auth/login');
  }
  
  res.render('authcode', { 
    authCode: req.session.user.authCode 
  });
});

// Logout route
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

export default router;