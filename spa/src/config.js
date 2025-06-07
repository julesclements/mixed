import dotenv from 'dotenv';
dotenv.config();

// Entra ID / Azure AD Configuration
export const config = {
  auth: {
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    tenantId: process.env.TENANT_ID,
    redirectUri: process.env.REDIRECT_URI,
  },
  endpoints: {
    authorizeEndpoint: `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`,
  },
  scopes: ['openid', 'profile', 'email', 'User.Read']
};